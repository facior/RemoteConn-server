//! TLS for QUIC.
//!
//! Between peers, identity comes from Noise, so certificates are throwaway and
//! accepted as-is. The rendezvous server instead has a persistent certificate
//! that clients pin (trust on first use), so a fake server is detected.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::{Result, TransportError};

pub const SERVER_NAME: &str = "remoteconn";
const ALPN: &[u8] = b"remoteconn/1";
/// Control + bulk per peer session; a few rendezvous/relay streams per server
/// connection. More is never needed, so a peer cannot open hundreds.
const MAX_BIDI_STREAMS: u32 = 8;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut cfg = quinn::TransportConfig::default();
    cfg.keep_alive_interval(Some(Duration::from_secs(5)))
        .max_idle_timeout(Some(
            Duration::from_secs(30).try_into().expect("valid timeout"),
        ))
        .max_concurrent_bidi_streams(MAX_BIDI_STREAMS.into())
        .max_concurrent_uni_streams(0u32.into())
        .datagram_receive_buffer_size(Some(8 << 20))
        .datagram_send_buffer_size(8 << 20);
    Arc::new(cfg)
}

/// A certificate and its key, kept across restarts by the rendezvous server.
pub struct ServerIdentity {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}

impl ServerIdentity {
    /// Throwaway identity (peer-to-peer hosts).
    pub fn ephemeral() -> Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.into()])?;
        Ok(Self {
            cert: cert.cert.der().clone(),
            key: cert.key_pair.serialize_der(),
        })
    }

    /// Loads `server.crt` / `server.key` from `dir`, creating them on first run.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let (cert_path, key_path) = (dir.join("server.crt"), dir.join("server.key"));
        if let (Ok(cert), Ok(key)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
            return Ok(Self {
                cert: CertificateDer::from(cert),
                key,
            });
        }
        std::fs::create_dir_all(dir)?;
        let identity = Self::ephemeral()?;
        // A key without its certificate (interrupted first run) is replaced.
        let _ = std::fs::remove_file(&key_path);
        write_private(&key_path, &identity.key)?;
        std::fs::write(&cert_path, identity.cert.as_ref())?;
        Ok(identity)
    }

    /// What clients pin: BLAKE3 of the certificate.
    pub fn fingerprint(&self) -> [u8; 32] {
        cert_fingerprint(&self.cert)
    }
}

/// Writes a secret readable by the owner only (0600 on Unix), created that
/// way from the start so it is never briefly world-readable.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(data)
}

pub fn cert_fingerprint(cert: &CertificateDer<'_>) -> [u8; 32] {
    *blake3::hash(cert.as_ref()).as_bytes()
}

pub fn server_config(identity: &ServerIdentity) -> Result<quinn::ServerConfig> {
    let key = PrivatePkcs8KeyDer::from(identity.key.clone());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert.clone()], key.into())?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicServerConfig::try_from(crypto)
        .map_err(|_| TransportError::Protocol("no QUIC cipher suite"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
    cfg.transport_config(transport_config());
    Ok(cfg)
}

fn client_config_with(verifier: Arc<dyn ServerCertVerifier>) -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(crypto)
        .map_err(|_| TransportError::Protocol("no QUIC cipher suite"))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(quic));
    cfg.transport_config(transport_config());
    Ok(cfg)
}

/// For peer connections: any certificate (Noise authenticates the peer).
pub fn client_config() -> Result<quinn::ClientConfig> {
    client_config_with(Arc::new(CertCheck {
        provider: provider(),
        expected: None,
        seen: Arc::default(),
    }))
}

/// Fingerprint of the server certificate seen by a pinned connection.
pub type SeenFingerprint = Arc<Mutex<Option<[u8; 32]>>>;

/// For the rendezvous server: with `expected`, any other certificate is
/// rejected; without it (first contact) the seen fingerprint is recorded so
/// the caller can pin it.
pub fn pinned_client_config(
    expected: Option<[u8; 32]>,
) -> Result<(quinn::ClientConfig, SeenFingerprint)> {
    let seen = SeenFingerprint::default();
    let cfg = client_config_with(Arc::new(CertCheck {
        provider: provider(),
        expected,
        seen: seen.clone(),
    }))?;
    Ok((cfg, seen))
}

/// Error text for a pin mismatch, recognisable by callers.
pub const PIN_MISMATCH: &str = "server certificate does not match the pinned one";

/// Handshake signatures are always checked, so the TLS session itself is
/// sound; the certificate is accepted, pinned or compared with the pin.
#[derive(Debug)]
struct CertCheck {
    provider: Arc<CryptoProvider>,
    expected: Option<[u8; 32]>,
    seen: SeenFingerprint,
}

impl ServerCertVerifier for CertCheck {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fingerprint = cert_fingerprint(end_entity);
        *self.seen.lock().unwrap() = Some(fingerprint);
        match self.expected {
            Some(expected) if expected != fingerprint => {
                Err(rustls::Error::General(PIN_MISMATCH.into()))
            }
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
