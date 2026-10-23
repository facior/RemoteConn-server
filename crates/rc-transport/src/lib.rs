//! QUIC transport.
//!
//! TLS only gives us a QUIC connection; certificates are throwaway and not
//! verified. Peers authenticate each other with the Noise XX handshake that
//! runs on the first bidirectional stream, and everything afterwards is sealed
//! with that end-to-end channel (so a relay sees only ciphertext).
//!
//! Wire format on the control stream: records of `u32 BE length || bytes`.
//! After the handshake each record is `seal(flag || chunk)`, where `flag = 1`
//! means more chunks of the same envelope follow.

pub mod frame;
pub mod relay;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rc_crypto::noise::{MAX_PLAINTEXT, OVERHEAD};
use rc_crypto::{DeviceIdentity, Halves, Handshake, Lane, Opener, Sealer};
use rc_proto::{envelope, Datagram, Envelope, Message, MAX_ENVELOPE_LEN};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

pub use quinn::{ClientConfig, Connection, Endpoint, Incoming, RecvStream, SendStream};
pub use tls::{cert_fingerprint, pinned_client_config, SeenFingerprint, ServerIdentity};

/// Default UDP port the host listens on.
pub const DEFAULT_PORT: u16 = 21118;

const MAX_RECORD: usize = MAX_PLAINTEXT + OVERHEAD;
const MAX_CHUNK: usize = MAX_PLAINTEXT - 1;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Relayed datagrams cross two QUIC paths whose MTUs may differ; stay below
/// the 1200-byte minimum QUIC MTU so the relay never has to drop them.
const RELAY_DATAGRAM_CAP: usize = 1100;
/// First record on the bulk stream, proving it belongs to this session.
const BULK_HELLO: &[u8] = b"rc-bulk";
/// How long hole-punching packets keep being sent towards a peer.
const PUNCH_DURATION: Duration = Duration::from_secs(5);

/// How a session reaches the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Direct,
    Relayed,
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("write: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("read: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("datagram: {0}")]
    Datagram(#[from] quinn::SendDatagramError),
    #[error(transparent)]
    Crypto(#[from] rc_crypto::CryptoError),
    #[error("decode: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate: {0}")]
    Cert(#[from] rcgen::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("handshake timed out")]
    Timeout,
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
}

pub type Result<T> = std::result::Result<T, TransportError>;

/// Endpoint accepting incoming sessions (host side). It can also dial out, so
/// the host registers, punches and reaches relays from the same UDP socket
/// (and therefore the same NAT mapping) it accepts viewers on.
pub fn server_endpoint(bind: SocketAddr) -> Result<Endpoint> {
    server_endpoint_with(bind, &ServerIdentity::ephemeral()?)
}

/// Server endpoint with a given (e.g. persistent, pinned) certificate.
pub fn server_endpoint_with(bind: SocketAddr, identity: &ServerIdentity) -> Result<Endpoint> {
    let mut endpoint = Endpoint::server(tls::server_config(identity)?, bind)?;
    endpoint.set_default_client_config(tls::client_config()?);
    Ok(endpoint)
}

/// True when a connection failed because the server's certificate differs
/// from the pinned one.
pub fn is_pin_mismatch(err: &TransportError) -> bool {
    err.to_string().contains(tls::PIN_MISMATCH)
}

/// Endpoint for outgoing sessions (viewer side).
pub fn client_endpoint(bind: SocketAddr) -> Result<Endpoint> {
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(tls::client_config()?);
    Ok(endpoint)
}

/// Unspecified bind address of the same family as `target`.
pub fn any_addr_for(target: SocketAddr) -> SocketAddr {
    if target.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    }
}

/// Connects to whichever candidate answers first; the others are abandoned.
pub async fn dial(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    timeout: Duration,
) -> Result<Connection> {
    dial_with(endpoint, candidates, timeout, None).await
}

/// Like [`dial`], with a specific client config (e.g. a pinned server).
pub async fn dial_with(
    endpoint: &Endpoint,
    candidates: &[SocketAddr],
    timeout: Duration,
    config: Option<quinn::ClientConfig>,
) -> Result<Connection> {
    let mut attempts = JoinSet::new();
    for &addr in candidates {
        let connecting = match &config {
            Some(cfg) => endpoint.connect_with(cfg.clone(), addr, tls::SERVER_NAME)?,
            None => endpoint.connect(addr, tls::SERVER_NAME)?,
        };
        attempts.spawn(connecting);
    }
    let first = tokio::time::timeout(timeout, async {
        let mut last_err = TransportError::Protocol("no address to dial");
        while let Some(result) = attempts.join_next().await {
            match result {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => last_err = e.into(),
                Err(_) => {}
            }
        }
        Err(last_err)
    })
    .await
    .map_err(|_| TransportError::Timeout)?;
    // Dropping the set aborts the slower attempts.
    first
}

/// Sends QUIC Initial packets towards `addr` for a few seconds so this side's
/// NAT lets the peer's packets in (UDP hole punching). Nothing is expected
/// back: the peer is a client and ignores them.
pub fn punch(endpoint: &Endpoint, addr: SocketAddr) {
    if let Ok(connecting) = endpoint.connect(addr, tls::SERVER_NAME) {
        tokio::spawn(async move {
            let _ = tokio::time::timeout(PUNCH_DURATION, connecting).await;
        });
    }
}

/// Viewer: connects directly to `addr` and runs the Noise handshake.
pub async fn connect(
    endpoint: &Endpoint,
    addr: SocketAddr,
    identity: &DeviceIdentity,
) -> Result<SecureConnection> {
    let conn = dial(endpoint, &[addr], HANDSHAKE_TIMEOUT).await?;
    secure_initiator(conn, identity).await
}

/// Host: accepts an incoming connection and runs the handshake as responder.
pub async fn accept(incoming: Incoming, identity: &DeviceIdentity) -> Result<SecureConnection> {
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming)
        .await
        .map_err(|_| TransportError::Timeout)??;
    secure_responder(conn, identity).await
}

/// Noise initiator on a fresh direct connection.
pub async fn secure_initiator(
    conn: Connection,
    identity: &DeviceIdentity,
) -> Result<SecureConnection> {
    let (send, recv) = conn.open_bi().await?;
    initiator_over(conn, send, recv, identity, Path::Direct).await
}

/// Noise responder on a fresh direct connection.
pub async fn secure_responder(
    conn: Connection,
    identity: &DeviceIdentity,
) -> Result<SecureConnection> {
    let (send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.accept_bi())
        .await
        .map_err(|_| TransportError::Timeout)??;
    responder_over(conn, send, recv, identity, Path::Direct).await
}

/// Noise initiator over an existing stream (direct, or piped by a relay).
pub async fn initiator_over(
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    identity: &DeviceIdentity,
    path: Path,
) -> Result<SecureConnection> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut hs = Handshake::initiator(identity)?;
        write_record(&mut send, &hs.write_message(&[])?).await?;
        hs.read_message(&read_record(&mut recv).await?)?;
        write_record(&mut send, &hs.write_message(&[])?).await?;
        SecureConnection::establish(conn, hs, send, recv, path, true).await
    })
    .await
    .map_err(|_| TransportError::Timeout)?
}

/// Noise responder over an existing stream (direct, or piped by a relay).
pub async fn responder_over(
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    identity: &DeviceIdentity,
    path: Path,
) -> Result<SecureConnection> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut hs = Handshake::responder(identity)?;
        hs.read_message(&read_record(&mut recv).await?)?;
        write_record(&mut send, &hs.write_message(&[])?).await?;
        hs.read_message(&read_record(&mut recv).await?)?;
        SecureConnection::establish(conn, hs, send, recv, path, false).await
    })
    .await
    .map_err(|_| TransportError::Timeout)?
}

/// Authenticated session, split into independently usable parts.
pub struct SecureConnection {
    pub path: Path,
    /// Peer address (the relay's address on a relayed session).
    pub remote_addr: SocketAddr,
    /// Peer's Noise static key.
    pub remote_static: [u8; 32],
    /// Channel binding for password authentication.
    pub handshake_hash: [u8; 32],
    pub sender: Sender,
    pub stream: StreamReceiver,
    /// File data, on its own QUIC stream so it never delays input.
    pub bulk: StreamReceiver,
    pub datagrams: DatagramReceiver,
}

impl SecureConnection {
    /// Finishes the handshake and opens (initiator) or accepts (responder)
    /// the bulk stream, which starts with a sealed hello.
    async fn establish(
        conn: quinn::Connection,
        hs: Handshake,
        send: SendStream,
        recv: RecvStream,
        path: Path,
        initiator: bool,
    ) -> Result<Self> {
        let channel = hs.into_channel()?;
        let remote_static = *channel.remote_static();
        let handshake_hash = *channel.handshake_hash();
        let Halves {
            sealer,
            stream: stream_opener,
            datagram: dgram_opener,
            bulk: mut bulk_opener,
        } = channel.split();
        let (bulk_send, bulk_recv) = if initiator {
            let (mut s, r) = conn.open_bi().await?;
            write_record(&mut s, &sealer.seal(Lane::Bulk, BULK_HELLO)?).await?;
            (s, r)
        } else {
            let (s, mut r) = conn.accept_bi().await?;
            if bulk_opener.open(&read_record(&mut r).await?)? != BULK_HELLO {
                return Err(TransportError::Protocol("bad bulk stream hello"));
            }
            (s, r)
        };
        // Input and control go first when both streams have data queued.
        let _ = bulk_send.set_priority(-1);
        Ok(Self {
            path,
            remote_addr: conn.remote_address(),
            remote_static,
            handshake_hash,
            sender: Sender(Arc::new(SenderInner {
                conn: conn.clone(),
                sealer,
                stream: Mutex::new(send),
                bulk: Mutex::new(bulk_send),
                datagram_cap: match path {
                    Path::Direct => usize::MAX,
                    Path::Relayed => RELAY_DATAGRAM_CAP,
                },
            })),
            stream: StreamReceiver {
                recv,
                opener: stream_opener,
            },
            bulk: StreamReceiver {
                recv: bulk_recv,
                opener: bulk_opener,
            },
            datagrams: DatagramReceiver {
                conn,
                opener: dgram_opener,
            },
        })
    }
}

struct SenderInner {
    conn: quinn::Connection,
    sealer: Sealer,
    stream: Mutex<SendStream>,
    bulk: Mutex<SendStream>,
    datagram_cap: usize,
}

/// Sending half; clone it freely across tasks and threads.
#[derive(Clone)]
pub struct Sender(Arc<SenderInner>);

impl Sender {
    /// Sends on the control stream.
    pub async fn send(&self, msg: envelope::Msg) -> Result<()> {
        self.send_on(Lane::Stream, msg).await
    }

    /// Sends on the bulk stream (file transfer).
    pub async fn send_bulk(&self, msg: envelope::Msg) -> Result<()> {
        self.send_on(Lane::Bulk, msg).await
    }

    async fn send_on(&self, lane: Lane, msg: envelope::Msg) -> Result<()> {
        let bytes = Envelope { msg: Some(msg) }.encode_to_vec();
        let chunks: Vec<&[u8]> = bytes.chunks(MAX_CHUNK).collect();
        let mut stream = match lane {
            Lane::Bulk => self.0.bulk.lock().await,
            _ => self.0.stream.lock().await,
        };
        for (i, chunk) in chunks.iter().enumerate() {
            let more = (i + 1 < chunks.len()) as u8;
            let mut plain = Vec::with_capacity(chunk.len() + 1);
            plain.push(more);
            plain.extend_from_slice(chunk);
            let sealed = self.0.sealer.seal(lane, &plain)?;
            write_record(&mut stream, &sealed).await?;
        }
        Ok(())
    }

    /// Fire-and-forget media datagram; may be dropped by the network.
    pub fn send_datagram(&self, datagram: &Datagram) -> Result<()> {
        let sealed = self
            .0
            .sealer
            .seal(Lane::Datagram, &datagram.encode_to_vec())?;
        self.0.conn.send_datagram(Bytes::from(sealed))?;
        Ok(())
    }

    /// Largest encoded [`Datagram`] that fits in one QUIC datagram right now.
    pub fn max_datagram_payload(&self) -> Option<usize> {
        self.0
            .conn
            .max_datagram_size()
            .map(|m| m.min(self.0.datagram_cap).saturating_sub(OVERHEAD))
    }

    pub fn rtt(&self) -> Duration {
        self.0.conn.rtt()
    }

    pub fn stats(&self) -> quinn::ConnectionStats {
        self.0.conn.stats()
    }

    pub fn close(&self, reason: &str) {
        self.0.conn.close(0u32.into(), reason.as_bytes());
    }

    /// Resolves when the connection is closed for any reason.
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.0.conn.closed().await
    }
}

pub struct StreamReceiver {
    recv: RecvStream,
    opener: Opener,
}

impl StreamReceiver {
    pub async fn recv(&mut self) -> Result<envelope::Msg> {
        let mut message = Vec::new();
        loop {
            let plain = self.opener.open(&read_record(&mut self.recv).await?)?;
            let (&more, chunk) = plain
                .split_first()
                .ok_or(TransportError::Protocol("empty record"))?;
            if message.len() + chunk.len() > MAX_ENVELOPE_LEN {
                return Err(TransportError::Protocol("envelope too large"));
            }
            message.extend_from_slice(chunk);
            if more == 0 {
                break;
            }
        }
        Envelope::decode(message.as_slice())?
            .msg
            .ok_or(TransportError::Protocol("empty envelope"))
    }
}

pub struct DatagramReceiver {
    conn: quinn::Connection,
    opener: Opener,
}

impl DatagramReceiver {
    pub async fn recv(&mut self) -> Result<Datagram> {
        loop {
            let raw = self.conn.read_datagram().await?;
            // Forged, replayed or corrupt datagrams are silently dropped.
            let Ok(plain) = self.opener.open(&raw) else {
                continue;
            };
            if let Ok(datagram) = Datagram::decode(plain.as_slice()) {
                return Ok(datagram);
            }
        }
    }
}

async fn write_record(stream: &mut SendStream, data: &[u8]) -> Result<()> {
    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

async fn read_record(stream: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_RECORD {
        return Err(TransportError::Protocol("record too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_proto::{datagram, ChatMessage, VideoPacket};

    async fn pair() -> (SecureConnection, SecureConnection, [u8; 32], [u8; 32]) {
        let (viewer_id, host_id) = (DeviceIdentity::generate(), DeviceIdentity::generate());
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let host_pub = host_id.noise_public();
        let viewer_pub = viewer_id.noise_public();
        let host_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            accept(incoming, &host_id).await.unwrap()
        });
        let viewer = connect(&client, addr, &viewer_id).await.unwrap();
        let host = host_task.await.unwrap();
        (viewer, host, viewer_pub, host_pub)
    }

    #[tokio::test]
    async fn handshake_and_messages() {
        let (viewer, mut host, viewer_pub, host_pub) = pair().await;
        assert_eq!(viewer.remote_static, host_pub);
        assert_eq!(host.remote_static, viewer_pub);
        assert_eq!(viewer.handshake_hash, host.handshake_hash);

        let chat = envelope::Msg::Chat(ChatMessage {
            text: "cześć".into(),
            sent_unix_ms: 42,
        });
        viewer.sender.send(chat.clone()).await.unwrap();
        assert_eq!(host.stream.recv().await.unwrap(), chat);
    }

    #[tokio::test]
    async fn large_envelope_is_chunked() {
        let (viewer, mut host, _, _) = pair().await;
        let big = envelope::Msg::Chat(ChatMessage {
            text: "x".repeat(300_000),
            sent_unix_ms: 0,
        });
        viewer.sender.send(big.clone()).await.unwrap();
        assert_eq!(host.stream.recv().await.unwrap(), big);
    }

    #[tokio::test]
    async fn bulk_stream_is_independent() {
        let (viewer, mut host, _, _) = pair().await;
        let file = envelope::Msg::Chat(ChatMessage {
            text: "f".repeat(200_000),
            sent_unix_ms: 0,
        });
        let input = envelope::Msg::Chat(ChatMessage {
            text: "click".into(),
            sent_unix_ms: 1,
        });
        viewer.sender.send_bulk(file.clone()).await.unwrap();
        viewer.sender.send(input.clone()).await.unwrap();
        assert_eq!(host.stream.recv().await.unwrap(), input);
        assert_eq!(host.bulk.recv().await.unwrap(), file);
    }

    #[tokio::test]
    async fn datagrams_roundtrip() {
        let (mut viewer, host, _, _) = pair().await;
        let max = host.sender.max_datagram_payload().unwrap();
        assert!(max > 1000, "datagram payload {max}");
        let dg = Datagram {
            msg: Some(datagram::Msg::Video(VideoPacket {
                frame_id: 1,
                fragment_count: 1,
                data: vec![7; 900],
                ..Default::default()
            })),
        };
        host.sender.send_datagram(&dg).unwrap();
        assert_eq!(viewer.datagrams.recv().await.unwrap(), dg);
    }
}
