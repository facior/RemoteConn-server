//! Client side of the rendezvous server.
//!
//! Both functions must use the endpoint that carries the peer-to-peer
//! session: the server reports the endpoint's public address to the other
//! peer, and that address is only valid for this UDP socket.
//!
//! The server's certificate is pinned (trust on first use): callers pass the
//! fingerprint saved earlier, and get the observed one back to save it.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use rc_crypto::DeviceIdentity;
use rc_proto::rendezvous::{
    client_message, lookup_result::Status, open, server_message::Msg, ClientMessage, Lookup, Open,
    Register, RendezvousOpen, RequestRelay, ServerHello, ServerMessage, PROTOCOL_VERSION,
    REGISTER_CONTEXT,
};
use rc_transport::{
    dial_with, frame, pinned_client_config, ClientConfig, Endpoint, RecvStream, SendStream,
    TransportError,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

mod account;
mod config_code;

pub use account::{
    account_call, account_login, account_register, change_password, AccountLogin, AccountOp,
};
pub use config_code::{ConfigCode, ConfigCodeError};
pub use rc_proto::rendezvous::relay_bind::Role as RelayRole;
pub use rc_proto::rendezvous::{AccountDevice, AccountUpdate};

/// Default UDP port of the rendezvous server.
pub const DEFAULT_PORT: u16 = 21116;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum RendezvousError {
    #[error("rendezvous server unreachable: {0}")]
    Transport(#[from] TransportError),
    #[error("the server's certificate changed since it was first trusted")]
    PinMismatch,
    #[error("the server refused access: {0}")]
    AccessDenied(String),
    #[error("unknown ID")]
    NotFound,
    #[error("the device is offline")]
    Offline,
    #[error("too many lookups, try again in a minute")]
    RateLimited,
    #[error("server error: {0}")]
    Server(String),
    #[error("unexpected reply from server")]
    Protocol,
}

pub type Result<T> = std::result::Result<T, RendezvousError>;

/// How to reach and trust a rendezvous server.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub addr: SocketAddr,
    /// The server's access key; empty if it has none.
    pub access_key: String,
    /// Certificate fingerprint trusted earlier; `None` on first contact.
    pub pin: Option<[u8; 32]>,
}

impl ServerInfo {
    /// Client config for connections to the server itself (or its relay):
    /// pinned when a fingerprint is known.
    fn pinned(&self) -> Result<(ClientConfig, rc_transport::SeenFingerprint)> {
        Ok(pinned_client_config(self.pin)?)
    }

    /// Relay connection parameters: the pin applies only when the relay is
    /// this server (a separate relay has its own certificate; the relay
    /// token and end-to-end Noise protect that path).
    pub fn relay_config(&self, relay: SocketAddr) -> Result<Option<ClientConfig>> {
        (relay == self.addr)
            .then(|| self.pinned().map(|(c, _)| c))
            .transpose()
    }
}

/// Formats a 9-digit ID as `123 456 789`.
pub fn format_id(id: &str) -> String {
    let digits: Vec<char> = id.chars().filter(char::is_ascii_digit).collect();
    digits
        .chunks(3)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Accepts `123 456 789`, `123-456-789` or `123456789`.
pub fn parse_id(input: &str) -> Option<String> {
    let trimmed: String = input.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
    (trimmed.len() == 9 && trimmed.chars().all(|c| c.is_ascii_digit())).then_some(trimmed)
}

/// This machine's LAN addresses combined with `port`, for same-network peers.
pub fn local_addrs(port: u16) -> Vec<SocketAddr> {
    // Connecting a UDP socket sends nothing; it only selects the interface.
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("192.0.2.1:9").map(|_| s))
        .and_then(|s| s.local_addr())
        .ok()
        .filter(|a| !a.ip().is_unspecified())
        .map(|a| vec![SocketAddr::new(a.ip(), port)])
        .unwrap_or_default()
}

/// Opens a rendezvous stream; returns it with the server's hello and the
/// certificate fingerprint that was seen.
pub(crate) async fn open_rendezvous(
    endpoint: &Endpoint,
    server: &ServerInfo,
) -> Result<(SendStream, RecvStream, ServerHello, [u8; 32])> {
    let (config, seen) = server.pinned()?;
    let conn = dial_with(endpoint, &[server.addr], CONNECT_TIMEOUT, Some(config))
        .await
        .map_err(|e| {
            if rc_transport::is_pin_mismatch(&e) {
                RendezvousError::PinMismatch
            } else {
                e.into()
            }
        })?;
    let fingerprint = seen.lock().unwrap().ok_or(RendezvousError::Protocol)?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(TransportError::from)?;
    frame::write(
        &mut send,
        &Open {
            kind: Some(open::Kind::Rendezvous(RendezvousOpen {
                protocol_version: PROTOCOL_VERSION,
                access_key: server.access_key.clone(),
            })),
        },
    )
    .await?;
    let hello: ServerHello = read_timeout(&mut recv).await?;
    if !hello.error.is_empty() {
        return Err(RendezvousError::AccessDenied(hello.error));
    }
    Ok((send, recv, hello, fingerprint))
}

pub(crate) async fn read_timeout<M: rc_proto::Message + Default>(
    recv: &mut RecvStream,
) -> Result<M> {
    Ok(tokio::time::timeout(REPLY_TIMEOUT, frame::read(recv))
        .await
        .map_err(|_| TransportError::Timeout)??)
}

/// Checks that a rendezvous server answers and accepts our access key;
/// returns its certificate fingerprint.
pub async fn ping(endpoint: &Endpoint, server: &ServerInfo) -> Result<[u8; 32]> {
    open_rendezvous(endpoint, server).await.map(|r| r.3)
}

pub(crate) fn client(msg: client_message::Msg) -> ClientMessage {
    ClientMessage { msg: Some(msg) }
}

/// LAN addresses are only useful (and only safe to act on) when both sides
/// are behind the same public IP, i.e. on the same network.
fn same_network(a: &str, b: &str) -> bool {
    let ip = |s: &str| s.parse::<SocketAddr>().ok().map(|a| a.ip());
    matches!((ip(a), ip(b)), (Some(x), Some(y)) if x == y)
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------

pub struct HostRegistration {
    pub server: ServerInfo,
    pub identity: Arc<DeviceIdentity>,
    /// ID from a previous registration, empty for a new device.
    pub device_id: String,
    pub device_name: String,
    /// Account this host trusts (empty: none); the server then sends updates.
    pub account_name: String,
}

#[derive(Debug, Clone)]
pub enum HostEvent {
    Registered {
        device_id: String,
        public_addr: String,
        /// Certificate fingerprint of the server (save it to pin).
        server_fingerprint: [u8; 32],
    },
    Disconnected(RendezvousErrorKind, String),
    /// A viewer could not connect directly; meet it at the relay.
    RelayOffer {
        relay: SocketAddr,
        token: Vec<u8>,
        viewer_addr: SocketAddr,
        relay_config: Option<ClientConfig>,
    },
    /// Key changes and revoked devices of the trusted account (from the
    /// server: verify rotations before following them).
    AccountUpdate(AccountUpdate),
}

/// Coarse reason for a lost registration, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousErrorKind {
    Unreachable,
    PinMismatch,
    AccessDenied,
    Other,
}

impl RendezvousError {
    pub fn kind(&self) -> RendezvousErrorKind {
        match self {
            RendezvousError::Transport(_) => RendezvousErrorKind::Unreachable,
            RendezvousError::PinMismatch => RendezvousErrorKind::PinMismatch,
            RendezvousError::AccessDenied(_) => RendezvousErrorKind::AccessDenied,
            _ => RendezvousErrorKind::Other,
        }
    }
}

/// Keeps the host registered (reconnecting with backoff) and answers punch
/// requests. Abort the returned task to unregister.
pub fn spawn_host(
    endpoint: Endpoint,
    cfg: HostRegistration,
    events: mpsc::UnboundedSender<HostEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut cfg = cfg;
        let mut backoff = Duration::from_secs(1);
        loop {
            let result = run_host(&endpoint, &mut cfg, &events, &mut backoff).await;
            let (kind, reason) = match result {
                Ok(()) => (
                    RendezvousErrorKind::Unreachable,
                    "server closed the connection".to_string(),
                ),
                Err(e) => (e.kind(), e.to_string()),
            };
            tracing::warn!(server = %cfg.server.addr, "rendezvous: {reason}");
            if events.send(HostEvent::Disconnected(kind, reason)).is_err() {
                return;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    })
}

async fn run_host(
    endpoint: &Endpoint,
    cfg: &mut HostRegistration,
    events: &mpsc::UnboundedSender<HostEvent>,
    backoff: &mut Duration,
) -> Result<()> {
    let (mut send, mut recv, hello, fingerprint) = open_rendezvous(endpoint, &cfg.server).await?;
    // Pin for the rest of this run (the caller persists it).
    cfg.server.pin.get_or_insert(fingerprint);
    let noise_public = cfg.identity.noise_public();
    let signed = [REGISTER_CONTEXT, &hello.challenge, &noise_public].concat();
    let port = endpoint.local_addr().map_err(TransportError::from)?.port();
    frame::write(
        &mut send,
        &client(client_message::Msg::Register(Register {
            device_id: cfg.device_id.clone(),
            verifying_key: cfg.identity.verifying_key().to_vec(),
            noise_public: noise_public.to_vec(),
            signature: cfg.identity.sign(&signed).to_vec(),
            local_addrs: local_addrs(port).iter().map(ToString::to_string).collect(),
            device_name: cfg.device_name.clone(),
            account_name: cfg.account_name.clone(),
        })),
    )
    .await?;
    let public_addr = match read_timeout::<ServerMessage>(&mut recv).await?.msg {
        Some(Msg::Registered(r)) => {
            cfg.device_id = r.device_id.clone();
            *backoff = Duration::from_secs(1);
            let _ = events.send(HostEvent::Registered {
                device_id: r.device_id,
                public_addr: r.observed_addr.clone(),
                server_fingerprint: fingerprint,
            });
            r.observed_addr
        }
        Some(Msg::Error(e)) => return Err(RendezvousError::Server(e.message)),
        _ => return Err(RendezvousError::Protocol),
    };

    loop {
        let msg: ServerMessage = frame::read(&mut recv).await?;
        match msg.msg {
            Some(Msg::Punch(p)) => {
                // LAN addresses only for a viewer on our own network: anything
                // else would let a stranger make us send packets into our LAN.
                let lan = same_network(&p.viewer_addr, &public_addr);
                let targets = std::iter::once(&p.viewer_addr)
                    .chain(p.viewer_local_addrs.iter().filter(|_| lan))
                    .filter_map(|a| a.parse::<SocketAddr>().ok())
                    .filter(|a| is_routable_target(a.ip()));
                for addr in targets {
                    rc_transport::punch(endpoint, addr);
                }
            }
            Some(Msg::AccountUpdate(update)) => {
                let _ = events.send(HostEvent::AccountUpdate(update));
            }
            Some(Msg::RelayOffer(offer)) => {
                let relay = resolve_relay(&offer.relay_addr, cfg.server.addr);
                let viewer_addr = offer.viewer_addr.parse();
                if let (Some(relay), Ok(viewer_addr)) = (relay, viewer_addr) {
                    let _ = events.send(HostEvent::RelayOffer {
                        relay,
                        token: offer.session_token,
                        viewer_addr,
                        relay_config: cfg.server.relay_config(relay)?,
                    });
                }
            }
            _ => {}
        }
    }
}

/// Never punch towards loopback (no NAT to open), unspecified or multicast
/// addresses.
fn is_routable_target(ip: IpAddr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_loopback())
}

/// An empty relay address means the rendezvous server itself.
fn resolve_relay(relay_addr: &str, server: SocketAddr) -> Option<SocketAddr> {
    if relay_addr.is_empty() {
        Some(server)
    } else {
        relay_addr.parse().ok()
    }
}

// ---------------------------------------------------------------------------
// Viewer
// ---------------------------------------------------------------------------

/// A successful lookup. Keep it alive until connected: dropping it closes the
/// stream through which a relay can still be requested.
pub struct Found {
    pub device_name: String,
    /// LAN addresses first (same-network peers), then the public one.
    pub candidates: Vec<SocketAddr>,
    /// The only Noise key the viewer may accept from this host.
    pub noise_public: [u8; 32],
    /// Certificate fingerprint of the server (save it to pin).
    pub server_fingerprint: [u8; 32],
    server: ServerInfo,
    token: Vec<u8>,
    send: SendStream,
    recv: RecvStream,
}

pub async fn lookup(endpoint: &Endpoint, server: &ServerInfo, device_id: &str) -> Result<Found> {
    let (mut send, mut recv, _hello, fingerprint) = open_rendezvous(endpoint, server).await?;
    let port = endpoint.local_addr().map_err(TransportError::from)?.port();
    frame::write(
        &mut send,
        &client(client_message::Msg::Lookup(Lookup {
            device_id: device_id.into(),
            local_addrs: local_addrs(port).iter().map(ToString::to_string).collect(),
        })),
    )
    .await?;
    let result = match read_timeout::<ServerMessage>(&mut recv).await?.msg {
        Some(Msg::LookupResult(r)) => r,
        Some(Msg::Error(e)) => return Err(RendezvousError::Server(e.message)),
        _ => return Err(RendezvousError::Protocol),
    };
    match result.status() {
        Status::Online => {}
        Status::Offline => return Err(RendezvousError::Offline),
        Status::NotFound => return Err(RendezvousError::NotFound),
        Status::RateLimited => return Err(RendezvousError::RateLimited),
        Status::Unspecified => return Err(RendezvousError::Protocol),
    }
    let noise_public = result
        .noise_public
        .as_slice()
        .try_into()
        .map_err(|_| RendezvousError::Protocol)?;
    let candidates = result
        .local_addrs
        .iter()
        .chain(std::iter::once(&result.observed_addr))
        .filter_map(|a| a.parse().ok())
        .collect();
    let mut server = server.clone();
    server.pin.get_or_insert(fingerprint);
    Ok(Found {
        device_name: result.device_name,
        candidates,
        noise_public,
        server_fingerprint: fingerprint,
        server,
        token: result.session_token,
        send,
        recv,
    })
}

impl Found {
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    pub fn access_key(&self) -> &str {
        &self.server.access_key
    }

    /// Asks the server to bring the host to a relay; returns the relay address
    /// and the client config to reach it.
    pub async fn request_relay(&mut self) -> Result<(SocketAddr, Option<ClientConfig>)> {
        frame::write(
            &mut self.send,
            &client(client_message::Msg::RequestRelay(RequestRelay {
                session_token: self.token.clone(),
            })),
        )
        .await?;
        match read_timeout::<ServerMessage>(&mut self.recv).await?.msg {
            Some(Msg::RelayOffer(offer)) => {
                let relay = resolve_relay(&offer.relay_addr, self.server.addr)
                    .ok_or(RendezvousError::Protocol)?;
                Ok((relay, self.server.relay_config(relay)?))
            }
            Some(Msg::Error(e)) => Err(RendezvousError::Server(e.message)),
            _ => Err(RendezvousError::Protocol),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_formatting() {
        assert_eq!(format_id("123456789"), "123 456 789");
        assert_eq!(parse_id("123 456 789").as_deref(), Some("123456789"));
        assert_eq!(parse_id("123-456-789").as_deref(), Some("123456789"));
        assert_eq!(parse_id("12345678"), None);
        assert_eq!(parse_id("192.168.1.2"), None);
    }

    #[test]
    fn lan_only_for_same_public_ip() {
        assert!(same_network("203.0.113.5:4000", "203.0.113.5:21118"));
        assert!(!same_network("198.51.100.7:4000", "203.0.113.5:21118"));
        assert!(!same_network("garbage", "203.0.113.5:21118"));
    }
}
