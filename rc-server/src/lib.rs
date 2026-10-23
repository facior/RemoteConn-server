//! Rendezvous and relay server.
//!
//! One QUIC endpoint serves both roles; the first frame on each client stream
//! (`Open`) says which. The server never sees session content: peers run their
//! own Noise handshake end to end, through the relay if needed.
//!
//! Abuse protection: address validation (QUIC Retry) before any state is
//! kept, per-client and global connection limits, rate limits on lookups and
//! on new device IDs, a cap on relay sessions, and an optional access key that
//! limits the server to your own clients.

pub mod accounts;
pub mod admin;
pub mod blocklist;
mod events;
mod limiter;
mod registry;
mod relay;
mod rendezvous;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use limiter::{ConnectionCounter, Limiter};
use rc_proto::rendezvous::{open, Open, ServerHello, PROTOCOL_VERSION};
use rc_transport::{frame, Connection, Endpoint, Result, ServerIdentity, TransportError};

pub use registry::Registry;

pub const DEFAULT_PORT: u16 = 21116;

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ServerConfig {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    /// Advertised relay (`host:port`); empty means this server.
    pub relay_addr: String,
    /// Clients must present this key; empty = open server.
    pub access_key: String,
    /// Concurrent relayed sessions.
    pub max_relays: usize,
    /// Open connections per client (IPv4 address or IPv6 /64).
    pub max_connections_per_client: u32,
    /// Admin web panel address; `None` disables it. Keep it on loopback and
    /// reach it through an SSH tunnel.
    pub admin_bind: Option<SocketAddr>,
    /// Extra host names the panel answers to (besides localhost), needed only
    /// when it is reached without a tunnel.
    pub admin_hosts: Vec<String>,
    /// Who may create accounts (`RC_ACCOUNTS`).
    pub signup: accounts::Signup,
    /// Address clients type in (`host:port`, `RC_PUBLIC_ADDR`), shown in the
    /// panel's configuration code; empty = unknown.
    pub public_addr: String,
}

impl ServerConfig {
    pub fn new(bind: SocketAddr, data_dir: PathBuf) -> Self {
        Self {
            bind,
            data_dir,
            relay_addr: String::new(),
            access_key: String::new(),
            max_relays: 200,
            max_connections_per_client: 32,
            admin_bind: None,
            admin_hosts: Vec::new(),
            signup: accounts::Signup::default(),
            public_addr: String::new(),
        }
    }
}

const MAX_CONNECTIONS: u32 = 50_000;

pub(crate) struct Server {
    pub registry: Registry,
    pub sessions: rendezvous::Sessions,
    pub relay: relay::Relay,
    pub lookups: Mutex<Limiter>,
    /// New device IDs per client.
    pub new_devices: Mutex<Limiter>,
    pub connections: Mutex<ConnectionCounter>,
    pub blocklist: RwLock<blocklist::Blocklist>,
    pub relay_addr: String,
    access_key_hash: Option<blake3::Hash>,
    /// Kept for the configuration code shown to panel administrators.
    access_key: String,
    pub public_addr: String,
    pub events: events::EventLog,
    pub data_dir: PathBuf,
    pub started_unix: i64,
    pub fingerprint: [u8; 32],
    pub max_relays: usize,
    pub accounts: accounts::AccountStore,
    pub signup: accounts::Signup,
    /// Account sign-up and login attempts per client.
    pub account_ops: Mutex<Limiter>,
}

impl Server {
    /// Constant-time comparison (through hashes) with the configured key.
    pub fn access_allowed(&self, key: &str) -> bool {
        match &self.access_key_hash {
            None => true,
            Some(expected) => *expected == blake3::hash(key.as_bytes()),
        }
    }

    pub fn access_key_set(&self) -> bool {
        self.access_key_hash.is_some()
    }

    /// Server address, access key and certificate for the app, or `None`
    /// while the public address is not configured.
    pub fn config_code(&self) -> Option<rc_rendezvous::ConfigCode> {
        (!self.public_addr.is_empty()).then(|| rc_rendezvous::ConfigCode {
            server: self.public_addr.clone(),
            access_key: self.access_key.clone(),
            fingerprint: self.fingerprint,
        })
    }

    /// Replaces the blocklist file and applies it at once (admin actions).
    pub fn save_blocklist(&self, entries: &[blocklist::Entry]) -> std::io::Result<()> {
        blocklist::write(&blocklist::path_in(&self.data_dir), entries)?;
        self.apply_blocklist(blocklist::Blocklist::from_entries(entries));
        Ok(())
    }

    /// Blocked hosts that are online lose their registration at once.
    fn apply_blocklist(&self, list: blocklist::Blocklist) {
        for id in self.sessions.kick(|id| list.device_blocked(id)) {
            self.events
                .push("blocked", format!("{id} rozłączony (zablokowany)"));
        }
        *self.blocklist.write().unwrap() = list;
    }
}

pub struct ServerHandle {
    endpoint: Endpoint,
    pub local_addr: SocketAddr,
    /// Certificate fingerprint clients pin (shown at startup).
    pub fingerprint: [u8; 32],
    /// Where the admin panel listens, if enabled.
    pub admin_addr: Option<SocketAddr>,
}

impl ServerHandle {
    pub fn stop(&self) {
        self.endpoint.close(0u32.into(), b"server stopping");
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub async fn start(cfg: ServerConfig) -> Result<ServerHandle> {
    let registry = Registry::open(cfg.data_dir.join("devices.json"))?;
    let data_dir = cfg.data_dir.clone();
    let identity = ServerIdentity::load_or_create(&cfg.data_dir)?;
    let endpoint = rc_transport::server_endpoint_with(cfg.bind, &identity)?;
    let local_addr = endpoint.local_addr()?;
    let access_key = cfg.access_key.trim();
    let server = Arc::new(Server {
        registry,
        sessions: Default::default(),
        relay: relay::Relay::new(cfg.max_relays),
        lookups: Mutex::new(Limiter::new(Duration::from_secs(60), 30)),
        new_devices: Mutex::new(Limiter::new(Duration::from_secs(3600), 10)),
        connections: Mutex::new(ConnectionCounter::new(
            cfg.max_connections_per_client,
            MAX_CONNECTIONS,
        )),
        blocklist: RwLock::new(blocklist::Blocklist::default()),
        relay_addr: cfg.relay_addr,
        access_key_hash: (!access_key.is_empty()).then(|| blake3::hash(access_key.as_bytes())),
        access_key: access_key.to_string(),
        public_addr: cfg.public_addr.trim().to_string(),
        events: Default::default(),
        data_dir: data_dir.clone(),
        started_unix: events::unix_now(),
        fingerprint: identity.fingerprint(),
        max_relays: cfg.max_relays,
        accounts: accounts::AccountStore::open(&data_dir)?,
        signup: cfg.signup,
        account_ops: Mutex::new(Limiter::new(Duration::from_secs(60), 20)),
    });
    let admin_addr = match cfg.admin_bind {
        Some(bind) => Some(admin::start(server.clone(), bind, cfg.admin_hosts).await?),
        None => None,
    };

    let ep = endpoint.clone();
    let srv = server.clone();
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            // Make the client prove it owns its source address before we keep
            // any state, so spoofed packets cannot use up others' limits.
            if !incoming.remote_address_validated() {
                let _ = incoming.retry();
                continue;
            }
            let ip = incoming.remote_address().ip();
            if srv.blocklist.read().unwrap().ip_blocked(ip) {
                incoming.refuse();
                continue;
            }
            if !srv.connections.lock().unwrap().acquire(ip) {
                incoming.refuse();
                continue;
            }
            let srv = srv.clone();
            tokio::spawn(async move {
                if let Ok(Ok(conn)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
                    serve_connection(srv.clone(), conn).await;
                }
                srv.connections.lock().unwrap().release(ip);
            });
        }
    });

    let srv = server.clone();
    let mut watcher = blocklist::Watcher::new(blocklist::path_in(&data_dir));
    if let Some(list) = watcher.poll() {
        *server.blocklist.write().unwrap() = list;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut rounds = 0u32;
        loop {
            tick.tick().await;
            if let Some(list) = watcher.poll() {
                srv.apply_blocklist(list);
            }
            rounds += 1;
            if rounds % 2 == 0 {
                srv.sessions.expire();
                srv.relay.expire();
            }
        }
    });

    Ok(ServerHandle {
        endpoint,
        local_addr,
        fingerprint: identity.fingerprint(),
        admin_addr,
    })
}

async fn serve_connection(server: Arc<Server>, conn: Connection) {
    let peer = conn.remote_address();
    if let Err(e) = dispatch_streams(server, conn.clone()).await {
        tracing::debug!(%peer, "connection ended: {e}");
    }
    // Keep the slot until the connection is really gone.
    conn.closed().await;
}

/// Each rendezvous stream is served on its own task. A relay bind takes over
/// the whole connection: later streams (the peers' bulk stream) belong to the
/// relay, so this loop must stop accepting them.
async fn dispatch_streams(server: Arc<Server>, conn: Connection) -> Result<()> {
    loop {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let open: Open = tokio::time::timeout(OPEN_TIMEOUT, frame::read(&mut recv))
            .await
            .map_err(|_| TransportError::Timeout)??;
        match open.kind {
            Some(open::Kind::Rendezvous(o)) => {
                if !server.access_allowed(&o.access_key) {
                    let refusal = ServerHello {
                        error: "access denied".into(),
                        protocol_version: PROTOCOL_VERSION,
                        ..Default::default()
                    };
                    let _ = frame::write(&mut send, &refusal).await;
                    let _ = send.finish();
                    return Err(TransportError::Protocol("wrong access key"));
                }
                let (server, conn) = (server.clone(), conn.clone());
                tokio::spawn(async move {
                    let peer = conn.remote_address();
                    if let Err(e) = rendezvous::serve(server, conn, send, recv).await {
                        tracing::debug!(%peer, "rendezvous stream ended: {e}");
                    }
                });
            }
            Some(open::Kind::Relay(bind)) => {
                return relay::bind(server, conn, send, recv, bind).await;
            }
            None => return Err(TransportError::Protocol("empty Open")),
        }
    }
}

/// First 8 bytes as `xxxx-xxxx-xxxx-xxxx`, the form the app shows.
pub fn short_fingerprint(fp: &[u8; 32]) -> String {
    fp[..8]
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join("-")
}

/// True when both addresses share a public IP (same network behind one NAT).
pub(crate) fn same_ip(a: SocketAddr, b: SocketAddr) -> bool {
    let norm = |ip: IpAddr| match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    norm(a.ip()) == norm(b.ip())
}
