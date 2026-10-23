//! Relay: pairs the two peers of a session by token and pipes their control
//! stream and datagrams. Contents are Noise ciphertext the relay cannot read.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;

use rc_proto::rendezvous::{relay_bind::Role, RelayBind, RelayReady};
use rc_transport::relay::BIND_TIMEOUT;
use rc_transport::{frame, Connection, RecvStream, Result, SendStream, TransportError};

use crate::Server;

const CHUNK: usize = 64 * 1024;

struct Waiting {
    role: Role,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    since: Instant,
}

/// Peers waiting for their partner, at most.
const MAX_WAITING: usize = 10_000;

struct Session {
    a: Connection,
    b: Connection,
    since_unix: i64,
    bytes: Arc<AtomicU64>,
}

/// What the admin panel shows about a relayed session (never its content).
#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub id: u64,
    pub a: String,
    pub b: String,
    pub since_unix: i64,
    pub bytes: u64,
}

pub struct Relay {
    waiting: Mutex<HashMap<Vec<u8>, Waiting>>,
    active: AtomicUsize,
    max_active: usize,
    sessions: Mutex<HashMap<u64, Session>>,
    next_id: AtomicU64,
    total_bytes: AtomicU64,
}

/// Counts one active relayed session for its lifetime.
struct ActiveSlot<'a>(&'a AtomicUsize);

impl Drop for ActiveSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Relay {
    pub fn new(max_active: usize) -> Self {
        Self {
            waiting: Mutex::new(HashMap::new()),
            active: AtomicUsize::new(0),
            max_active,
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            total_bytes: AtomicU64::new(0),
        }
    }

    fn try_activate(&self) -> Option<ActiveSlot<'_>> {
        let previous = self.active.fetch_add(1, Ordering::Relaxed);
        let slot = ActiveSlot(&self.active);
        (previous < self.max_active).then_some(slot)
    }

    /// Drops peers whose partner never arrived.
    pub fn expire(&self) {
        self.waiting
            .lock()
            .unwrap()
            .retain(|_, w| w.since.elapsed() < BIND_TIMEOUT);
    }

    pub fn active_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Bytes relayed since start, finished sessions included.
    pub fn total_bytes(&self) -> u64 {
        let live: u64 = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| s.bytes.load(Ordering::Relaxed))
            .sum();
        self.total_bytes.load(Ordering::Relaxed) + live
    }

    pub fn snapshot(&self) -> Vec<SessionSnapshot> {
        let mut out: Vec<_> = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, s)| SessionSnapshot {
                id,
                a: s.a.remote_address().to_string(),
                b: s.b.remote_address().to_string(),
                since_unix: s.since_unix,
                bytes: s.bytes.load(Ordering::Relaxed),
            })
            .collect();
        out.sort_by_key(|s| s.id);
        out
    }

    /// Ends a relayed session; both peers see the connection close.
    pub fn close(&self, id: u64) -> bool {
        match self.sessions.lock().unwrap().get(&id) {
            Some(s) => {
                s.a.close(0u32.into(), b"closed by admin");
                s.b.close(0u32.into(), b"closed by admin");
                true
            }
            None => false,
        }
    }
}

pub async fn bind(
    server: Arc<Server>,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    bind: RelayBind,
) -> Result<()> {
    if !server.access_allowed(&bind.access_key) {
        return Err(TransportError::Protocol("wrong access key"));
    }
    let role = bind.role();
    if role == Role::Unspecified {
        return Err(TransportError::Protocol("relay role missing"));
    }
    let token = bind.session_token;
    if !server.sessions.token_valid(&token) {
        return Err(TransportError::Protocol("unknown relay token"));
    }
    let me = Waiting {
        role,
        conn,
        send,
        recv,
        since: Instant::now(),
    };
    let other = {
        let mut waiting = server.relay.waiting.lock().unwrap();
        match waiting.remove(&token) {
            Some(other) if other.role != me.role => other,
            // First to arrive (or a duplicate of the same side) waits.
            _ if waiting.len() >= MAX_WAITING => {
                return Err(TransportError::Protocol("relay busy"));
            }
            _ => {
                waiting.insert(token, me);
                return Ok(());
            }
        }
    };
    server.sessions.consume_token(&token);
    let Some(_slot) = server.relay.try_activate() else {
        tracing::warn!("relay session limit reached");
        me.conn.close(0u32.into(), b"relay busy");
        other.conn.close(0u32.into(), b"relay busy");
        return Err(TransportError::Protocol("relay session limit reached"));
    };
    pipe(&server, me, other).await
}

async fn pipe(server: &Server, mut a: Waiting, mut b: Waiting) -> Result<()> {
    frame::write(&mut a.send, &RelayReady {}).await?;
    frame::write(&mut b.send, &RelayReady {}).await?;
    let (ac, bc) = (a.conn.clone(), b.conn.clone());
    let (a_addr, b_addr) = (ac.remote_address(), bc.remote_address());
    tracing::info!(a = %a_addr, b = %b_addr, "relay paired");
    let relay = &server.relay;
    let id = relay.next_id.fetch_add(1, Ordering::Relaxed);
    let bytes = Arc::new(AtomicU64::new(0));
    relay.sessions.lock().unwrap().insert(
        id,
        Session {
            a: ac.clone(),
            b: bc.clone(),
            since_unix: crate::events::unix_now(),
            bytes: bytes.clone(),
        },
    );
    server
        .events
        .push("relay_start", format!("relay #{id}: {a_addr} ⇄ {b_addr}"));

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(copy(a.recv, b.send, bytes.clone()));
    tasks.spawn(copy(b.recv, a.send, bytes.clone()));
    tasks.spawn(forward(ac.clone(), bc.clone(), bytes.clone()));
    tasks.spawn(forward(bc.clone(), ac.clone(), bytes.clone()));
    // Streams opened later (e.g. the bulk file stream) are mirrored too.
    tasks.spawn(mirror_streams(ac.clone(), bc.clone(), bytes.clone()));
    tasks.spawn(mirror_streams(bc.clone(), ac.clone(), bytes.clone()));
    tokio::select! {
        _ = ac.closed() => {}
        _ = bc.closed() => {}
    }
    ac.close(0u32.into(), b"relay closed");
    bc.close(0u32.into(), b"relay closed");
    tasks.abort_all();

    relay.sessions.lock().unwrap().remove(&id);
    let total = bytes.load(Ordering::Relaxed);
    relay.total_bytes.fetch_add(total, Ordering::Relaxed);
    tracing::info!(bytes = total, "relay session ended");
    server.events.push(
        "relay_end",
        format!("relay #{id} zakończony ({} KiB)", total / 1024),
    );
    Ok(())
}

async fn mirror_streams(from: Connection, to: Connection, bytes: Arc<AtomicU64>) {
    while let Ok((from_send, from_recv)) = from.accept_bi().await {
        let Ok((to_send, to_recv)) = to.open_bi().await else {
            return;
        };
        tokio::spawn(copy(from_recv, to_send, bytes.clone()));
        tokio::spawn(copy(to_recv, from_send, bytes.clone()));
    }
}

async fn copy(mut from: RecvStream, mut to: SendStream, bytes: Arc<AtomicU64>) {
    while let Ok(Some(chunk)) = from.read_chunk(CHUNK, true).await {
        bytes.fetch_add(chunk.bytes.len() as u64, Ordering::Relaxed);
        if to.write_chunk(chunk.bytes).await.is_err() {
            return;
        }
    }
    let _ = to.finish();
}

async fn forward(from: Connection, to: Connection, bytes: Arc<AtomicU64>) {
    while let Ok(datagram) = from.read_datagram().await {
        bytes.fetch_add(datagram.len() as u64, Ordering::Relaxed);
        // Too large or congested datagrams are dropped, like on any lossy path.
        let _ = to.send_datagram(datagram);
    }
}
