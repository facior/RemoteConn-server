//! Device registration, lookup and NAT traversal signalling.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngCore;
use rc_crypto::identity::verify_signature;
use rc_proto::rendezvous::{
    client_message, lookup_result::Status, server_message::Msg, ClientMessage, Error, Lookup,
    LookupResult, PunchRequest, Register, Registered, RelayOffer, ServerHello, ServerMessage,
    PROTOCOL_VERSION, REGISTER_CONTEXT,
};
use rc_transport::{frame, Connection, RecvStream, Result, SendStream, TransportError};
use tokio::sync::mpsc;

use crate::registry::RegisterError;
use crate::Server;

const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
/// A lookup's token is valid for punching and relaying this long.
const TOKEN_TTL: Duration = Duration::from_secs(120);
const MAX_LOCAL_ADDRS: usize = 8;

struct OnlineHost {
    push: mpsc::UnboundedSender<ServerMessage>,
    observed: SocketAddr,
    local_addrs: Vec<String>,
    noise_public: Vec<u8>,
    name: String,
    generation: u64,
    since_unix: i64,
}

/// What the admin panel shows about an online host.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OnlineSnapshot {
    pub id: String,
    pub name: String,
    pub observed: String,
    pub since_unix: i64,
}

struct TokenInfo {
    created: Instant,
    /// A relay may be requested once per lookup; repeated requests would make
    /// the host open relay connections over and over.
    relay_requested: bool,
}

#[derive(Default)]
pub struct Sessions {
    online: Mutex<HashMap<String, OnlineHost>>,
    tokens: Mutex<HashMap<Vec<u8>, TokenInfo>>,
    generation: AtomicU64,
}

impl Sessions {
    pub fn expire(&self) {
        self.tokens
            .lock()
            .unwrap()
            .retain(|_, t| t.created.elapsed() < TOKEN_TTL);
    }

    pub fn token_valid(&self, token: &[u8]) -> bool {
        self.tokens
            .lock()
            .unwrap()
            .get(token)
            .is_some_and(|t| t.created.elapsed() < TOKEN_TTL)
    }

    /// Drops the registration of every online host matching `blocked`;
    /// returns their IDs.
    pub fn kick(&self, blocked: impl Fn(&str) -> bool) -> Vec<String> {
        let mut kicked = Vec::new();
        self.online.lock().unwrap().retain(|id, _| {
            let keep = !blocked(id);
            if !keep {
                tracing::info!(%id, "blocked host disconnected");
                kicked.push(id.clone());
            }
            keep
        });
        kicked
    }

    /// Disconnects one host (it reconnects on its own unless blocked).
    pub fn kick_one(&self, id: &str) -> bool {
        self.online.lock().unwrap().remove(id).is_some()
    }

    pub fn online_count(&self) -> usize {
        self.online.lock().unwrap().len()
    }

    pub fn online(&self) -> Vec<OnlineSnapshot> {
        let mut out: Vec<_> = self
            .online
            .lock()
            .unwrap()
            .iter()
            .map(|(id, h)| OnlineSnapshot {
                id: id.clone(),
                name: h.name.clone(),
                observed: h.observed.to_string(),
                since_unix: h.since_unix,
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Records the relay request; false if one was already made.
    pub fn mark_relay_requested(&self, token: &[u8]) -> bool {
        match self.tokens.lock().unwrap().get_mut(token) {
            Some(t) if !t.relay_requested => {
                t.relay_requested = true;
                true
            }
            _ => false,
        }
    }

    /// A token pairs exactly one relay session.
    pub fn consume_token(&self, token: &[u8]) {
        self.tokens.lock().unwrap().remove(token);
    }

    /// Sends a message to an online host; false if it is not online.
    pub fn push(&self, device_id: &str, msg: Msg) -> bool {
        self.online
            .lock()
            .unwrap()
            .get(device_id)
            .is_some_and(|h| h.push.send(ServerMessage { msg: Some(msg) }).is_ok())
    }
}

fn server_msg(msg: Msg) -> ServerMessage {
    ServerMessage { msg: Some(msg) }
}

pub async fn serve(
    server: Arc<Server>,
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    frame::write(
        &mut send,
        &ServerHello {
            challenge: challenge.to_vec(),
            protocol_version: PROTOCOL_VERSION,
            error: String::new(),
        },
    )
    .await?;
    let first: ClientMessage = tokio::time::timeout(FIRST_MESSAGE_TIMEOUT, frame::read(&mut recv))
        .await
        .map_err(|_| TransportError::Timeout)??;
    let account_request = matches!(
        first.msg,
        Some(
            client_message::Msg::AccountPrelogin(_)
                | client_message::Msg::AccountRegister(_)
                | client_message::Msg::AccountLogin(_)
                | client_message::Msg::AccountCall(_)
        )
    );
    if account_request {
        let peer = conn.remote_address();
        return crate::accounts::serve_stream(server, peer, send, recv, &challenge, first).await;
    }
    match first.msg {
        Some(client_message::Msg::Register(r)) => {
            serve_host(server, conn, send, recv, &challenge, r).await
        }
        Some(client_message::Msg::Lookup(l)) => serve_viewer(server, conn, send, recv, l).await,
        _ => Err(TransportError::Protocol("expected Register or Lookup")),
    }
}

async fn reply_error(send: &mut SendStream, message: &str) {
    let _ = frame::write(
        send,
        &server_msg(Msg::Error(Error {
            message: message.into(),
        })),
    )
    .await;
}

fn sanitize_addrs(addrs: Vec<String>) -> Vec<String> {
    addrs
        .into_iter()
        .filter(|a| a.parse::<SocketAddr>().is_ok())
        .take(MAX_LOCAL_ADDRS)
        .collect()
}

async fn serve_host(
    server: Arc<Server>,
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    challenge: &[u8],
    reg: Register,
) -> Result<()> {
    let keys = (
        <[u8; 32]>::try_from(reg.verifying_key.as_slice()),
        <[u8; 32]>::try_from(reg.noise_public.as_slice()),
        <[u8; 64]>::try_from(reg.signature.as_slice()),
    );
    let (Ok(vk), Ok(noise_public), Ok(sig)) = keys else {
        reply_error(&mut send, "malformed keys").await;
        return Err(TransportError::Protocol("malformed keys"));
    };
    let signed = [REGISTER_CONTEXT, challenge, &noise_public].concat();
    if verify_signature(&vk, &signed, &sig).is_err() {
        reply_error(&mut send, "invalid signature").await;
        return Err(TransportError::Protocol("invalid signature"));
    }

    let name = rc_proto::text::clean_label(&reg.device_name, 64);
    let observed = conn.remote_address();
    let registered = server
        .registry
        .register(&reg.device_id, &vk, &noise_public, &name, || {
            server
                .new_devices
                .lock()
                .unwrap()
                .allow(observed.ip(), Instant::now())
        });
    let id = match registered {
        Ok(id) => id,
        Err(e) => {
            let message = match e {
                RegisterError::RateLimited => "too many new devices from this network, try later",
                RegisterError::Full => "the server is full",
                RegisterError::Io(_) => "server storage error",
            };
            reply_error(&mut send, message).await;
            return Err(TransportError::Protocol("registration refused"));
        }
    };
    if server.blocklist.read().unwrap().device_blocked(&id) {
        reply_error(&mut send, "this device is blocked on the server").await;
        return Err(TransportError::Protocol("blocked device"));
    }
    let (push, mut pushes) = mpsc::unbounded_channel();
    let generation = server.sessions.generation.fetch_add(1, Ordering::Relaxed);
    // Replacing an older connection drops its push channel, which ends it.
    server.sessions.online.lock().unwrap().insert(
        id.clone(),
        OnlineHost {
            push,
            observed,
            local_addrs: sanitize_addrs(reg.local_addrs),
            noise_public: noise_public.to_vec(),
            name: name.clone(),
            generation,
            since_unix: crate::events::unix_now(),
        },
    );
    frame::write(
        &mut send,
        &server_msg(Msg::Registered(Registered {
            device_id: id.clone(),
            observed_addr: observed.to_string(),
        })),
    )
    .await?;
    tracing::info!(%id, %observed, "host online");
    server
        .events
        .push("host_online", format!("{id} „{name}” online z {observed}"));
    // A host on an account learns about key changes and revoked devices.
    let account = rc_crypto::account::normalize_name(&reg.account_name);
    if !account.is_empty() && server.accounts.device_bound(&account, &id) {
        if let Some(update) = server.accounts.update_for(&account) {
            server.sessions.push(&id, Msg::AccountUpdate(update));
        }
    }

    let result = loop {
        tokio::select! {
            msg = pushes.recv() => match msg {
                Some(msg) => {
                    if let Err(e) = frame::write(&mut send, &msg).await {
                        break Err(e);
                    }
                }
                None => break Ok(()),
            },
            // Hosts send nothing after registering; this only detects closure.
            read = frame::read::<ClientMessage>(&mut recv) => {
                if let Err(e) = read {
                    break Err(e);
                }
            }
        }
    };

    {
        let mut online = server.sessions.online.lock().unwrap();
        if online.get(&id).is_some_and(|h| h.generation == generation) {
            online.remove(&id);
        }
    }
    tracing::info!(%id, "host offline");
    server.events.push("host_offline", format!("{id} offline"));
    result
}

async fn serve_viewer(
    server: Arc<Server>,
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    lookup: Lookup,
) -> Result<()> {
    let viewer_addr = conn.remote_address();
    let device_id: String = lookup
        .device_id
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let allowed = server
        .lookups
        .lock()
        .unwrap()
        .allow(viewer_addr.ip(), Instant::now());

    let mut token = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let blocked = server.blocklist.read().unwrap().device_blocked(&device_id);
    let result = if !allowed {
        status_only(Status::RateLimited)
    } else if blocked {
        // Indistinguishable from an unknown ID.
        status_only(Status::NotFound)
    } else {
        let online = server.sessions.online.lock().unwrap();
        match online.get(&device_id) {
            Some(host) => {
                server.sessions.tokens.lock().unwrap().insert(
                    token.clone(),
                    TokenInfo {
                        created: Instant::now(),
                        relay_requested: false,
                    },
                );
                // LAN addresses are shared only within one network (same public
                // IP): they are useless elsewhere, reveal the internal network,
                // and would let a stranger make the host send packets into it.
                let same_network = crate::same_ip(viewer_addr, host.observed);
                let _ = host.push.send(server_msg(Msg::Punch(PunchRequest {
                    session_token: token.clone(),
                    viewer_addr: viewer_addr.to_string(),
                    viewer_local_addrs: if same_network {
                        sanitize_addrs(lookup.local_addrs)
                    } else {
                        Vec::new()
                    },
                })));
                LookupResult {
                    status: Status::Online as i32,
                    observed_addr: host.observed.to_string(),
                    local_addrs: if same_network {
                        host.local_addrs.clone()
                    } else {
                        Vec::new()
                    },
                    noise_public: host.noise_public.clone(),
                    session_token: token.clone(),
                    device_name: host.name.clone(),
                }
            }
            None if server.registry.exists(&device_id) => status_only(Status::Offline),
            None => status_only(Status::NotFound),
        }
    };
    let online = result.status() == Status::Online;
    frame::write(&mut send, &server_msg(Msg::LookupResult(result))).await?;
    if !online {
        return Ok(());
    }

    // The viewer keeps the stream open in case it needs the relay.
    loop {
        let msg: ClientMessage = frame::read(&mut recv).await?;
        let Some(client_message::Msg::RequestRelay(req)) = msg.msg else {
            continue;
        };
        if req.session_token != token || !server.sessions.token_valid(&token) {
            reply_error(&mut send, "session expired").await;
            continue;
        }
        if !server.sessions.mark_relay_requested(&token) {
            reply_error(&mut send, "relay already requested").await;
            continue;
        }
        let offer = RelayOffer {
            session_token: token.clone(),
            relay_addr: server.relay_addr.clone(),
            viewer_addr: viewer_addr.to_string(),
        };
        if !server
            .sessions
            .push(&device_id, Msg::RelayOffer(offer.clone()))
        {
            reply_error(&mut send, "host went offline").await;
            continue;
        }
        tracing::info!(id = %device_id, viewer = %viewer_addr, "relaying session");
        server.events.push(
            "relay_request",
            format!("relay do {device_id} dla {viewer_addr}"),
        );
        frame::write(&mut send, &server_msg(Msg::RelayOffer(offer))).await?;
    }
}

fn status_only(status: Status) -> LookupResult {
    LookupResult {
        status: status as i32,
        ..Default::default()
    }
}
