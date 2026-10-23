//! User accounts (`accounts.json` in the data directory).
//!
//! The server keeps each account's public key and salt, never a password or
//! a private key (see rc-crypto `account`): it can tell devices apart and
//! take access away, but it cannot let anyone into a computer.
//!
//! Sign-up is by invitation by default (`RC_ACCOUNTS=invite`): an
//! administrator creates a one-time code in the panel or with
//! `rc-server account invite`.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngCore;
use rc_crypto::account::{self as acc, SALT_LEN};
use rc_crypto::identity::verify_signature;
use rc_proto::rendezvous::{
    account_call, client_message, server_message::Msg, AccountCall, AccountDevice, AccountReply,
    AccountSalt, AccountSession, AccountUpdate, ClientMessage, KeyRotation, ServerMessage,
};
use rc_transport::{frame, RecvStream, Result, SendStream, TransportError};
use serde::{Deserialize, Serialize};

use crate::events::unix_now;
use crate::Server;

const FILE: &str = "accounts.json";
const SECRET_FILE: &str = "accounts.secret";
const SESSION_TTL_SECS: i64 = 30 * 24 * 3600;
const MAX_SESSIONS: usize = 20;
const MAX_DEVICES: usize = 100;
const MAX_ACCOUNTS: usize = 100_000;
pub const INVITE_TTL_SECS: i64 = 7 * 24 * 3600;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_MESSAGES_PER_STREAM: usize = 50;
const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_LOGIN_FAILURES: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Signup {
    Off,
    #[default]
    Invite,
    Open,
}

impl Signup {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "off" => Some(Signup::Off),
            "invite" => Some(Signup::Invite),
            "open" => Some(Signup::Open),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    #[serde(default)]
    pub device_id: String,
    pub noise_public: String,
    pub name: String,
    pub added_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rotation {
    old: String,
    new: String,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRecord {
    token_hash: String,
    created_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub display_name: String,
    pub public_key: String,
    salt: String,
    pub created_unix: i64,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub revoked: Vec<String>,
    #[serde(default)]
    rotations: Vec<Rotation>,
    #[serde(default)]
    sessions: Vec<SessionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub created_unix: i64,
    pub expires_unix: i64,
    pub note: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Data {
    accounts: BTreeMap<String, Account>,
    /// Keyed by the BLAKE3 hash of the code.
    invites: BTreeMap<String, Invite>,
}

/// What the admin panel shows about an account.
#[derive(Debug, Clone, Serialize)]
pub struct AccountSummary {
    pub name: String,
    pub display_name: String,
    pub created_unix: i64,
    pub disabled: bool,
    pub devices: Vec<Device>,
    pub revoked: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccountError {
    Message(&'static str),
    Io(String),
}

impl AccountError {
    fn text(&self) -> String {
        match self {
            AccountError::Message(m) => (*m).to_string(),
            AccountError::Io(_) => "błąd zapisu na serwerze".into(),
        }
    }
}

type AResult<T> = std::result::Result<T, AccountError>;

fn msg(m: &'static str) -> AccountError {
    AccountError::Message(m)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn key32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

fn token_hash(token: &[u8]) -> String {
    hex(blake3::hash(token).as_bytes())
}

pub struct AccountStore {
    path: PathBuf,
    secret: [u8; 32],
    data: Mutex<Data>,
    /// Modification time of the file as last read or written; a different
    /// one means `rc-server account …` changed it, so it is read again.
    seen: Mutex<Option<std::time::SystemTime>>,
    failures: Mutex<HashMap<String, (Instant, u32)>>,
}

impl AccountStore {
    pub fn open(data_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(FILE);
        let data = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Data::default(),
            Err(e) => return Err(e),
        };
        let secret_path = data_dir.join(SECRET_FILE);
        let secret = match std::fs::read(&secret_path) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => {
                let mut fresh = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut fresh);
                write_private(&secret_path, &fresh)?;
                fresh
            }
        };
        let seen = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        Ok(Self {
            path,
            secret,
            data: Mutex::new(data),
            seen: Mutex::new(seen),
            failures: Mutex::new(HashMap::new()),
        })
    }

    /// The data, re-read first if the file was changed by someone else.
    fn lock(&self) -> std::sync::MutexGuard<'_, Data> {
        let mut data = self.data.lock().unwrap();
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        let mut seen = self.seen.lock().unwrap();
        if modified.is_some() && modified != *seen {
            match std::fs::read(&self.path).map(|b| serde_json::from_slice::<Data>(&b)) {
                Ok(Ok(fresh)) => *data = fresh,
                _ => tracing::warn!(
                    "accounts.json changed but cannot be read; keeping the loaded data"
                ),
            }
            *seen = modified;
        }
        data
    }

    fn save(&self, data: &Data) -> AResult<()> {
        let bytes = serde_json::to_vec_pretty(data).map_err(|e| AccountError::Io(e.to_string()))?;
        write_private(&self.path, &bytes).map_err(|e| AccountError::Io(e.to_string()))?;
        *self.seen.lock().unwrap() = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        Ok(())
    }

    /// The account's salt, or a stable fake one for unknown names.
    pub fn salt_for(&self, name: &str) -> [u8; SALT_LEN] {
        if let Some(salt) = self
            .lock()
            .accounts
            .get(name)
            .and_then(|a| unhex(&a.salt))
            .and_then(|s| s.try_into().ok())
        {
            return salt;
        }
        let fake = blake3::keyed_hash(&self.secret, format!("salt\0{name}").as_bytes());
        fake.as_bytes()[..SALT_LEN].try_into().unwrap()
    }

    pub fn create_invite(&self, note: &str) -> AResult<String> {
        const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let mut raw = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let code: String = raw
            .iter()
            .map(|b| CHARS[*b as usize % CHARS.len()] as char)
            .collect::<String>()
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-");
        let now = unix_now();
        let mut data = self.lock();
        data.invites.retain(|_, i| i.expires_unix > now);
        data.invites.insert(
            invite_key(&code),
            Invite {
                created_unix: now,
                expires_unix: now + INVITE_TTL_SECS,
                note: rc_proto::text::clean_label(note, 64),
            },
        );
        self.save(&data)?;
        Ok(code)
    }

    pub fn invites(&self) -> Vec<(String, Invite)> {
        let now = unix_now();
        self.lock()
            .invites
            .iter()
            .filter(|(_, i)| i.expires_unix > now)
            .map(|(k, i)| (k[..8].to_string(), i.clone()))
            .collect()
    }

    pub fn delete_invite(&self, key_prefix: &str) -> AResult<bool> {
        let mut data = self.lock();
        let before = data.invites.len();
        data.invites
            .retain(|k, _| key_prefix.len() < 8 || !k.starts_with(key_prefix));
        let removed = data.invites.len() != before;
        if removed {
            self.save(&data)?;
        }
        Ok(removed)
    }

    fn new_session(account: &mut Account) -> Vec<u8> {
        let mut token = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token);
        let now = unix_now();
        account
            .sessions
            .retain(|s| now - s.created_unix < SESSION_TTL_SECS);
        if account.sessions.len() >= MAX_SESSIONS {
            account.sessions.remove(0);
        }
        account.sessions.push(SessionRecord {
            token_hash: token_hash(&token),
            created_unix: now,
        });
        token
    }

    pub fn register(
        &self,
        signup: Signup,
        name: &str,
        invite: &str,
        salt: &[u8],
        public_key: &[u8],
        display_name: &str,
    ) -> AResult<Vec<u8>> {
        if signup == Signup::Off {
            return Err(msg("zakładanie kont jest wyłączone na tym serwerze"));
        }
        if !acc::valid_name(name) {
            return Err(msg("nieprawidłowa nazwa konta"));
        }
        let (Some(_), Ok(salt)) = (key32(public_key), <[u8; SALT_LEN]>::try_from(salt)) else {
            return Err(msg("nieprawidłowy klucz"));
        };
        let mut data = self.lock();
        if data.accounts.contains_key(name) {
            return Err(msg("konto o tej nazwie już istnieje"));
        }
        if data.accounts.len() >= MAX_ACCOUNTS {
            return Err(msg("serwer jest pełny"));
        }
        let now = unix_now();
        if signup == Signup::Invite {
            let key = invite_key(invite);
            match data.invites.get(&key) {
                Some(i) if i.expires_unix > now => {
                    data.invites.remove(&key);
                }
                _ => return Err(msg("nieprawidłowy lub wygasły kod zaproszenia")),
            }
        }
        let display = rc_proto::text::clean_label(display_name, 64);
        let mut account = Account {
            display_name: if display.trim().is_empty() {
                name.to_string()
            } else {
                display
            },
            public_key: hex(public_key),
            salt: hex(&salt),
            created_unix: now,
            disabled: false,
            devices: Vec::new(),
            revoked: Vec::new(),
            rotations: Vec::new(),
            sessions: Vec::new(),
        };
        let token = Self::new_session(&mut account);
        data.accounts.insert(name.to_string(), account);
        self.save(&data)?;
        Ok(token)
    }

    fn locked_out(&self, name: &str) -> bool {
        let mut failures = self.failures.lock().unwrap();
        failures.retain(|_, (start, _)| start.elapsed() < LOGIN_WINDOW);
        failures
            .get(name)
            .is_some_and(|(_, n)| *n >= MAX_LOGIN_FAILURES)
    }

    fn record_failure(&self, name: &str) {
        let mut failures = self.failures.lock().unwrap();
        let entry = failures
            .entry(name.to_string())
            .or_insert((Instant::now(), 0));
        entry.1 += 1;
    }

    /// Checks the challenge signature; returns (token, display name).
    pub fn login(
        &self,
        name: &str,
        challenge: &[u8],
        signature: &[u8],
    ) -> AResult<(Vec<u8>, String)> {
        const BAD: &str = "nieprawidłowa nazwa konta lub hasło";
        if self.locked_out(name) {
            return Err(msg("zbyt wiele nieudanych logowań, spróbuj za 15 minut"));
        }
        let mut data = self.lock();
        let verified = data.accounts.get(name).is_some_and(|a| {
            let (Some(public), Ok(sig)) = (
                unhex(&a.public_key).and_then(|k| key32(&k)),
                <[u8; 64]>::try_from(signature),
            ) else {
                return false;
            };
            acc::verify_login(&public, name, challenge, &sig)
        });
        if !verified {
            drop(data);
            self.record_failure(name);
            return Err(msg(BAD));
        }
        let account = data.accounts.get_mut(name).expect("verified above");
        if account.disabled {
            return Err(msg("konto jest zablokowane przez administratora"));
        }
        let token = Self::new_session(account);
        let display = account.display_name.clone();
        self.save(&data)?;
        drop(data);
        self.failures.lock().unwrap().remove(name);
        Ok((token, display))
    }

    /// Name of the account a session token belongs to.
    fn session_owner(data: &Data, token: &[u8]) -> Option<String> {
        let hash = token_hash(token);
        let now = unix_now();
        data.accounts
            .iter()
            .find(|(_, a)| {
                !a.disabled
                    && a.sessions
                        .iter()
                        .any(|s| s.token_hash == hash && now - s.created_unix < SESSION_TTL_SECS)
            })
            .map(|(name, _)| name.clone())
    }

    pub fn update_for(&self, name: &str) -> Option<AccountUpdate> {
        let data = self.lock();
        let a = data.accounts.get(name)?;
        Some(AccountUpdate {
            public_key: unhex(&a.public_key).unwrap_or_default(),
            rotations: a
                .rotations
                .iter()
                .map(|r| KeyRotation {
                    old_public_key: unhex(&r.old).unwrap_or_default(),
                    new_public_key: unhex(&r.new).unwrap_or_default(),
                    signature: unhex(&r.signature).unwrap_or_default(),
                })
                .collect(),
            revoked: a.revoked.iter().filter_map(|r| unhex(r)).collect(),
            disabled: a.disabled,
        })
    }

    /// True when `device_id` is on account `name` (and not revoked).
    pub fn device_bound(&self, name: &str, device_id: &str) -> bool {
        self.lock()
            .accounts
            .get(name)
            .is_some_and(|a| a.devices.iter().any(|d| d.device_id == device_id))
    }

    /// Device IDs on the account (to push updates to those online).
    pub fn bound_ids(&self, name: &str) -> Vec<String> {
        self.lock()
            .accounts
            .get(name)
            .map(|a| {
                a.devices
                    .iter()
                    .filter(|d| !d.device_id.is_empty())
                    .map(|d| d.device_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn summaries(&self) -> Vec<AccountSummary> {
        self.lock()
            .accounts
            .iter()
            .map(|(name, a)| AccountSummary {
                name: name.clone(),
                display_name: a.display_name.clone(),
                created_unix: a.created_unix,
                disabled: a.disabled,
                devices: a.devices.clone(),
                revoked: a.revoked.len(),
            })
            .collect()
    }

    /// Owner account of each bound device ID (for the devices list).
    pub fn owners(&self) -> HashMap<String, String> {
        let data = self.lock();
        let mut out = HashMap::new();
        for (name, a) in &data.accounts {
            for d in &a.devices {
                if !d.device_id.is_empty() {
                    out.insert(d.device_id.clone(), name.clone());
                }
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.lock().accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn set_disabled(&self, name: &str, disabled: bool) -> AResult<()> {
        let mut data = self.lock();
        let a = data
            .accounts
            .get_mut(name)
            .ok_or(msg("nie ma takiego konta"))?;
        a.disabled = disabled;
        if disabled {
            a.sessions.clear();
        }
        self.save(&data)
    }

    pub fn delete(&self, name: &str) -> AResult<()> {
        let mut data = self.lock();
        data.accounts
            .remove(name)
            .ok_or(msg("nie ma takiego konta"))?;
        self.save(&data)
    }

    /// Revokes a device (noise key, hex) on an account.
    pub fn revoke(&self, name: &str, noise_public_hex: &str) -> AResult<()> {
        let mut data = self.lock();
        let a = data
            .accounts
            .get_mut(name)
            .ok_or(msg("nie ma takiego konta"))?;
        revoke_in(a, noise_public_hex);
        self.save(&data)
    }

    /// Handles a call made with a session token.
    pub(crate) fn call(
        &self,
        server: &Server,
        call: AccountCall,
    ) -> (AccountReply, Option<String>) {
        let mut data = self.lock();
        let Some(name) = Self::session_owner(&data, &call.token) else {
            return (reply_error("sesja wygasła, zaloguj się ponownie"), None);
        };
        let now = unix_now();
        let account = data.accounts.get_mut(&name).expect("owner exists");
        let mut changed_for_hosts = false;
        let result: AResult<AccountReply> = match call.op {
            Some(account_call::Op::ListDevices(_)) => Ok(AccountReply::default()),
            Some(account_call::Op::BindDevice(b)) => (|| {
                let noise = key32(&b.noise_public).ok_or(msg("nieprawidłowy klucz urządzenia"))?;
                let vk = key32(&b.verifying_key).ok_or(msg("nieprawidłowy klucz urządzenia"))?;
                let sig = <[u8; 64]>::try_from(b.signature.as_slice())
                    .map_err(|_| msg("nieprawidłowy podpis"))?;
                let device_id: String = b.device_id.chars().filter(char::is_ascii_digit).collect();
                verify_signature(&vk, &acc::bind_message(&name, &device_id, &noise), &sig)
                    .map_err(|_| msg("nieprawidłowy podpis urządzenia"))?;
                if !device_id.is_empty() && !server.registry.matches(&device_id, &vk, &noise) {
                    return Err(msg("to ID należy do innego urządzenia"));
                }
                let noise_hex = hex(&noise);
                if account.revoked.contains(&noise_hex) {
                    return Err(msg("to urządzenie zostało zablokowane na tym koncie"));
                }
                account.devices.retain(|d| d.noise_public != noise_hex);
                if account.devices.len() >= MAX_DEVICES {
                    return Err(msg("za dużo urządzeń na koncie"));
                }
                account.devices.push(Device {
                    device_id,
                    noise_public: noise_hex,
                    name: rc_proto::text::clean_label(&b.device_name, 64),
                    added_unix: now,
                });
                Ok(AccountReply::default())
            })(),
            Some(account_call::Op::UnbindDevice(u)) => {
                let noise_hex = hex(&u.noise_public);
                account.devices.retain(|d| d.noise_public != noise_hex);
                Ok(AccountReply::default())
            }
            Some(account_call::Op::RevokeDevice(r)) => {
                if r.noise_public.len() == 32 {
                    revoke_in(account, &hex(&r.noise_public));
                    changed_for_hosts = true;
                    Ok(AccountReply::default())
                } else {
                    Err(msg("nieprawidłowy klucz urządzenia"))
                }
            }
            Some(account_call::Op::ChangeKey(c)) => (|| {
                let old = unhex(&account.public_key)
                    .and_then(|k| key32(&k))
                    .ok_or(msg("uszkodzone konto"))?;
                let new = key32(&c.new_public_key).ok_or(msg("nieprawidłowy klucz"))?;
                let salt = <[u8; SALT_LEN]>::try_from(c.new_salt.as_slice())
                    .map_err(|_| msg("nieprawidłowy klucz"))?;
                let sig = <[u8; 64]>::try_from(c.signature.as_slice())
                    .map_err(|_| msg("nieprawidłowy podpis"))?;
                if !acc::verify_rotation(&old, &new, &sig) {
                    return Err(msg("nieprawidłowy podpis zmiany hasła"));
                }
                account.rotations.push(Rotation {
                    old: hex(&old),
                    new: hex(&new),
                    signature: hex(&sig),
                });
                account.public_key = hex(&new);
                account.salt = hex(&salt);
                // Other sessions end; this one stays.
                let keep = token_hash(&call.token);
                account.sessions.retain(|s| s.token_hash == keep);
                changed_for_hosts = true;
                Ok(AccountReply::default())
            })(),
            Some(account_call::Op::Logout(_)) => {
                let hash = token_hash(&call.token);
                account.sessions.retain(|s| s.token_hash != hash);
                Ok(AccountReply::default())
            }
            None => Err(msg("brak operacji")),
        };
        let mut reply = match result {
            Ok(r) => r,
            Err(e) => return (reply_error(&e.text()), None),
        };
        let online: std::collections::HashSet<String> =
            server.sessions.online().into_iter().map(|h| h.id).collect();
        reply.devices = account
            .devices
            .iter()
            .map(|d| AccountDevice {
                online: !d.device_id.is_empty() && online.contains(&d.device_id),
                device_id: d.device_id.clone(),
                noise_public: unhex(&d.noise_public).unwrap_or_default(),
                name: d.name.clone(),
                added_unix: d.added_unix,
            })
            .collect();
        if let Err(e) = self.save(&data) {
            return (reply_error(&e.text()), None);
        }
        (reply, changed_for_hosts.then_some(name))
    }
}

fn revoke_in(account: &mut Account, noise_hex: &str) {
    account.devices.retain(|d| d.noise_public != noise_hex);
    if !account.revoked.iter().any(|r| r == noise_hex) {
        account.revoked.push(noise_hex.to_string());
    }
}

fn reply_error(text: &str) -> AccountReply {
    AccountReply {
        error: text.to_string(),
        devices: Vec::new(),
    }
}

fn invite_key(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    hex(blake3::hash(normalized.as_bytes()).as_bytes())
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(tmp, path)
}

/// Sends the current account state to its online hosts (after a revocation,
/// key change or admin action).
pub(crate) fn push_updates(server: &Server, name: &str) {
    let Some(update) = server.accounts.update_for(name) else {
        return;
    };
    for id in server.accounts.bound_ids(name) {
        server
            .sessions
            .push(&id, Msg::AccountUpdate(update.clone()));
    }
}

fn server_msg(msg: Msg) -> ServerMessage {
    ServerMessage { msg: Some(msg) }
}

/// Serves account requests on one rendezvous stream; `first` is the message
/// that opened it, `challenge` the stream's ServerHello challenge.
pub(crate) async fn serve_stream(
    server: Arc<Server>,
    peer: SocketAddr,
    mut send: SendStream,
    mut recv: RecvStream,
    challenge: &[u8],
    first: ClientMessage,
) -> Result<()> {
    let mut next = Some(first);
    for _ in 0..MAX_MESSAGES_PER_STREAM {
        let message = match next.take() {
            Some(m) => m,
            None => match tokio::time::timeout(IDLE_TIMEOUT, frame::read(&mut recv)).await {
                Ok(Ok(m)) => m,
                _ => return Ok(()),
            },
        };
        let limited = matches!(
            message.msg,
            Some(
                client_message::Msg::AccountPrelogin(_)
                    | client_message::Msg::AccountRegister(_)
                    | client_message::Msg::AccountLogin(_)
            )
        ) && !server
            .account_ops
            .lock()
            .unwrap()
            .allow(peer.ip(), Instant::now());
        let reply = if limited {
            Msg::Error(rc_proto::rendezvous::Error {
                message: "zbyt wiele prób, spróbuj za chwilę".into(),
            })
        } else {
            handle(&server, peer, challenge, message)
        };
        frame::write(&mut send, &server_msg(reply)).await?;
    }
    let _ = send.finish();
    Err(TransportError::Protocol("too many account requests"))
}

fn handle(server: &Arc<Server>, peer: SocketAddr, challenge: &[u8], message: ClientMessage) -> Msg {
    let error = |text: String| Msg::Error(rc_proto::rendezvous::Error { message: text });
    let store = &server.accounts;
    match message.msg {
        Some(client_message::Msg::AccountPrelogin(p)) => {
            let name = acc::normalize_name(&p.name);
            Msg::AccountSalt(AccountSalt {
                salt: store.salt_for(&name).to_vec(),
            })
        }
        Some(client_message::Msg::AccountRegister(r)) => {
            let name = acc::normalize_name(&r.name);
            match store.register(
                server.signup,
                &name,
                &r.invite,
                &r.salt,
                &r.public_key,
                &r.display_name,
            ) {
                Ok(token) => {
                    server
                        .events
                        .push("account", format!("nowe konto {name} (z {peer})"));
                    let display = store
                        .summaries()
                        .into_iter()
                        .find(|s| s.name == name)
                        .map(|s| s.display_name)
                        .unwrap_or_default();
                    Msg::AccountSession(AccountSession {
                        token,
                        name,
                        display_name: display,
                    })
                }
                Err(e) => error(e.text()),
            }
        }
        Some(client_message::Msg::AccountLogin(l)) => {
            let name = acc::normalize_name(&l.name);
            match store.login(&name, challenge, &l.signature) {
                Ok((token, display_name)) => {
                    server
                        .events
                        .push("account", format!("logowanie na konto {name} z {peer}"));
                    Msg::AccountSession(AccountSession {
                        token,
                        name,
                        display_name,
                    })
                }
                Err(e) => {
                    server.events.push(
                        "account",
                        format!("nieudane logowanie na konto {name} z {peer}"),
                    );
                    error(e.text())
                }
            }
        }
        Some(client_message::Msg::AccountCall(call)) => {
            let (reply, changed) = store.call(server, call);
            if let Some(name) = changed {
                push_updates(server, &name);
            }
            Msg::AccountReply(reply)
        }
        _ => error("nieoczekiwana wiadomość".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_crypto::account::AccountKey;

    fn temp_store(name: &str) -> (AccountStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("rc-accounts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (AccountStore::open(&dir).unwrap(), dir)
    }

    #[test]
    fn invite_register_login() {
        let (store, dir) = temp_store("flow");
        let salt = [5u8; SALT_LEN];
        let key = AccountKey::derive("ania", "haslo-ani", &salt).unwrap();
        // Unknown names still get a salt, the same every time.
        assert_eq!(store.salt_for("ktos"), store.salt_for("ktos"));
        assert_ne!(store.salt_for("ktos"), store.salt_for("ktos2"));

        let err = store.register(
            Signup::Invite,
            "ania",
            "ZLY-KOD",
            &salt,
            &key.public(),
            "Ania",
        );
        assert!(err.is_err());
        let code = store.create_invite("dla Ani").unwrap();
        store
            .register(
                Signup::Invite,
                "ania",
                &code.to_lowercase(),
                &salt,
                &key.public(),
                "Ania",
            )
            .unwrap();
        assert_eq!(store.salt_for("ania"), salt);
        // The invite works once.
        let key2 = AccountKey::derive("bartek", "x", &salt).unwrap();
        assert!(store
            .register(Signup::Invite, "bartek", &code, &salt, &key2.public(), "")
            .is_err());

        let challenge = b"server challenge";
        let (token, display) = store
            .login("ania", challenge, &key.sign_login("ania", challenge))
            .unwrap();
        assert_eq!(display, "Ania");
        assert_eq!(token.len(), 32);
        let wrong = AccountKey::derive("ania", "zle", &salt).unwrap();
        for _ in 0..MAX_LOGIN_FAILURES {
            assert!(store
                .login("ania", challenge, &wrong.sign_login("ania", challenge))
                .is_err());
        }
        // Locked out now, even with the right password.
        assert!(store
            .login("ania", challenge, &key.sign_login("ania", challenge))
            .is_err());

        drop(store);
        let reopened = AccountStore::open(&dir).unwrap();
        assert_eq!(reopened.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
