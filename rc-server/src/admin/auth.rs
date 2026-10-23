//! Panel logins, sessions, lockout and the audit log.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, Method, StatusCode};
use rand::RngCore;
use tokio::sync::Semaphore;

use super::{totp, users, ApiError};
use crate::events::{fmt_utc, unix_now};

pub const COOKIE: &str = "rc_session";
pub const CSRF_HEADER: &str = "x-rc-csrf";

const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_SESSION_AGE: Duration = Duration::from_secs(12 * 3600);
const MAX_SESSIONS: usize = 64;
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_USER_FAILURES: u32 = 5;
const MAX_IP_FAILURES: u32 = 20;
const FAILURE_DELAY: Duration = Duration::from_secs(1);
const AUDIT_FILE: &str = "panel-audit.log";

const BAD_LOGIN: &str = "Nieprawidłowy login, hasło lub kod 2FA";

struct PanelSession {
    user: String,
    csrf: String,
    created: Instant,
    last_seen: Instant,
}

struct Failures {
    count: u32,
    first: Instant,
}

pub struct Auth {
    data_dir: PathBuf,
    /// Keyed by the BLAKE3 hash of the cookie token: a leaked memory dump or
    /// log line holds no usable token.
    sessions: Mutex<HashMap<[u8; 32], PanelSession>>,
    failures: Mutex<HashMap<String, Failures>>,
    /// Last TOTP step accepted per user: a code works only once.
    last_step: Mutex<HashMap<String, i64>>,
    /// Argon2 is expensive; at most two checks run at once.
    verifying: Semaphore,
    audit_lock: Mutex<()>,
}

pub struct Login {
    pub user: String,
    pub token: String,
    pub csrf: String,
}

pub struct Authed {
    pub user: String,
    pub csrf: String,
    pub ip: IpAddr,
    key: [u8; 32],
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn token_key(token: &str) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
}

pub fn session_cookie(token: &str) -> String {
    format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        MAX_SESSION_AGE.as_secs()
    )
}

pub fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// Safe to write into the one-line-per-entry audit log.
fn log_safe(text: &str) -> String {
    rc_proto::text::clean_label(text, 200).replace(['\n', '\r'], " ")
}

impl Auth {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            last_step: Mutex::new(HashMap::new()),
            verifying: Semaphore::new(2),
            audit_lock: Mutex::new(()),
        }
    }

    fn locked(&self, key: &str, max: u32) -> bool {
        let mut failures = self.failures.lock().unwrap();
        failures.retain(|_, f| f.first.elapsed() < FAILURE_WINDOW);
        failures.get(key).is_some_and(|f| f.count >= max)
    }

    fn record_failure(&self, key: String) {
        let mut failures = self.failures.lock().unwrap();
        let entry = failures.entry(key).or_insert(Failures {
            count: 0,
            first: Instant::now(),
        });
        entry.count += 1;
    }

    pub async fn login(
        &self,
        ip: IpAddr,
        user: &str,
        password: &str,
        code: &str,
    ) -> Result<Login, ApiError> {
        let user = user.trim().to_string();
        let user_key = format!("user:{}", user.to_lowercase());
        let ip_key = format!("ip:{ip}");
        if self.locked(&user_key, MAX_USER_FAILURES) || self.locked(&ip_key, MAX_IP_FAILURES) {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Zbyt wiele nieudanych prób. Spróbuj ponownie za 15 minut.",
            ));
        }

        let checked = {
            let _permit = self.verifying.acquire().await.map_err(ApiError::internal)?;
            let (dir, name, pass) = (self.data_dir.clone(), user.clone(), password.to_string());
            tokio::task::spawn_blocking(move || {
                let all = users::load(&dir)?;
                let ok = users::valid_name(&name) && pass.len() <= 256;
                let name = if ok { name } else { String::new() };
                Ok::<_, std::io::Error>(users::verify_password(&all, &name, &pass))
            })
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)?
        };

        let accepted = checked.and_then(|account| match &account.totp {
            None => Some(()),
            Some(secret) => {
                let step = totp::verify(secret, code, unix_now())?;
                let mut last = self.last_step.lock().unwrap();
                let previous = last.get(&user).copied().unwrap_or(i64::MIN);
                (step > previous).then(|| {
                    last.insert(user.clone(), step);
                })
            }
        });

        if accepted.is_none() {
            self.record_failure(user_key);
            self.record_failure(ip_key);
            self.audit(&format!("({})", log_safe(&user)), ip, "nieudane logowanie");
            tokio::time::sleep(FAILURE_DELAY).await;
            return Err(ApiError::new(StatusCode::UNAUTHORIZED, BAD_LOGIN));
        }

        self.failures.lock().unwrap().remove(&user_key);
        let token = random_hex(32);
        let csrf = random_hex(32);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| Self::alive(s));
        if sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, s)| s.created)
                .map(|(k, _)| *k)
            {
                sessions.remove(&oldest);
            }
        }
        let now = Instant::now();
        sessions.insert(
            token_key(&token),
            PanelSession {
                user: user.clone(),
                csrf: csrf.clone(),
                created: now,
                last_seen: now,
            },
        );
        Ok(Login { user, token, csrf })
    }

    fn alive(s: &PanelSession) -> bool {
        s.last_seen.elapsed() < IDLE_TIMEOUT && s.created.elapsed() < MAX_SESSION_AGE
    }

    pub fn logout(&self, authed: &Authed) {
        self.sessions.lock().unwrap().remove(&authed.key);
    }

    fn session(&self, token: &str) -> Option<(String, String, [u8; 32])> {
        let key = token_key(token);
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(&key)?;
        if !Self::alive(session) {
            sessions.remove(&key);
            return None;
        }
        session.last_seen = Instant::now();
        Some((session.user.clone(), session.csrf.clone(), key))
    }

    fn drop_session(&self, key: &[u8; 32]) {
        self.sessions.lock().unwrap().remove(key);
    }

    pub fn audit(&self, user: &str, ip: IpAddr, action: &str) {
        let line = format!(
            "{} {} {} {}\n",
            fmt_utc(unix_now()),
            log_safe(user),
            ip,
            log_safe(action)
        );
        let _guard = self.audit_lock.lock().unwrap();
        let mut options = std::fs::OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = options
            .open(self.data_dir.join(AUDIT_FILE))
            .and_then(|mut f| f.write_all(line.as_bytes()));
        if let Err(e) = result {
            tracing::error!("cannot write the panel audit log: {e}");
        }
    }

    /// Up to `limit` most recent audit lines, newest first.
    pub fn audit_tail(&self, limit: usize) -> std::io::Result<Vec<String>> {
        let text = match std::fs::read_to_string(self.data_dir.join(AUDIT_FILE)) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        Ok(text.lines().rev().take(limit).map(str::to_string).collect())
    }
}

fn cookie_token(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value.to_string())
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl FromRequestParts<super::AppState> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &super::AppState,
    ) -> Result<Self, Self::Rejection> {
        let unauthorized = || ApiError::new(StatusCode::UNAUTHORIZED, "Zaloguj się ponownie");
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .ok_or_else(unauthorized)?;
        let token = cookie_token(parts).ok_or_else(unauthorized)?;
        let auth = &state.auth;
        let (user, csrf, key) = auth.session(&token).ok_or_else(unauthorized)?;

        // A removed account loses its sessions at once.
        let exists = users::load(&auth.data_dir)
            .map(|u| u.contains_key(&user))
            .unwrap_or(false);
        if !exists {
            auth.drop_session(&key);
            return Err(unauthorized());
        }

        if parts.method != Method::GET && parts.method != Method::HEAD {
            let sent = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if blake3::hash(sent.as_bytes()) != blake3::hash(csrf.as_bytes()) {
                return Err(ApiError::new(StatusCode::FORBIDDEN, "Brak tokenu CSRF"));
            }
        }
        Ok(Authed {
            user,
            csrf,
            ip,
            key,
        })
    }
}
