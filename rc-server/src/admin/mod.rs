//! Admin web panel: server status, devices, relayed sessions, blocklist and
//! events, with a "connect" link that opens the desktop app.
//!
//! It listens on loopback by default and is meant to be reached through an SSH
//! tunnel. Protections, in case it is exposed anyway or another local user
//! tries it:
//! - accounts in `panel-users.json` (Argon2id, optional TOTP), constant-time
//!   behaviour for unknown names, lockout after repeated failures;
//! - session cookie that is HttpOnly + SameSite=Strict, stored only as a hash,
//!   with idle and absolute expiry;
//! - CSRF token header on every change, Origin check, JSON-only bodies;
//! - Host header allowlist against DNS rebinding;
//! - strict security headers (CSP, no framing, no caching);
//! - audit log of logins and every change (`panel-audit.log`).

mod auth;
pub mod totp;
mod updates;
pub mod users;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::blocklist::{self, Entry};
use crate::Server;
use auth::{Auth, Authed};

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const STYLE_CSS: &str = include_str!("assets/style.css");

const MAX_LISTED_DEVICES: usize = 500;

#[derive(Clone)]
struct AppState {
    server: Arc<Server>,
    auth: Arc<Auth>,
    allowed_hosts: Arc<Vec<String>>,
}

pub(crate) async fn start(
    server: Arc<Server>,
    bind: SocketAddr,
    extra_hosts: Vec<String>,
) -> std::io::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    if !addr.ip().is_loopback() {
        tracing::warn!(
            %addr,
            "admin panel is reachable from the network without TLS; prefer 127.0.0.1 and an SSH tunnel"
        );
    }
    let mut allowed_hosts: Vec<String> = ["localhost", "127.0.0.1", "[::1]"]
        .iter()
        .map(|h| h.to_string())
        .collect();
    allowed_hosts.extend(
        extra_hosts
            .into_iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty()),
    );
    let state = AppState {
        auth: Arc::new(Auth::new(server.data_dir.clone())),
        server,
        allowed_hosts: Arc::new(allowed_hosts),
    };
    let app = router(state);
    tokio::spawn(async move {
        let service = app.into_make_service_with_connect_info::<SocketAddr>();
        if let Err(e) = axum::serve(listener, service).await {
            tracing::error!("admin panel stopped: {e}");
        }
    });
    tracing::info!(%addr, "admin panel listening");
    Ok(addr)
}

fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { asset(INDEX_HTML, "text/html; charset=utf-8") }),
        )
        .route(
            "/app.js",
            get(|| async { asset(APP_JS, "text/javascript; charset=utf-8") }),
        )
        .route(
            "/style.css",
            get(|| async { asset(STYLE_CSS, "text/css; charset=utf-8") }),
        )
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/overview", get(overview))
        .route("/api/devices", get(devices))
        .route("/api/devices/{id}/kick", post(kick))
        .route("/api/relays", get(relays))
        .route("/api/relays/{id}/close", post(close_relay))
        .route("/api/blocklist", get(get_blocklist))
        .route("/api/block", post(block))
        .route("/api/unblock", post(unblock))
        .route("/api/events", get(events))
        .route("/api/update", get(updates::status).post(updates::request))
        .route("/api/accounts", get(accounts))
        .route("/api/accounts/{name}/disable", post(account_disable))
        .route("/api/accounts/{name}/enable", post(account_enable))
        .route("/api/accounts/{name}/delete", post(account_delete))
        .route("/api/accounts/{name}/revoke", post(account_revoke))
        .route("/api/invites", get(invites).post(create_invite))
        .route("/api/invites/{key}/delete", post(delete_invite))
        .route("/api/audit", get(audit))
        .fallback(|| async { ApiError::new(StatusCode::NOT_FOUND, "Nie znaleziono") })
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

fn asset(body: &'static str, content_type: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

/// Host / Origin checks before any handler, security headers after.
async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(host_name);
    if !host.is_some_and(|h| state.allowed_hosts.contains(&h)) {
        return secured(
            ApiError::new(StatusCode::MISDIRECTED_REQUEST, "Nieznany host").into_response(),
        );
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        // Browsers send Origin on cross-site POSTs; it must be this panel.
        if let Some(origin) = headers.get(header::ORIGIN) {
            let same = origin
                .to_str()
                .ok()
                .and_then(|o| o.split_once("://").map(|(_, rest)| rest.to_string()))
                .zip(headers.get(header::HOST).and_then(|h| h.to_str().ok()))
                .is_some_and(|(origin_host, host)| origin_host.eq_ignore_ascii_case(host));
            if !same {
                return secured(
                    ApiError::new(StatusCode::FORBIDDEN, "Niedozwolone źródło").into_response(),
                );
            }
        }
    }
    secured(next.run(request).await)
}

/// `Host` value without the port, lower case (`[::1]` keeps its brackets).
fn host_name(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    if host.starts_with('[') {
        return host.split_inclusive(']').next().unwrap_or("").to_string();
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name.to_string(),
        _ => host,
    }
}

fn secured(mut response: Response) -> Response {
    let headers = response.headers_mut();
    let set = |headers: &mut HeaderMap, name: &'static str, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(
        headers,
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
         connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
    set(headers, "x-frame-options", "DENY");
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "referrer-policy", "no-referrer");
    set(headers, "cache-control", "no-store");
    set(headers, "cross-origin-opener-policy", "same-origin");
    set(headers, "cross-origin-resource-policy", "same-origin");
    set(
        headers,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), clipboard-read=()",
    );
    response
}

pub(crate) struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!("admin panel: {e}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Błąd serwera")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

#[derive(Deserialize)]
struct LoginRequest {
    user: String,
    password: String,
    #[serde(default)]
    code: String,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Response {
    match state
        .auth
        .login(peer.ip(), &req.user, &req.password, &req.code)
        .await
    {
        Ok(login) => {
            state.auth.audit(&login.user, peer.ip(), "logowanie");
            let cookie = auth::session_cookie(&login.token);
            let owner = updates::is_owner(&state.server.data_dir, &login.user);
            (
                [(header::SET_COOKIE, cookie)],
                Json(json!({ "user": login.user, "csrf": login.csrf, "owner": owner })),
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

async fn logout(State(state): State<AppState>, authed: Authed) -> Response {
    state.auth.logout(&authed);
    state.auth.audit(&authed.user, authed.ip, "wylogowanie");
    (
        [(header::SET_COOKIE, auth::clear_cookie())],
        Json(json!({ "ok": true })),
    )
        .into_response()
}

async fn me(State(state): State<AppState>, authed: Authed) -> ApiResult {
    let owner = updates::is_owner(&state.server.data_dir, &authed.user);
    Ok(Json(
        json!({ "user": authed.user, "csrf": authed.csrf, "owner": owner }),
    ))
}

async fn overview(State(state): State<AppState>, _authed: Authed) -> ApiResult {
    let s = &state.server;
    let now = crate::events::unix_now();
    let blocklist_len = s.blocklist.read().unwrap().len();
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "started_unix": s.started_unix,
        "now_unix": now,
        "fingerprint": crate::short_fingerprint(&s.fingerprint),
        "fingerprint_full": s.fingerprint.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "access_key_set": s.access_key_set(),
        "registered": s.registry.len(),
        "online": s.sessions.online_count(),
        "relays_active": s.relay.active_count(),
        "max_relays": s.max_relays,
        "relay_bytes": s.relay.total_bytes(),
        "blocklist": blocklist_len,
        "accounts": s.accounts.len(),
        "signup": signup_name(s.signup),
    })))
}

#[derive(Deserialize)]
struct DeviceQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    online: bool,
}

async fn devices(
    State(state): State<AppState>,
    _authed: Authed,
    Query(query): Query<DeviceQuery>,
) -> ApiResult {
    let s = &state.server;
    let online: std::collections::HashMap<String, crate::rendezvous::OnlineSnapshot> = s
        .sessions
        .online()
        .into_iter()
        .map(|h| (h.id.clone(), h))
        .collect();
    let needle = query.q.trim().to_lowercase();
    let needle_digits: String = needle.chars().filter(char::is_ascii_digit).collect();
    let owners = s.accounts.owners();
    let blocklist = s.blocklist.read().unwrap();
    let mut matched = 0usize;
    let mut list = Vec::new();
    for (id, name) in s.registry.list() {
        let host = online.get(&id);
        if query.online && host.is_none() {
            continue;
        }
        if !needle.is_empty()
            && !name.to_lowercase().contains(&needle)
            && (needle_digits.is_empty() || !id.contains(&needle_digits))
        {
            continue;
        }
        matched += 1;
        if list.len() < MAX_LISTED_DEVICES {
            list.push(json!({
                "id": id,
                // The current name of an online host, else the registered one.
                "name": host.map(|h| h.name.as_str()).unwrap_or(&name),
                "online": host.is_some(),
                "observed": host.map(|h| h.observed.as_str()),
                "since_unix": host.map(|h| h.since_unix),
                "blocked": blocklist.device_blocked(&id),
                "account": owners.get(&id),
            }));
        }
    }
    // Online first, then by ID.
    list.sort_by_key(|d| (!d["online"].as_bool().unwrap_or(false), d["id"].to_string()));
    Ok(Json(json!({ "matched": matched, "devices": list })))
}

fn device_id(raw: &str) -> Result<String, ApiError> {
    let id: String = raw.chars().filter(char::is_ascii_digit).collect();
    if id.len() == 9 {
        Ok(id)
    } else {
        Err(ApiError::bad_request("ID urządzenia ma 9 cyfr"))
    }
}

async fn kick(State(state): State<AppState>, authed: Authed, Path(id): Path<String>) -> ApiResult {
    let id = device_id(&id)?;
    if !state.server.sessions.kick_one(&id) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Urządzenie nie jest online",
        ));
    }
    state.admin_action(&authed, format!("rozłączenie urządzenia {id}"));
    Ok(Json(json!({ "ok": true })))
}

async fn relays(State(state): State<AppState>, _authed: Authed) -> ApiResult {
    Ok(Json(json!({ "relays": state.server.relay.snapshot() })))
}

async fn close_relay(
    State(state): State<AppState>,
    authed: Authed,
    Path(id): Path<u64>,
) -> ApiResult {
    if !state.server.relay.close(id) {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Nie ma takiej sesji"));
    }
    state.admin_action(&authed, format!("zamknięcie sesji relay #{id}"));
    Ok(Json(json!({ "ok": true })))
}

async fn get_blocklist(State(state): State<AppState>, _authed: Authed) -> ApiResult {
    let (entries, errors) = blocklist::read(&blocklist::path_in(&state.server.data_dir));
    let entries: Vec<Value> = entries
        .iter()
        .map(|e| {
            let line = e.to_line();
            let (kind, value) = line.split_once(' ').unwrap_or(("", ""));
            json!({ "line": line, "kind": kind, "value": value })
        })
        .collect();
    Ok(Json(json!({ "entries": entries, "errors": errors })))
}

#[derive(Deserialize)]
struct BlockRequest {
    kind: String,
    value: String,
}

async fn block(
    State(state): State<AppState>,
    authed: Authed,
    Json(req): Json<BlockRequest>,
) -> ApiResult {
    let kind = req.kind.trim();
    if !matches!(kind, "ip" | "net" | "device") || req.value.len() > 64 {
        return Err(ApiError::bad_request("Nieprawidłowy wpis"));
    }
    let entry = Entry::parse(&format!("{kind} {}", req.value)).map_err(ApiError::bad_request)?;
    let path = blocklist::path_in(&state.server.data_dir);
    let (mut entries, _) = blocklist::read(&path);
    if !entries.contains(&entry) {
        entries.push(entry.clone());
        state
            .server
            .save_blocklist(&entries)
            .map_err(ApiError::internal)?;
        state.admin_action(&authed, format!("blokada: {}", entry.to_line()));
    }
    Ok(Json(json!({ "ok": true, "line": entry.to_line() })))
}

#[derive(Deserialize)]
struct UnblockRequest {
    line: String,
}

async fn unblock(
    State(state): State<AppState>,
    authed: Authed,
    Json(req): Json<UnblockRequest>,
) -> ApiResult {
    let target = Entry::parse(&req.line).map_err(ApiError::bad_request)?;
    let path = blocklist::path_in(&state.server.data_dir);
    let (entries, _) = blocklist::read(&path);
    let before = entries.len();
    let kept: Vec<Entry> = entries.into_iter().filter(|e| *e != target).collect();
    if kept.len() == before {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Nie ma takiego wpisu"));
    }
    state
        .server
        .save_blocklist(&kept)
        .map_err(ApiError::internal)?;
    state.admin_action(&authed, format!("odblokowanie: {}", target.to_line()));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

async fn events(
    State(state): State<AppState>,
    _authed: Authed,
    Query(q): Query<LimitQuery>,
) -> ApiResult {
    let limit = q.limit.unwrap_or(200).min(500);
    Ok(Json(json!({ "events": state.server.events.recent(limit) })))
}

async fn audit(
    State(state): State<AppState>,
    _authed: Authed,
    Query(q): Query<LimitQuery>,
) -> ApiResult {
    let limit = q.limit.unwrap_or(200).min(1000);
    let lines = state.auth.audit_tail(limit).map_err(ApiError::internal)?;
    Ok(Json(json!({ "lines": lines })))
}

fn signup_name(signup: crate::accounts::Signup) -> &'static str {
    match signup {
        crate::accounts::Signup::Off => "off",
        crate::accounts::Signup::Invite => "invite",
        crate::accounts::Signup::Open => "open",
    }
}

fn account_error(e: crate::accounts::AccountError) -> ApiError {
    match e {
        crate::accounts::AccountError::Message(m) => ApiError::new(StatusCode::NOT_FOUND, m),
        crate::accounts::AccountError::Io(e) => ApiError::internal(e),
    }
}

async fn accounts(State(state): State<AppState>, _authed: Authed) -> ApiResult {
    let s = &state.server;
    let online: std::collections::HashSet<String> =
        s.sessions.online().into_iter().map(|h| h.id).collect();
    let list: Vec<Value> = s
        .accounts
        .summaries()
        .into_iter()
        .map(|a| {
            let devices: Vec<Value> = a
                .devices
                .iter()
                .map(|d| {
                    let key = d.noise_public.clone();
                    json!({
                        "device_id": d.device_id,
                        "name": d.name,
                        "public_key": key,
                        "online": !d.device_id.is_empty() && online.contains(&d.device_id),
                        "added_unix": d.added_unix,
                    })
                })
                .collect();
            json!({
                "name": a.name,
                "display_name": a.display_name,
                "created_unix": a.created_unix,
                "disabled": a.disabled,
                "revoked": a.revoked,
                "devices": devices,
            })
        })
        .collect();
    Ok(Json(
        json!({ "signup": signup_name(s.signup), "accounts": list }),
    ))
}

fn account_name(raw: &str) -> Result<String, ApiError> {
    let name = rc_crypto::account::normalize_name(raw);
    if rc_crypto::account::valid_name(&name) {
        Ok(name)
    } else {
        Err(ApiError::bad_request("Nieprawidłowa nazwa konta"))
    }
}

async fn account_disable(
    State(state): State<AppState>,
    authed: Authed,
    Path(name): Path<String>,
) -> ApiResult {
    let name = account_name(&name)?;
    state
        .server
        .accounts
        .set_disabled(&name, true)
        .map_err(account_error)?;
    crate::accounts::push_updates(&state.server, &name);
    state.admin_action(&authed, format!("zablokowanie konta {name}"));
    Ok(Json(json!({ "ok": true })))
}

async fn account_enable(
    State(state): State<AppState>,
    authed: Authed,
    Path(name): Path<String>,
) -> ApiResult {
    let name = account_name(&name)?;
    state
        .server
        .accounts
        .set_disabled(&name, false)
        .map_err(account_error)?;
    crate::accounts::push_updates(&state.server, &name);
    state.admin_action(&authed, format!("odblokowanie konta {name}"));
    Ok(Json(json!({ "ok": true })))
}

async fn account_delete(
    State(state): State<AppState>,
    authed: Authed,
    Path(name): Path<String>,
) -> ApiResult {
    let name = account_name(&name)?;
    // Hosts keep trusting the key until told otherwise: disable first.
    let _ = state.server.accounts.set_disabled(&name, true);
    crate::accounts::push_updates(&state.server, &name);
    state.server.accounts.delete(&name).map_err(account_error)?;
    state.admin_action(&authed, format!("usunięcie konta {name}"));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct RevokeRequest {
    public_key: String,
}

async fn account_revoke(
    State(state): State<AppState>,
    authed: Authed,
    Path(name): Path<String>,
    Json(req): Json<RevokeRequest>,
) -> ApiResult {
    let name = account_name(&name)?;
    let key = req.public_key.trim().to_ascii_lowercase();
    if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("Nieprawidłowy klucz urządzenia"));
    }
    state
        .server
        .accounts
        .revoke(&name, &key)
        .map_err(account_error)?;
    crate::accounts::push_updates(&state.server, &name);
    state.admin_action(
        &authed,
        format!(
            "odebranie dostępu urządzeniu {} na koncie {name}",
            &key[..16]
        ),
    );
    Ok(Json(json!({ "ok": true })))
}

async fn invites(State(state): State<AppState>, _authed: Authed) -> ApiResult {
    let list: Vec<Value> = state
        .server
        .accounts
        .invites()
        .into_iter()
        .map(|(key, i)| {
            json!({ "key": key, "note": i.note, "created_unix": i.created_unix, "expires_unix": i.expires_unix })
        })
        .collect();
    Ok(Json(json!({ "invites": list })))
}

#[derive(Deserialize)]
struct InviteRequest {
    #[serde(default)]
    note: String,
}

async fn create_invite(
    State(state): State<AppState>,
    authed: Authed,
    Json(req): Json<InviteRequest>,
) -> ApiResult {
    let code = state
        .server
        .accounts
        .create_invite(&req.note)
        .map_err(account_error)?;
    state.admin_action(&authed, format!("nowe zaproszenie ({})", req.note.trim()));
    Ok(Json(json!({ "code": code })))
}

async fn delete_invite(
    State(state): State<AppState>,
    authed: Authed,
    Path(key): Path<String>,
) -> ApiResult {
    if !state
        .server
        .accounts
        .delete_invite(&key)
        .map_err(account_error)?
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Nie ma takiego zaproszenia",
        ));
    }
    state.admin_action(&authed, "usunięcie zaproszenia".into());
    Ok(Json(json!({ "ok": true })))
}

impl AppState {
    fn admin_action(&self, authed: &Authed, action: String) {
        self.server
            .events
            .push("admin", format!("{}: {action}", authed.user));
        self.auth.audit(&authed.user, authed.ip, &action);
    }
}

#[cfg(test)]
mod tests {
    use super::host_name;

    #[test]
    fn host_names() {
        assert_eq!(host_name("LocalHost:8080"), "localhost");
        assert_eq!(host_name("127.0.0.1"), "127.0.0.1");
        assert_eq!(host_name("[::1]:9000"), "[::1]");
        assert_eq!(host_name("evil.example:80"), "evil.example");
    }
}
