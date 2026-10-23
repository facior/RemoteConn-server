//! Server updates in the panel, for the main administrator only.
//!
//! The server runs unprivileged, so it never updates itself. The work is done
//! by two root jobs installed by `install.sh` (both are `rc-admin`
//! subcommands):
//! - `update-check` (daily timer) fetches release tags (`vX.Y.Z`) from the
//!   repository and writes `update-available.json`;
//! - `update-apply` runs when `update-request.json` appears, checks out the
//!   requested tag, rebuilds, restarts (rolling back if the new version does
//!   not start) and writes `update-status.json`.
//!
//! The panel only reads those files and writes the request. The updater
//! accepts nothing but a release tag that the check found, so the request
//! file cannot make root run anything else.

use std::path::Path;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::auth::Authed;
use super::{users, ApiError, ApiResult, AppState};
use crate::events::unix_now;

const AVAILABLE: &str = "update-available.json";
const STATUS: &str = "update-status.json";
const REQUEST: &str = "update-request.json";

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Available {
    #[serde(default)]
    pub latest: String,
    #[serde(default)]
    pub checked_unix: i64,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Status {
    /// "requested" | "running" | "done" | "failed" | "skipped"
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub requested_by: String,
    #[serde(default)]
    pub updated_unix: i64,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub log: String,
}

#[derive(Serialize, Deserialize)]
struct Request {
    version: String,
    requested_by: String,
    at_unix: i64,
}

/// `v1.2.3` or `1.2.3` as numbers, for comparing versions.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.trim().trim_start_matches('v').split('.');
    let n = |p: Option<&str>| p?.parse::<u64>().ok();
    let version = (n(parts.next())?, n(parts.next())?, n(parts.next())?);
    parts.next().is_none().then_some(version)
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    matches!(
        (parse_version(candidate), parse_version(current)),
        (Some(a), Some(b)) if a > b
    )
}

fn read<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// The account must be the main administrator.
fn require_owner(state: &AppState, authed: &Authed) -> Result<users::User, ApiError> {
    let all = users::load(&state.server.data_dir).map_err(ApiError::internal)?;
    if users::owner_of(&all) != Some(authed.user.as_str()) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Aktualizacje widzi i instaluje tylko główny administrator.",
        ));
    }
    all.get(&authed.user)
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "Brak konta"))
}

pub async fn status(State(state): State<AppState>, authed: Authed) -> ApiResult {
    let owner = require_owner(&state, &authed)?;
    let dir = &state.server.data_dir;
    let available: Option<Available> = read(&dir.join(AVAILABLE));
    let status: Option<Status> = read(&dir.join(STATUS));
    let update = available
        .as_ref()
        .filter(|a| is_newer(&a.latest, CURRENT))
        .map(|a| a.latest.clone());
    Ok(Json(json!({
        "current": CURRENT,
        "available": available,
        "update": update,
        "status": status,
        "pending": dir.join(REQUEST).exists(),
        "totp_enabled": owner.totp.is_some(),
    })))
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    version: String,
}

pub async fn request(
    State(state): State<AppState>,
    authed: Authed,
    Json(req): Json<UpdateRequest>,
) -> ApiResult {
    let owner = require_owner(&state, &authed)?;
    if owner.totp.is_none() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Instalacja aktualizacji wymaga włączonego 2FA: sudo rc-admin panel user totp <nazwa>",
        ));
    }
    let dir = &state.server.data_dir;
    let available: Available = read(&dir.join(AVAILABLE)).unwrap_or_default();
    if req.version != available.latest || !is_newer(&available.latest, CURRENT) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Ta wersja nie jest dostępną aktualizacją. Odśwież stronę.",
        ));
    }
    let status: Option<Status> = read(&dir.join(STATUS));
    let busy = dir.join(REQUEST).exists()
        || status.is_some_and(|s| s.state == "running" || s.state == "requested");
    if busy {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Aktualizacja już trwa.",
        ));
    }
    let now = unix_now();
    write_json(
        &dir.join(STATUS),
        &Status {
            state: "requested".into(),
            version: req.version.clone(),
            requested_by: authed.user.clone(),
            updated_unix: now,
            message: "Czeka na uruchomienie aktualizacji…".into(),
            log: String::new(),
        },
    )
    .map_err(ApiError::internal)?;
    // Written last: its appearance starts the root updater.
    write_json(
        &dir.join(REQUEST),
        &Request {
            version: req.version.clone(),
            requested_by: authed.user.clone(),
            at_unix: now,
        },
    )
    .map_err(ApiError::internal)?;
    state.admin_action(
        &authed,
        format!("zlecenie aktualizacji serwera do {}", req.version),
    );
    Ok(Json(json!({ "ok": true })))
}

fn write_json(path: &Path, value: &impl Serialize) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(tmp, path)
}

/// For `/api/me`: whether the user is the main administrator.
pub fn is_owner(data_dir: &Path, user: &str) -> bool {
    users::load(data_dir)
        .map(|all| users::owner_of(&all) == Some(user))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.10.0"), Some((0, 10, 0)));
        assert_eq!(parse_version("v1.2"), None);
        assert_eq!(parse_version("v1.2.3-rc1"), None);
        assert!(is_newer("v0.10.0", "0.9.9"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("garbage", "0.1.0"));
    }
}
