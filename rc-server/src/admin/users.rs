//! Admin panel accounts: `panel-users.json` in the data directory.
//!
//! Passwords are stored as Argon2id hashes (PHC strings), TOTP secrets in
//! base32. The file is created with mode 0600 and re-read on every login, so
//! `rc-server panel-user …` changes apply without a restart.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(default)]
    pub created_unix: i64,
}

pub type Users = BTreeMap<String, User>;

pub fn path_in(data_dir: &Path) -> PathBuf {
    data_dir.join("panel-users.json")
}

pub fn load(data_dir: &Path) -> io::Result<Users> {
    match std::fs::read(path_in(data_dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Users::new()),
        Err(e) => Err(e),
    }
}

pub fn save(data_dir: &Path, users: &Users) -> io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let path = path_in(data_dir);
    let tmp = path.with_extension("json.tmp");
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
        file.write_all(&serde_json::to_vec_pretty(users).map_err(io::Error::other)?)?;
        file.sync_all()?;
    }
    std::fs::rename(tmp, path)
}

pub fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

pub fn check_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must have at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    if password.len() > 256 {
        return Err("password is too long".into());
    }
    Ok(())
}

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 with default parameters")
        .to_string()
}

fn verify_hash(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// A hash of a random password, verified for unknown user names so that
/// response time does not reveal which names exist.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("not a real password, only for timing"))
}

/// Checks name and password (slow on purpose: Argon2). Returns the user.
pub fn verify_password(users: &Users, name: &str, password: &str) -> Option<User> {
    match users.get(name) {
        Some(user) if verify_hash(&user.hash, password) => Some(user.clone()),
        Some(_) => None,
        None => {
            verify_hash(dummy_hash(), password);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verify_and_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rc-panel-users-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut users = Users::new();
        users.insert(
            "admin".into(),
            User {
                hash: hash_password("correct horse battery"),
                totp: None,
                created_unix: 1,
            },
        );
        save(&dir, &users).unwrap();
        let loaded = load(&dir).unwrap();
        assert!(verify_password(&loaded, "admin", "correct horse battery").is_some());
        assert!(verify_password(&loaded, "admin", "wrong").is_none());
        assert!(verify_password(&loaded, "nobody", "correct horse battery").is_none());
        assert!(valid_name("ops.admin-1") && !valid_name("a b") && !valid_name(""));
        assert!(check_password("short").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
