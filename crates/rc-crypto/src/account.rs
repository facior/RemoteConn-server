//! Accounts: passwordless access between your own devices.
//!
//! The account key (Ed25519) is derived from the account password on the
//! device (Argon2id, salt kept by the server). The server stores only the
//! public key, so it never learns the password and cannot act for the account.
//!
//! - **Login**: the device signs the server's challenge with the account key.
//! - **Device certificate**: at login the device signs its own Noise key with
//!   the account key, valid for [`CERT_VALIDITY_SECS`]. It presents the
//!   certificate to hosts; Noise already proves it owns that key.
//! - **Host trust**: a host on the account remembers the account public key
//!   and lets in devices with a valid certificate from it, without password.
//! - **Password change**: the old key signs the new one; hosts follow such a
//!   rotation automatically and certificates of the old key stop working.
//!
//! A compromised server can refuse service or withhold a revocation, but it
//! cannot issue certificates, so it cannot open anyone's computer.

use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::identity::verify_signature;
use crate::{CryptoError, Result};

/// Certificates are valid for a year; logging in again renews them.
pub const CERT_VALIDITY_SECS: i64 = 365 * 24 * 3600;
pub const SALT_LEN: usize = 16;
pub const MAX_NAME_LEN: usize = 64;

const LOGIN_CONTEXT: &[u8] = b"rc-account-login-v1";
const CERT_CONTEXT: &[u8] = b"rc-account-cert-v1";
const ROTATE_CONTEXT: &[u8] = b"rc-account-rotate-v1";
const BIND_CONTEXT: &[u8] = b"rc-account-bind-v1";
const CERT_VERSION: u8 = 1;

/// Argon2id parameters: 64 MiB, 3 passes (well under a second on a PC).
fn kdf() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("valid Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Account names: 3-32 characters, lower-case letters, digits, `.`, `_`, `-`,
/// or an e-mail address. Callers lower-case before checking.
pub fn valid_name(name: &str) -> bool {
    (3..=MAX_NAME_LEN).contains(&name.len())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'-' | b'@' | b'+')
        })
}

pub fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

/// The account's private key; exists only briefly during login.
pub struct AccountKey {
    signing: SigningKey,
}

impl AccountKey {
    /// Slow on purpose (Argon2id). The name is mixed in so equal passwords
    /// on different accounts give different keys even with equal salts.
    pub fn derive(name: &str, password: &str, salt: &[u8]) -> Result<Self> {
        if salt.len() != SALT_LEN || password.is_empty() {
            return Err(CryptoError::InvalidKey);
        }
        let mut full_salt = Vec::with_capacity(SALT_LEN + 16 + name.len());
        full_salt.extend_from_slice(b"rc-account-v1");
        full_salt.extend_from_slice(salt);
        full_salt.extend_from_slice(name.as_bytes());
        let mut seed = Zeroizing::new([0u8; 32]);
        kdf()
            .hash_password_into(password.as_bytes(), &full_salt, &mut *seed)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign_login(&self, name: &str, challenge: &[u8]) -> [u8; 64] {
        self.signing
            .sign(&login_message(name, challenge))
            .to_bytes()
    }

    /// Certificate for a device's Noise key, valid from `now_unix`.
    pub fn issue_cert(&self, name: &str, device_noise_public: &[u8; 32], now_unix: i64) -> Vec<u8> {
        let cert = DeviceCert {
            account_name: name.to_string(),
            account_public: self.public(),
            device_public: *device_noise_public,
            issued_unix: now_unix,
            expires_unix: now_unix + CERT_VALIDITY_SECS,
        };
        let body = cert.encode();
        let sig = self.signing.sign(&[CERT_CONTEXT, &body].concat());
        [body, sig.to_bytes().to_vec()].concat()
    }

    /// Proof, by this (old) key, that `new_public` replaces it.
    pub fn sign_rotation(&self, new_public: &[u8; 32]) -> [u8; 64] {
        self.signing
            .sign(&rotation_message(&self.public(), new_public))
            .to_bytes()
    }
}

fn login_message(name: &str, challenge: &[u8]) -> Vec<u8> {
    [LOGIN_CONTEXT, name.as_bytes(), b"\0", challenge].concat()
}

fn rotation_message(old: &[u8; 32], new: &[u8; 32]) -> Vec<u8> {
    [ROTATE_CONTEXT, old.as_slice(), new.as_slice()].concat()
}

/// What a device signs (with its identity key) to put itself on an account.
pub fn bind_message(name: &str, device_id: &str, noise_public: &[u8; 32]) -> Vec<u8> {
    [
        BIND_CONTEXT,
        name.as_bytes(),
        b"\0",
        device_id.as_bytes(),
        b"\0",
        noise_public.as_slice(),
    ]
    .concat()
}

pub fn verify_login(public: &[u8; 32], name: &str, challenge: &[u8], sig: &[u8; 64]) -> bool {
    verify_signature(public, &login_message(name, challenge), sig).is_ok()
}

pub fn verify_rotation(old: &[u8; 32], new: &[u8; 32], sig: &[u8; 64]) -> bool {
    verify_signature(old, &rotation_message(old, new), sig).is_ok()
}

/// Proof that a device (identified by its Noise key) belongs to an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    pub account_name: String,
    pub account_public: [u8; 32],
    pub device_public: [u8; 32],
    pub issued_unix: i64,
    pub expires_unix: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    #[error("malformed certificate")]
    Malformed,
    #[error("certificate of another account")]
    WrongAccount,
    #[error("invalid certificate signature")]
    BadSignature,
    #[error("certificate issued for another device")]
    WrongDevice,
    #[error("certificate expired")]
    Expired,
}

impl DeviceCert {
    fn encode(&self) -> Vec<u8> {
        let name = self.account_name.as_bytes();
        let mut out = Vec::with_capacity(1 + 32 + 32 + 16 + 1 + name.len());
        out.push(CERT_VERSION);
        out.extend_from_slice(&self.account_public);
        out.extend_from_slice(&self.device_public);
        out.extend_from_slice(&self.issued_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_unix.to_be_bytes());
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out
    }

    /// Parses without checking the signature (to show who it claims to be).
    pub fn parse(blob: &[u8]) -> std::result::Result<(Self, [u8; 64]), CertError> {
        const FIXED: usize = 1 + 32 + 32 + 8 + 8 + 1;
        if blob.len() < FIXED + 64 || blob[0] != CERT_VERSION {
            return Err(CertError::Malformed);
        }
        let name_len = blob[FIXED - 1] as usize;
        if name_len > MAX_NAME_LEN || blob.len() != FIXED + name_len + 64 {
            return Err(CertError::Malformed);
        }
        let take32 = |at: usize| -> [u8; 32] { blob[at..at + 32].try_into().unwrap() };
        let take8 = |at: usize| -> i64 { i64::from_be_bytes(blob[at..at + 8].try_into().unwrap()) };
        let account_name = std::str::from_utf8(&blob[FIXED..FIXED + name_len])
            .map_err(|_| CertError::Malformed)?
            .to_string();
        let sig: [u8; 64] = blob[FIXED + name_len..].try_into().unwrap();
        Ok((
            Self {
                account_public: take32(1),
                device_public: take32(33),
                issued_unix: take8(65),
                expires_unix: take8(73),
                account_name,
            },
            sig,
        ))
    }

    /// Full check: issued by `trusted_account`, for the device that proved
    /// `device_public` in the Noise handshake, and not expired.
    pub fn verify(
        blob: &[u8],
        trusted_account: &[u8; 32],
        device_public: &[u8; 32],
        now_unix: i64,
    ) -> std::result::Result<Self, CertError> {
        let (cert, sig) = Self::parse(blob)?;
        if &cert.account_public != trusted_account {
            return Err(CertError::WrongAccount);
        }
        let body = &blob[..blob.len() - 64];
        verify_signature(trusted_account, &[CERT_CONTEXT, body].concat(), &sig)
            .map_err(|_| CertError::BadSignature)?;
        if &cert.device_public != device_public {
            return Err(CertError::WrongDevice);
        }
        if now_unix > cert.expires_unix || now_unix + 300 < cert.issued_unix {
            return Err(CertError::Expired);
        }
        Ok(cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 16] = [7; 16];

    #[test]
    fn derivation_is_deterministic_and_name_bound() {
        let a = AccountKey::derive("ania", "dlugie haslo", &SALT).unwrap();
        let b = AccountKey::derive("ania", "dlugie haslo", &SALT).unwrap();
        let c = AccountKey::derive("bartek", "dlugie haslo", &SALT).unwrap();
        let d = AccountKey::derive("ania", "inne haslo", &SALT).unwrap();
        assert_eq!(a.public(), b.public());
        assert_ne!(a.public(), c.public());
        assert_ne!(a.public(), d.public());
        assert!(AccountKey::derive("ania", "x", &[1; 3]).is_err());
    }

    #[test]
    fn login_signature() {
        let key = AccountKey::derive("ania", "pw", &SALT).unwrap();
        let sig = key.sign_login("ania", b"challenge");
        assert!(verify_login(&key.public(), "ania", b"challenge", &sig));
        assert!(!verify_login(&key.public(), "ania", b"other", &sig));
        assert!(!verify_login(&key.public(), "bartek", b"challenge", &sig));
    }

    #[test]
    fn certificates() {
        let key = AccountKey::derive("ania", "pw", &SALT).unwrap();
        let other = AccountKey::derive("ania", "pw2", &SALT).unwrap();
        let device = [9u8; 32];
        let now = 1_800_000_000;
        let blob = key.issue_cert("ania", &device, now);

        let cert = DeviceCert::verify(&blob, &key.public(), &device, now + 10).unwrap();
        assert_eq!(cert.account_name, "ania");
        assert_eq!(
            DeviceCert::verify(&blob, &other.public(), &device, now),
            Err(CertError::WrongAccount)
        );
        assert_eq!(
            DeviceCert::verify(&blob, &key.public(), &[8u8; 32], now),
            Err(CertError::WrongDevice)
        );
        assert_eq!(
            DeviceCert::verify(&blob, &key.public(), &device, now + CERT_VALIDITY_SECS + 1),
            Err(CertError::Expired)
        );
        let mut forged = blob.clone();
        forged[40] ^= 1; // change the device key inside the signed body
        assert_eq!(
            DeviceCert::verify(&forged, &key.public(), &device, now),
            Err(CertError::BadSignature)
        );
        assert_eq!(
            DeviceCert::verify(&blob[..20], &key.public(), &device, now),
            Err(CertError::Malformed)
        );
    }

    #[test]
    fn rotation() {
        let old = AccountKey::derive("ania", "stare", &SALT).unwrap();
        let new = AccountKey::derive("ania", "nowe", &[3; 16]).unwrap();
        let sig = old.sign_rotation(&new.public());
        assert!(verify_rotation(&old.public(), &new.public(), &sig));
        assert!(!verify_rotation(&new.public(), &old.public(), &sig));
    }

    #[test]
    fn names() {
        assert!(valid_name("ania.kowalska@firma.pl"));
        assert!(!valid_name("Ania"));
        assert!(!valid_name("ab"));
        assert!(!valid_name("ania kowalska"));
        assert_eq!(normalize_name("  Ania@Firma.PL "), "ania@firma.pl");
    }
}
