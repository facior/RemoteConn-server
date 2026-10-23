//! Long-term device identity, generated once at install time.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// Serialized length of [`DeviceIdentity::to_secret_bytes`].
pub const SECRET_LEN: usize = 64;

/// Static Noise key (X25519) plus a signing key (Ed25519) used to register the
/// device with the rendezvous server.
pub struct DeviceIdentity {
    noise_secret: StaticSecret,
    noise_public: PublicKey,
    signing: SigningKey,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        let noise_secret = StaticSecret::random_from_rng(OsRng);
        Self {
            noise_public: PublicKey::from(&noise_secret),
            noise_secret,
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Secret material for the platform key store (DPAPI / Keychain).
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; SECRET_LEN]> {
        let mut out = Zeroizing::new([0u8; SECRET_LEN]);
        out[..32].copy_from_slice(self.noise_secret.as_bytes());
        out[32..].copy_from_slice(self.signing.as_bytes());
        out
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let mut noise = Zeroizing::new([0u8; 32]);
        let mut sign = Zeroizing::new([0u8; 32]);
        noise.copy_from_slice(&bytes[..32]);
        sign.copy_from_slice(&bytes[32..]);
        let noise_secret = StaticSecret::from(*noise);
        Ok(Self {
            noise_public: PublicKey::from(&noise_secret),
            noise_secret,
            signing: SigningKey::from_bytes(&sign),
        })
    }

    pub fn noise_public(&self) -> [u8; 32] {
        self.noise_public.to_bytes()
    }

    pub(crate) fn noise_secret(&self) -> &[u8; 32] {
        self.noise_secret.as_bytes()
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// Short human-readable fingerprint shown in the accept dialog.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.noise_public())
    }
}

/// Fingerprint of a Noise public key, e.g. `3f2a-91c0-77de-0b14`.
pub fn fingerprint(noise_public: &[u8; 32]) -> String {
    let hash = blake3::hash(noise_public);
    hash.as_bytes()[..8]
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join("-")
}

pub fn verify_signature(verifying_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    let key = VerifyingKey::from_bytes(verifying_key).map_err(|_| CryptoError::InvalidKey)?;
    key.verify(msg, &Signature::from_bytes(sig))
        .map_err(|_| CryptoError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_roundtrip() {
        let id = DeviceIdentity::generate();
        let restored = DeviceIdentity::from_secret_bytes(&*id.to_secret_bytes()).unwrap();
        assert_eq!(id.noise_public(), restored.noise_public());
        assert_eq!(id.verifying_key(), restored.verifying_key());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(DeviceIdentity::from_secret_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn signature_verifies() {
        let id = DeviceIdentity::generate();
        let sig = id.sign(b"register 123456789");
        verify_signature(&id.verifying_key(), b"register 123456789", &sig).unwrap();
        assert!(verify_signature(&id.verifying_key(), b"register 987654321", &sig).is_err());
    }

    #[test]
    fn fingerprint_format() {
        let fp = DeviceIdentity::generate().fingerprint();
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.matches('-').count(), 3);
    }
}
