//! Password authentication with SPAKE2 plus key confirmation.
//!
//! Flow (inside the Noise channel):
//! 1. Both sides call [`PasswordAuth::start`] and exchange the returned message.
//! 2. Both call [`PasswordAuth::finish`] with the peer message, getting a
//!    [`ConfirmedKey`] candidate, and exchange [`ConfirmedKey::my_tag`].
//! 3. [`ConfirmedKey::verify_peer`] succeeds only if both used the same password
//!    over the same Noise session.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PakeRole {
    Viewer,
    Host,
}

impl PakeRole {
    fn label(self) -> &'static [u8] {
        match self {
            PakeRole::Viewer => b"rc-viewer",
            PakeRole::Host => b"rc-host",
        }
    }

    fn peer(self) -> Self {
        match self {
            PakeRole::Viewer => PakeRole::Host,
            PakeRole::Host => PakeRole::Viewer,
        }
    }
}

pub struct PasswordAuth {
    role: PakeRole,
    state: Spake2<Ed25519Group>,
}

impl PasswordAuth {
    /// `handshake_hash` comes from [`crate::SecureChannel::handshake_hash`].
    pub fn start(role: PakeRole, password: &str, handshake_hash: &[u8; 32]) -> (Self, Vec<u8>) {
        let id_a = Identity::new(&[PakeRole::Viewer.label(), handshake_hash].concat());
        let id_b = Identity::new(&[PakeRole::Host.label(), handshake_hash].concat());
        let pw = Password::new(password.as_bytes());
        let (state, msg) = match role {
            PakeRole::Viewer => Spake2::<Ed25519Group>::start_a(&pw, &id_a, &id_b),
            PakeRole::Host => Spake2::<Ed25519Group>::start_b(&pw, &id_a, &id_b),
        };
        (Self { role, state }, msg)
    }

    pub fn finish(self, peer_msg: &[u8]) -> Result<ConfirmedKey> {
        let key = self
            .state
            .finish(peer_msg)
            .map_err(|_| CryptoError::AuthFailed)?;
        let key: [u8; 32] = key.try_into().map_err(|_| CryptoError::AuthFailed)?;
        Ok(ConfirmedKey {
            role: self.role,
            key: Zeroizing::new(key),
        })
    }
}

/// SPAKE2 output that is trusted only after [`ConfirmedKey::verify_peer`].
pub struct ConfirmedKey {
    role: PakeRole,
    key: Zeroizing<[u8; 32]>,
}

impl ConfirmedKey {
    fn tag(&self, role: PakeRole) -> blake3::Hash {
        blake3::keyed_hash(&self.key, role.label())
    }

    pub fn my_tag(&self) -> [u8; 32] {
        *self.tag(self.role).as_bytes()
    }

    pub fn verify_peer(&self, peer_tag: &[u8]) -> Result<()> {
        let peer_tag: [u8; 32] = peer_tag.try_into().map_err(|_| CryptoError::AuthFailed)?;
        // blake3::Hash equality is constant time.
        if self.tag(self.role.peer()) == blake3::Hash::from(peer_tag) {
            Ok(())
        } else {
            Err(CryptoError::AuthFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::tests::connected_pair;
    use crate::DeviceIdentity;

    fn run(viewer_pw: &str, host_pw: &str, v_hash: &[u8; 32], h_hash: &[u8; 32]) -> Result<()> {
        let (v, v_msg) = PasswordAuth::start(PakeRole::Viewer, viewer_pw, v_hash);
        let (h, h_msg) = PasswordAuth::start(PakeRole::Host, host_pw, h_hash);
        let v_key = v.finish(&h_msg)?;
        let h_key = h.finish(&v_msg)?;
        h_key.verify_peer(&v_key.my_tag())?;
        v_key.verify_peer(&h_key.my_tag())
    }

    #[test]
    fn same_password_succeeds() {
        let (v, h) = connected_pair(&DeviceIdentity::generate(), &DeviceIdentity::generate());
        run("k7#pQ2", "k7#pQ2", v.handshake_hash(), h.handshake_hash()).unwrap();
    }

    #[test]
    fn wrong_password_fails() {
        let (v, h) = connected_pair(&DeviceIdentity::generate(), &DeviceIdentity::generate());
        assert!(run("guess", "k7#pQ2", v.handshake_hash(), h.handshake_hash()).is_err());
    }

    #[test]
    fn spliced_sessions_fail() {
        // A MITM terminating two separate Noise sessions sees different hashes.
        let (v, _) = connected_pair(&DeviceIdentity::generate(), &DeviceIdentity::generate());
        let (_, h) = connected_pair(&DeviceIdentity::generate(), &DeviceIdentity::generate());
        assert!(run("k7#pQ2", "k7#pQ2", v.handshake_hash(), h.handshake_hash()).is_err());
    }

    #[test]
    fn reflected_tag_rejected() {
        let (v, _) = connected_pair(&DeviceIdentity::generate(), &DeviceIdentity::generate());
        let (auth, _) = PasswordAuth::start(PakeRole::Viewer, "pw", v.handshake_hash());
        let (_, h_msg) = PasswordAuth::start(PakeRole::Host, "pw", v.handshake_hash());
        let key = auth.finish(&h_msg).unwrap();
        assert!(key.verify_peer(&key.my_tag()).is_err());
    }
}
