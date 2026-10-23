//! Cryptography for RemoteConn.
//!
//! Session setup between viewer and host:
//! 1. Noise XX handshake ([`noise`]) authenticates both device keys and yields
//!    an end-to-end [`noise::SecureChannel`] that relays cannot read.
//! 2. SPAKE2 ([`pake`]) proves both sides know the host password, bound to the
//!    Noise handshake hash so a man in the middle cannot splice two sessions.

pub mod account;
pub mod identity;
pub mod noise;
pub mod pake;

pub use identity::DeviceIdentity;
pub use noise::{Halves, Handshake, Lane, Opener, Sealer, SecureChannel};
pub use pake::{PakeRole, PasswordAuth};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("handshake not finished")]
    HandshakeIncomplete,
    #[error("message too short")]
    Truncated,
    #[error("replayed or too old message")]
    Replay,
    #[error("invalid key material")]
    InvalidKey,
    #[error("password authentication failed")]
    AuthFailed,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
