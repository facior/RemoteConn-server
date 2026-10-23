//! Noise XX handshake and the resulting end-to-end channel.
//!
//! The channel uses snow's stateless transport with an explicit 8-byte nonce
//! prefix, so it can protect both ordered streams and lossy, reordering QUIC
//! datagrams. Traffic is split into [`Lane`]s: each lane has its own nonce
//! counter and replay window, so streams and the datagram path never reject
//! each other's nonces. The top two bits of the nonce carry the lane.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use snow::{HandshakeState, StatelessTransportState};

use crate::identity::DeviceIdentity;
use crate::{CryptoError, Result};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const NOISE_MAX_MSG: usize = 65535;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 8;
const LANE_MASK: u64 = 0b11 << 62;

/// Largest plaintext accepted by [`Sealer::seal`].
pub const MAX_PLAINTEXT: usize = NOISE_MAX_MSG - TAG_LEN;

/// Bytes added by [`Sealer::seal`] on top of the plaintext.
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Messages older than this many nonces behind the newest one are dropped.
const REPLAY_WINDOW: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Reliable, ordered QUIC stream.
    Stream,
    /// Unreliable QUIC datagrams (media).
    Datagram,
    /// Second reliable stream for file data, so it never delays input.
    Bulk,
}

impl Lane {
    fn bits(self) -> u64 {
        match self {
            Lane::Stream => 0,
            Lane::Datagram => 1 << 62,
            Lane::Bulk => 2 << 62,
        }
    }

    fn index(self) -> usize {
        (self.bits() >> 62) as usize
    }
}

pub struct Handshake {
    state: HandshakeState,
}

impl Handshake {
    /// Viewer side.
    pub fn initiator(identity: &DeviceIdentity) -> Result<Self> {
        Ok(Self {
            state: builder(identity).build_initiator()?,
        })
    }

    /// Host side.
    pub fn responder(identity: &DeviceIdentity) -> Result<Self> {
        Ok(Self {
            state: builder(identity).build_responder()?,
        })
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn is_my_turn(&self) -> bool {
        self.state.is_my_turn()
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; NOISE_MAX_MSG];
        let len = self.state.write_message(payload, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; NOISE_MAX_MSG];
        let len = self.state.read_message(msg, &mut out)?;
        out.truncate(len);
        Ok(out)
    }

    pub fn into_channel(self) -> Result<SecureChannel> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeIncomplete);
        }
        let remote_static: [u8; 32] = self
            .state
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
            .ok_or(CryptoError::InvalidKey)?;
        let handshake_hash: [u8; 32] = self
            .state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(SecureChannel {
            transport: Arc::new(self.state.into_stateless_transport_mode()?),
            remote_static,
            handshake_hash,
        })
    }
}

fn builder(identity: &DeviceIdentity) -> snow::Builder<'_> {
    snow::Builder::new(PATTERN.parse().expect("valid noise pattern"))
        .local_private_key(identity.noise_secret())
}

/// Established session; [`SecureChannel::split`] it into the halves used by
/// the transport.
pub struct SecureChannel {
    transport: Arc<StatelessTransportState>,
    remote_static: [u8; 32],
    handshake_hash: [u8; 32],
}

impl SecureChannel {
    /// Peer's Noise public key; compared with the key the rendezvous server
    /// returned for the dialed ID.
    pub fn remote_static(&self) -> &[u8; 32] {
        &self.remote_static
    }

    /// Unique per session; channel binding for password authentication.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Returns one shared sealer and an opener per lane.
    pub fn split(self) -> Halves {
        let opener = |lane| Opener {
            transport: self.transport.clone(),
            lane,
            replay: ReplayWindow::default(),
        };
        Halves {
            stream: opener(Lane::Stream),
            datagram: opener(Lane::Datagram),
            bulk: opener(Lane::Bulk),
            sealer: Sealer(Arc::new(SealerInner {
                transport: self.transport.clone(),
                counters: Default::default(),
            })),
        }
    }
}

pub struct Halves {
    pub sealer: Sealer,
    pub stream: Opener,
    pub datagram: Opener,
    pub bulk: Opener,
}

struct SealerInner {
    transport: Arc<StatelessTransportState>,
    counters: [AtomicU64; 3],
}

/// Encrypting half; cheap to clone and usable from several threads.
#[derive(Clone)]
pub struct Sealer(Arc<SealerInner>);

impl Sealer {
    pub fn seal(&self, lane: Lane, plaintext: &[u8]) -> Result<Vec<u8>> {
        let n = self.0.counters[lane.index()].fetch_add(1, Ordering::Relaxed);
        if n & LANE_MASK != 0 {
            return Err(CryptoError::Replay);
        }
        let nonce = n | lane.bits();
        let mut out = vec![0u8; OVERHEAD + plaintext.len()];
        out[..NONCE_LEN].copy_from_slice(&nonce.to_be_bytes());
        let len = self
            .0
            .transport
            .write_message(nonce, plaintext, &mut out[NONCE_LEN..])?;
        out.truncate(NONCE_LEN + len);
        Ok(out)
    }
}

/// Decrypting half for one lane.
pub struct Opener {
    transport: Arc<StatelessTransportState>,
    lane: Lane,
    replay: ReplayWindow,
}

impl Opener {
    pub fn open(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if msg.len() < OVERHEAD {
            return Err(CryptoError::Truncated);
        }
        let nonce = u64::from_be_bytes(msg[..NONCE_LEN].try_into().unwrap());
        if nonce & LANE_MASK != self.lane.bits() {
            return Err(CryptoError::Replay);
        }
        let n = nonce & !LANE_MASK;
        if !self.replay.can_accept(n) {
            return Err(CryptoError::Replay);
        }
        let mut out = vec![0u8; msg.len() - NONCE_LEN];
        let len = self
            .transport
            .read_message(nonce, &msg[NONCE_LEN..], &mut out)?;
        // Only authenticated messages may move the window.
        self.replay.mark(n);
        out.truncate(len);
        Ok(out)
    }
}

/// Sliding-window replay filter (RFC 6479 style, bitmap of recent nonces).
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: [u64; (REPLAY_WINDOW / 64) as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            bitmap: [0; (REPLAY_WINDOW / 64) as usize],
        }
    }
}

impl ReplayWindow {
    fn bit(nonce: u64) -> (usize, u64) {
        let idx = nonce % REPLAY_WINDOW;
        ((idx / 64) as usize, 1u64 << (idx % 64))
    }

    fn can_accept(&self, nonce: u64) -> bool {
        match self.highest {
            None => true,
            Some(h) if nonce > h => true,
            Some(h) if h - nonce >= REPLAY_WINDOW => false,
            Some(_) => {
                let (word, mask) = Self::bit(nonce);
                self.bitmap[word] & mask == 0
            }
        }
    }

    fn mark(&mut self, nonce: u64) {
        let advance_from = match self.highest {
            None => Some(0),
            Some(h) if nonce > h => Some(h + 1),
            Some(_) => None,
        };
        if let Some(start) = advance_from {
            // Clear bits of nonces that slide into the window.
            if nonce - start >= REPLAY_WINDOW {
                self.bitmap = [0; (REPLAY_WINDOW / 64) as usize];
            } else {
                for n in start..=nonce {
                    let (word, mask) = Self::bit(n);
                    self.bitmap[word] &= !mask;
                }
            }
            self.highest = Some(nonce);
        }
        let (word, mask) = Self::bit(nonce);
        self.bitmap[word] |= mask;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Runs a full XX handshake in memory and returns (viewer, host) channels.
    pub(crate) fn connected_pair(
        viewer: &DeviceIdentity,
        host: &DeviceIdentity,
    ) -> (SecureChannel, SecureChannel) {
        let mut i = Handshake::initiator(viewer).unwrap();
        let mut r = Handshake::responder(host).unwrap();
        let m1 = i.write_message(&[]).unwrap();
        r.read_message(&m1).unwrap();
        let m2 = r.write_message(&[]).unwrap();
        i.read_message(&m2).unwrap();
        let m3 = i.write_message(&[]).unwrap();
        r.read_message(&m3).unwrap();
        assert!(i.is_finished() && r.is_finished());
        (i.into_channel().unwrap(), r.into_channel().unwrap())
    }

    fn halves() -> ((Sealer, Opener, Opener), (Sealer, Opener, Opener)) {
        let (v, h) = connected_pair(&DeviceIdentity::generate(), &DeviceIdentity::generate());
        let (v, h) = (v.split(), h.split());
        (
            (v.sealer, v.stream, v.datagram),
            (h.sealer, h.stream, h.datagram),
        )
    }

    #[test]
    fn handshake_authenticates_static_keys() {
        let (viewer, host) = (DeviceIdentity::generate(), DeviceIdentity::generate());
        let (v, h) = connected_pair(&viewer, &host);
        assert_eq!(v.remote_static(), &host.noise_public());
        assert_eq!(h.remote_static(), &viewer.noise_public());
        assert_eq!(v.handshake_hash(), h.handshake_hash());
    }

    #[test]
    fn bidirectional_encryption() {
        let ((v_seal, mut v_open, _), (h_seal, mut h_open, _)) = halves();
        let ct = v_seal.seal(Lane::Stream, b"mouse move").unwrap();
        assert_eq!(h_open.open(&ct).unwrap(), b"mouse move");
        let ct = h_seal.seal(Lane::Stream, b"hello").unwrap();
        assert_eq!(v_open.open(&ct).unwrap(), b"hello");
    }

    #[test]
    fn lanes_are_independent() {
        let ((seal, _, _), (_, mut stream, mut dgram)) = halves();
        let s = seal.seal(Lane::Stream, b"s").unwrap();
        let d = seal.seal(Lane::Datagram, b"d").unwrap();
        // Both start at counter 0 yet neither is treated as a replay.
        assert_eq!(dgram.open(&d).unwrap(), b"d");
        assert_eq!(stream.open(&s).unwrap(), b"s");
        // A message from one lane is not accepted on the other.
        assert!(matches!(stream.open(&d), Err(CryptoError::Replay)));
    }

    #[test]
    fn bulk_lane_is_separate() {
        let (v, h) = connected_pair(&DeviceIdentity::generate(), &DeviceIdentity::generate());
        let (v, mut h) = (v.split(), h.split());
        let s = v.sealer.seal(Lane::Stream, b"input").unwrap();
        let b = v.sealer.seal(Lane::Bulk, b"file").unwrap();
        assert_eq!(h.bulk.open(&b).unwrap(), b"file");
        assert_eq!(h.stream.open(&s).unwrap(), b"input");
        assert!(matches!(h.bulk.open(&s), Err(CryptoError::Replay)));
    }

    #[test]
    fn out_of_order_accepted_replay_rejected() {
        let ((seal, _, _), (_, _, mut dgram)) = halves();
        let msgs: Vec<_> = (0..5)
            .map(|i| seal.seal(Lane::Datagram, &[i]).unwrap())
            .collect();
        for idx in [3, 0, 4, 1, 2] {
            assert_eq!(dgram.open(&msgs[idx]).unwrap(), [idx as u8]);
        }
        assert!(matches!(dgram.open(&msgs[2]), Err(CryptoError::Replay)));
    }

    #[test]
    fn too_old_rejected() {
        let ((seal, _, _), (_, _, mut dgram)) = halves();
        let old = seal.seal(Lane::Datagram, b"old").unwrap();
        for _ in 0..REPLAY_WINDOW {
            seal.seal(Lane::Datagram, b"skip").unwrap();
        }
        let newest = seal.seal(Lane::Datagram, b"new").unwrap();
        dgram.open(&newest).unwrap();
        assert!(matches!(dgram.open(&old), Err(CryptoError::Replay)));
    }

    #[test]
    fn tampering_detected_and_window_untouched() {
        let ((seal, _, _), (_, mut stream, _)) = halves();
        let mut ct = seal.seal(Lane::Stream, b"secret").unwrap();
        let good = ct.clone();
        *ct.last_mut().unwrap() ^= 1;
        assert!(matches!(stream.open(&ct), Err(CryptoError::Noise(_))));
        assert_eq!(stream.open(&good).unwrap(), b"secret");
    }

    #[test]
    fn relay_cannot_read() {
        let ((seal, _, _), _) = halves();
        let ct = seal.seal(Lane::Stream, b"password123").unwrap();
        assert!(!ct.windows(11).any(|w| w == b"password123"));
    }
}
