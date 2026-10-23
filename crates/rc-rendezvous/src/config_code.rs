//! Configuration code: the server address, access key and certificate
//! fingerprint in one string that an administrator copies from the server
//! (panel or `rc-admin app`) and a user pastes into the app.
//!
//! Format: `RC1-` + base64url (no padding) of `server\naccess_key\nfp_hex`.
//! The fingerprint makes the pasted server trusted from the first contact,
//! instead of trust on first use.

use std::fmt;

const PREFIX: &str = "RC1-";
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigCode {
    /// `host:port` (or `host`, then the default port applies).
    pub server: String,
    /// Empty when the server does not require one.
    pub access_key: String,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigCodeError {
    #[error("to nie jest kod konfiguracji RemoteConn (zaczyna się od RC1-)")]
    NotACode,
    #[error("kod konfiguracji jest uszkodzony albo niepełny")]
    Corrupt,
}

impl ConfigCode {
    pub fn encode(&self) -> String {
        let fp: String = self
            .fingerprint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let raw = format!("{}\n{}\n{fp}", self.server.trim(), self.access_key.trim());
        format!("{PREFIX}{}", encode_b64(raw.as_bytes()))
    }

    /// Accepts the code with surrounding text whitespace or line breaks added
    /// by copying it from a terminal or a message.
    pub fn decode(code: &str) -> Result<Self, ConfigCodeError> {
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let body = code
            .get(..PREFIX.len())
            .filter(|p| p.eq_ignore_ascii_case(PREFIX))
            .map(|_| &code[PREFIX.len()..])
            .ok_or(ConfigCodeError::NotACode)?;
        let raw = decode_b64(body).ok_or(ConfigCodeError::Corrupt)?;
        let raw = String::from_utf8(raw).map_err(|_| ConfigCodeError::Corrupt)?;
        let mut parts = raw.split('\n');
        let (Some(server), Some(access_key), Some(fp), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ConfigCodeError::Corrupt);
        };
        let fingerprint = parse_hex32(fp).ok_or(ConfigCodeError::Corrupt)?;
        let valid = |s: &str| s.chars().all(|c| c.is_ascii_graphic());
        if server.is_empty() || !valid(server) || !valid(access_key) {
            return Err(ConfigCodeError::Corrupt);
        }
        Ok(Self {
            server: server.to_string(),
            access_key: access_key.to_string(),
            fingerprint,
        })
    }
}

impl fmt::Display for ConfigCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn encode_b64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let v = ALPHABET.iter().position(|&a| a == c)? as u32;
            n |= v << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConfigCode {
        ConfigCode {
            server: "203.0.113.10:21116".into(),
            access_key: "AbCdEfGh23456789".into(),
            fingerprint: core::array::from_fn(|i| i as u8 * 7),
        }
    }

    #[test]
    fn round_trips() {
        let code = sample().encode();
        assert!(code.starts_with("RC1-"));
        assert_eq!(ConfigCode::decode(&code).unwrap(), sample());
    }

    #[test]
    fn round_trips_every_length() {
        for len in 0..6 {
            let mut c = sample();
            c.access_key = "k".repeat(len);
            assert_eq!(ConfigCode::decode(&c.encode()).unwrap(), c);
        }
    }

    #[test]
    fn tolerates_line_breaks_and_case_of_prefix() {
        let code = sample().encode();
        let (a, b) = code.split_at(20);
        let pasted = format!("  rc1-{}\n  {b}\n", &a[4..]);
        assert_eq!(ConfigCode::decode(&pasted).unwrap(), sample());
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(
            ConfigCode::decode("203.0.113.10:21116"),
            Err(ConfigCodeError::NotACode)
        );
        assert_eq!(
            ConfigCode::decode("RC1-@@@@"),
            Err(ConfigCodeError::Corrupt)
        );
        let truncated = &sample().encode()[..40];
        assert_eq!(ConfigCode::decode(truncated), Err(ConfigCodeError::Corrupt));
        let two_lines = format!("{PREFIX}{}", encode_b64(b"host\nkey"));
        assert_eq!(
            ConfigCode::decode(&two_lines),
            Err(ConfigCodeError::Corrupt)
        );
    }
}
