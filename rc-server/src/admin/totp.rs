//! TOTP (RFC 6238): HMAC-SHA1, 30-second steps, 6 digits, as in every
//! authenticator app.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

const STEP: i64 = 30;
const DIGITS: u32 = 6;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn generate_secret() -> String {
    let mut bytes = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Accepts lower case, spaces and padding, as people type them.
pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let c = c.to_ascii_uppercase() as u8;
        let value = ALPHABET.iter().position(|&a| a == c)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

pub fn code_at(secret: &[u8], step: i64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&(step as u64).to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0x0f) as usize;
    let value = u32::from_be_bytes(hash[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    value % 10u32.pow(DIGITS)
}

pub fn step_of(unix: i64) -> i64 {
    unix.div_euclid(STEP)
}

/// The time step the code matches (±1 step for clock drift), if any.
pub fn verify(secret_b32: &str, code: &str, unix: i64) -> Option<i64> {
    let secret = base32_decode(secret_b32)?;
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let code: u32 = code.parse().ok()?;
    let now = step_of(unix);
    (now - 1..=now + 1).find(|&step| code_at(&secret, step) == code)
}

/// `otpauth://` link that authenticator apps import (also as a QR code).
pub fn otpauth_uri(secret_b32: &str, user: &str, issuer: &str) -> String {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    format!(
        "otpauth://totp/{}:{}?secret={secret_b32}&issuer={}&digits={DIGITS}&period={STEP}",
        enc(issuer),
        enc(user),
        enc(issuer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        // RFC 6238 appendix B, SHA-1 key, truncated to 6 digits.
        let secret = b"12345678901234567890";
        for (time, expected) in [
            (59, 287082),
            (1111111109, 81804),
            (1234567890, 5924),
            (2000000000, 279037),
        ] {
            assert_eq!(code_at(secret, step_of(time)), expected, "t={time}");
        }
    }

    #[test]
    fn base32_roundtrip_and_verify() {
        let secret = generate_secret();
        let bytes = base32_decode(&secret).unwrap();
        assert_eq!(bytes.len(), 20);
        assert_eq!(base32_encode(&bytes), secret);
        assert_eq!(
            base32_decode("GEZDGNBV GY3TQOJQ").unwrap(),
            b"1234567890".to_vec()
        );

        let now = 1_700_000_000;
        let code = format!("{:06}", code_at(&bytes, step_of(now - 30)));
        assert_eq!(verify(&secret, &code, now), Some(step_of(now) - 1));
        let stale = format!("{:06}", code_at(&bytes, step_of(now - 90)));
        assert_eq!(verify(&secret, &stale, now), None);
        assert_eq!(verify(&secret, "12345", now), None);
    }
}
