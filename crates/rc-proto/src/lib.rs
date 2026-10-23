//! RemoteConn wire protocol.
//!
//! Reliable messages travel as length-delimited [`Envelope`]s over QUIC streams,
//! media travels as single [`Datagram`]s over QUIC datagrams.

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/remoteconn.v1.rs"));
}

/// Rendezvous / relay server protocol.
pub mod rendezvous {
    include!(concat!(env!("OUT_DIR"), "/remoteconn.rendezvous.v1.rs"));

    /// Bumped on every incompatible change to `rendezvous.proto`.
    pub const PROTOCOL_VERSION: u32 = 1;

    /// Domain separation for the registration signature.
    pub const REGISTER_CONTEXT: &[u8] = b"rc-register-v1";
}

pub mod text;

pub use prost::Message;
pub use v1::*;

/// Bumped on every incompatible change to `remoteconn.proto`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Upper bound for one reliable message; larger payloads (files) are chunked.
pub const MAX_ENVELOPE_LEN: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("message too large: {0} bytes")]
    TooLarge(usize),
    #[error("empty envelope")]
    Empty,
    #[error(transparent)]
    Prost(#[from] prost::DecodeError),
}

/// Encodes an envelope with a varint length prefix.
pub fn encode_envelope(msg: envelope::Msg) -> Vec<u8> {
    Envelope { msg: Some(msg) }.encode_length_delimited_to_vec()
}

/// Decodes one length-delimited envelope from the start of `buf`.
///
/// Returns `Ok(None)` when `buf` does not yet hold a complete message, otherwise
/// the message and the number of bytes consumed.
pub fn decode_envelope(buf: &[u8]) -> Result<Option<(envelope::Msg, usize)>, DecodeError> {
    let mut cursor = buf;
    let len = match prost::encoding::decode_varint(&mut cursor) {
        Ok(len) => len as usize,
        // A truncated varint is just an incomplete prefix.
        Err(_) if buf.len() < 10 => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if len > MAX_ENVELOPE_LEN {
        return Err(DecodeError::TooLarge(len));
    }
    let prefix = buf.len() - cursor.len();
    if cursor.len() < len {
        return Ok(None);
    }
    let env = Envelope::decode(&cursor[..len])?;
    let msg = env.msg.ok_or(DecodeError::Empty)?;
    Ok(Some((msg, prefix + len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let hello = envelope::Msg::Hello(Hello {
            protocol_version: PROTOCOL_VERSION,
            device_name: "office-pc".into(),
            video_codecs: vec!["h264".into()],
            ..Default::default()
        });
        let bytes = encode_envelope(hello.clone());
        let (decoded, used) = decode_envelope(&bytes).unwrap().unwrap();
        assert_eq!(decoded, hello);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn partial_envelope_waits_for_more() {
        let bytes = encode_envelope(envelope::Msg::Chat(ChatMessage {
            text: "hej".into(),
            sent_unix_ms: 1,
        }));
        for cut in 0..bytes.len() {
            assert!(decode_envelope(&bytes[..cut]).unwrap().is_none());
        }
    }

    #[test]
    fn two_envelopes_in_one_buffer() {
        let mut buf = encode_envelope(envelope::Msg::KeyframeRequest(KeyframeRequest {
            monitor_id: 1,
        }));
        buf.extend(encode_envelope(envelope::Msg::SelectMonitor(
            SelectMonitor { monitor_id: 2 },
        )));
        let (first, used) = decode_envelope(&buf).unwrap().unwrap();
        assert!(matches!(first, envelope::Msg::KeyframeRequest(_)));
        let (second, _) = decode_envelope(&buf[used..]).unwrap().unwrap();
        assert_eq!(
            second,
            envelope::Msg::SelectMonitor(SelectMonitor { monitor_id: 2 })
        );
    }

    #[test]
    fn rejects_oversized_length() {
        let mut buf = Vec::new();
        prost::encoding::encode_varint((MAX_ENVELOPE_LEN + 1) as u64, &mut buf);
        assert!(matches!(
            decode_envelope(&buf),
            Err(DecodeError::TooLarge(_))
        ));
    }

    #[test]
    fn datagram_roundtrip() {
        let dg = Datagram {
            msg: Some(datagram::Msg::Video(VideoPacket {
                frame_id: 7,
                fragment_count: 1,
                keyframe: true,
                data: vec![0, 0, 0, 1, 0x65],
                ..Default::default()
            })),
        };
        let bytes = dg.encode_to_vec();
        assert_eq!(Datagram::decode(bytes.as_slice()).unwrap(), dg);
    }
}
