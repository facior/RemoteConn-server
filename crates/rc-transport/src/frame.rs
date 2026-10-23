//! Plain (TLS-only) protobuf frames, used to talk to the rendezvous server.
//! Peer-to-peer traffic never uses these; it goes through the Noise channel.

use quinn::{RecvStream, SendStream};
use rc_proto::Message;

use crate::{read_record, write_record, Result};

pub async fn write<M: Message>(send: &mut SendStream, msg: &M) -> Result<()> {
    write_record(send, &msg.encode_to_vec()).await
}

pub async fn read<M: Message + Default>(recv: &mut RecvStream) -> Result<M> {
    Ok(M::decode(read_record(recv).await?.as_slice())?)
}
