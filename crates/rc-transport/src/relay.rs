//! Relay client. Both peers bind to the relay with the same session token;
//! once paired, the relay pipes the stream and datagrams between them and the
//! Noise handshake runs end to end on top (see [`crate::initiator_over`]).

use std::net::SocketAddr;
use std::time::Duration;

use quinn::{ClientConfig, Connection, RecvStream, SendStream};
use rc_proto::rendezvous::{open, relay_bind::Role, Open, RelayBind, RelayReady};

use crate::{dial_with, frame, Endpoint, Result, TransportError};

/// How long to wait for the other peer to show up at the relay.
pub const BIND_TIMEOUT: Duration = Duration::from_secs(20);

/// `config` pins the relay's certificate when it is the rendezvous server
/// itself; `access_key` is the server's access key (empty if none).
pub async fn bind(
    endpoint: &Endpoint,
    relay: SocketAddr,
    token: &[u8],
    role: Role,
    access_key: &str,
    config: Option<ClientConfig>,
) -> Result<(Connection, SendStream, RecvStream)> {
    let conn = dial_with(endpoint, &[relay], Duration::from_secs(10), config).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    frame::write(
        &mut send,
        &Open {
            kind: Some(open::Kind::Relay(RelayBind {
                session_token: token.to_vec(),
                role: role as i32,
                access_key: access_key.to_string(),
            })),
        },
    )
    .await?;
    tokio::time::timeout(BIND_TIMEOUT, frame::read::<RelayReady>(&mut recv))
        .await
        .map_err(|_| TransportError::Timeout)??;
    Ok((conn, send, recv))
}
