//! Account client: sign-up, login, device list and password change.
//!
//! The password never leaves the device: it is turned into the account key
//! here (rc-crypto `account`, Argon2id on a blocking thread), and only the
//! public key and signatures are sent.

use rand::RngCore;
use rc_crypto::account::{self as acc, AccountKey, SALT_LEN};
use rc_proto::rendezvous::{
    account_call, client_message, server_message::Msg, AccountBindDevice, AccountCall,
    AccountChangeKey, AccountDevice, AccountListDevices, AccountLogin as LoginMsg, AccountLogout,
    AccountPrelogin, AccountRegister, AccountRevokeDevice, AccountUnbindDevice, ServerMessage,
};
use rc_transport::{frame, Endpoint, RecvStream, SendStream};

use crate::{client, open_rendezvous, read_timeout, RendezvousError, Result, ServerInfo};

/// A successful login or sign-up. `key` is the account's private key: use it
/// right away (certificate for this device) and drop it.
pub struct AccountLogin {
    pub token: Vec<u8>,
    pub name: String,
    pub display_name: String,
    pub key: AccountKey,
    /// Server certificate fingerprint seen (to pin).
    pub server_fingerprint: [u8; 32],
}

/// Operations that need a session token.
pub enum AccountOp {
    ListDevices,
    /// Signed with the device identity: see rc-crypto `bind_message`.
    BindDevice {
        device_id: String,
        noise_public: [u8; 32],
        verifying_key: [u8; 32],
        signature: [u8; 64],
        device_name: String,
    },
    UnbindDevice([u8; 32]),
    RevokeDevice([u8; 32]),
    Logout,
}

async fn derive(name: String, password: String, salt: Vec<u8>) -> Result<AccountKey> {
    tokio::task::spawn_blocking(move || AccountKey::derive(&name, &password, &salt))
        .await
        .map_err(|_| RendezvousError::Protocol)?
        .map_err(|_| RendezvousError::Server("nieprawidłowe dane konta".into()))
}

async fn request(
    send: &mut SendStream,
    recv: &mut RecvStream,
    msg: client_message::Msg,
) -> Result<Msg> {
    frame::write(send, &client(msg)).await?;
    match read_timeout::<ServerMessage>(recv).await?.msg {
        Some(Msg::Error(e)) => Err(RendezvousError::Server(e.message)),
        Some(m) => Ok(m),
        None => Err(RendezvousError::Protocol),
    }
}

fn check_name(name: &str) -> Result<String> {
    let name = acc::normalize_name(name);
    if acc::valid_name(&name) {
        Ok(name)
    } else {
        Err(RendezvousError::Server(
            "nazwa konta: 3-64 znaki, małe litery, cyfry, . _ - @ +".into(),
        ))
    }
}

pub async fn account_register(
    endpoint: &Endpoint,
    server: &ServerInfo,
    name: &str,
    password: &str,
    invite: &str,
    display_name: &str,
) -> Result<AccountLogin> {
    let name = check_name(name)?;
    let mut salt = vec![0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive(name.clone(), password.to_string(), salt.clone()).await?;
    let (mut send, mut recv, _hello, fingerprint) = open_rendezvous(endpoint, server).await?;
    let reply = request(
        &mut send,
        &mut recv,
        client_message::Msg::AccountRegister(AccountRegister {
            name: name.clone(),
            invite: invite.trim().to_string(),
            salt,
            public_key: key.public().to_vec(),
            display_name: display_name.to_string(),
        }),
    )
    .await?;
    let Msg::AccountSession(session) = reply else {
        return Err(RendezvousError::Protocol);
    };
    Ok(AccountLogin {
        token: session.token,
        name: session.name,
        display_name: session.display_name,
        key,
        server_fingerprint: fingerprint,
    })
}

pub async fn account_login(
    endpoint: &Endpoint,
    server: &ServerInfo,
    name: &str,
    password: &str,
) -> Result<AccountLogin> {
    let name = check_name(name)?;
    let (mut send, mut recv, hello, fingerprint) = open_rendezvous(endpoint, server).await?;
    let Msg::AccountSalt(salt) = request(
        &mut send,
        &mut recv,
        client_message::Msg::AccountPrelogin(AccountPrelogin { name: name.clone() }),
    )
    .await?
    else {
        return Err(RendezvousError::Protocol);
    };
    let key = derive(name.clone(), password.to_string(), salt.salt).await?;
    let signature = key.sign_login(&name, &hello.challenge).to_vec();
    let Msg::AccountSession(session) = request(
        &mut send,
        &mut recv,
        client_message::Msg::AccountLogin(LoginMsg {
            name: name.clone(),
            signature,
        }),
    )
    .await?
    else {
        return Err(RendezvousError::Protocol);
    };
    Ok(AccountLogin {
        token: session.token,
        name: session.name,
        display_name: session.display_name,
        key,
        server_fingerprint: fingerprint,
    })
}

async fn call(
    endpoint: &Endpoint,
    server: &ServerInfo,
    token: &[u8],
    op: account_call::Op,
) -> Result<Vec<AccountDevice>> {
    let (mut send, mut recv, _hello, _) = open_rendezvous(endpoint, server).await?;
    let reply = request(
        &mut send,
        &mut recv,
        client_message::Msg::AccountCall(AccountCall {
            token: token.to_vec(),
            op: Some(op),
        }),
    )
    .await?;
    match reply {
        Msg::AccountReply(r) if r.error.is_empty() => Ok(r.devices),
        Msg::AccountReply(r) => Err(RendezvousError::Server(r.error)),
        _ => Err(RendezvousError::Protocol),
    }
}

/// Runs an operation; returns the account's devices afterwards.
pub async fn account_call(
    endpoint: &Endpoint,
    server: &ServerInfo,
    token: &[u8],
    op: AccountOp,
) -> Result<Vec<AccountDevice>> {
    let op = match op {
        AccountOp::ListDevices => account_call::Op::ListDevices(AccountListDevices {}),
        AccountOp::BindDevice {
            device_id,
            noise_public,
            verifying_key,
            signature,
            device_name,
        } => account_call::Op::BindDevice(AccountBindDevice {
            device_id,
            noise_public: noise_public.to_vec(),
            verifying_key: verifying_key.to_vec(),
            signature: signature.to_vec(),
            device_name,
        }),
        AccountOp::UnbindDevice(key) => account_call::Op::UnbindDevice(AccountUnbindDevice {
            noise_public: key.to_vec(),
        }),
        AccountOp::RevokeDevice(key) => account_call::Op::RevokeDevice(AccountRevokeDevice {
            noise_public: key.to_vec(),
        }),
        AccountOp::Logout => account_call::Op::Logout(AccountLogout {}),
    };
    call(endpoint, server, token, op).await
}

/// Changes the password: proves the old one (by deriving the old key and
/// signing the new key with it). Returns the new key.
pub async fn change_password(
    endpoint: &Endpoint,
    server: &ServerInfo,
    token: &[u8],
    name: &str,
    old_password: &str,
    new_password: &str,
) -> Result<AccountKey> {
    let name = check_name(name)?;
    let salt = {
        let (mut send, mut recv, _hello, _) = open_rendezvous(endpoint, server).await?;
        match request(
            &mut send,
            &mut recv,
            client_message::Msg::AccountPrelogin(AccountPrelogin { name: name.clone() }),
        )
        .await?
        {
            Msg::AccountSalt(s) => s.salt,
            _ => return Err(RendezvousError::Protocol),
        }
    };
    let old = derive(name.clone(), old_password.to_string(), salt).await?;
    let mut new_salt = vec![0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut new_salt);
    let new = derive(name, new_password.to_string(), new_salt.clone()).await?;
    let signature = old.sign_rotation(&new.public());
    call(
        endpoint,
        server,
        token,
        account_call::Op::ChangeKey(AccountChangeKey {
            new_public_key: new.public().to_vec(),
            new_salt,
            signature: signature.to_vec(),
        }),
    )
    .await
    .map_err(|e| match e {
        // A wrong old password produces a signature the server rejects.
        RendezvousError::Server(_) => RendezvousError::Server("nieprawidłowe obecne hasło".into()),
        other => other,
    })?;
    Ok(new)
}
