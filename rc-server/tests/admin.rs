//! Admin panel API against a real server on loopback.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rc_crypto::identity::DeviceIdentity;
use rc_rendezvous::{HostEvent, HostRegistration, ServerInfo};
use rc_server::admin::{totp, users};
use rc_server::{ServerConfig, ServerHandle};
use reqwest::{header, Client, StatusCode};
use serde_json::{json, Value};

const PASSWORD: &str = "correct horse battery staple";

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rc-admin-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn add_user(dir: &Path, name: &str, totp: Option<String>) {
    let mut all = users::load(dir).unwrap();
    all.insert(
        name.into(),
        users::User {
            hash: users::hash_password(PASSWORD),
            totp,
            created_unix: 0,
        },
    );
    users::save(dir, &all).unwrap();
}

async fn start(dir: &Path) -> (ServerHandle, String) {
    let mut cfg = ServerConfig::new("127.0.0.1:0".parse().unwrap(), dir.to_path_buf());
    cfg.admin_bind = Some("127.0.0.1:0".parse().unwrap());
    let server = rc_server::start(cfg).await.unwrap();
    let base = format!("http://{}", server.admin_addr.unwrap());
    (server, base)
}

struct Session {
    client: Client,
    base: String,
    cookie: String,
    csrf: String,
}

impl Session {
    async fn get(&self, path: &str) -> (StatusCode, Value) {
        let r = self
            .client
            .get(format!("{}{path}", self.base))
            .header(header::COOKIE, &self.cookie)
            .send()
            .await
            .unwrap();
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let r = self
            .client
            .post(format!("{}{path}", self.base))
            .header(header::COOKIE, &self.cookie)
            .header("x-rc-csrf", &self.csrf)
            .json(&body)
            .send()
            .await
            .unwrap();
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }
}

async fn login(base: &str, user: &str, password: &str, code: &str) -> Result<Session, StatusCode> {
    let client = Client::new();
    let r = client
        .post(format!("{base}/api/login"))
        .json(&json!({ "user": user, "password": password, "code": code }))
        .send()
        .await
        .unwrap();
    if !r.status().is_success() {
        return Err(r.status());
    }
    let set_cookie = r.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"));
    let cookie = set_cookie.split(';').next().unwrap().to_string();
    let body: Value = r.json().await.unwrap();
    Ok(Session {
        client,
        base: base.into(),
        cookie,
        csrf: body["csrf"].as_str().unwrap().into(),
    })
}

#[tokio::test]
async fn login_csrf_and_blocklist() {
    let dir = temp_dir("main");
    add_user(&dir, "admin", None);
    let (server, base) = start(&dir).await;
    let client = Client::new();

    // The page itself is public, with strict headers.
    let page = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let csp = page.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'") && csp.contains("script-src 'self'"));
    assert_eq!(page.headers()["x-frame-options"], "DENY");
    assert_eq!(page.headers()["cache-control"], "no-store");

    // DNS rebinding: a foreign Host name is refused.
    let rebound = client
        .get(format!("{base}/api/overview"))
        .header(header::HOST, "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), StatusCode::MISDIRECTED_REQUEST);

    // No session, no data.
    let anon = client
        .get(format!("{base}/api/overview"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        login(&base, "admin", "wrong password!!", "").await.err(),
        Some(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        login(&base, "nobody", PASSWORD, "").await.err(),
        Some(StatusCode::UNAUTHORIZED)
    );

    let s = login(&base, "admin", PASSWORD, "").await.unwrap();
    let (status, overview) = s.get("/api/overview").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        overview["fingerprint"],
        rc_server::short_fingerprint(&server.fingerprint)
    );
    assert_eq!(overview["access_key_set"], false);

    // Changes need the CSRF token...
    let no_csrf = s
        .client
        .post(format!("{base}/api/block"))
        .header(header::COOKIE, &s.cookie)
        .json(&json!({ "kind": "ip", "value": "203.0.113.5" }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
    // ...and must not come from another site.
    let cross = s
        .client
        .post(format!("{base}/api/block"))
        .header(header::COOKIE, &s.cookie)
        .header("x-rc-csrf", &s.csrf)
        .header(header::ORIGIN, "https://evil.example")
        .json(&json!({ "kind": "ip", "value": "203.0.113.5" }))
        .send()
        .await
        .unwrap();
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);

    let (status, _) = s
        .post(
            "/api/block",
            json!({ "kind": "device", "value": "123 456 789" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = s
        .post("/api/block", json!({ "kind": "net", "value": "not-a-net" }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, list) = s.get("/api/blocklist").await;
    assert_eq!(list["entries"][0]["line"], "device 123456789");
    let file = std::fs::read_to_string(dir.join("blocklist.txt")).unwrap();
    assert!(file.contains("device 123456789"));

    let (status, _) = s
        .post("/api/unblock", json!({ "line": "device 123456789" }))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, list) = s.get("/api/blocklist").await;
    assert_eq!(list["entries"].as_array().unwrap().len(), 0);

    // Everything is in the audit log, failed logins included.
    let (_, audit) = s.get("/api/audit").await;
    let lines: Vec<&str> = audit["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert!(lines
        .iter()
        .any(|l| l.contains("admin") && l.contains("blokada: device 123456789")));
    assert!(lines
        .iter()
        .any(|l| l.contains("(nobody)") && l.contains("nieudane logowanie")));

    // Removing the account ends its sessions at once.
    let mut all = users::load(&dir).unwrap();
    all.remove("admin");
    users::save(&dir, &all).unwrap();
    assert_eq!(s.get("/api/overview").await.0, StatusCode::UNAUTHORIZED);

    server.stop();
    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn invites_and_accounts() {
    let dir = temp_dir("accounts");
    add_user(&dir, "admin", None);
    let (server, base) = start(&dir).await;
    let s = login(&base, "admin", PASSWORD, "").await.unwrap();

    let (status, created) = s.post("/api/invites", json!({ "note": "dla Ani" })).await;
    assert_eq!(status, StatusCode::OK);
    let code = created["code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 14, "XXXX-XXXX-XXXX");
    let (_, list) = s.get("/api/invites").await;
    assert_eq!(list["invites"][0]["note"], "dla Ani");
    let (_, accounts) = s.get("/api/accounts").await;
    assert_eq!(accounts["signup"], "invite");
    assert_eq!(accounts["accounts"].as_array().unwrap().len(), 0);

    // A user signs up with the code through the rendezvous protocol.
    let endpoint = rc_transport::client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    let info = ServerInfo {
        addr: server.local_addr,
        access_key: String::new(),
        pin: None,
    };
    rc_rendezvous::account_register(&endpoint, &info, "ania", "dlugie-haslo-ani", &code, "Ania")
        .await
        .expect("sign-up with the invite");
    let (_, accounts) = s.get("/api/accounts").await;
    assert_eq!(accounts["accounts"][0]["name"], "ania");
    let (_, list) = s.get("/api/invites").await;
    assert_eq!(
        list["invites"].as_array().unwrap().len(),
        0,
        "invite used up"
    );

    let (status, _) = s.post("/api/accounts/ania/disable", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let (_, accounts) = s.get("/api/accounts").await;
    assert_eq!(accounts["accounts"][0]["disabled"], true);
    assert!(
        rc_rendezvous::account_login(&endpoint, &info, "ania", "dlugie-haslo-ani")
            .await
            .is_err(),
        "disabled account cannot log in"
    );

    server.stop();
    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn lockout_and_totp() {
    let dir = temp_dir("lock");
    let secret = totp::generate_secret();
    add_user(&dir, "victim", None);
    add_user(&dir, "secure", Some(secret.clone()));
    let (server, base) = start(&dir).await;

    for _ in 0..5 {
        assert_eq!(
            login(&base, "victim", "guess guess guess", "").await.err(),
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    // Locked: even the right password is refused now.
    assert_eq!(
        login(&base, "victim", PASSWORD, "").await.err(),
        Some(StatusCode::TOO_MANY_REQUESTS)
    );

    // 2FA: the password alone is not enough, a code works once.
    assert_eq!(
        login(&base, "secure", PASSWORD, "").await.err(),
        Some(StatusCode::UNAUTHORIZED)
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = totp::base32_decode(&secret).unwrap();
    let code = format!("{:06}", totp::code_at(&key, totp::step_of(now)));
    assert!(login(&base, "secure", PASSWORD, &code).await.is_ok());
    assert_eq!(
        login(&base, "secure", PASSWORD, &code).await.err(),
        Some(StatusCode::UNAUTHORIZED),
        "a TOTP code must not be accepted twice"
    );

    server.stop();
    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn devices_show_online_hosts_and_block_kicks_them() {
    let dir = temp_dir("devices");
    add_user(&dir, "admin", None);
    let (server, base) = start(&dir).await;

    let host_endpoint = rc_transport::server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let addr: SocketAddr = server.local_addr;
    let _host = rc_rendezvous::spawn_host(
        host_endpoint,
        HostRegistration {
            server: ServerInfo {
                addr,
                access_key: String::new(),
                pin: None,
            },
            identity: Arc::new(DeviceIdentity::generate()),
            device_id: String::new(),
            device_name: "Biuro-PC".into(),
            account_name: String::new(),
        },
        tx,
    );
    let id = loop {
        match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
            Ok(Some(HostEvent::Registered { device_id, .. })) => break device_id,
            Ok(Some(_)) => continue,
            other => panic!("host did not register: {other:?}"),
        }
    };

    let s = login(&base, "admin", PASSWORD, "").await.unwrap();
    let (_, data) = s.get("/api/devices?online=true").await;
    let device = &data["devices"][0];
    assert_eq!(device["id"], id.as_str());
    assert_eq!(device["name"], "Biuro-PC");
    assert_eq!(device["online"], true);
    let (_, data) = s.get("/api/devices?q=biuro").await;
    assert_eq!(data["matched"], 1);
    let (_, data) = s.get("/api/devices?q=nothing-like-this").await;
    assert_eq!(data["matched"], 0);

    // Blocking from the panel disconnects the host at once.
    let (status, _) = s
        .post("/api/block", json!({ "kind": "device", "value": id }))
        .await;
    assert_eq!(status, StatusCode::OK);
    let disconnected = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(HostEvent::Disconnected(..)) = rx.recv().await {
                return;
            }
        }
    })
    .await;
    assert!(disconnected.is_ok(), "blocked host must be disconnected");
    let (_, data) = s.get("/api/devices").await;
    assert_eq!(data["devices"][0]["blocked"], true);
    let (_, events) = s.get("/api/events").await;
    let texts: Vec<String> = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(texts.contains(&"host_online".to_string()));
    assert!(texts.contains(&"blocked".to_string()));
    assert!(texts.contains(&"admin".to_string()));

    server.stop();
    drop(server);
    let _ = std::fs::remove_dir_all(dir);
}
