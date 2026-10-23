use std::net::SocketAddr;
use std::path::PathBuf;

use rand::Rng;
use rc_server::accounts::{AccountStore, Signup};
use rc_server::admin::{totp, users};
use rc_server::blocklist::{self, Entry};
use rc_server::{short_fingerprint, Registry, ServerConfig, DEFAULT_PORT};
use rc_transport::ServerIdentity;
use tracing_subscriber::EnvFilter;

const HELP: &str = "\
rc-server - RemoteConn rendezvous and relay server

Usage:
  rc-server [run]                         start the server
  rc-server fingerprint                   certificate fingerprint clients pin
  rc-server devices                       registered devices (ID, name)
  rc-server blocklist                     current blocklist
  rc-server block <ip|net|device> <value> block an address, network or device
  rc-server unblock <value>               remove a blocklist entry
  rc-server gen-key                       print a new random access key
  rc-server config-code                   code to paste into the app (needs
                                          RC_PUBLIC_ADDR and RC_ACCESS_KEY)

Admin panel accounts:
  rc-server panel-user list
  rc-server panel-user add <name>         create (asks for the password)
  rc-server panel-user passwd <name>      change the password
  rc-server panel-user totp <name>        enable 2FA (shows a QR code)
  rc-server panel-user totp-off <name>    disable 2FA
  rc-server panel-user remove <name>      delete (its sessions end at once)
  rc-server panel-user owner <name>       make it the main administrator (updates)
  rc-server version                       version of this server

User accounts (passwordless access between a user's own devices):
  rc-server account list                  accounts and their devices
  rc-server account invite [note]         one-time sign-up code (7 days)
  rc-server account disable <name>        block (better from the panel: it
  rc-server account enable <name>          also tells online hosts at once)
  rc-server account delete <name>
  (add/passwd accept --password-stdin to read the password from standard input)

Configuration (environment):
  RC_BIND                 UDP address (default 0.0.0.0:21116)
  RC_DATA_DIR             registry, certificate, blocklist (default ./data)
  RC_ACCESS_KEY           key clients must present; unset = open server
  RC_PUBLIC_ADDR          host:port clients type in (for the configuration
                          code in the panel)
  RC_RELAY_ADDR           advertise a separate relay host:port
  RC_MAX_RELAYS           concurrent relayed sessions (default 200)
  RC_MAX_CONN_PER_CLIENT  connections per IP / IPv6 /64 (default 32)
  RC_ADMIN_BIND           admin panel TCP address (default 127.0.0.1:8080;
                          `off` disables it)
  RC_ADMIN_HOSTS          extra host names the panel answers to, comma
                          separated (only without an SSH tunnel)
  RC_ACCOUNTS             who may create accounts: invite (default), open,
                          off

Blocklist changes are picked up by a running server within seconds.";

const DEFAULT_ADMIN_BIND: &str = "127.0.0.1:8080";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn data_dir() -> PathBuf {
    PathBuf::from(env("RC_DATA_DIR").unwrap_or_else(|| "data".into()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] | ["run"] => run().await,
        ["fingerprint"] => {
            let identity = ServerIdentity::load_or_create(&data_dir())?;
            let fp = identity.fingerprint();
            println!("{}", short_fingerprint(&fp));
            println!(
                "{}",
                fp.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            Ok(())
        }
        ["devices"] => {
            let registry = Registry::open(data_dir().join("devices.json"))?;
            let devices = registry.list();
            for (id, name) in &devices {
                println!("{id}  {name}");
            }
            eprintln!("{} device(s)", devices.len());
            Ok(())
        }
        ["blocklist"] => {
            let (entries, errors) = blocklist::read(&blocklist::path_in(&data_dir()));
            for e in &entries {
                println!("{}", e.to_line());
            }
            for e in &errors {
                eprintln!("warning: {e}");
            }
            Ok(())
        }
        ["block", kind, value] => {
            let entry = Entry::parse(&format!("{kind} {value}"))?;
            let path = blocklist::path_in(&data_dir());
            let (mut entries, _) = blocklist::read(&path);
            if entries.contains(&entry) {
                println!("already blocked: {}", entry.to_line());
                return Ok(());
            }
            entries.push(entry.clone());
            blocklist::write(&path, &entries)?;
            println!("blocked: {}", entry.to_line());
            Ok(())
        }
        ["unblock", value] => {
            let path = blocklist::path_in(&data_dir());
            let (entries, _) = blocklist::read(&path);
            let digits: String = value.chars().filter(char::is_ascii_digit).collect();
            let before = entries.len();
            let kept: Vec<Entry> = entries
                .into_iter()
                .filter(|e| match e {
                    Entry::Ip(ip) => ip.to_string() != *value,
                    Entry::Net(ip, len) => format!("{ip}/{len}") != *value,
                    Entry::Device(id) => *id != digits,
                })
                .collect();
            if kept.len() == before {
                return Err(format!("not in the blocklist: {value}").into());
            }
            blocklist::write(&path, &kept)?;
            println!("unblocked: {value}");
            Ok(())
        }
        ["gen-key"] => {
            const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
            let mut rng = rand::rngs::OsRng;
            let key: String = (0..32)
                .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
                .collect();
            println!("{key}");
            Ok(())
        }
        ["config-code"] => {
            let identity = ServerIdentity::load_or_create(&data_dir())?;
            let server = env("RC_PUBLIC_ADDR").ok_or("RC_PUBLIC_ADDR is not set")?;
            let code = rc_rendezvous::ConfigCode {
                server: server.trim().to_string(),
                access_key: env("RC_ACCESS_KEY").unwrap_or_default().trim().to_string(),
                fingerprint: identity.fingerprint(),
            };
            println!("{code}");
            Ok(())
        }
        ["version" | "--version"] => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        ["panel-user", rest @ ..] => panel_user(rest),
        ["account", rest @ ..] => account(rest),
        ["help" | "--help" | "-h"] => {
            println!("{HELP}");
            Ok(())
        }
        _ => {
            eprintln!("{HELP}");
            Err("unknown command".into())
        }
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let bind: SocketAddr = env("RC_BIND")
        .unwrap_or_else(|| format!("0.0.0.0:{DEFAULT_PORT}"))
        .parse()?;
    let mut cfg = ServerConfig::new(bind, data_dir());
    cfg.relay_addr = env("RC_RELAY_ADDR").unwrap_or_default();
    cfg.access_key = env("RC_ACCESS_KEY").unwrap_or_default();
    cfg.public_addr = env("RC_PUBLIC_ADDR").unwrap_or_default();
    if let Some(v) = env("RC_MAX_RELAYS") {
        cfg.max_relays = v.parse()?;
    }
    if let Some(v) = env("RC_MAX_CONN_PER_CLIENT") {
        cfg.max_connections_per_client = v.parse()?;
    }
    if let Some(v) = env("RC_ACCOUNTS") {
        cfg.signup = Signup::parse(&v).ok_or("RC_ACCOUNTS must be invite, open or off")?;
    }
    if cfg.access_key.is_empty() {
        tracing::warn!("RC_ACCESS_KEY is not set: anyone can use this server and its relay");
    }
    let admin_bind = env("RC_ADMIN_BIND").unwrap_or_else(|| DEFAULT_ADMIN_BIND.into());
    if !matches!(admin_bind.trim(), "off" | "none" | "0") {
        cfg.admin_bind = Some(admin_bind.trim().parse()?);
        cfg.admin_hosts = env("RC_ADMIN_HOSTS")
            .map(|h| h.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        if users::load(&cfg.data_dir)
            .map(|u| u.is_empty())
            .unwrap_or(true)
        {
            tracing::warn!(
                "no admin panel accounts yet: create one with `rc-server panel-user add <name>`"
            );
        }
    }

    let server = rc_server::start(cfg).await?;
    let fingerprint = short_fingerprint(&server.fingerprint);
    tracing::info!(addr = %server.local_addr, %fingerprint, "rc-server running");
    shutdown_signal().await;
    tracing::info!("shutting down");
    server.stop();
    Ok(())
}

fn ask_new_password(from_stdin: bool) -> Result<String> {
    if from_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        // Some shells (PowerShell) put a byte order mark in front of piped text.
        let password = line
            .trim_start_matches('\u{feff}')
            .trim_end_matches(['\r', '\n'])
            .to_string();
        users::check_password(&password)?;
        return Ok(password);
    }
    // Interactive (installer, rc-admin): ask again instead of giving up.
    for _ in 0..5 {
        let first = rpassword::prompt_password(format!(
            "Hasło do panelu (min. {} znaków): ",
            users::MIN_PASSWORD_LEN
        ))?;
        if first.chars().count() < users::MIN_PASSWORD_LEN {
            eprintln!(
                "  Za krótkie: {} znaków, potrzeba co najmniej {}. Spróbuj jeszcze raz.",
                first.chars().count(),
                users::MIN_PASSWORD_LEN
            );
            continue;
        }
        if let Err(e) = users::check_password(&first) {
            eprintln!("  {e}");
            continue;
        }
        let second = rpassword::prompt_password("Powtórz hasło: ")?;
        if first != second {
            eprintln!("  Hasła się różnią. Spróbuj jeszcze raz.");
            continue;
        }
        return Ok(first);
    }
    Err("nie ustawiono hasła (za dużo prób)".into())
}

fn panel_user(args: &[&str]) -> Result<()> {
    let dir = data_dir();
    let mut all = users::load(&dir)?;
    let from_stdin = args.contains(&"--password-stdin");
    let args: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| *a != "--password-stdin")
        .collect();
    match args.as_slice() {
        ["list"] => {
            let owner = users::owner_of(&all).map(str::to_string);
            for (name, user) in &all {
                let twofa = if user.totp.is_some() {
                    "2FA on"
                } else {
                    "2FA off"
                };
                let role = if owner.as_deref() == Some(name.as_str()) {
                    "  owner"
                } else {
                    ""
                };
                println!("{name}  {twofa}{role}");
            }
            eprintln!("{} account(s)", all.len());
            return Ok(());
        }
        ["add", name] => {
            if !users::valid_name(name) {
                return Err("name: 1-32 characters, letters, digits, . _ -".into());
            }
            if all.contains_key(*name) {
                return Err(format!("account exists: {name}").into());
            }
            let password = ask_new_password(from_stdin)?;
            // The first account is the main administrator.
            let owner = all.is_empty();
            all.insert(
                name.to_string(),
                users::User {
                    hash: users::hash_password(&password),
                    totp: None,
                    created_unix: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs() as i64,
                    owner,
                },
            );
            users::save(&dir, &all)?;
            if owner {
                println!("Utworzono konto panelu: {name} (główny administrator: widzi i instaluje aktualizacje)");
            } else {
                println!("Utworzono konto panelu: {name}");
            }
        }
        ["passwd", name] => {
            let password = ask_new_password(from_stdin)?;
            let user = all.get_mut(*name).ok_or("no such account")?;
            user.hash = users::hash_password(&password);
            users::save(&dir, &all)?;
            println!("password changed: {name}");
        }
        ["totp", name] => {
            if !all.contains_key(*name) {
                return Err("no such account".into());
            }
            let secret = totp::generate_secret();
            let uri = totp::otpauth_uri(&secret, name, "RemoteConn");
            println!(
                "Zeskanuj kod QR aplikacją uwierzytelniającą na telefonie\n\
                 (Google Authenticator, Microsoft Authenticator, Aegis, 1Password…):\n"
            );
            if qr2term::print_qr(&uri).is_err() {
                println!("{uri}");
            }
            println!("\nAlbo wpisz klucz ręcznie: {secret}\n");
            let now = || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or_default()
            };
            let mut confirmed = false;
            for _ in 0..5 {
                let mut code = String::new();
                eprint!("6-cyfrowy kod z aplikacji: ");
                std::io::stdin().read_line(&mut code)?;
                if totp::verify(&secret, &code, now()).is_some() {
                    confirmed = true;
                    break;
                }
                eprintln!(
                    "  Nieprawidłowy kod. Wpisz aktualny (zmienia się co 30 s); sprawdź też, czy zegar \
                     telefonu jest ustawiony automatycznie."
                );
            }
            if !confirmed {
                return Err("2FA nie zostało włączone".into());
            }
            all.get_mut(*name).ok_or("no such account")?.totp = Some(secret);
            users::save(&dir, &all)?;
            println!(
                "Włączono 2FA dla konta {name}. Przy logowaniu do panelu podaj kod z aplikacji."
            );
        }
        ["owner", name] => {
            if !all.contains_key(*name) {
                return Err("no such account".into());
            }
            for (n, user) in all.iter_mut() {
                user.owner = n == name;
            }
            users::save(&dir, &all)?;
            println!("Główny administrator: {name}");
        }
        ["totp-off", name] => {
            all.get_mut(*name).ok_or("no such account")?.totp = None;
            users::save(&dir, &all)?;
            println!("2FA disabled: {name}");
        }
        ["remove", name] => {
            if all.remove(*name).is_none() {
                return Err("no such account".into());
            }
            users::save(&dir, &all)?;
            println!("removed: {name}");
        }
        _ => {
            eprintln!("{HELP}");
            return Err("unknown panel-user command".into());
        }
    }
    Ok(())
}

fn account(args: &[&str]) -> Result<()> {
    let store = AccountStore::open(&data_dir())?;
    let name_of = |raw: &str| rc_crypto::account::normalize_name(raw);
    let fail = |e: rc_server::accounts::AccountError| -> Box<dyn std::error::Error> {
        format!("{e:?}").into()
    };
    match args {
        ["list"] => {
            for a in store.summaries() {
                let state = if a.disabled { "  [disabled]" } else { "" };
                println!("{}  ({}){state}", a.name, a.display_name);
                for d in &a.devices {
                    let id = if d.device_id.is_empty() {
                        "-"
                    } else {
                        &d.device_id
                    };
                    println!("    {id:<10} {}", d.name);
                }
            }
            eprintln!("{} account(s)", store.len());
        }
        ["invite", note @ ..] => {
            let code = store.create_invite(&note.join(" ")).map_err(fail)?;
            println!("{code}");
            eprintln!(
                "one-time code, valid 7 days: the user enters it in the app (Settings → Konto)"
            );
        }
        ["disable", name] => {
            store.set_disabled(&name_of(name), true).map_err(fail)?;
            println!("disabled; online hosts learn it when they reconnect (the panel tells them at once)");
        }
        ["enable", name] => {
            store.set_disabled(&name_of(name), false).map_err(fail)?;
            println!("enabled");
        }
        ["delete", name] => {
            store.delete(&name_of(name)).map_err(fail)?;
            println!("deleted");
        }
        _ => {
            eprintln!("{HELP}");
            return Err("unknown account command".into());
        }
    }
    Ok(())
}

/// Ctrl+C, or SIGTERM from systemd on Unix.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
