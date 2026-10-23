//! Admin blocklist: `blocklist.txt` in the data directory, one entry per line.
//!
//! ```text
//! # comment
//! ip 203.0.113.5
//! net 198.51.100.0/24
//! net 2001:db8:42::/48
//! device 123456789
//! ```
//!
//! The server re-reads the file when it changes (checked every few seconds),
//! so `rc-admin block …` takes effect without a restart: blocked addresses
//! cannot connect, blocked devices cannot register or be looked up, and a
//! blocked host that is online is disconnected.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Ip(IpAddr),
    Net(IpAddr, u8),
    Device(String),
}

impl Entry {
    pub fn parse(line: &str) -> Result<Self, String> {
        let usage = || format!("expected `<ip|net|device> <value>`: {line}");
        let (kind, value) = line
            .trim()
            .split_once(char::is_whitespace)
            .ok_or_else(usage)?;
        let value = value.trim();
        // Device IDs may be written with spaces ("123 456 789"); nothing else.
        if value.is_empty() || (kind != "device" && value.contains(char::is_whitespace)) {
            return Err(usage());
        }
        match kind {
            "ip" => value
                .parse()
                .map(Entry::Ip)
                .map_err(|_| format!("invalid IP address: {value}")),
            "net" => {
                let (addr, len) = value
                    .split_once('/')
                    .ok_or_else(|| format!("expected address/prefix: {value}"))?;
                let addr: IpAddr = addr
                    .parse()
                    .map_err(|_| format!("invalid network: {value}"))?;
                let len: u8 = len
                    .parse()
                    .map_err(|_| format!("invalid prefix: {value}"))?;
                let max = if addr.is_ipv4() { 32 } else { 128 };
                if len > max {
                    return Err(format!("prefix too long: {value}"));
                }
                Ok(Entry::Net(addr, len))
            }
            "device" => {
                let id: String = value.chars().filter(char::is_ascii_digit).collect();
                if id.len() == 9 {
                    Ok(Entry::Device(id))
                } else {
                    Err(format!("device ID must have 9 digits: {value}"))
                }
            }
            _ => Err(format!(
                "unknown entry type `{kind}` (use ip, net or device)"
            )),
        }
    }

    pub fn to_line(&self) -> String {
        match self {
            Entry::Ip(ip) => format!("ip {ip}"),
            Entry::Net(ip, len) => format!("net {ip}/{len}"),
            Entry::Device(id) => format!("device {id}"),
        }
    }
}

fn prefix_matches(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    match (net, normalize(ip)) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

#[derive(Default)]
pub struct Blocklist {
    ips: HashSet<IpAddr>,
    nets: Vec<(IpAddr, u8)>,
    devices: HashSet<String>,
}

impl Blocklist {
    pub fn from_entries(entries: &[Entry]) -> Self {
        let mut list = Self::default();
        for entry in entries {
            match entry {
                Entry::Ip(ip) => {
                    list.ips.insert(normalize(*ip));
                }
                Entry::Net(net, len) => list.nets.push((*net, *len)),
                Entry::Device(id) => {
                    list.devices.insert(id.clone());
                }
            }
        }
        list
    }

    pub fn ip_blocked(&self, ip: IpAddr) -> bool {
        self.ips.contains(&normalize(ip))
            || self.nets.iter().any(|&(n, l)| prefix_matches(n, l, ip))
    }

    pub fn device_blocked(&self, id: &str) -> bool {
        self.devices.contains(id)
    }

    pub fn devices(&self) -> impl Iterator<Item = &String> {
        self.devices.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.ips.len() + self.nets.len() + self.devices.len()
    }
}

/// Reads the file; invalid lines are reported and skipped, so one typo never
/// unblocks everything else.
pub fn read(path: &Path) -> (Vec<Entry>, Vec<String>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (Vec::new(), Vec::new());
    };
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match Entry::parse(line) {
            Ok(e) => entries.push(e),
            Err(e) => errors.push(format!("line {}: {e}", n + 1)),
        }
    }
    (entries, errors)
}

pub fn write(path: &Path, entries: &[Entry]) -> std::io::Result<()> {
    let mut text =
        String::from("# RemoteConn blocklist (managed with rc-admin; reloaded automatically)\n");
    for e in entries {
        text.push_str(&e.to_line());
        text.push('\n');
    }
    let tmp = path.with_extension("txt.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(tmp, path)
}

pub fn path_in(data_dir: &Path) -> PathBuf {
    data_dir.join("blocklist.txt")
}

/// Tracks the file's modification time to reload only on change.
pub struct Watcher {
    path: PathBuf,
    seen: Option<SystemTime>,
}

impl Watcher {
    pub fn new(path: PathBuf) -> Self {
        Self { path, seen: None }
    }

    /// The new list if the file changed (or appeared/disappeared).
    pub fn poll(&mut self) -> Option<Blocklist> {
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        if modified == self.seen && self.seen.is_some() {
            return None;
        }
        let first = self.seen.is_none() && modified.is_none();
        self.seen = modified;
        if first {
            return None;
        }
        let (entries, errors) = read(&self.path);
        for e in &errors {
            tracing::warn!("blocklist {e}");
        }
        let list = Blocklist::from_entries(&entries);
        tracing::info!(entries = list.len(), "blocklist loaded");
        Some(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches() {
        let entries: Vec<Entry> = [
            "ip 203.0.113.5",
            "net 198.51.100.0/24",
            "net 2001:db8:42::/48",
            "device 123 456 789",
        ]
        .iter()
        .map(|l| Entry::parse(l).unwrap())
        .collect();
        let list = Blocklist::from_entries(&entries);
        assert!(list.ip_blocked("203.0.113.5".parse().unwrap()));
        assert!(list.ip_blocked("::ffff:203.0.113.5".parse().unwrap()));
        assert!(!list.ip_blocked("203.0.113.6".parse().unwrap()));
        assert!(list.ip_blocked("198.51.100.200".parse().unwrap()));
        assert!(!list.ip_blocked("198.51.101.1".parse().unwrap()));
        assert!(list.ip_blocked("2001:db8:42:ffff::1".parse().unwrap()));
        assert!(!list.ip_blocked("2001:db8:43::1".parse().unwrap()));
        assert!(list.device_blocked("123456789"));
        assert_eq!(entries[3].to_line(), "device 123456789");
    }

    #[test]
    fn rejects_bad_lines() {
        for bad in [
            "ip nope",
            "net 10.0.0.0/33",
            "device 12",
            "host 1.2.3.4",
            "ip",
        ] {
            assert!(Entry::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn file_roundtrip_and_watch() {
        let dir = std::env::temp_dir().join(format!("rc-block-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = path_in(&dir);
        let _ = std::fs::remove_file(&path);
        let mut watcher = Watcher::new(path.clone());
        assert!(watcher.poll().is_none(), "no file, nothing to load");
        write(&path, &[Entry::Device("111222333".into())]).unwrap();
        let list = watcher.poll().expect("file appeared");
        assert!(list.device_blocked("111222333"));
        assert!(watcher.poll().is_none(), "unchanged");
        std::fs::write(&path, "ip 10.0.0.1\nthis is junk\n").unwrap();
        // Make sure the modification time differs on coarse filesystems.
        let later = SystemTime::now() + std::time::Duration::from_secs(2);
        let _ = std::fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(later));
        let list = watcher.poll().expect("file changed");
        assert!(list.ip_blocked("10.0.0.1".parse().unwrap()));
        assert_eq!(list.len(), 1, "junk line skipped");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
