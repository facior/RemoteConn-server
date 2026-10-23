//! Persistent device registry: 9-digit ID ↔ device signing key.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
struct DeviceRecord {
    verifying_key: String,
    noise_public: String,
    name: String,
}

/// Upper bound on registered devices (protects disk and memory).
const MAX_DEVICES: usize = 1_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// Too many new devices from this client recently.
    RateLimited,
    Full,
    Io(String),
}

pub struct Registry {
    path: PathBuf,
    devices: Mutex<HashMap<String, DeviceRecord>>,
}

impl Registry {
    pub fn open(path: PathBuf) -> io::Result<Self> {
        let devices = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Ok(Self {
            path,
            devices: Mutex::new(devices),
        })
    }

    /// Returns the device's ID: the requested one if it belongs to this key,
    /// otherwise the key's existing ID, otherwise a fresh one, which needs
    /// `allow_new()` to agree (rate limiting).
    pub fn register(
        &self,
        requested_id: &str,
        verifying_key: &[u8; 32],
        noise_public: &[u8; 32],
        name: &str,
        allow_new: impl FnOnce() -> bool,
    ) -> Result<String, RegisterError> {
        let vk = hex(verifying_key);
        let record = DeviceRecord {
            verifying_key: vk.clone(),
            noise_public: hex(noise_public),
            name: name.to_string(),
        };
        let mut devices = self.devices.lock().unwrap();
        let existing = devices
            .get(requested_id)
            .filter(|r| r.verifying_key == vk)
            .map(|_| requested_id.to_string())
            .or_else(|| {
                devices
                    .iter()
                    .find(|(_, r)| r.verifying_key == vk)
                    .map(|(id, _)| id.clone())
            });
        let id = match existing {
            Some(id) => {
                let current = &devices[&id];
                if current.noise_public == record.noise_public && current.name == record.name {
                    return Ok(id);
                }
                id
            }
            None => {
                if devices.len() >= MAX_DEVICES {
                    return Err(RegisterError::Full);
                }
                if !allow_new() {
                    return Err(RegisterError::RateLimited);
                }
                let mut rng = rand::rngs::OsRng;
                loop {
                    let candidate = rng.gen_range(100_000_000u32..1_000_000_000).to_string();
                    if !devices.contains_key(&candidate) {
                        break candidate;
                    }
                }
            }
        };
        devices.insert(id.clone(), record);
        self.save(&devices)
            .map_err(|e| RegisterError::Io(e.to_string()))?;
        Ok(id)
    }

    /// (ID, name) of every registered device, sorted by ID.
    pub fn list(&self) -> Vec<(String, String)> {
        let mut out: Vec<_> = self
            .devices
            .lock()
            .unwrap()
            .iter()
            .map(|(id, r)| (id.clone(), r.name.clone()))
            .collect();
        out.sort();
        out
    }

    pub fn len(&self) -> usize {
        self.devices.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True when `id` is registered to exactly these keys.
    pub fn matches(&self, id: &str, verifying_key: &[u8; 32], noise_public: &[u8; 32]) -> bool {
        self.devices.lock().unwrap().get(id).is_some_and(|r| {
            r.verifying_key == hex(verifying_key) && r.noise_public == hex(noise_public)
        })
    }

    pub fn exists(&self, id: &str) -> bool {
        self.devices.lock().unwrap().contains_key(id)
    }

    fn save(&self, devices: &HashMap<String, DeviceRecord>) -> io::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(devices).map_err(io::Error::other)?,
        )?;
        std::fs::rename(tmp, &self.path)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_registry(name: &str) -> (Registry, PathBuf) {
        let path = std::env::temp_dir()
            .join(format!("rc-registry-{name}-{}", std::process::id()))
            .join("devices.json");
        let _ = std::fs::remove_file(&path);
        (Registry::open(path.clone()).unwrap(), path)
    }

    #[test]
    fn ids_are_stable_per_key_and_persisted() {
        let (reg, path) = temp_registry("stable");
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let id_a = reg.register("", &a, &[9; 32], "pc-a", || true).unwrap();
        assert_eq!(id_a.len(), 9);
        // Same key keeps its ID, even without asking for it.
        // Known keys do not count as new devices.
        assert_eq!(
            reg.register("", &a, &[9; 32], "pc-a", || false).unwrap(),
            id_a
        );
        assert_eq!(
            reg.register(&id_a, &a, &[8; 32], "renamed", || false)
                .unwrap(),
            id_a
        );
        // Another key cannot take over the ID.
        assert_eq!(
            reg.register(&id_a, &b, &[9; 32], "pc-b", || false),
            Err(RegisterError::RateLimited)
        );
        let id_b = reg.register(&id_a, &b, &[9; 32], "pc-b", || true).unwrap();
        assert_ne!(id_b, id_a);
        drop(reg);
        let reopened = Registry::open(path).unwrap();
        assert!(reopened.exists(&id_a) && reopened.exists(&id_b));
    }
}
