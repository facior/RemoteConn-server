//! Fixed-window rate limits and per-IP connection counting.
//!
//! IPv6 clients are grouped by /64: a single subscriber usually controls a
//! whole /64, so limits per address would be trivial to bypass.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

/// The unit limits apply to: the IPv4 address, or the IPv6 /64 prefix.
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
        v4 => v4,
    }
}

pub struct Limiter {
    window: Duration,
    max_per_window: u32,
    windows: HashMap<IpAddr, (Instant, u32)>,
}

impl Limiter {
    pub fn new(window: Duration, max_per_window: u32) -> Self {
        Self {
            window,
            max_per_window,
            windows: HashMap::new(),
        }
    }

    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.windows.len() > 100_000 {
            let window = self.window;
            self.windows
                .retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let (start, count) = self.windows.entry(client_key(ip)).or_insert((now, 0));
        if now.duration_since(*start) >= self.window {
            *start = now;
            *count = 0;
        }
        *count += 1;
        *count <= self.max_per_window
    }
}

/// Counts open connections per client; [`ConnectionCounter::acquire`]
/// refuses beyond the per-client and global limits.
pub struct ConnectionCounter {
    per_client: u32,
    total_max: u32,
    total: u32,
    counts: HashMap<IpAddr, u32>,
}

impl ConnectionCounter {
    pub fn new(per_client: u32, total_max: u32) -> Self {
        Self {
            per_client,
            total_max,
            total: 0,
            counts: HashMap::new(),
        }
    }

    pub fn acquire(&mut self, ip: IpAddr) -> bool {
        let key = client_key(ip);
        let count = self.counts.entry(key).or_insert(0);
        if *count >= self.per_client || self.total >= self.total_max {
            if *count == 0 {
                self.counts.remove(&key);
            }
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }

    pub fn release(&mut self, ip: IpAddr) {
        let key = client_key(ip);
        if let Some(count) = self.counts.get_mut(&key) {
            *count -= 1;
            self.total -= 1;
            if *count == 0 {
                self.counts.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_ip_and_resets() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let t0 = Instant::now();
        let mut l = Limiter::new(Duration::from_secs(60), 30);
        assert!((0..30).all(|_| l.allow(ip, t0)));
        assert!(!l.allow(ip, t0));
        assert!(l.allow("203.0.113.8".parse().unwrap(), t0));
        assert!(l.allow(ip, t0 + Duration::from_secs(60)));
    }

    #[test]
    fn ipv6_grouped_by_prefix() {
        let t0 = Instant::now();
        let mut l = Limiter::new(Duration::from_secs(60), 1);
        assert!(l.allow("2001:db8:1:2::1".parse().unwrap(), t0));
        // Same /64, different address: same bucket.
        assert!(!l.allow("2001:db8:1:2:ffff::9".parse().unwrap(), t0));
        assert!(l.allow("2001:db8:1:3::1".parse().unwrap(), t0));
    }

    #[test]
    fn connection_counter_limits() {
        let mut c = ConnectionCounter::new(2, 3);
        let (a, b): (IpAddr, IpAddr) = (
            "198.51.100.1".parse().unwrap(),
            "198.51.100.2".parse().unwrap(),
        );
        assert!(c.acquire(a) && c.acquire(a));
        assert!(!c.acquire(a), "per-client limit");
        assert!(c.acquire(b));
        assert!(!c.acquire(b), "global limit");
        c.release(a);
        assert!(c.acquire(b));
    }
}
