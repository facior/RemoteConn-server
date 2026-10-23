//! Recent server events for the admin panel (in memory, newest last).

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::Serialize;

const CAPACITY: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub at_unix: i64,
    /// "host_online", "host_offline", "relay_request", "relay_start",
    /// "relay_end", "blocked", "admin"
    pub kind: &'static str,
    pub text: String,
}

#[derive(Default)]
pub struct EventLog {
    events: Mutex<VecDeque<Event>>,
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// `2026-10-23 14:05:09 UTC`
pub fn fmt_utc(unix: i64) -> String {
    let (days, secs) = (unix.div_euclid(86_400), unix.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

impl EventLog {
    pub fn push(&self, kind: &'static str, text: impl Into<String>) {
        let mut events = self.events.lock().unwrap();
        if events.len() == CAPACITY {
            events.pop_front();
        }
        events.push_back(Event {
            at_unix: unix_now(),
            kind,
            text: text.into(),
        });
    }

    /// Up to `limit` most recent events, newest first.
    pub fn recent(&self, limit: usize) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_newest_first_and_bounded() {
        let log = EventLog::default();
        for i in 0..(CAPACITY + 10) {
            log.push("admin", format!("e{i}"));
        }
        let recent = log.recent(3);
        assert_eq!(recent[0].text, format!("e{}", CAPACITY + 9));
        assert_eq!(log.recent(usize::MAX).len(), CAPACITY);
    }

    #[test]
    fn formats_utc() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(fmt_utc(1_792_764_309), "2026-10-23 14:05:09 UTC");
    }
}
