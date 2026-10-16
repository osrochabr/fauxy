//! In-memory log of proxied traffic, read by the TUI through the control API.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_CAPACITY: usize = 1000;

/// Body bytes kept per event; larger bodies are truncated.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// Header bytes kept per header list, so a client sending huge headers cannot
/// grow the in-memory log without bound.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    /// Answered by a mock rule.
    Mock,
    /// Forwarded to the real server.
    Pass,
    /// HTTPS host without rules, relayed without decryption.
    Tunnel,
    Error,
}

impl EventKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Mock => "MOCK",
            Self::Pass => "PASS",
            Self::Tunnel => "TUNNEL",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Assigned by the log, starting at 1.
    pub id: u64,
    pub timestamp_ms: u64,
    pub kind: EventKind,
    pub method: String,
    /// Full URL, or `host:port` for tunnels.
    pub url: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub rule: Option<String>,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    /// Mocked responses only, truncated to [`MAX_BODY_BYTES`].
    pub response_body: Option<String>,
    pub error: Option<String>,
}

impl Event {
    pub fn new(kind: EventKind, method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            id: 0,
            timestamp_ms: now_ms(),
            kind,
            method: method.into(),
            url: url.into(),
            status: None,
            duration_ms: None,
            rule: None,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            response_body: None,
            error: None,
        }
    }

    /// One-line summary written to the daemon log.
    pub fn summary(&self) -> String {
        let mut line = format!("{:<6} {} {}", self.kind.label(), self.method, self.url);
        if let Some(status) = self.status {
            line.push_str(&format!(" -> {status}"));
        }
        if let Some(duration) = self.duration_ms {
            line.push_str(&format!(" ({duration} ms)"));
        }
        if let Some(rule) = &self.rule {
            line.push_str(&format!(" [rule {rule}]"));
        }
        if let Some(error) = &self.error {
            line.push_str(&format!(" error: {error}"));
        }
        line
    }
}

/// Headers as text, up to [`MAX_HEADER_BYTES`]; the rest is summarized.
pub fn header_pairs(headers: &http::HeaderMap) -> Vec<(String, String)> {
    let mut budget = MAX_HEADER_BYTES;
    let mut pairs = Vec::new();
    for (name, value) in headers {
        let size = name.as_str().len() + value.len();
        if size > budget {
            let omitted = headers.len() - pairs.len();
            pairs.push(("…".to_owned(), format!("{omitted} more header(s) omitted")));
            break;
        }
        budget -= size;
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        pairs.push((name.as_str().to_owned(), value));
    }
    pairs
}

/// Text that is safe to print on a terminal. Control characters (except line
/// breaks) and invisible formatting characters such as bidirectional
/// overrides are replaced, so data received from the network can neither
/// inject escape sequences nor disguise itself.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\n' => '\n',
            '\t' => ' ',
            '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' => '\u{fffd}',
            '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}' => '\u{fffd}',
            '\u{00AD}' | '\u{180E}' | '\u{FFF9}'..='\u{FFFB}' | '\u{1D173}'..='\u{1D17A}' => {
                '\u{fffd}'
            }
            // Tag characters render as nothing and can smuggle hidden text.
            '\u{E0000}'..='\u{E007F}' => '\u{fffd}',
            c if c.is_control() => '\u{fffd}',
            c => c,
        })
        .collect()
}

/// Body as text, truncated to [`MAX_BODY_BYTES`].
pub fn body_preview(body: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(&body[..body.len().min(MAX_BODY_BYTES)]).into_owned();
    if body.len() > MAX_BODY_BYTES {
        text.push_str(&format!("\n… ({} bytes total)", body.len()));
    }
    text
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Bounded, thread-safe event log; the oldest events are dropped first.
#[derive(Debug)]
pub struct EventLog {
    inner: Mutex<Inner>,
    capacity: usize,
}

#[derive(Debug, Default)]
struct Inner {
    events: VecDeque<Event>,
    last_id: u64,
}

impl EventLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            capacity: capacity.max(1),
        }
    }

    /// Stores the event and returns the id assigned to it.
    pub fn push(&self, mut event: Event) -> u64 {
        let mut inner = self.lock();
        inner.last_id += 1;
        event.id = inner.last_id;
        if inner.events.len() == self.capacity {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
        inner.last_id
    }

    /// Events with id greater than `after`, oldest first. When more than
    /// `limit` are available, the most recent ones are returned.
    pub fn since(&self, after: u64, limit: usize) -> Vec<Event> {
        let inner = self.lock();
        let newer: Vec<&Event> = inner.events.iter().filter(|e| e.id > after).collect();
        let skip = newer.len().saturating_sub(limit);
        newer.into_iter().skip(skip).cloned().collect()
    }

    pub fn last_id(&self) -> u64 {
        self.lock().last_id
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_assigns_sequential_ids() {
        let log = EventLog::new(10);
        assert_eq!(log.last_id(), 0);
        assert_eq!(log.push(Event::new(EventKind::Mock, "GET", "u1")), 1);
        assert_eq!(log.push(Event::new(EventKind::Pass, "GET", "u2")), 2);
        assert_eq!(log.last_id(), 2);
        let all = log.since(0, 10);
        assert_eq!(all.iter().map(|e| e.id).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn capacity_drops_oldest() {
        let log = EventLog::new(2);
        for i in 0..5 {
            log.push(Event::new(EventKind::Pass, "GET", format!("u{i}")));
        }
        let all = log.since(0, 10);
        assert_eq!(all.iter().map(|e| e.id).collect::<Vec<_>>(), vec![4, 5]);
    }

    #[test]
    fn since_filters_and_limits_to_most_recent() {
        let log = EventLog::new(10);
        for i in 0..6 {
            log.push(Event::new(EventKind::Pass, "GET", format!("u{i}")));
        }
        let ids = |events: Vec<Event>| events.iter().map(|e| e.id).collect::<Vec<_>>();
        assert_eq!(ids(log.since(4, 10)), vec![5, 6]);
        assert_eq!(ids(log.since(0, 2)), vec![5, 6]);
        assert!(log.since(6, 10).is_empty());
    }

    #[test]
    fn zero_capacity_is_clamped() {
        let log = EventLog::new(0);
        log.push(Event::new(EventKind::Pass, "GET", "a"));
        assert_eq!(log.since(0, 10).len(), 1);
    }

    #[test]
    fn poisoned_lock_is_recovered() {
        let log = std::sync::Arc::new(EventLog::new(10));
        let clone = std::sync::Arc::clone(&log);
        let _ = std::thread::spawn(move || {
            let _guard = clone.lock();
            panic!("poison the lock");
        })
        .join();
        assert_eq!(log.push(Event::new(EventKind::Pass, "GET", "a")), 1);
    }

    #[test]
    fn summary_includes_details() {
        let mut event = Event::new(EventKind::Mock, "POST", "https://x.com/a");
        event.status = Some(200);
        event.duration_ms = Some(3);
        event.rule = Some("login".into());
        assert_eq!(
            event.summary(),
            "MOCK   POST https://x.com/a -> 200 (3 ms) [rule login]"
        );
        let mut error = Event::new(EventKind::Error, "GET", "http://y");
        error.error = Some("refused".into());
        assert_eq!(error.summary(), "ERROR  GET http://y error: refused");
    }

    #[test]
    fn serializes_kind_in_lowercase() {
        let event = Event::new(EventKind::Tunnel, "CONNECT", "x.com:443");
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["kind"], "tunnel");
        let back: Event = serde_json::from_value(json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn body_preview_truncates() {
        assert_eq!(body_preview(b"abc"), "abc");
        let big = vec![b'a'; MAX_BODY_BYTES + 10];
        let preview = body_preview(&big);
        assert!(preview.starts_with("aaa"));
        assert!(preview.ends_with(&format!("({} bytes total)", MAX_BODY_BYTES + 10)));
    }

    #[test]
    fn huge_header_lists_are_capped() {
        let mut headers = http::HeaderMap::new();
        let big = "x".repeat(3000);
        for name in ["a", "b", "c", "d", "e"] {
            headers.insert(name, http::HeaderValue::from_str(&big).unwrap());
        }
        let pairs = header_pairs(&headers);
        assert_eq!(pairs.len(), 3, "two headers fit, then a summary");
        assert_eq!(
            pairs[2],
            ("…".to_owned(), "3 more header(s) omitted".to_owned())
        );
    }

    #[test]
    fn printable_text_has_no_terminal_tricks() {
        assert_eq!(
            printable("a\u{1b}[31mb\tc\u{7}\nd"),
            "a\u{fffd}[31mb c\u{fffd}\nd"
        );
        assert_eq!(
            printable("x\u{202E}y\u{200B}z\u{2028}w\u{FEFF}"),
            "x\u{fffd}y\u{fffd}z\u{fffd}w\u{fffd}"
        );
        assert_eq!(
            printable("\u{061C}\u{2066}\u{2060}é"),
            "\u{fffd}\u{fffd}\u{fffd}é"
        );
        let hidden = "a\u{E0041}\u{00AD}\u{180E}\u{FFF9}\u{1D173}b";
        let replaced = "a\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{fffd}b";
        assert_eq!(printable(hidden), replaced);
    }

    #[test]
    fn header_pairs_are_lossy() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-a", http::HeaderValue::from_static("1"));
        headers.insert("x-b", http::HeaderValue::from_bytes(b"\xff").unwrap());
        let pairs = header_pairs(&headers);
        assert_eq!(pairs[0], ("x-a".to_owned(), "1".to_owned()));
        assert_eq!(pairs[1].1, "\u{fffd}");
    }

    #[test]
    fn labels() {
        assert_eq!(EventKind::Mock.label(), "MOCK");
        assert_eq!(EventKind::Pass.label(), "PASS");
        assert_eq!(EventKind::Tunnel.label(), "TUNNEL");
        assert_eq!(EventKind::Error.label(), "ERROR");
    }

    #[test]
    fn clock_is_after_2020() {
        assert!(now_ms() > 1_577_836_800_000);
    }
}
