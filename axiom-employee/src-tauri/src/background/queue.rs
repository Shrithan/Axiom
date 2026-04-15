use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Serialize, Deserialize)]
pub struct ContentEvent {
    pub id: String,
    pub timestamp: f64,
    pub source: String,
    pub action: String,
    pub content_type: String,
    pub file_path: String,
    pub destination: String,
    pub source_application: String,
    pub source_application_id: String,
}
impl ContentEvent {
    pub fn new(source: &str, action: &str, path: Option<&std::path::Path>) -> Self {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            id: format!(
                "evt-{}-{}",
                (timestamp * 1000.) as u64,
                SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ),
            timestamp,
            source: source.into(),
            action: action.into(),
            content_type: if source == "clipboard" {
                "text"
            } else {
                "document"
            }
            .into(),
            file_path: path
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            destination: "UNSPECIFIED".into(),
            source_application: String::new(),
            source_application_id: String::new(),
        }
    }
}

pub struct Pending {
    pub event: ContentEvent,
    pub generation: u64,
    pub clipboard: Option<(i64, String)>,
}
pub struct EventQueue {
    items: Mutex<(VecDeque<Pending>, bool)>,
    ready: Condvar,
    capacity: usize,
}
impl EventQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Mutex::new((VecDeque::new(), false)),
            ready: Condvar::new(),
            capacity,
        }
    }
    pub fn push(&self, item: Pending) -> bool {
        let mut guard = self.items.lock().unwrap();
        if guard.1 {
            return false;
        }
        // Clipboard events have priority, and only the newest version remains queued.
        guard.0.retain(|old| {
            !(old.event.source == item.event.source
                && (item.event.source == "clipboard"
                    || old.event.file_path == item.event.file_path))
        });
        if guard.0.len() >= self.capacity {
            if item.event.source == "clipboard" {
                guard.0.pop_back();
            } else {
                return false;
            }
        }
        if item.event.source == "clipboard" {
            guard.0.push_front(item);
        } else {
            guard.0.push_back(item);
        }
        self.ready.notify_one();
        true
    }
    pub fn pop(&self) -> Option<Pending> {
        let mut guard = self.items.lock().unwrap();
        while guard.0.is_empty() && !guard.1 {
            guard = self.ready.wait(guard).unwrap();
        }
        guard.0.pop_front()
    }
    pub fn clear(&self) {
        self.items.lock().unwrap().0.clear();
    }
    pub fn close(&self) {
        let mut guard = self.items.lock().unwrap();
        guard.1 = true;
        guard.0.clear();
        self.ready.notify_all();
    }
    pub fn len(&self) -> usize {
        self.items.lock().unwrap().0.len()
    }
}

pub struct FileDebouncer {
    pending: HashMap<PathBuf, (Instant, bool)>,
    delay: Duration,
}
impl FileDebouncer {
    pub fn new(delay: Duration) -> Self {
        Self {
            pending: HashMap::new(),
            delay,
        }
    }
    pub fn add(&mut self, path: PathBuf, created: bool, now: Instant) -> bool {
        if self.pending.len() >= 1024 && !self.pending.contains_key(&path) {
            return false;
        }
        let was_created = self.pending.get(&path).map(|v| v.1).unwrap_or(false);
        self.pending
            .insert(path, (now + self.delay, created || was_created));
        true
    }
    pub fn due(&mut self, now: Instant) -> Vec<(PathBuf, bool)> {
        let paths: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, (time, _))| *time <= now)
            .map(|(path, (_, created))| (path.clone(), *created))
            .collect();
        for (path, _) in &paths {
            self.pending.remove(path);
        }
        paths
    }
    pub fn wait(&self) -> Option<Duration> {
        self.pending
            .values()
            .map(|(time, _)| time.saturating_duration_since(Instant::now()))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file(path: &str) -> Pending {
        Pending {
            event: ContentEvent::new(
                "filesystem",
                "FILE_MODIFIED",
                Some(std::path::Path::new(path)),
            ),
            generation: 0,
            clipboard: None,
        }
    }
    fn clip(version: i64) -> Pending {
        Pending {
            event: ContentEvent::new("clipboard", "COPY", None),
            generation: 0,
            clipboard: Some((version, "private".into())),
        }
    }
    #[test]
    fn queue_bounds() {
        let q = EventQueue::new(1);
        assert!(q.push(file("a")));
        assert!(!q.push(file("b")));
        assert_eq!(q.len(), 1);
    }
    #[test]
    fn queue_deduplicates_paths() {
        let q = EventQueue::new(2);
        q.push(file("a"));
        q.push(file("a"));
        assert_eq!(q.len(), 1);
    }
    #[test]
    fn newest_clipboard_has_priority() {
        let q = EventQueue::new(2);
        q.push(file("a"));
        q.push(clip(1));
        q.push(clip(2));
        assert_eq!(q.pop().unwrap().clipboard.unwrap().0, 2);
        assert_eq!(q.len(), 1);
    }
    #[test]
    fn close_unblocks_and_rejects() {
        let q = EventQueue::new(2);
        q.close();
        assert!(q.pop().is_none());
        assert!(!q.push(file("a")));
    }
    #[test]
    fn pause_clears_queue() {
        let q = EventQueue::new(2);
        q.push(clip(1));
        q.clear();
        assert_eq!(q.len(), 0);
    }
    #[test]
    fn debounce_quiet_period() {
        let now = Instant::now();
        let mut d = FileDebouncer::new(Duration::from_millis(600));
        d.add("a".into(), true, now);
        d.add("a".into(), false, now + Duration::from_millis(400));
        assert!(d.due(now + Duration::from_millis(700)).is_empty());
        assert_eq!(
            d.due(now + Duration::from_millis(1100)),
            vec![(PathBuf::from("a"), true)]
        );
    }
    #[test]
    fn debounce_independent_files() {
        let now = Instant::now();
        let mut d = FileDebouncer::new(Duration::from_millis(1));
        d.add("a".into(), false, now);
        d.add("b".into(), false, now);
        assert_eq!(d.due(now + Duration::from_millis(2)).len(), 2);
    }
    #[test]
    fn event_has_no_inferred_destination() {
        let e = ContentEvent::new("clipboard", "COPY", None);
        assert_eq!(e.destination, "UNSPECIFIED");
        assert!(e.file_path.is_empty());
    }
}
