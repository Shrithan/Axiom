use super::platform;

pub trait ClipboardPort: Send + Sync {
    fn version(&self) -> i64;
    fn read(&self) -> Result<Option<(i64, String)>, String>;
    fn replace(&self, expected: i64, text: Option<&str>) -> Result<Option<i64>, String>;
}
pub struct MacClipboard;
impl ClipboardPort for MacClipboard {
    fn version(&self) -> i64 {
        platform::version()
    }
    fn read(&self) -> Result<Option<(i64, String)>, String> {
        platform::read()
    }
    fn replace(&self, expected: i64, text: Option<&str>) -> Result<Option<i64>, String> {
        platform::replace(expected, text)
    }
}
#[derive(Default)]
pub struct ClipboardTracker {
    seen: Option<i64>,
}
impl ClipboardTracker {
    pub fn baseline(&mut self, version: i64) {
        self.seen = Some(version);
    }
    pub fn changed(&mut self, version: i64, own: i64) -> bool {
        let changed = self.seen != Some(version);
        self.seen = Some(version);
        changed && version != own
    }
}
pub fn enforce(
    port: &dyn ClipboardPort,
    expected: i64,
    action: &str,
    protected: Option<&str>,
    active: bool,
) -> Result<(&'static str, Option<i64>), String> {
    if !active {
        return Ok(("PAUSED_SKIPPED", None));
    }
    if port.version() != expected {
        return Ok(("STALE_SKIPPED", None));
    }
    match action {
        "ALLOW" => Ok(("UNCHANGED", None)),
        "WARN" => Ok(("WARNED", None)),
        "REDACT" | "BLOCK" => {
            let text = if action == "REDACT" {
                Some(protected.ok_or("Missing protected clipboard output")?)
            } else {
                None
            };
            let version = port.replace(expected, text)?;
            Ok((
                if version.is_none() {
                    "STALE_SKIPPED"
                } else if action == "BLOCK" {
                    "CLIPBOARD_CLEARED"
                } else {
                    "CLIPBOARD_REPLACED"
                },
                version,
            ))
        }
        _ => Err("Unsupported action".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Fake(Mutex<(i64, String)>);
    impl ClipboardPort for Fake {
        fn version(&self) -> i64 {
            self.0.lock().unwrap().0
        }
        fn read(&self) -> Result<Option<(i64, String)>, String> {
            Ok(Some(self.0.lock().unwrap().clone()))
        }
        fn replace(&self, expected: i64, text: Option<&str>) -> Result<Option<i64>, String> {
            let mut s = self.0.lock().unwrap();
            if s.0 != expected {
                return Ok(None);
            }
            s.0 += 1;
            s.1 = text.unwrap_or("").into();
            Ok(Some(s.0))
        }
    }
    #[test]
    fn redaction_replaces() {
        let f = Fake(Mutex::new((1, "Project Penguin".into())));
        let out = enforce(&f, 1, "REDACT", Some("Project ███████"), true).unwrap();
        assert_eq!(out.0, "CLIPBOARD_REPLACED");
        assert_eq!(f.read().unwrap().unwrap().1, "Project ███████");
    }
    #[test]
    fn block_clears() {
        let f = Fake(Mutex::new((1, "secret".into())));
        assert_eq!(
            enforce(&f, 1, "BLOCK", None, true).unwrap().0,
            "CLIPBOARD_CLEARED"
        );
        assert!(f.read().unwrap().unwrap().1.is_empty());
    }
    #[test]
    fn stale_never_overwrites() {
        let f = Fake(Mutex::new((2, "new copy".into())));
        assert_eq!(
            enforce(&f, 1, "REDACT", Some("older"), true).unwrap().0,
            "STALE_SKIPPED"
        );
        assert_eq!(f.read().unwrap().unwrap().1, "new copy");
    }
    #[test]
    fn pause_prevents_mutation() {
        let f = Fake(Mutex::new((1, "secret".into())));
        assert_eq!(
            enforce(&f, 1, "BLOCK", None, false).unwrap().0,
            "PAUSED_SKIPPED"
        );
        assert_eq!(f.version(), 1);
    }
    #[test]
    fn warn_leaves_unchanged() {
        let f = Fake(Mutex::new((1, "secret".into())));
        assert_eq!(enforce(&f, 1, "WARN", None, true).unwrap().0, "WARNED");
        assert_eq!(f.version(), 1);
    }
    #[test]
    fn own_changes_suppressed() {
        let mut t = ClipboardTracker::default();
        t.baseline(1);
        assert!(!t.changed(1, -1));
        assert!(t.changed(2, -1));
        assert!(!t.changed(3, 3));
    }
    #[test]
    fn repeated_original_copy_must_protect_again() {
        let mut t = ClipboardTracker::default();
        t.baseline(1);
        assert!(t.changed(2, -1));
        assert!(!t.changed(3, 3));
        assert!(t.changed(4, 3));
    }
    #[test]
    fn missing_output_fails_safely() {
        let f = Fake(Mutex::new((1, "secret".into())));
        assert!(enforce(&f, 1, "REDACT", None, true).is_err());
        assert_eq!(f.version(), 1);
    }
}
