//! Authenticated same-user Unix socket behind Chrome Native Messaging. No HTTP listener.
use crate::{background::Agent, engine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{Read, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{Emitter, Manager};
const MAX_MESSAGE: usize = 30 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    request_id: String,
    #[serde(default)]
    payload: Value,
}
struct Decision {
    summary: Value,
    receipt: String,
    generation: u64,
    created: Instant,
    authorized: bool,
}
pub struct BrowserBridge {
    app: tauri::AppHandle,
    agent: Arc<Agent>,
    path: PathBuf,
    token: String,
    settings: Mutex<Value>,
    stopping: AtomicBool,
    last_seen: AtomicU64,
    decisions: Mutex<HashMap<String, Decision>>,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| "Local random source unavailable")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 100 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn authenticated(value: &Value, token: &str) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 2 || !object.contains_key("message") {
        return false;
    }
    let Some(candidate) = value["token"].as_str() else {
        return false;
    };
    candidate.len() == token.len()
        && candidate
            .bytes()
            .zip(token.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}
#[cfg(unix)]
impl BrowserBridge {
    pub fn new(app: tauri::AppHandle, agent: Arc<Agent>) -> Result<Arc<Self>, String> {
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
        let root = std::env::var_os("AXIOM_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or(
                app.path()
                    .home_dir()
                    .map_err(|_| "Home directory unavailable")?
                    .join(".axiom-local"),
            );
        let path = root.join("browser.sock");
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket() {
                return Err("Browser socket path is not a socket".into());
            }
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Err("Browser bridge already running".into());
            }
            std::fs::remove_file(&path).map_err(|_| "Stale browser socket unavailable")?;
        }
        let token = random_token()?;
        let temp = root.join(format!(".browser-token-{}", random_token()?));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|_| "Browser credential unavailable")?;
        file.write_all(token.as_bytes())
            .map_err(|_| "Browser credential unavailable")?;
        std::fs::rename(&temp, root.join("browser-token"))
            .map_err(|_| "Browser credential unavailable")?;
        let listener = std::os::unix::net::UnixListener::bind(&path)
            .map_err(|_| "Browser bridge socket unavailable")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "Browser socket permissions unavailable")?;
        let settings = engine::execute(&app, &json!({"op":"browser_settings"}))?;
        let bridge = Arc::new(Self {
            app,
            agent,
            path,
            token,
            settings: Mutex::new(settings),
            stopping: AtomicBool::new(false),
            last_seen: AtomicU64::new(0),
            decisions: Mutex::new(HashMap::new()),
            handle: Mutex::new(None),
        });
        bridge.agent.source("browser", "disconnected", None);
        let worker = bridge.clone();
        *bridge.handle.lock().unwrap() = Some(std::thread::spawn(move || {
            for stream in listener.incoming() {
                if worker.stopping.load(Ordering::SeqCst) || worker.agent.quitting() {
                    break;
                }
                if let Ok(mut stream) = stream {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
                    if !same_user(&stream) {
                        continue;
                    }
                    let response = match read_frame(&mut stream) {
                        Ok(value) => worker.dispatch(value),
                        Err(_) => json!({"request_id":"","ok":false,"error":"INVALID_MESSAGE"}),
                    };
                    let _ = write_frame(&mut stream, &response);
                }
            }
        }));
        Ok(bridge)
    }
    pub fn shutdown(&self) {
        if self.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = std::os::unix::net::UnixStream::connect(&self.path);
        if let Some(handle) = self.handle.lock().unwrap().take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
    pub fn status(&self) -> Value {
        let settings = self.settings.lock().unwrap().clone();
        let state = if !self.agent.settings().protection {
            "paused"
        } else if settings["enabled"] != true {
            "disabled"
        } else if self.last_seen.load(Ordering::SeqCst) > 0
            && now().saturating_sub(self.last_seen.load(Ordering::SeqCst)) < 60
        {
            "connected"
        } else {
            "disconnected"
        };
        json!({"status":state,"settings":settings,"transport":"Chrome Native Messaging / private Unix socket","coverage":"Opt-in standard HTML multipart forms"})
    }
    pub fn configure(&self, settings: Value) -> Result<Value, String> {
        let result = engine::execute(
            &self.app,
            &json!({"op":"browser_configure","settings":settings}),
        )?;
        *self.settings.lock().unwrap() = result;
        self.agent.policy_changed();
        self.decisions.lock().unwrap().clear();
        let _ = self.app.emit("axiom-browser-status", self.status());
        Ok(self.status())
    }
    fn dispatch(&self, value: Value) -> Value {
        if !authenticated(&value, &self.token) {
            return json!({"request_id":"","ok":false,"error":"UNAUTHORIZED"});
        }
        let request: Request = match serde_json::from_value(value["message"].clone()) {
            Ok(request) => request,
            Err(_) => return json!({"request_id":"","ok":false,"error":"INVALID_MESSAGE"}),
        };
        if !valid_id(&request.request_id) {
            return json!({"request_id":"","ok":false,"error":"INVALID_REQUEST_ID"});
        }
        let id = request.request_id.clone();
        let result = self.handle_request(request);
        match result {
            Ok(result) => json!({"request_id":id,"ok":true,"result":result}),
            Err(code) => json!({"request_id":id,"ok":false,"error":code}),
        }
    }
    fn handle_request(&self, request: Request) -> Result<Value, String> {
        if request.op == "disconnect" {
            self.last_seen.store(0, Ordering::SeqCst);
            self.agent.source("browser", "disconnected", None);
            let _ = self.app.emit("axiom-browser-status", self.status());
            return Ok(json!({"connected":false}));
        }
        self.last_seen.store(now(), Ordering::SeqCst);
        if request.op == "hello" {
            self.agent.source(
                "browser",
                if self.agent.settings().protection {
                    "connected"
                } else {
                    "paused"
                },
                None,
            );
            let _ = self.app.emit("axiom-browser-status", self.status());
            return Ok(self.status());
        }
        if request.op == "open_app" {
            if let Some(window) = self.app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
            let _ = self.app.emit("axiom-navigate", "activity");
            return Ok(json!({"opened":true}));
        }
        if !self.agent.settings().protection || self.settings.lock().unwrap()["enabled"] != true {
            return Err("AGENT_UNAVAILABLE".into());
        }
        self.agent.source("browser", "connected", None);
        match request.op.as_str() {
            "classify" => {
                if request.payload.as_object().map(|o| o.len()) != Some(1) {
                    return Err("INVALID_MESSAGE".into());
                }
                engine::execute(
                    &self.app,
                    &json!({"op":"browser_classify","origin":request.payload["origin"]}),
                )
                .map_err(|_| "INVALID_DESTINATION".into())
            }
            "evaluate" => {
                if request.payload["request_id"] != request.request_id {
                    return Err("MISMATCHED_REQUEST_ID".into());
                }
                let generation = self.agent.generation();
                let mut summary = engine::execute_cancelable(
                    &self.app,
                    &json!({"op":"browser_evaluate","payload":request.payload}),
                    || !self.agent.active(generation),
                )
                .map_err(|_| "UNASSESSED".to_string())?;
                if !self.agent.active(generation) {
                    return Err("STALE_DECISION".into());
                }
                let receipt = random_token()?;
                summary["receipt"] = json!(receipt);
                let mut decisions = self.decisions.lock().unwrap();
                decisions.retain(|_, d| d.created.elapsed() < Duration::from_secs(60));
                if decisions.len() >= 64 {
                    return Err("BUSY".into());
                }
                if decisions.contains_key(&request.request_id) {
                    return Err("DUPLICATE_REQUEST".into());
                }
                // Keep metadata only. Protected file bytes remain only in the response and extension's transient memory.
                let mut metadata = summary.clone();
                metadata.as_object_mut().unwrap().remove("files");
                decisions.insert(
                    request.request_id,
                    Decision {
                        summary: metadata,
                        receipt,
                        generation,
                        created: Instant::now(),
                        authorized: false,
                    },
                );
                Ok(summary)
            }
            "authorize" | "commit" => {
                let allowed = if request.op == "authorize" {
                    vec!["decision_id", "receipt"]
                } else {
                    vec!["decision_id", "receipt", "outcome"]
                };
                let Some(object) = request.payload.as_object() else {
                    return Err("INVALID_MESSAGE".into());
                };
                if object.len() != allowed.len()
                    || object.keys().any(|k| !allowed.contains(&k.as_str()))
                {
                    return Err("INVALID_MESSAGE".into());
                }
                let decision_id = request.payload["decision_id"]
                    .as_str()
                    .ok_or("INVALID_MESSAGE")?;
                let mut decisions = self.decisions.lock().unwrap();
                let decision = decisions.get_mut(decision_id).ok_or("STALE_DECISION")?;
                if decision.created.elapsed() > Duration::from_secs(60)
                    || decision.receipt != request.payload["receipt"]
                    || !self.agent.active(decision.generation)
                {
                    return Err("STALE_DECISION".into());
                }
                if request.op == "authorize" {
                    let revision = engine::execute(&self.app, &json!({"op":"browser_revision"}))
                        .map_err(|_| "UNASSESSED")?;
                    if revision != decision.summary["policy_revision"] {
                        return Err("STALE_POLICY".into());
                    }
                    decision.authorized = true;
                    return Ok(json!({"authorized":true}));
                }
                let outcome = request.payload["outcome"]
                    .as_str()
                    .ok_or("INVALID_OUTCOME")?;
                if !valid_outcome(
                    decision.summary["disposition"]
                        .as_str()
                        .unwrap_or("UNASSESSED"),
                    outcome,
                    decision.authorized,
                ) {
                    return Err("INVALID_OUTCOME".into());
                }
                let mut record = decision.summary.clone();
                let object = record.as_object_mut().unwrap();
                for key in [
                    "request_id",
                    "disposition",
                    "origin",
                    "policy_revision",
                    "elapsed_ms",
                    "receipt",
                ] {
                    object.remove(key);
                }
                record["id"] = json!(decision_id);
                record["source"] = json!("browser");
                record["event"] = json!("UPLOAD");
                record["outcome"] = json!(outcome);
                let saved = engine::execute(
                    &self.app,
                    &json!({"op":"background_record","record":record}),
                )
                .map_err(|_| "AUDIT_FAILED")?;
                decisions.remove(decision_id);
                let _ = self.app.emit("axiom-activity", &saved);
                Ok(json!({"recorded":true}))
            }
            _ => Err("UNKNOWN_OPERATION".into()),
        }
    }
}
fn valid_outcome(disposition: &str, outcome: &str, authorized: bool) -> bool {
    outcome == "UPLOAD_CANCELED"
        || match disposition {
            "BLOCK" => outcome == "UPLOAD_BLOCKED",
            "UNASSESSED" => outcome == "UPLOAD_UNASSESSED",
            "REVIEW_REQUIRED" => outcome == "UPLOAD_REVIEW_REQUIRED",
            "ALLOW" => authorized && outcome == "UPLOAD_ALLOWED",
            "WARN" => authorized && outcome == "UPLOAD_WARNED",
            "REDACT" => authorized && outcome == "UPLOAD_REDACTED",
            _ => false,
        }
}
#[cfg(unix)]
fn same_user(stream: &std::os::unix::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut uid = 0;
    let mut gid = 0;
    unsafe {
        libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0 && uid == libc::geteuid()
    }
}
fn read_frame(input: &mut impl Read) -> Result<Value, String> {
    let mut header = [0u8; 4];
    input.read_exact(&mut header).map_err(|_| "Invalid frame")?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > MAX_MESSAGE {
        return Err("Message exceeds limits".into());
    }
    let mut bytes = vec![0u8; size];
    input.read_exact(&mut bytes).map_err(|_| "Invalid frame")?;
    serde_json::from_slice(&bytes).map_err(|_| "Invalid JSON".into())
}
fn write_frame(output: &mut impl Write, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "Invalid response")?;
    if bytes.len() > 1024 * 1024 {
        return Err("Response exceeds Chrome limits".into());
    }
    output
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .and_then(|_| output.write_all(&bytes))
        .map_err(|_| "Response unavailable".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_missing_or_wrong_token() {
        assert!(!authenticated(
            &json!({"token":"wrong","message":{}}),
            "secret"
        ));
        assert!(!authenticated(
            &json!({"token":"secret","message":{},"extra":true}),
            "secret"
        ));
        assert!(authenticated(
            &json!({"token":"secret","message":{}}),
            "secret"
        ));
    }
    #[test]
    fn bounded_frames() {
        assert!(read_frame(&mut std::io::Cursor::new(
            (MAX_MESSAGE as u32 + 1).to_le_bytes()
        ))
        .is_err());
        assert!(read_frame(&mut std::io::Cursor::new([2, 0, 0, 0, b'{'])).is_err());
    }
    #[test]
    fn valid_frame() {
        let mut bytes = vec![];
        write_frame(&mut bytes, &json!({"ok":true})).unwrap();
        assert_eq!(
            read_frame(&mut std::io::Cursor::new(bytes)).unwrap()["ok"],
            true
        );
    }
    #[test]
    fn schema_rejects_unknown_fields() {
        assert!(serde_json::from_value::<Request>(
            json!({"op":"hello","request_id":"one","shell":"bad"})
        )
        .is_err());
    }
    #[test]
    fn cannot_report_allow_for_block() {
        assert!(!valid_outcome("BLOCK", "UPLOAD_ALLOWED", true));
        assert!(valid_outcome("BLOCK", "UPLOAD_BLOCKED", false));
    }
    #[test]
    fn released_upload_requires_authorization() {
        assert!(!valid_outcome("ALLOW", "UPLOAD_ALLOWED", false));
        assert!(valid_outcome("ALLOW", "UPLOAD_ALLOWED", true));
        assert!(!valid_outcome("UNASSESSED", "UPLOAD_ALLOWED", true));
    }
    #[test]
    fn identifiers_are_bounded() {
        assert!(valid_id("uuid-123"));
        assert!(!valid_id("../../path"));
        assert!(!valid_id(&"a".repeat(101)));
    }
}
