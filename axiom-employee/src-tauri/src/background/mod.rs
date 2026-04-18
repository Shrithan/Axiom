//! One local queue/worker; OS sources never run their own detector logic.
mod clipboard;
mod files;
mod platform;
mod queue;
mod sources;
use base64::Engine;
use queue::{ContentEvent, EventQueue, Pending};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sources::EventSource;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub protection: bool,
    pub clipboard: bool,
    pub files: bool,
    pub notifications: bool,
    pub folders: Vec<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            protection: true,
            clipboard: true,
            files: true,
            notifications: false,
            folders: vec![],
        }
    }
}
#[derive(Clone, Serialize, PartialEq)]
struct SourceStatus {
    status: String,
    error: Option<String>,
}

pub struct Agent {
    app: tauri::AppHandle,
    data_dir: PathBuf,
    config: Mutex<Settings>,
    changed: Condvar,
    epoch: AtomicU64,
    stopping: AtomicBool,
    pub queue: EventQueue,
    clipboard: Arc<dyn clipboard::ClipboardPort>,
    own_clipboard: AtomicI64,
    file_signal: Mutex<Option<std::sync::mpsc::SyncSender<sources::FileSignal>>>,
    health: Mutex<HashMap<String, SourceStatus>>,
    handles: Mutex<Vec<std::thread::JoinHandle<()>>>,
    reviews: Mutex<VecDeque<(String, PathBuf)>>,
    busy: AtomicBool,
    dropped_count: AtomicU64,
    last_error: Mutex<Option<String>>,
    _instance_lock: std::fs::File,
    tray_state: Mutex<Option<tauri::menu::MenuItem<tauri::Wry>>>,
    tray_toggle: Mutex<Option<tauri::menu::MenuItem<tauri::Wry>>>,
}
impl Agent {
    pub fn new(app: tauri::AppHandle) -> Result<Arc<Self>, String> {
        let data_dir = std::env::var_os("AXIOM_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or(
                app.path()
                    .home_dir()
                    .map_err(|_| "Home directory unavailable")?
                    .join(".axiom-local"),
            );
        std::fs::create_dir_all(&data_dir).map_err(|_| "Local agent directory unavailable")?;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let instance_lock = options
            .open(data_dir.join("agent.lock"))
            .map_err(|_| "Agent lock unavailable")?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(instance_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
            {
                return Err("Axiom agent already runs with this local data directory".into());
            }
        }
        let config_path = data_dir.join("agent-settings.json");
        let (config, config_error) = if config_path.exists() {
            match std::fs::read(&config_path).ok().and_then(|b|serde_json::from_slice::<Settings>(&b).ok()){
            Some(mut config)=>{match validate_folders(&config.folders,&data_dir){Ok(folders)=>{config.folders=folders;(config,None)},Err(_)=>(Settings{protection:false,..Settings::default()},Some("Configured folders are unavailable or unsafe. Protection is paused until settings are saved.".into()))}},None=>(Settings{protection:false,..Settings::default()},Some("Settings are invalid. Protection is paused until valid settings are saved.".into()))
        }
        } else {
            (Settings::default(), None)
        };
        let agent = Arc::new(Self {
            app,
            data_dir,
            config: Mutex::new(config),
            changed: Condvar::new(),
            epoch: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
            queue: EventQueue::new(64),
            clipboard: Arc::new(clipboard::MacClipboard),
            own_clipboard: AtomicI64::new(-1),
            file_signal: Mutex::new(None),
            health: Mutex::new(HashMap::new()),
            handles: Mutex::new(vec![]),
            reviews: Mutex::new(VecDeque::new()),
            busy: AtomicBool::new(false),
            dropped_count: AtomicU64::new(0),
            last_error: Mutex::new(config_error),
            _instance_lock: instance_lock,
            tray_state: Mutex::new(None),
            tray_toggle: Mutex::new(None),
        });
        Ok(agent)
    }
    pub fn start(self: &Arc<Self>) {
        let mut handles = self.handles.lock().unwrap();
        handles.push(sources::MacFileEventSource.start(self.clone()));
        handles.push(sources::MacClipboardEventSource.start(self.clone()));
        let agent = self.clone();
        handles.push(std::thread::spawn(move || agent.work()));
    }
    pub fn settings(&self) -> Settings {
        self.config.lock().unwrap().clone()
    }
    pub fn snapshot(&self) -> (Settings, u64) {
        let settings = self.config.lock().unwrap();
        (settings.clone(), self.generation())
    }
    pub fn generation(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }
    pub fn quitting(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
    pub fn active(&self, generation: u64) -> bool {
        !self.quitting() && self.generation() == generation && self.settings().protection
    }
    pub fn wait(&self, delay: Option<Duration>) {
        let mut settings = self.config.lock().unwrap();
        if let Some(delay) = delay {
            let _unused = self.changed.wait_timeout(settings, delay).unwrap();
        } else {
            while !self.quitting()
                && (!settings.protection || !settings.clipboard || !cfg!(target_os = "macos"))
            {
                settings = self.changed.wait(settings).unwrap();
            }
        }
    }
    pub fn source(&self, name: &str, status: &str, error: Option<&str>) {
        let next = SourceStatus {
            status: status.into(),
            error: error.map(str::to_string),
        };
        let changed = {
            let mut health = self.health.lock().unwrap();
            if health.get(name) == Some(&next) {
                false
            } else {
                health.insert(name.into(), next);
                true
            }
        };
        if changed {
            let _ = self.app.emit("axiom-status", self.status());
        }
    }
    pub fn dropped(&self) {
        self.dropped_count.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock().unwrap() =
            Some("Event capacity reached. Some events were dropped; review source status.".into());
    }
    pub fn status(&self) -> Value {
        let settings = self.settings();
        let health = self.health.lock().unwrap().clone();
        json!({"native":cfg!(target_os="macos"),"settings":settings,"sources":health,"queued":self.queue.len(),"worker_busy":self.busy.load(Ordering::Relaxed),"dropped":self.dropped_count.load(Ordering::Relaxed),"last_error":self.last_error.lock().unwrap().clone(),"application_context":if cfg!(target_os="macos"){"on clipboard changes"}else{"unsupported"},"email":"not_configured","browser_upload":"not_configured","autostart":"deferred"})
    }
    pub fn update(&self, mut settings: Settings) -> Result<Value, String> {
        settings.folders = validate_folders(&settings.folders, &self.data_dir)?;
        if settings.notifications && !self.settings().notifications {
            // macOS may separately require enabling notifications for this development bundle.
            self.app
                .notification()
                .request_permission()
                .map_err(|_| "Notification permission request failed")?;
        }
        let path = self.data_dir.join("agent-settings.json");
        let tmp = self.data_dir.join(format!(
            ".agent-settings-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp).map_err(|_| "Settings cannot be saved")?;
            file.write_all(&serde_json::to_vec(&settings).map_err(|_| "Invalid settings")?)
                .map_err(|_| "Settings cannot be saved")?;
            std::fs::rename(&tmp, &path).map_err(|_| "Settings cannot be saved")?;
        }
        {
            let mut config = self.config.lock().unwrap();
            *config = settings;
            self.epoch.fetch_add(1, Ordering::SeqCst);
        }
        self.queue.clear();
        self.changed.notify_all();
        self.signal_files();
        self.update_tray();
        let status = self.status();
        let _ = self.app.emit("axiom-status", &status);
        Ok(status)
    }
    pub fn policy_changed(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.queue.clear();
        self.changed.notify_all();
        self.signal_files();
    }
    fn signal_files(&self) {
        if let Some(tx) = self.file_signal.lock().unwrap().as_ref() {
            let _ = tx.try_send(sources::FileSignal::Reconfigure);
        }
    }
    fn update_tray(&self) {
        let active = self.settings().protection;
        if let Some(item) = self.tray_state.lock().unwrap().as_ref() {
            let _ = item.set_text(if active {
                "Protection Active"
            } else {
                "Protection Paused"
            });
        }
        if let Some(item) = self.tray_toggle.lock().unwrap().as_ref() {
            let _ = item.set_text(if active {
                "Pause Protection"
            } else {
                "Resume Protection"
            });
        }
        if let Some(tray) = self.app.tray_by_id("axiom-agent") {
            let active = self.settings().protection;
            let _ = tray.set_title(Some(if active { "Axiom ●" } else { "Axiom ○" }));
            let _ = tray.set_tooltip(Some(if active {
                "Protection active"
            } else {
                "Protection paused"
            }));
        }
    }
    pub fn shutdown(&self) {
        if self.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.queue.close();
        self.changed.notify_all();
        self.signal_files();
        for handle in self.handles.lock().unwrap().drain(..) {
            let _ = handle.join();
        }
    }
    fn work(&self) {
        let mut fingerprints = files::Fingerprints::default();
        let mut last_notification: Option<Instant> = None;
        while let Some(pending) = self.queue.pop() {
            if !self.active(pending.generation) {
                continue;
            }
            self.busy.store(true, Ordering::Relaxed);
            let result = self.process(pending, &mut fingerprints);
            self.busy.store(false, Ordering::Relaxed);
            match result {
                Ok(Some(record)) => {
                    if record["outcome"] == "ERROR" {
                        *self.last_error.lock().unwrap() = Some(
                            "An event failed; inspect Activity. Agent continues running.".into(),
                        );
                    }
                    if !self.quitting() {
                        let _ = crate::engine::execute(
                            &self.app,
                            &json!({"op":"background_record","record":record}),
                        )
                        .map_err(|_| {
                            *self.last_error.lock().unwrap() =
                                Some("Local activity persistence failed".into());
                        });
                        let _ = self.app.emit("axiom-activity", &record);
                        let action = record["action"].as_str().unwrap_or("ALLOW");
                        if self.settings().notifications
                            && action != "ALLOW"
                            && record["outcome"] != "PAUSED_SKIPPED"
                            && record["outcome"] != "STALE_SKIPPED"
                            && last_notification
                                .map(|t| t.elapsed() > Duration::from_secs(10))
                                .unwrap_or(true)
                        {
                            let app = self.app.clone();
                            let count = record["policies"].as_array().map(Vec::len).unwrap_or(0);
                            let dispatched=self.app.run_on_main_thread(move||{
                                if app.notification().builder().title("Axiom privacy activity").body(format!("{count} policies matched. Open Axiom → Activity to review. No sensitive values are shown here.")).show().is_err(){
                                    let agent=app.state::<Arc<Agent>>();*agent.last_error.lock().unwrap()=Some("Notification delivery failed; review Activity directly.".into());let _=app.emit("axiom-status",agent.status());
                                }
                            });
                            if dispatched.is_err() {
                                *self.last_error.lock().unwrap() = Some(
                                    "Notification dispatch failed; review Activity directly."
                                        .into(),
                                );
                            }
                            last_notification = Some(Instant::now());
                        }
                    }
                }
                Ok(None) => (),
                Err(_) => {
                    *self.last_error.lock().unwrap() =
                        Some("Background operation failed; agent continues running".into());
                }
            }
            let _ = self.app.emit("axiom-status", self.status());
        }
    }
    fn process(
        &self,
        pending: Pending,
        fingerprints: &mut files::Fingerprints,
    ) -> Result<Option<Value>, String> {
        let event = pending.event;
        let generation = pending.generation;
        let (name, bytes, path, version) = if let Some((version, text)) = pending.clipboard {
            (
                "clipboard.txt".to_string(),
                text.into_bytes(),
                None,
                Some(version),
            )
        } else {
            match files::resolve(Path::new(&event.file_path), &self.settings().folders) {
                Ok((path, data)) => {
                    if fingerprints.unchanged(path.clone(), &data, generation) {
                        return Ok(None);
                    }
                    (
                        path.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                        data,
                        Some(path),
                        None,
                    )
                }
                Err(_) => {
                    return Ok(Some(
                        json!({"id":event.id,"source":event.source,"event":event.action,"action":"UNASSESSED","outcome":"ERROR","policies":[],"detection_count":0,"document_type":"unknown"}),
                    ))
                }
            }
        };
        let mut result = match crate::engine::execute_cancelable(
            &self.app,
            &json!({"op":"background_scan","name":name,"data":base64::engine::general_purpose::STANDARD.encode(bytes),"event":event}),
            || !self.active(generation),
        ) {
            Ok(result) => result,
            Err(_) => {
                return Ok(Some(
                    json!({"id":event.id,"source":event.source,"event":event.action,"action":"UNASSESSED","outcome":if self.active(generation){"ERROR"}else{"PAUSED_SKIPPED"},"policies":[],"detection_count":0,"document_type":"unknown"}),
                ));
            }
        };
        let action = result["action"].as_str().unwrap_or("ALLOW");
        let outcome = if let Some(version) = version {
            // Holding configuration lock prevents a local pause racing the write itself.
            let config = self.config.lock().unwrap();
            let active = config.protection
                && config.clipboard
                && self.generation() == generation
                && !self.quitting();
            match clipboard::enforce(
                self.clipboard.as_ref(),
                version,
                action,
                result["protected_text"].as_str(),
                active,
            ) {
                Ok((outcome, own)) => {
                    if let Some(own) = own {
                        self.own_clipboard.store(own, Ordering::SeqCst);
                    }
                    outcome
                }
                Err(_) => "ERROR",
            }
        } else {
            if let Some(path) = path {
                let mut reviews = self.reviews.lock().unwrap();
                if reviews.len() >= 100 {
                    reviews.pop_front();
                }
                reviews.push_back((event.id.clone(), path));
            }
            if !self.active(generation) {
                "PAUSED_SKIPPED"
            } else {
                match action {
                    "ALLOW" => "UNCHANGED",
                    "WARN" => "WARNED",
                    "REDACT" => "REVIEW_REQUIRED",
                    "BLOCK" => "BOUNDARY_NOT_INTERCEPTED",
                    _ => "ERROR",
                }
            }
        };
        result
            .as_object_mut()
            .ok_or("Invalid worker response")?
            .remove("protected_text");
        result["outcome"] = json!(outcome);
        if outcome == "ERROR" {
            *self.last_error.lock().unwrap()=Some("Event could not be protected. Source is unchanged; inspect Activity and source health.".into());
        }
        Ok(Some(result))
    }
    pub fn review(&self, id: &str) -> Result<Value, String> {
        let path = self
            .reviews
            .lock()
            .unwrap()
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, p)| p.clone())
            .ok_or(
                "This file reference expired or is not reviewable. Import the document manually.",
            )?;
        let (path, data) = files::resolve(&path, &self.settings().folders)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let result = crate::engine::execute(
            &self.app,
            &json!({"op":"scan","name":name,"data":encoded,"context":{"action":"OPEN","destination":"UNSPECIFIED"}}),
        )?;
        Ok(json!({"result":result,"name":name,"data":encoded}))
    }
}

pub fn copy_example() -> Result<(), String> {
    platform::replace(
        platform::version(),
        Some("Project Penguin launches Friday."),
    )?
    .ok_or("Clipboard changed; try again")?;
    Ok(())
}

pub fn install_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::TrayIconBuilder;
    let status = MenuItem::with_id(app, "state", "Protection Active", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open Axiom", true, None::<&str>)?;
    let activity = MenuItem::with_id(app, "activity", "Recent Activity", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Pause Protection", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Axiom", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[&status, &separator, &open, &activity, &toggle, &quit],
    )?;
    let active = app.state::<Arc<Agent>>().settings().protection;
    {
        let agent = app.state::<Arc<Agent>>();
        *agent.tray_state.lock().unwrap() = Some(status.clone());
        *agent.tray_toggle.lock().unwrap() = Some(toggle.clone());
        agent.update_tray();
    }
    TrayIconBuilder::with_id("axiom-agent")
        .title(if active { "Axiom ●" } else { "Axiom ○" })
        .menu(&menu)
        .on_menu_event(|app, event| {
            let agent = app.state::<Arc<Agent>>();
            match event.id.as_ref() {
                "open" | "activity" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                    if event.id.as_ref() == "activity" {
                        let _ = app.emit("axiom-navigate", "activity");
                    }
                }
                "toggle" => {
                    let mut settings = agent.settings();
                    settings.protection = !settings.protection;
                    let _ = agent.update(settings);
                }
                "quit" => {
                    agent.shutdown();
                    app.exit(0);
                }
                _ => (),
            }
        })
        .build(app)?;
    Ok(())
}

fn validate_folders(input: &[String], data_dir: &Path) -> Result<Vec<String>, String> {
    if input.len() > 16 {
        return Err("Select at most 16 monitored folders".into());
    }
    let data = data_dir
        .canonicalize()
        .map_err(|_| "Local data directory unavailable")?;
    let mut folders = vec![];
    for folder in input {
        let path = Path::new(folder)
            .canonicalize()
            .map_err(|_| "Monitored folder unavailable; choose an existing folder")?;
        if !path.is_dir()
            || path.parent().is_none()
            || path == Path::new("/Users")
            || path == Path::new("/private/tmp")
            || data.starts_with(&path)
            || path.starts_with(&data)
        {
            return Err("Choose a specific document folder, not the disk, home, temporary root or agent data directory".into());
        }
        let value = path.to_string_lossy().to_string();
        if !folders.contains(&value) {
            folders.push(value);
        }
    }
    Ok(folders)
}
