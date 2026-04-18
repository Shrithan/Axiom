use super::clipboard::ClipboardTracker;
use super::queue::FileDebouncer;
use super::{Agent, ContentEvent, Pending};
use notify::{EventKind, RecursiveMode, Watcher};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

pub trait EventSource {
    fn name(&self) -> &'static str;
    fn start(&self, agent: Arc<Agent>) -> std::thread::JoinHandle<()>;
}
pub struct MacFileEventSource;
pub struct MacClipboardEventSource;
pub enum FileSignal {
    Event(notify::Result<notify::Event>),
    Reconfigure,
}
impl EventSource for MacFileEventSource {
    fn name(&self) -> &'static str {
        "filesystem"
    }
    fn start(&self, agent: Arc<Agent>) -> std::thread::JoinHandle<()> {
        let source_name = self.name();
        std::thread::spawn(move || {
            let (tx, rx) = mpsc::sync_channel(1024);
            *agent.file_signal.lock().unwrap() = Some(tx.clone());
            let mut watcher = None;
            let mut generation = u64::MAX;
            let mut debounce = FileDebouncer::new(Duration::from_millis(700));
            loop {
                if agent.quitting() {
                    break;
                }
                let (settings, current) = agent.snapshot();
                if generation != current {
                    watcher = None;
                    debounce = FileDebouncer::new(Duration::from_millis(700));
                    generation = current;
                    if !cfg!(target_os = "macos") {
                        agent.source(source_name, "unsupported", None);
                    } else if !settings.protection {
                        agent.source(source_name, "paused", None);
                    } else if !settings.files {
                        agent.source(source_name, "disabled", None);
                    } else if settings.folders.is_empty() {
                        agent.source(source_name, "not_configured", None);
                    } else {
                        let callback_tx = tx.clone();
                        let weak = Arc::downgrade(&agent);
                        match notify::recommended_watcher(move |event| {
                            if callback_tx.try_send(FileSignal::Event(event)).is_err() {
                                if let Some(agent) = weak.upgrade() {
                                    agent.dropped();
                                }
                            }
                        }) {
                            Ok(mut w) => {
                                let mut failures = 0;
                                for folder in &settings.folders {
                                    if w.watch(
                                        std::path::Path::new(folder),
                                        RecursiveMode::Recursive,
                                    )
                                    .is_err()
                                    {
                                        failures += 1;
                                    }
                                }
                                agent.source(source_name,if failures==0{"active"}else{"error"},if failures==0{None}else{Some("Some folders cannot be watched. Check macOS folder access and select them again.")});
                                watcher = Some(w);
                            }
                            Err(_) => agent.source(
                                source_name,
                                "error",
                                Some("Filesystem watcher unavailable"),
                            ),
                        }
                    }
                }
                let wait = debounce.wait().unwrap_or(Duration::from_secs(3600));
                match rx.recv_timeout(wait) {
                    Ok(FileSignal::Reconfigure)=>continue,
                    Ok(FileSignal::Event(Ok(event))) if watcher.is_some()=> {
                        if matches!(event.kind,EventKind::Create(_)|EventKind::Modify(_)) {
                            for path in event.paths {
                                if super::files::supported(&path)&&!debounce.add(path,matches!(event.kind,EventKind::Create(_)),Instant::now()){agent.dropped();}
                            }
                        }
                    },
                    Ok(FileSignal::Event(Err(_)))=>agent.source(source_name,"error",Some("Filesystem watcher reported an error; monitoring continues where available")),
                    Err(mpsc::RecvTimeoutError::Disconnected)=>break,_=>(),
                }
                for (path, created) in debounce.due(Instant::now()) {
                    if agent.active(current) && path.is_file() {
                        let event = ContentEvent::new(
                            "filesystem",
                            if created {
                                "FILE_CREATED"
                            } else {
                                "FILE_MODIFIED"
                            },
                            Some(&path),
                        );
                        if !agent.queue.push(Pending {
                            event,
                            generation: current,
                            clipboard: None,
                        }) {
                            agent.dropped();
                        }
                    }
                }
            }
            drop(watcher);
            agent.source(source_name, "stopped", None);
        })
    }
}
impl EventSource for MacClipboardEventSource {
    fn name(&self) -> &'static str {
        "clipboard"
    }
    fn start(&self, agent: Arc<Agent>) -> std::thread::JoinHandle<()> {
        let source_name = self.name();
        std::thread::spawn(move || {
            let mut tracker = ClipboardTracker::default();
            let mut running = false;
            let mut last_generation = u64::MAX;
            loop {
                let (settings, generation) = agent.snapshot();
                if agent.quitting() {
                    break;
                }
                let enabled =
                    cfg!(target_os = "macos") && settings.protection && settings.clipboard;
                if !enabled {
                    agent.source(
                        source_name,
                        if !cfg!(target_os = "macos") {
                            "unsupported"
                        } else if !settings.protection {
                            "paused"
                        } else {
                            "disabled"
                        },
                        None,
                    );
                    running = false;
                    agent.wait(None);
                    continue;
                }
                if !running || last_generation != generation {
                    last_generation = generation;
                    tracker.baseline(agent.clipboard.version());
                    running = true;
                    agent.source(source_name, "active", None);
                }
                agent.wait(Some(Duration::from_secs(1)));
                if !agent.active(generation) || !agent.settings().clipboard {
                    continue;
                }
                let version = agent.clipboard.version();
                let own = agent
                    .own_clipboard
                    .load(std::sync::atomic::Ordering::SeqCst);
                if tracker.changed(version, own) {
                    match agent.clipboard.read() {
                        Ok(Some((version,text))) if !text.is_empty()=>{
                            let mut event=ContentEvent::new("clipboard","COPY",None);
                            let (name,id)=super::platform::application();event.source_application=name;event.source_application_id=id;
                            if !agent.queue.push(Pending{event,generation,clipboard:Some((version,text))}){agent.dropped();}
                            agent.source(source_name,"active",None);
                        },Ok(_)=>(),Err(_)=>agent.source(source_name,"error",Some("Clipboard unavailable or exceeds text limit; verify clipboard access")),
                    }
                }
            }
            agent.source(source_name, "stopped", None);
        })
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[test]
    fn native_fsevents_observes_created_document() {
        let root = std::env::temp_dir().join(format!(
            "axiom-fsevents-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let (tx, rx) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |event| {
            let _ = tx.send(event);
        })
        .unwrap();
        watcher.watch(&root, RecursiveMode::Recursive).unwrap();
        let file = root.join("acquisition.txt");
        std::fs::write(&file, b"Project Penguin launches Friday.").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut observed = false;
        while Instant::now() < deadline {
            if let Ok(Ok(event)) = rx.recv_timeout(Duration::from_millis(200)) {
                if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
                    && event
                        .paths
                        .iter()
                        .any(|p| p.file_name() == file.file_name())
                {
                    observed = true;
                    break;
                }
            }
        }
        drop(watcher);
        std::fs::remove_dir_all(root).unwrap();
        assert!(
            observed,
            "macOS native watcher did not observe new document"
        );
    }
}
