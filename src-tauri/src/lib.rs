// src-tauri/src/lib.rs
// Axiom — Preview PDF Data Leakage Prevention
//
// Pipeline (no screen recording required):
//   1. AppleScript asks Preview for the path of its front document
//   2. Python reads the PDF with pdfminer and extracts all text
//   3. Regex patterns scan the text for PII
//   4. Detections are emitted to the side panel
//   5. Overlay window shows a badge over the Preview app window
//
// No PaliGemma, no camera, no screen recording permission needed.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource { Pdf, Clipboard }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: String,
    pub pattern_name: String,
    pub matched_text: String,
    pub severity: Severity,
    pub source: DetectionSource,
    pub page: Option<u32>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub detections: Vec<Detection>,
    pub raw_text_snippet: String,
    pub pdf_path: Option<String>,
}

/// One detection returned by the Python subprocess.
#[derive(Debug, Deserialize)]
struct PyDetection {
    label:    String,
    severity: String,
    redacted: String,
    #[serde(default)]
    page: u32,
}

/// Response envelope from the Python subprocess.
#[derive(Debug, Deserialize)]
struct PyResponse {
    id:         String,
    detections: Vec<PyDetection>,
    error:      Option<String>,
    #[serde(default)]
    ready:      bool,
}

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

pub struct PdfScanProcess {
    pub child:  Child,
    pub stdin:  ChildStdin,
    pub stdout: BufReader<ChildStdout>,
}

pub struct AppState {
    pub scanning:       Arc<Mutex<bool>>,
    pub overlay_active: Arc<Mutex<bool>>,
    pub py_process:     Arc<Mutex<Option<PdfScanProcess>>>,
    pub model_ready:    Arc<Mutex<bool>>,
    pub script_path:    String,
    pub last_pdf_path:  Arc<Mutex<Option<String>>>,
}

impl Default for AppState {
    fn default() -> Self {
        let script = std::env::var("AXIOM_PY_SCRIPT")
            .unwrap_or_else(|_| "scripts/pdf_scanner.py".to_string());
        AppState {
            scanning:      Arc::new(Mutex::new(false)),
            overlay_active: Arc::new(Mutex::new(false)),
            py_process:    Arc::new(Mutex::new(None)),
            model_ready:   Arc::new(Mutex::new(false)),
            script_path:   script,
            last_pdf_path: Arc::new(Mutex::new(None)),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn severity_from_str(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH"     => Severity::High,
        "MEDIUM"   => Severity::Medium,
        _          => Severity::Low,
    }
}

/// Ask Preview (via AppleScript) for the path of its front document.
/// Returns None if Preview isn't open or has no document.
fn get_preview_pdf_path() -> Option<String> {
    let output = Command::new("osascript")
        .arg("-e")
        .arg(r#"tell application "Preview"
    if (count of documents) > 0 then
        set f to file of front document
        POSIX path of f
    else
        ""
    end if
end tell"#)
        .output()
        .ok()?;

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() || !path.ends_with(".pdf") {
        None
    } else {
        Some(path)
    }
}

fn get_clipboard_text() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use arboard::Clipboard;
    Ok(Clipboard::new()?.get_text().unwrap_or_default())
}

fn scan_clipboard_for_pii(text: &str) -> Vec<Detection> {
    use lazy_static::lazy_static;
    use regex::Regex;

    lazy_static! {
        static ref PATTERNS: Vec<(&'static str, &'static str, Regex)> = vec![
            ("SSN",         "CRITICAL", Regex::new(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b").unwrap()),
            ("CREDIT_CARD", "CRITICAL", Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap()),
            ("EMAIL",       "MEDIUM",   Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap()),
            ("AWS_KEY",     "CRITICAL", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
            ("JWT",         "CRITICAL", Regex::new(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b").unwrap()),
            ("PASSWORD",    "CRITICAL", Regex::new(r"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*\S+").unwrap()),
            ("PRIVATE_KEY", "CRITICAL", Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap()),
            ("PHONE",       "MEDIUM",   Regex::new(r"\b(?:\+1[\s\-]?)?\(?[0-9]{3}\)?[\s\-]?[0-9]{3}[\s\-]?[0-9]{4}\b").unwrap()),
        ];
    }

    let ts = timestamp_ms();
    PATTERNS.iter().flat_map(|(name, sev, re)| {
        re.find_iter(text).map(|m| {
            let raw = m.as_str();
            let redacted = if raw.len() <= 4 { "*".repeat(raw.len()) }
                           else { format!("{}****", &raw[..4]) };
            Detection {
                id: format!("{}-{}-{}", name, m.start(), ts),
                pattern_name: name.to_string(),
                matched_text: redacted,
                severity: severity_from_str(sev),
                source: DetectionSource::Clipboard,
                page: None,
                timestamp_ms: ts,
            }
        }).collect::<Vec<_>>()
    }).collect()
}

// ---------------------------------------------------------------------------
// Python subprocess management
// ---------------------------------------------------------------------------

fn find_python() -> String {
    // We'll check the paths based on your screenshot (venv at root)
    let candidates = ["venv/bin/python3", "venv/bin/python", "python3", "python"];
    
    for c in &candidates {
        match Command::new(c).arg("--version").output() {
            Ok(output) => {
                let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                eprintln!("[Axiom-Debug] Found Python candidate '{}' -> {}", c, version);
                return c.to_string();
            }
            Err(e) => {
                eprintln!("[Axiom-Debug] Candidate '{}' failed: {}", c, e);
            }
        }
    }
    eprintln!("[Axiom-Debug] No venv found! Falling back to system 'python3'");
    "python3".to_string()
}

fn spawn_pdf_scanner(script_path: &str) -> anyhow::Result<PdfScanProcess> {
    let python = find_python();
    let current_dir = std::env::current_dir().unwrap_or_default();
    
    eprintln!("[Axiom-Debug] CWD: {:?}", current_dir);
    eprintln!("[Axiom-Debug] Spawning: {} {}", python, script_path);

    let mut child = Command::new(&python)
        .arg(script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // This is vital: it sends Python Tracebacks to your terminal
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn process: {}. Is '{}' installed?", e, python))?;

    let stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("Failed to open stdin"))?;
    let stdout_raw = child.stdout.take().ok_or_else(|| anyhow::anyhow!("Failed to open stdout"))?;
    let mut stdout = BufReader::new(stdout_raw);

    // Wait for ready signal with detailed timeout error
    let mut line = String::new();
    loop {
        line.clear();
        match stdout.read_line(&mut line) {
            Ok(0) => {
                // The process exited. Let's try to see why.
                let status = child.try_wait()?;
                anyhow::bail!(
                    "Subprocess exited immediately. Exit Status: {:?}. \nCheck if 'scripts/pdf_scanner.py' exists and if 'pdfminer.six' is installed in your venv.", 
                    status
                );
            }
            Ok(_) => {
                let t = line.trim();
                if t.is_empty() { continue; }
                eprintln!("[Axiom-Debug] Python Init Output: {}", t);
                let resp: PyResponse = serde_json::from_str(t)
                    .map_err(|e| anyhow::anyhow!("JSON Parse Error: {} - Raw line: {}", e, t))?;
                if let Some(err) = resp.error {
                    anyhow::bail!("Python Script Error: {}", err);
                }
                if resp.ready { break; }
            }
            Err(e) => anyhow::bail!("Read error: {}", e),
        }
    }

    Ok(PdfScanProcess { child, stdin, stdout })
}

fn query_subprocess(proc: &mut PdfScanProcess, req_id: &str, pdf_path: &str) -> anyhow::Result<Vec<PyDetection>> {
    let req = serde_json::json!({ "id": req_id, "pdf_path": pdf_path });
    let mut line_out = serde_json::to_string(&req)?;
    line_out.push('\n');
    proc.stdin.write_all(line_out.as_bytes())?;
    proc.stdin.flush()?;

    let mut resp_line = String::new();
    loop {
        resp_line.clear();
        let n = proc.stdout.read_line(&mut resp_line)?;
        if n == 0 { anyhow::bail!("Subprocess closed stdout unexpectedly"); }
        let t = resp_line.trim();
        if t.is_empty() { continue; }
        let resp: PyResponse = serde_json::from_str(t)
            .map_err(|e| anyhow::anyhow!("Bad response JSON: {e} — raw: {t}"))?;
        if let Some(err) = resp.error { anyhow::bail!("Subprocess error: {err}"); }
        return Ok(resp.detections);
    }
}

fn py_to_detections(items: Vec<PyDetection>) -> Vec<Detection> {
    let ts = timestamp_ms();
    items.into_iter().enumerate().map(|(i, item)| Detection {
        id: format!("{}-{}-{}", item.label, i, ts),
        pattern_name: item.label,
        matched_text: item.redacted,
        severity: severity_from_str(&item.severity),
        source: DetectionSource::Pdf,
        page: if item.page > 0 { Some(item.page) } else { None },
        timestamp_ms: ts,
    }).collect()
}

// ---------------------------------------------------------------------------
// Overlay window
// ---------------------------------------------------------------------------

fn get_or_create_overlay(app: &AppHandle) -> anyhow::Result<tauri::WebviewWindow> {
    if let Some(w) = app.get_webview_window("overlay") { return Ok(w); }

    let (sw, sh) = app.primary_monitor().ok().flatten()
        .map(|m| { let s = m.size(); (s.width, s.height) })
        .unwrap_or((1920, 1080));

    let overlay = WebviewWindowBuilder::new(app, "overlay", WebviewUrl::App("/overlay".into()))
        .title("Axiom Overlay")
        .transparent(true).decorations(false).always_on_top(true)
        .skip_taskbar(true).resizable(false)
        .inner_size(sw as f64, sh as f64).position(0.0, 0.0).focused(false)
        .build()?;

    overlay.set_ignore_cursor_events(true)?;
    Ok(overlay)
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

mod commands {
    use super::*;

    #[tauri::command]
    pub async fn start_scanning(
        app: AppHandle,
        state: State<'_, AppState>,
    ) -> Result<(), String> {
        {
            let mut s = state.scanning.lock().map_err(|e| e.to_string())?;
            if *s { return Ok(()); }
            *s = true;
        }

        get_or_create_overlay(&app).map_err(|e| e.to_string())?;

        let flag         = Arc::clone(&state.scanning);
        let py_proc_arc  = Arc::clone(&state.py_process);
        let ready_arc    = Arc::clone(&state.model_ready);
        let pdf_path_arc = Arc::clone(&state.last_pdf_path);
        let handle       = app.clone();
        let script_path  = state.script_path.clone();

        thread::spawn(move || {
            // Spawn Python subprocess
            let proc = match spawn_pdf_scanner(&script_path) {
                Ok(p) => p,
                Err(e) => {
                    let msg = format!(
                        "{e}\n\nSetup:\n\
                         cd scripts && pip install pdfminer.six"
                    );
                    eprintln!("[Axiom] {msg}");
                    let _ = handle.emit_to("main", "paligemma_error", &msg);
                    if let Ok(mut s) = flag.lock() { *s = false; }
                    return;
                }
            };

            if let Ok(mut g) = py_proc_arc.lock() { *g = Some(proc); }
            if let Ok(mut r) = ready_arc.lock()   { *r = true; }
            let _ = handle.emit_to("main", "paligemma_ready", ());

            let mut req_counter: u64 = 0;
            let mut last_scanned_path: Option<String> = None;

            while *flag.lock().unwrap() {
                // Ask Preview which PDF it has open
                let pdf_path = match get_preview_pdf_path() {
                    Some(p) => p,
                    None => {
                        eprintln!("[Axiom] Preview not open or no PDF — waiting…");
                        let _ = handle.emit_to("main", "preview_status",
                            serde_json::json!({"status": "waiting", "message": "Open a PDF in Preview to begin scanning"}));
                        thread::sleep(Duration::from_secs(3));
                        continue;
                    }
                };

                // Only re-scan if the file changed
                if Some(&pdf_path) == last_scanned_path.as_ref() {
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }

                eprintln!("[Axiom] Scanning PDF: {pdf_path}");
                let _ = handle.emit_to("main", "preview_status",
                    serde_json::json!({"status": "scanning", "message": format!("Scanning: {}", pdf_path.split('/').last().unwrap_or(&pdf_path))}));

                // Store path
                if let Ok(mut p) = pdf_path_arc.lock() { *p = Some(pdf_path.clone()); }

                req_counter += 1;
                let req_id = req_counter.to_string();

                let py_dets = {
                    let mut guard = py_proc_arc.lock().unwrap();
                    match guard.as_mut() {
                        Some(proc) => match query_subprocess(proc, &req_id, &pdf_path) {
                            Ok(d) => d,
                            Err(e) => {
                                eprintln!("[Axiom] Scan failed: {e}");
                                let _ = handle.emit_to("main", "paligemma_error", e.to_string());
                                Vec::new()
                            }
                        },
                        None => Vec::new(),
                    }
                };

                last_scanned_path = Some(pdf_path.clone());
                let mut all_det = py_to_detections(py_dets);

                // Also scan clipboard
                if let Ok(cb) = get_clipboard_text() {
                    all_det.append(&mut scan_clipboard_for_pii(&cb));
                }

                let snippet = all_det.iter()
                    .map(|d| format!("[{}] {}", d.pattern_name, d.matched_text))
                    .collect::<Vec<_>>().join(", ");

                let payload = ScanResult {
                    detections: all_det,
                    raw_text_snippet: snippet,
                    pdf_path: Some(pdf_path),
                };

                let _ = handle.emit_to("main",    "scan_result", &payload);
                let _ = handle.emit_to("overlay", "scan_result", &payload);

                thread::sleep(Duration::from_secs(3));
            }

            let _ = handle.emit_to("overlay", "clear_overlay", ());
        });

        Ok(())
    }

    #[tauri::command]
    pub async fn stop_scanning(state: State<'_, AppState>) -> Result<(), String> {
        *state.scanning.lock().map_err(|e| e.to_string())? = false;
        if let Ok(mut guard) = state.py_process.lock() {
            if let Some(mut proc) = guard.take() {
                let _ = proc.child.kill();
                let _ = proc.child.wait();
                eprintln!("[Axiom] PDF scanner subprocess stopped");
            }
        }
        *state.model_ready.lock().map_err(|e| e.to_string())? = false;
        Ok(())
    }

    #[tauri::command]
    pub async fn set_overlay_visible(
        app: AppHandle, state: State<'_, AppState>, visible: bool,
    ) -> Result<(), String> {
        *state.overlay_active.lock().map_err(|e| e.to_string())? = visible;
        if visible {
            get_or_create_overlay(&app).map_err(|e| e.to_string())?.show().map_err(|e| e.to_string())?;
        } else if let Some(w) = app.get_webview_window("overlay") {
            w.hide().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    #[tauri::command]
    pub async fn get_overlay_active(state: State<'_, AppState>) -> Result<bool, String> {
        Ok(*state.overlay_active.lock().map_err(|e| e.to_string())?)
    }

    #[tauri::command]
    pub async fn scan_clipboard_now() -> Result<Vec<Detection>, String> {
        let text = get_clipboard_text().map_err(|e| e.to_string())?;
        Ok(scan_clipboard_for_pii(&text))
    }

    #[tauri::command]
    pub async fn get_current_pdf(state: State<'_, AppState>) -> Result<Option<String>, String> {
        Ok(state.last_pdf_path.lock().map_err(|e| e.to_string())?.clone())
    }

    #[tauri::command]
    pub async fn get_model_info(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({
            "model":       "PDF Text Extractor (pdfminer)",
            "script_path": state.script_path,
            "ready":       *state.model_ready.lock().map_err(|e| e.to_string())?,
        }))
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::start_scanning,
            commands::stop_scanning,
            commands::set_overlay_visible,
            commands::get_overlay_active,
            commands::scan_clipboard_now,
            commands::get_current_pdf,
            commands::get_model_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Axiom");
}