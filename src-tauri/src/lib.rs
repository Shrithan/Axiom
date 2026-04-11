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
    /// Which detection layer(s) caught this: "regex", "gemma", or "regex+gemma"
    pub detection_layer: String,
    /// Gemma confidence: "high" | "medium" | "low"
    pub confidence: String,
    /// Raw matched value — used by the redactor, not shown in UI
    pub raw_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub detections:   Vec<Detection>,
    pub raw_text_snippet: String,
    pub pdf_path:     Option<String>,
    pub gemma_log:    Vec<GemmaPageLog>,
    /// Model info from init handshake
    pub model_id:     Option<String>,
    pub device:       Option<String>,
}

/// One detection returned by the Python subprocess.
#[derive(Debug, Deserialize)]
struct PyDetection {
    label:    String,
    severity: String,
    redacted: String,
    #[serde(default)]
    raw_value: String,
    #[serde(default)]
    page: u32,
    #[serde(default)]
    detection_layer: String,
    #[serde(default)]
    confidence: String,
}

/// Per-page Gemma activity log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GemmaPageLog {
    pub page:         u32,
    pub chunks:       u32,
    pub raw_findings: u32,
    pub kept:         u32,
    pub duration_ms:  u32,
    pub status:       String,  // "ok" | "empty" | "parse_error" | "blank"
}

/// Response envelope from the Python subprocess.
#[derive(Debug, Deserialize)]
struct PyResponse {
    id:         String,
    detections: Vec<PyDetection>,
    error:      Option<String>,
    #[serde(default)]
    ready:      bool,
    #[serde(default)]
    gemma_log:  Vec<GemmaPageLog>,
    model:      Option<String>,
    device:     Option<String>,
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
    pub scanning:        Arc<Mutex<bool>>,
    pub overlay_active:  Arc<Mutex<bool>>,
    pub py_process:      Arc<Mutex<Option<PdfScanProcess>>>,
    pub redact_process:  Arc<Mutex<Option<PdfScanProcess>>>,
    pub model_ready:     Arc<Mutex<bool>>,
    pub script_path:     String,
    pub last_pdf_path:   Arc<Mutex<Option<String>>>,
    pub last_detections: Arc<Mutex<Vec<serde_json::Value>>>,
    pub model_id:        Arc<Mutex<Option<String>>>,
    pub device:          Arc<Mutex<Option<String>>>,
}

impl Default for AppState {
    fn default() -> Self {
        let script = std::env::var("AXIOM_PY_SCRIPT")
            .unwrap_or_else(|_| "scripts/pdf_scanner.py".to_string());
        AppState {
            scanning:        Arc::new(Mutex::new(false)),
            overlay_active:  Arc::new(Mutex::new(false)),
            py_process:      Arc::new(Mutex::new(None)),
            redact_process:  Arc::new(Mutex::new(None)),
            model_ready:     Arc::new(Mutex::new(false)),
            script_path:     script,
            last_pdf_path:   Arc::new(Mutex::new(None)),
            last_detections: Arc::new(Mutex::new(Vec::new())),
            model_id:        Arc::new(Mutex::new(None)),
            device:          Arc::new(Mutex::new(None)),
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

/// Ask open apps for the frontmost document path via AppleScript.
/// Returns a POSIX path string, or None if nothing supported is open.
fn get_preview_pdf_path() -> Option<String> {
    const EXTS: &[&str] = &[".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt"];

    // Each entry: (app name, how to get the POSIX path of the front document)
    // Preview uses `file of front document` → coerce to alias → POSIX path
    // Office apps use `full name of front document` which is already a POSIX path
    let script = r#"
        set posixPath to ""

        try
            if application "Preview" is running then
                set posixPath to run script "tell application \"Preview\" to get path of front document"
                if posixPath is not "" then return posixPath
            end if
        end try

        try
            if application "Microsoft Word" is running then
                set posixPath to run script "tell application \"Microsoft Word\" to get full name of active document"
                if posixPath is not "" then return posixPath
            end if
        end try

        try
            if application "Microsoft Excel" is running then
                set posixPath to run script "tell application \"Microsoft Excel\" to get full name of active workbook"
                if posixPath is not "" then return posixPath
            end if
        end try

        try
            if application "Microsoft PowerPoint" is running then
                set posixPath to run script "tell application \"Microsoft PowerPoint\" to get full name of active presentation"
                if posixPath is not "" then return posixPath
            end if
        end try

        try
            if application "Pages" is running then
                set posixPath to run script "tell application \"Pages\" to get POSIX path of (file of front document as alias)"
                if posixPath is not "" then return posixPath
            end if
        end try

        try
            if application "Numbers" is running then
                set posixPath to run script "tell application \"Numbers\" to get POSIX path of (file of front document as alias)"
                if posixPath is not "" then return posixPath
            end if
        end try

        try
            if application "Keynote" is running then
                set posixPath to run script "tell application \"Keynote\" to get POSIX path of (file of front document as alias)"
                if posixPath is not "" then return posixPath
            end if
        end try

        return posixPath
    "#;

    // Write to a temp file — passing multi-line scripts via -e causes parse errors
    let script_path = std::env::temp_dir().join("axiom_detect.scpt");
    if std::fs::write(&script_path, script).is_err() {
        return None;
    }

    let output = Command::new("osascript")
        .arg(&script_path)
        .output()
        .ok()?;

    // Log stderr to help debug AppleScript errors
    let err_out = String::from_utf8_lossy(&output.stderr);
    if !err_out.trim().is_empty() {
        eprintln!("[Axiom] AppleScript stderr: {}", err_out.trim());
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    eprintln!("[Axiom] AppleScript raw output: {:?}", path);

    if path.is_empty() {
        return None;
    }

    let path_lower = path.to_lowercase();
    if EXTS.iter().any(|ext| path_lower.ends_with(ext)) {
        Some(path)
    } else {
        eprintln!("[Axiom] Unsupported extension, ignoring: {:?}", path);
        None
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
                detection_layer: "regex".to_string(),
                confidence: "high".to_string(),
                raw_value: raw.to_string(),
            }
        }).collect::<Vec<_>>()
    }).collect()
}

// ---------------------------------------------------------------------------
// Python subprocess management
// ---------------------------------------------------------------------------

fn find_python() -> String {
    // We are no longer looking for venv folders. 
    // This relies on your global system path.
    "python3".to_string()
}

fn spawn_pdf_scanner(script_path: &str) -> anyhow::Result<(PdfScanProcess, Option<String>, Option<String>)> {
    let python = find_python();
    
    // Resolve the absolute path to the script to avoid CWD issues
    let mut base_path = std::env::current_dir().unwrap_or_default();
    
    // If the app started inside src-tauri, go up one level to find /scripts
    if base_path.ends_with("src-tauri") {
        base_path.pop();
    }
    
    let absolute_script_path = base_path.join("scripts/pdf_scanner.py");
    
    eprintln!("[Axiom] Spawning: {} {:?}", python, absolute_script_path);

    let mut child = Command::new(&python)
        .arg(absolute_script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // Keeps Python errors visible in your terminal
        .spawn()?;

    let stdin = child.stdin.take()
        .ok_or_else(|| anyhow::anyhow!("Failed to open subprocess stdin"))?;
    let stdout_raw = child.stdout.take()
        .ok_or_else(|| anyhow::anyhow!("Failed to open subprocess stdout"))?;
    let mut stdout = BufReader::new(stdout_raw);

    // Wait for ready signal
    let mut line = String::new();
    loop {
        line.clear();
        let n = stdout.read_line(&mut line)?;
        if n == 0 { 
            let status = child.try_wait()?;
            anyhow::bail!("Subprocess exited immediately with status: {:?}", status); 
        }
        let t = line.trim();
        if t.is_empty() { continue; }
        let resp: PyResponse = serde_json::from_str(t)
            .map_err(|e| anyhow::anyhow!("Bad init JSON: {e} — raw: {t}"))?;
        if let Some(err) = resp.error {
            anyhow::bail!("Subprocess init error: {err}");
        }
        if resp.ready {
            let model = resp.model.clone();
            let device = resp.device.clone();
            return Ok((PdfScanProcess { child, stdin, stdout }, model, device));
        }
    }
    anyhow::bail!("Subprocess never sent ready signal")
}

fn spawn_redactor() -> anyhow::Result<PdfScanProcess> {
    let python = find_python();
    let mut base_path = std::env::current_dir().unwrap_or_default();
    if base_path.ends_with("src-tauri") { base_path.pop(); }
    let script = base_path.join("scripts/redact_document.py");

    eprintln!("[Axiom] Spawning redactor: {} {:?}", python, script);

    let mut child = Command::new(&python)
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let stdin      = child.stdin.take().ok_or_else(|| anyhow::anyhow!("redactor stdin"))?;
    let stdout_raw = child.stdout.take().ok_or_else(|| anyhow::anyhow!("redactor stdout"))?;
    let mut stdout = BufReader::new(stdout_raw);

    // Wait for ready signal
    let mut line = String::new();
    loop {
        line.clear();
        let n = stdout.read_line(&mut line)?;
        if n == 0 {
            let status = child.try_wait()?;
            anyhow::bail!("Redactor exited immediately: {:?}", status);
        }
        let t = line.trim();
        if t.is_empty() { continue; }
        let resp: serde_json::Value = serde_json::from_str(t)
            .map_err(|e| anyhow::anyhow!("Bad redactor init JSON: {e} raw: {t}"))?;
        if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
            if !err.is_empty() { anyhow::bail!("Redactor init error: {err}"); }
        }
        if resp.get("ready").and_then(|r| r.as_bool()).unwrap_or(false) { break; }
    }

    Ok(PdfScanProcess { child, stdin, stdout })
}

fn query_subprocess(proc: &mut PdfScanProcess, req_id: &str, pdf_path: &str) -> anyhow::Result<PyResponse> {
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
        return Ok(resp);
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
        detection_layer: if item.detection_layer.is_empty() {
            "gemma".to_string()
        } else {
            item.detection_layer.clone()
        },
        confidence: if item.confidence.is_empty() {
            "medium".to_string()
        } else {
            item.confidence.clone()
        },
        raw_value: item.raw_value.clone(),
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
        let pdf_path_arc  = Arc::clone(&state.last_pdf_path);
        let detections_arc = Arc::clone(&state.last_detections);
        let model_id_arc  = Arc::clone(&state.model_id);
        let device_arc    = Arc::clone(&state.device);
        let handle       = app.clone();
        let script_path  = state.script_path.clone();

        // Inside start_scanning in lib.rs
        thread::spawn(move || {
        // We pass a dummy string because spawn_pdf_scanner 
        // now calculates the absolute path internally
        let (proc, gemma_model_id, gemma_device) = match spawn_pdf_scanner("scripts/pdf_scanner.py") {
            Ok(t) => t,
            Err(e) => {
                let msg = format!("Scanner failed to start: {e}");
                eprintln!("[Axiom] {msg}");
                let _ = handle.emit_to("main", "paligemma_error", &msg);
                if let Ok(mut s) = flag.lock() { *s = false; }
                return;
            }
        };

            if let Ok(mut g) = py_proc_arc.lock() { *g = Some(proc); }
            if let Ok(mut r) = ready_arc.lock()   { *r = true; }
            if let Ok(mut m) = model_id_arc.lock() { *m = gemma_model_id.clone(); }
            if let Ok(mut d) = device_arc.lock()   { *d = gemma_device.clone(); }

            // The init response is already consumed in spawn_pdf_scanner.
            // We re-read model/device from a separate init_info if available.
            // (spawn_pdf_scanner returns PdfScanProcess after ready signal;
            //  model metadata is emitted via paligemma_ready payload below)
            let _ = handle.emit_to("main", "paligemma_ready", ());

            let mut req_counter: u64 = 0;
            let mut last_scanned_path: Option<String> = None;

            while *flag.lock().unwrap() {
                // Ask Preview which PDF it has open
                let pdf_path = match get_preview_pdf_path() {
                    Some(p) => p,
                    None => {
                        eprintln!("[Axiom] No supported document open — waiting…");
                        let _ = handle.emit_to("main", "preview_status",
                            serde_json::json!({"status": "waiting", "message": "Open a PDF, DOCX, XLSX, or PPTX to begin scanning"}));
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

                let (py_dets, gemma_log) = {
                    let mut guard = py_proc_arc.lock().unwrap();
                    match guard.as_mut() {
                        Some(proc) => match query_subprocess(proc, &req_id, &pdf_path) {
                            Ok(r) => (r.detections, r.gemma_log),
                            Err(e) => {
                                eprintln!("[Axiom] Scan failed: {e}");
                                let _ = handle.emit_to("main", "paligemma_error", e.to_string());
                                (Vec::new(), Vec::new())
                            }
                        },
                        None => (Vec::new(), Vec::new()),
                    }
                };

                last_scanned_path = Some(pdf_path.clone());
                let mut all_det = py_to_detections(py_dets);

                // Persist raw detections for the redactor
                if let Ok(mut d) = detections_arc.lock() {
                    *d = all_det.iter().map(|det| serde_json::json!({
                        "label":     det.pattern_name,
                        "severity":  format!("{:?}", det.severity),
                        "raw_value": det.raw_value,
                        "page":      det.page.unwrap_or(1),
                    })).collect();
                }

                // Also scan clipboard
                if let Ok(cb) = get_clipboard_text() {
                    all_det.append(&mut scan_clipboard_for_pii(&cb));
                }

                let snippet = all_det.iter()
                    .map(|d| format!("[{}] {}", d.pattern_name, d.matched_text))
                    .collect::<Vec<_>>().join(", ");

                let model_id_val = model_id_arc.lock().ok().and_then(|g| g.clone());
                let device_val   = device_arc.lock().ok().and_then(|g| g.clone());

                let payload = ScanResult {
                    detections: all_det,
                    raw_text_snippet: snippet,
                    pdf_path: Some(pdf_path),
                    gemma_log,
                    model_id: model_id_val,
                    device:   device_val,
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
        let ready    = *state.model_ready.lock().map_err(|e| e.to_string())?;
        let model_id = state.model_id.lock().map_err(|e| e.to_string())?.clone();
        let device   = state.device.lock().map_err(|e| e.to_string())?.clone();
        Ok(serde_json::json!({
            "model":       model_id.unwrap_or_else(|| "google/gemma-3-1b-it".to_string()),
            "device":      device.unwrap_or_else(|| "unknown".to_string()),
            "script_path": state.script_path,
            "ready":       ready,
        }))
    }

    /// Produce a redacted copy of the current document and open it in Preview.
    /// The original file is NEVER modified.
    #[tauri::command]
    pub async fn redact_document(state: State<'_, AppState>) -> Result<String, String> {
        // Get current path and detections
        let source_path = state.last_pdf_path.lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or("No document currently open")?;

        let detections = state.last_detections.lock()
            .map_err(|e| e.to_string())?
            .clone();

        if detections.is_empty() {
            return Err("No detections to redact — scan a document first".into());
        }

        // Spawn or reuse the redactor subprocess
        let mut guard = state.redact_process.lock().map_err(|e| e.to_string())?;
        if guard.is_none() {
            let proc = spawn_redactor().map_err(|e| e.to_string())?;
            *guard = Some(proc);
        }

        let proc = guard.as_mut().unwrap();

        // Send request
        let req = serde_json::json!({
            "id":          "redact-1",
            "source_path": source_path,
            "detections":  detections,
        });
        let mut req_str = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        req_str.push('\n');
        proc.stdin.write_all(req_str.as_bytes()).map_err(|e| e.to_string())?;
        proc.stdin.flush().map_err(|e| e.to_string())?;

        // Read response
        let mut resp_line = String::new();
        loop {
            resp_line.clear();
            let n = proc.stdout.read_line(&mut resp_line).map_err(|e| e.to_string())?;
            if n == 0 { return Err("Redactor subprocess closed unexpectedly".into()); }
            let t = resp_line.trim();
            if t.is_empty() { continue; }
            let resp: serde_json::Value = serde_json::from_str(t).map_err(|e| e.to_string())?;
            if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
                if !err.is_empty() { return Err(err.to_string()); }
            }
            let redacted_path = resp.get("redacted_path")
                .and_then(|p| p.as_str())
                .ok_or("No redacted_path in response")?
                .to_string();

            // Open in Preview via osascript
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg(format!(r#"tell application "Preview" to open POSIX file "{redacted_path}""#))
                .spawn();

            return Ok(redacted_path);
        }
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
            commands::redact_document,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Axiom");
}