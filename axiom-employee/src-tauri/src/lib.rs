// src-tauri/src/lib.rs  (Employee app)
// Axiom — PII Detection & Redaction
// SQLite removed; all persistence goes through firebase_uploader.py subprocess.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

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
    pub detection_layer: String,
    pub confidence: String,
    pub raw_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub detections:       Vec<Detection>,
    pub raw_text_snippet: String,
    pub pdf_path:         Option<String>,
    pub gemma_log:        Vec<GemmaPageLog>,
    pub model_id:         Option<String>,
    pub device:           Option<String>,
}

#[derive(Debug, Deserialize)]
struct PyDetection {
    label:    String,
    severity: String,
    redacted: String,
    #[serde(default)] raw_value:       String,
    #[serde(default)] page:            u32,
    #[serde(default)] detection_layer: String,
    #[serde(default)] confidence:      String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GemmaPageLog {
    pub page:         u32,
    pub chunks:       u32,
    pub raw_findings: u32,
    pub kept:         u32,
    pub duration_ms:  u32,
    pub status:       String,
}

#[derive(Debug, Deserialize)]
struct PyResponse {
    id:         String,
    #[serde(default)] detections: Vec<PyDetection>,
    error:      Option<String>,
    #[serde(default)] ready:      bool,
    #[serde(default)] gemma_log:  Vec<GemmaPageLog>,
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
    pub scanning:         Arc<Mutex<bool>>,
    pub py_process:       Arc<Mutex<Option<PdfScanProcess>>>,
    pub redact_process:   Arc<Mutex<Option<PdfScanProcess>>>,
    // Firebase uploader subprocess
    pub firebase_process: Arc<Mutex<Option<PdfScanProcess>>>,
    pub model_ready:      Arc<Mutex<bool>>,
    pub script_path:      String,
    pub last_pdf_path:    Arc<Mutex<Option<String>>>,
    pub last_detections:  Arc<Mutex<Vec<serde_json::Value>>>,
    pub model_id:         Arc<Mutex<Option<String>>>,
    pub device:           Arc<Mutex<Option<String>>>,
    pub scanned_paths:    Arc<Mutex<std::collections::HashSet<String>>>,
}

impl Default for AppState {
    fn default() -> Self {
        let script = std::env::var("AXIOM_PY_SCRIPT")
            .unwrap_or_else(|_| "scripts/pdf_scanner.py".to_string());
        AppState {
            scanning:         Arc::new(Mutex::new(false)),
            py_process:       Arc::new(Mutex::new(None)),
            redact_process:   Arc::new(Mutex::new(None)),
            firebase_process: Arc::new(Mutex::new(None)),
            model_ready:      Arc::new(Mutex::new(false)),
            script_path:      script,
            last_pdf_path:    Arc::new(Mutex::new(None)),
            last_detections:  Arc::new(Mutex::new(Vec::new())),
            model_id:         Arc::new(Mutex::new(None)),
            device:           Arc::new(Mutex::new(None)),
            scanned_paths:    Arc::new(Mutex::new(std::collections::HashSet::new())),
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

fn severity_label(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRITICAL",
        Severity::High     => "HIGH",
        Severity::Medium   => "MEDIUM",
        Severity::Low      => "LOW",
    }
}

fn highest_severity(dets: &[Detection]) -> Severity {
    let rank = |s: &Severity| match s {
        Severity::Critical => 3,
        Severity::High     => 2,
        Severity::Medium   => 1,
        Severity::Low      => 0,
    };
    dets.iter()
        .max_by_key(|d| rank(&d.severity))
        .map(|d| d.severity.clone())
        .unwrap_or(Severity::Low)
}

fn get_preview_pdf_path() -> Option<String> {
    const EXTS: &[&str] = &[".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt"];

    let script = r#"
        set posixPath to ""
        try
            if application "Numbers" is running then
                set posixPath to run script "tell application \"Numbers\" to get path of front document"
                if posixPath is not "" then return posixPath
            end if
        end try
        try
            if application "Preview" is running then
                set posixPath to run script "tell application \"Preview\" to get path of front document"
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
            if application "Microsoft Word" is running then
                set posixPath to run script "tell application \"Microsoft Word\" to get full name of active document"
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
            if application "Keynote" is running then
                set posixPath to run script "tell application \"Keynote\" to get POSIX path of (file of front document as alias)"
                if posixPath is not "" then return posixPath
            end if
        end try
        return posixPath
    "#;

    let script_path = std::env::temp_dir().join("axiom_detect.scpt");
    if std::fs::write(&script_path, script).is_err() { return None; }

    let output = Command::new("osascript").arg(&script_path).output().ok()?;
    let err_out = String::from_utf8_lossy(&output.stderr);
    if !err_out.trim().is_empty() {
        eprintln!("[Axiom] AppleScript stderr: {}", err_out.trim());
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() { return None; }
    let path_lower = path.to_lowercase();
    if EXTS.iter().any(|ext| path_lower.ends_with(ext)) { Some(path) } else { None }
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

fn find_python() -> String { "python3".to_string() }

fn resolve_script(rel_path: &str) -> std::path::PathBuf {
    let mut base = std::env::current_dir().unwrap_or_default();
    if base.ends_with("src-tauri") { base.pop(); }
    base.join(rel_path)
}

fn spawn_pdf_scanner(script_path: &str) -> anyhow::Result<(PdfScanProcess, Option<String>, Option<String>)> {
    let python = find_python();
    let mut child = Command::new(&python)
        .arg(resolve_script(script_path))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn()?;

    let stdin  = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let mut line = String::new();
    loop {
        line.clear();
        if stdout.read_line(&mut line)? == 0 { anyhow::bail!("Subprocess exited immediately"); }
        let t = line.trim();
        if t.is_empty() { continue; }
        let resp: PyResponse = serde_json::from_str(t)?;
        if let Some(err) = resp.error { anyhow::bail!("Subprocess init error: {err}"); }
        if resp.ready { return Ok((PdfScanProcess { child, stdin, stdout }, resp.model, resp.device)); }
    }
}

fn spawn_redactor() -> anyhow::Result<PdfScanProcess> {
    let python = find_python();
    let mut child = Command::new(&python)
        .arg(resolve_script("scripts/redact_document.py"))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn()?;

    let stdin  = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let mut line = String::new();
    loop {
        line.clear();
        if stdout.read_line(&mut line)? == 0 { anyhow::bail!("Redactor exited immediately"); }
        let t = line.trim();
        if t.is_empty() { continue; }
        let resp: serde_json::Value = serde_json::from_str(t)?;
        if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
            if !err.is_empty() { anyhow::bail!("Redactor init error: {err}"); }
        }
        if resp.get("ready").and_then(|r| r.as_bool()).unwrap_or(false) { break; }
    }

    Ok(PdfScanProcess { child, stdin, stdout })
}

/// Spawn the Firebase uploader subprocess and wait for its "ready" handshake.
fn spawn_firebase_uploader() -> anyhow::Result<PdfScanProcess> {
    let python = find_python();
    let mut child = Command::new(&python)
        .arg(resolve_script("scripts/firebase_uploader.py"))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
        .spawn()?;

    let stdin  = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let mut line = String::new();
    loop {
        line.clear();
        if stdout.read_line(&mut line)? == 0 { anyhow::bail!("Firebase uploader exited immediately"); }
        let t = line.trim();
        if t.is_empty() { continue; }
        let resp: serde_json::Value = serde_json::from_str(t)?;
        if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
            if !err.is_empty() { anyhow::bail!("Firebase uploader init error: {err}"); }
        }
        if resp.get("ready").and_then(|r| r.as_bool()).unwrap_or(false) { break; }
    }

    Ok(PdfScanProcess { child, stdin, stdout })
}

fn query_subprocess(proc: &mut PdfScanProcess, req_id: &str, pdf_path: &str) -> anyhow::Result<PyResponse> {
    let req = serde_json::json!({ "id": req_id, "pdf_path": pdf_path });
    let mut out = serde_json::to_string(&req)?;
    out.push('\n');
    proc.stdin.write_all(out.as_bytes())?;
    proc.stdin.flush()?;

    let mut resp_line = String::new();
    loop {
        resp_line.clear();
        if proc.stdout.read_line(&mut resp_line)? == 0 { anyhow::bail!("Subprocess closed stdout"); }
        let t = resp_line.trim();
        if t.is_empty() { continue; }
        let resp: PyResponse = serde_json::from_str(t)?;
        if let Some(err) = resp.error { anyhow::bail!("Subprocess error: {err}"); }
        return Ok(resp);
    }
}

/// Send a JSON request to the Firebase subprocess and read one response line.
fn firebase_send(proc: &mut PdfScanProcess, req: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let mut out = serde_json::to_string(&req)?;
    out.push('\n');
    proc.stdin.write_all(out.as_bytes())?;
    proc.stdin.flush()?;

    let mut resp_line = String::new();
    loop {
        resp_line.clear();
        if proc.stdout.read_line(&mut resp_line)? == 0 { anyhow::bail!("Firebase subprocess closed"); }
        let t = resp_line.trim();
        if t.is_empty() { continue; }
        return Ok(serde_json::from_str(t)?);
    }
}

fn py_to_detections(items: Vec<PyDetection>) -> Vec<Detection> {
    let ts = timestamp_ms();
    items.into_iter().enumerate().map(|(i, item)| Detection {
        id: format!("{}-{}-{}", item.label, i, ts),
        pattern_name: item.label.clone(),
        matched_text: item.redacted,
        severity: severity_from_str(&item.severity),
        source: DetectionSource::Pdf,
        page: if item.page > 0 { Some(item.page) } else { None },
        timestamp_ms: ts,
        detection_layer: if item.detection_layer.is_empty() { "gemma".to_string() } else { item.detection_layer },
        confidence: if item.confidence.is_empty() { "medium".to_string() } else { item.confidence },
        raw_value: item.raw_value,
    }).collect()
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

mod commands {
    use super::*;

    /// Authenticate an employee via Firebase.
    #[tauri::command]
    pub async fn login(
        state: State<'_, AppState>,
        username: String,
        pass: String,
    ) -> Result<serde_json::Value, String> {
        let mut guard = state.firebase_process.lock().map_err(|e| e.to_string())?;
        if guard.is_none() {
            let proc = spawn_firebase_uploader().map_err(|e| e.to_string())?;
            *guard = Some(proc);
        }
        let proc = guard.as_mut().unwrap();
        let req_id = format!("login-{}", timestamp_ms());
        let req = serde_json::json!({ "id": req_id, "op": "login", "username": username, "password": pass });
        let resp = firebase_send(proc, req).map_err(|e| e.to_string())?;

        if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            Ok(resp["user"].clone())
        } else {
            Err(resp["error"].as_str().unwrap_or("Login failed").to_string())
        }
    }

    #[tauri::command]
    pub async fn start_scanning(
        app: AppHandle,
        state: State<'_, AppState>,
        emp_id: String,
        emp_name: String,
        emp_dept: String,
    ) -> Result<(), String> {
        {
            let mut s = state.scanning.lock().map_err(|e| e.to_string())?;
            if *s { return Ok(()); }
            *s = true;
        }

        // Ensure Firebase subprocess is alive before spinning up the scan thread.
        {
            let mut guard = state.firebase_process.lock().map_err(|e| e.to_string())?;
            if guard.is_none() {
                let proc = spawn_firebase_uploader().map_err(|e| e.to_string())?;
                *guard = Some(proc);
            }
        }

        let flag              = Arc::clone(&state.scanning);
        let py_proc_arc       = Arc::clone(&state.py_process);
        let fb_proc_arc       = Arc::clone(&state.firebase_process);
        let ready_arc         = Arc::clone(&state.model_ready);
        let pdf_path_arc      = Arc::clone(&state.last_pdf_path);
        let dets_arc          = Arc::clone(&state.last_detections);
        let model_id_arc      = Arc::clone(&state.model_id);
        let device_arc        = Arc::clone(&state.device);
        let scanned_paths_arc = Arc::clone(&state.scanned_paths);
        let handle            = app.clone();

        thread::spawn(move || {
            // Spawn Gemma scanner
            let (proc, gemma_model_id, gemma_device) = match spawn_pdf_scanner("scripts/pdf_scanner.py") {
                Ok(t) => t,
                Err(e) => {
                    let _ = handle.emit("paligemma_error", e.to_string());
                    if let Ok(mut s) = flag.lock() { *s = false; }
                    return;
                }
            };

            if let Ok(mut g) = py_proc_arc.lock()  { *g = Some(proc); }
            if let Ok(mut r) = ready_arc.lock()     { *r = true; }
            if let Ok(mut m) = model_id_arc.lock()  { *m = gemma_model_id; }
            if let Ok(mut d) = device_arc.lock()    { *d = gemma_device; }

            let model_id_val = model_id_arc.lock().ok().and_then(|g| g.clone());
            let device_val   = device_arc.lock().ok().and_then(|g| g.clone());
            let _ = handle.emit("paligemma_ready", serde_json::json!({
                "model_id": model_id_val, "device": device_val,
            }));

            let mut req_counter: u64 = 0;

            while *flag.lock().unwrap() {
                let pdf_path = match get_preview_pdf_path() {
                    Some(p) if !p.is_empty() && !p.contains("_redacted") => p,
                    _ => { thread::sleep(Duration::from_secs(2)); continue; }
                };

                {
                    let mut cache = scanned_paths_arc.lock().unwrap();
                    if cache.contains(&pdf_path) {
                        thread::sleep(Duration::from_secs(3));
                        continue;
                    }
                    cache.insert(pdf_path.clone());
                }

                let file_name = pdf_path.split('/').last().unwrap_or(&pdf_path).to_string();
                let _ = handle.emit("file_detected", serde_json::json!({
                    "path": pdf_path, "file_name": file_name,
                }));
                let _ = handle.emit("preview_status", serde_json::json!({
                    "message": format!("Scanning: {}", file_name),
                }));

                if let Ok(mut p) = pdf_path_arc.lock() { *p = Some(pdf_path.clone()); }

                req_counter += 1;
                let req_id = req_counter.to_string();

                let (py_dets, gemma_log) = {
                    let mut guard = py_proc_arc.lock().unwrap();
                    match guard.as_mut() {
                        Some(proc) => match query_subprocess(proc, &req_id, &pdf_path) {
                            Ok(r) => (r.detections, r.gemma_log),
                            Err(e) => {
                                let _ = handle.emit("paligemma_error", e.to_string());
                                (Vec::new(), Vec::new())
                            }
                        },
                        None => (Vec::new(), Vec::new()),
                    }
                };

                let mut all_det = py_to_detections(py_dets);
                if let Ok(cb) = get_clipboard_text() {
                    all_det.append(&mut scan_clipboard_for_pii(&cb));
                }

                // Cache raw detections for redaction
                if let Ok(mut d) = dets_arc.lock() {
                    *d = all_det.iter().map(|det| serde_json::json!({
                        "label":     det.pattern_name,
                        "severity":  severity_label(&det.severity),
                        "raw_value": det.raw_value,
                        "page":      det.page.unwrap_or(1),
                    })).collect();
                }

                // Emit scan result to frontend
                let snippet = all_det.iter()
                    .map(|d| format!("[{}] {}", d.pattern_name, d.matched_text))
                    .collect::<Vec<_>>().join(", ");
                let payload = ScanResult {
                    detections: all_det.clone(),
                    raw_text_snippet: snippet,
                    pdf_path: Some(pdf_path.clone()),
                    gemma_log,
                    model_id: model_id_arc.lock().ok().and_then(|g| g.clone()),
                    device:   device_arc.lock().ok().and_then(|g| g.clone()),
                };
                let _ = handle.emit("scan_result", &payload);

                // Persist activity log to Firebase (fire-and-forget)
                if !all_det.is_empty() {
                    let top_sev  = highest_severity(&all_det);
                    let pii_types: Vec<String> = {
                        let mut seen = std::collections::HashSet::new();
                        all_det.iter().filter_map(|d| {
                            if seen.insert(d.pattern_name.clone()) { Some(d.pattern_name.clone()) } else { None }
                        }).collect()
                    };

                    let log_id  = format!("log_{}", timestamp_ms());
                    let fb_req  = serde_json::json!({
                        "id":   log_id.clone(),
                        "op":   "log_activity",
                        "data": {
                            "id":               log_id,
                            "employee_id":      emp_id,
                            "employee_name":    emp_name,
                            "department":       emp_dept,
                            "file_name":        file_name,
                            "detection_count":  all_det.len(),
                            "highest_severity": severity_label(&top_sev),
                            "timestamp":        timestamp_ms(),
                            "redacted":         false,
                            "pii_types":        pii_types,
                        }
                    });

                    let mut guard = fb_proc_arc.lock().unwrap();
                    if let Some(proc) = guard.as_mut() {
                        let _ = firebase_send(proc, fb_req);
                    }
                }

                thread::sleep(Duration::from_secs(3));
            }
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
            }
        }
        *state.model_ready.lock().map_err(|e| e.to_string())? = false;
        Ok(())
    }

    #[tauri::command]
    pub async fn scan_manual_file(
        app: AppHandle,
        state: State<'_, AppState>,
        path: String,
    ) -> Result<(), String> {
        let req_id = format!("manual-{}", timestamp_ms());

        let (py_dets, gemma_log) = {
            let mut guard = state.py_process.lock().map_err(|e| e.to_string())?;
            let proc = guard.as_mut().ok_or("Pipeline not running. Click 'Run Detection Alg' first.")?;
            match query_subprocess(proc, &req_id, &path) {
                Ok(r) => (r.detections, r.gemma_log),
                Err(e) => return Err(e.to_string()),
            }
        };

        let all_det = py_to_detections(py_dets);

        if let Ok(mut d) = state.last_detections.lock() {
            *d = all_det.iter().map(|det| serde_json::json!({
                "label":     det.pattern_name,
                "severity":  severity_label(&det.severity),
                "raw_value": det.raw_value,
                "page":      det.page.unwrap_or(1),
            })).collect();
        }

        if let Ok(mut p) = state.last_pdf_path.lock() { *p = Some(path.clone()); }
        if let Ok(mut cache) = state.scanned_paths.lock() { cache.insert(path.clone()); }

        let snippet = all_det.iter()
            .map(|d| format!("[{}] {}", d.pattern_name, d.matched_text))
            .collect::<Vec<_>>().join(", ");
        let payload = ScanResult {
            detections: all_det,
            raw_text_snippet: snippet,
            pdf_path: Some(path),
            gemma_log,
            model_id: state.model_id.lock().ok().and_then(|g| g.clone()),
            device:   state.device.lock().ok().and_then(|g| g.clone()),
        };

        let _ = app.emit("scan_result", &payload);
        Ok(())
    }

    #[tauri::command]
    pub async fn scan_clipboard_now() -> Result<Vec<Detection>, String> {
        let text = get_clipboard_text().map_err(|e| e.to_string())?;
        Ok(scan_clipboard_for_pii(&text))
    }

    #[tauri::command]
    pub async fn open_in_preview(path: String) -> Result<(), String> {
        let ext = std::path::Path::new(&path)
            .extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if ext == "pdf" {
            Command::new("osascript")
                .arg("-e").arg(format!(r#"tell application "Preview" to open POSIX file "{path}""#))
                .spawn().map_err(|e| e.to_string())?;
        } else {
            Command::new("open").arg(&path).spawn().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    #[tauri::command]
    pub async fn save_redacted_document(temp_path: String, dest_path: String) -> Result<(), String> {
        std::fs::copy(&temp_path, &dest_path).map_err(|e| e.to_string())?;
        Ok(())
    }



    /// Mark an activity log entry as redacted in Firestore
    #[tauri::command]
    pub fn mark_activity_redacted(state: State<'_, AppState'>, log_id: String) -> Result<(), String> {
        let mut guard = state.firebase_process.lock().map_err(|e| e.to_string())?;
        if guard.is_none() {
            let proc = spawn_firebase_uploader().map_err(|e| e.to_string())?;
            *guard = Some(proc);
        }
        let proc = guard.as_mut().unwrap();
        let req = serde_json::json!({
            "id":     format!("mr-{}", timestamp_ms()),
            "op":     "mark_redacted",
            "doc_id": log_id,
        });
        firebase_send(proc, req).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Save the employee's file log history to ~/.axiom_logs.json
    #[tauri::command]
    pub fn save_file_logs(logs: serde_json::Value) -> Result<(), String> {
        let path = dirs::home_dir()
            .ok_or("Cannot find home directory")?
            .join(".axiom_logs.json");
        let json = serde_json::to_string(&logs).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Load the employee's file log history from ~/.axiom_logs.json
    #[tauri::command]
    pub fn load_file_logs() -> Result<serde_json::Value, String> {
        let path = dirs::home_dir()
            .ok_or("Cannot find home directory")?
            .join(".axiom_logs.json");
        if !path.exists() {
            return Ok(serde_json::Value::Array(vec![]));
        }
        let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        serde_json::from_str(&json).map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub async fn redact_document(
        state: State<'_, AppState>,
        source_path: String,
        detections: Vec<serde_json::Value>,
    ) -> Result<String, String> {
        if detections.is_empty() { return Err("No detections to redact".into()); }
        if source_path.is_empty() { return Err("No source path provided".into()); }

        let mut guard = state.redact_process.lock().map_err(|e| e.to_string())?;
        if guard.is_none() {
            let proc = spawn_redactor().map_err(|e| e.to_string())?;
            *guard = Some(proc);
        }

        let proc   = guard.as_mut().unwrap();
        let req_id = format!("redact-{}", timestamp_ms());
        let req    = serde_json::json!({ "id": req_id, "source_path": source_path, "detections": detections });
        let mut req_str = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        req_str.push('\n');
        proc.stdin.write_all(req_str.as_bytes()).map_err(|e| e.to_string())?;
        proc.stdin.flush().map_err(|e| e.to_string())?;

        let mut resp_line = String::new();
        loop {
            resp_line.clear();
            if proc.stdout.read_line(&mut resp_line).map_err(|e| e.to_string())? == 0 {
                return Err("Redactor subprocess closed".into());
            }
            let t = resp_line.trim();
            if t.is_empty() { continue; }
            let resp: serde_json::Value = serde_json::from_str(t).map_err(|e| e.to_string())?;
            if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
                if !err.is_empty() { return Err(err.to_string()); }
            }
            return Ok(resp["redacted_path"].as_str().ok_or("No redacted_path")?.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::login,
            commands::start_scanning,
            commands::stop_scanning,
            commands::scan_clipboard_now,
            commands::scan_manual_file,
            commands::redact_document,
            commands::open_in_preview,
            commands::save_redacted_document,
            commands::save_file_logs,
            commands::load_file_logs,
            commands::mark_activity_redacted,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Axiom");
}