// src-tauri/src/lib.rs
// Axiom — Local-first Data Leakage Prevention
//
// Detection pipeline (v2):
//   1. Capture screenshot with xcap
//   2. Base64-encode the frame
//   3. POST to local Ollama (http://localhost:11434) running a vision model
//      (default: moondream, but llava / llava-phi3 / bakllava also work)
//   4. Parse JSON response → Vec<Detection> with pixel-level bounding boxes
//   5. Emit to overlay window → canvas draws highlight boxes
//
// No OCR library, no regex, no cloud. 100% local.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use xcap::Monitor;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundingBox {
    pub x: f32, pub y: f32, pub width: f32, pub height: f32,
    pub screen_width: u32, pub screen_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource { Screen, Clipboard }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: String,
    pub pattern_name: String,
    pub matched_text: String,
    pub severity: Severity,
    pub source: DetectionSource,
    pub bbox: Option<BoundingBox>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub detections: Vec<Detection>,
    pub raw_text_snippet: String,
}

// The VLM is asked to return an array of these objects.
#[derive(Debug, Deserialize)]
struct VlmDetection {
    label: String,          // e.g. "SSN", "CREDIT_CARD", "PASSWORD"
    severity: String,       // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    redacted: String,       // partially-masked value shown in UI
    // Normalised 0-1 coordinates relative to the image
    x: f32, y: f32,
    w: f32, h: f32,
}

pub struct AppState {
    pub scanning: Arc<Mutex<bool>>,
    pub overlay_active: Arc<Mutex<bool>>,
    /// Ollama model to use for vision inference.
    /// Override via the "AXIOM_MODEL" environment variable (default: moondream).
    pub model: String,
    /// Ollama base URL (default: http://localhost:11434)
    pub ollama_url: String,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            scanning: Arc::new(Mutex::new(false)),
            overlay_active: Arc::new(Mutex::new(false)),
            model: std::env::var("AXIOM_MODEL")
                .unwrap_or_else(|_| "moondream".to_string()),
            ollama_url: std::env::var("AXIOM_OLLAMA_URL")
                .unwrap_or_else(|_| "http://localhost:11434".to_string()),
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

fn get_clipboard_text() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use arboard::Clipboard;
    Ok(Clipboard::new()?.get_text().unwrap_or_default())
}

fn scan_clipboard_for_pii(text: &str) -> Vec<Detection> {
    use lazy_static::lazy_static;
    use regex::Regex;

    lazy_static! {
        static ref PATTERNS: Vec<(&'static str, &'static str, Regex)> = vec![
            ("SSN",            "CRITICAL", Regex::new(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b").unwrap()),
            ("CREDIT_CARD",    "CRITICAL", Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap()),
            ("EMAIL",          "MEDIUM",   Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap()),
            ("AWS_ACCESS_KEY", "CRITICAL", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
            ("JWT_TOKEN",      "CRITICAL", Regex::new(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b").unwrap()),
            ("PASSWORD",       "CRITICAL", Regex::new(r"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*\S+").unwrap()),
            ("PRIVATE_KEY",    "CRITICAL", Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap()),
            ("PHONE_US",       "MEDIUM",   Regex::new(r"\b(?:\+1[\s\-]?)?\(?[0-9]{3}\)?[\s\-]?[0-9]{3}[\s\-]?[0-9]{4}\b").unwrap()),
        ];
    }

    let ts = timestamp_ms();
    PATTERNS.iter().flat_map(|(name, sev, re)| {
        re.find_iter(text).map(|m| {
            let raw = m.as_str();
            let redacted = if raw.len() <= 4 {
                "*".repeat(raw.len())
            } else {
                format!("{}****", &raw[..4])
            };
            Detection {
                id: format!("{}-{}-{}", name, m.start(), ts),
                pattern_name: name.to_string(),
                matched_text: redacted,
                severity: severity_from_str(sev),
                source: DetectionSource::Clipboard,
                bbox: None,
                timestamp_ms: ts,
            }
        }).collect::<Vec<_>>()
    }).collect()
}

// ---------------------------------------------------------------------------
// VLM inference via Ollama
// ---------------------------------------------------------------------------

/// System prompt that instructs the VLM to return structured JSON.
const SYSTEM_PROMPT: &str = r#"You are a data-loss prevention AI. Your ONLY job is to identify personally identifiable information (PII) and secrets that are VISIBLE on the screenshot provided.

Return ONLY a JSON array (no markdown, no explanation). Each element must follow this exact schema:
{
  "label": "<type>",       // SSN | CREDIT_CARD | EMAIL | PHONE | AWS_KEY | PASSWORD | PRIVATE_KEY | JWT | API_KEY | CORP_SECRET | OTHER_PII
  "severity": "<level>",   // CRITICAL | HIGH | MEDIUM | LOW
  "redacted": "<masked>",  // First 4 chars + **** — never include the full value
  "x": <float 0-1>,        // left edge of the sensitive text, normalised to image width
  "y": <float 0-1>,        // top edge, normalised to image height
  "w": <float 0-1>,        // width, normalised
  "h": <float 0-1>         // height, normalised
}

If nothing sensitive is visible, return an empty array: []
Do NOT include any text outside the JSON array."#;

/// Calls Ollama's /api/generate (or /api/chat) with the screenshot image.
/// Returns raw model output string.
fn call_ollama(
    base_url: &str,
    model: &str,
    image_b64: &str,
) -> anyhow::Result<String> {
    // Use the blocking ureq client (no async needed inside the scan thread)
    let url = format!("{}/api/generate", base_url.trim_end_matches('/'));

    let body = serde_json::json!({
        "model": model,
        "prompt": "Analyse this screenshot for sensitive data and return JSON.",
        "system": SYSTEM_PROMPT,
        "images": [image_b64],
        "stream": false,
        "options": {
            "temperature": 0.0,
            "num_predict": 1024,
        }
    });

    let response = ureq::post(&url)
        .timeout(Duration::from_secs(60))
        .send_json(&body)?;

    let json: serde_json::Value = response.into_json()?;
    Ok(json["response"].as_str().unwrap_or("[]").to_string())
}

/// Parse VLM output string → Vec<Detection> with bounding boxes.
fn parse_vlm_response(
    raw: &str,
    screen_width: u32,
    screen_height: u32,
) -> Vec<Detection> {
    // Strip any markdown fences the model may have added
    let cleaned = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    // Find the JSON array
    let start = cleaned.find('[').unwrap_or(0);
    let end = cleaned.rfind(']').map(|i| i + 1).unwrap_or(cleaned.len());
    let json_str = &cleaned[start..end];

    let items: Vec<VlmDetection> = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[Axiom VLM] JSON parse error: {e}\nRaw output:\n{raw}");
            return Vec::new();
        }
    };

    let ts = timestamp_ms();
    items.into_iter().enumerate().map(|(i, item)| {
        // Convert normalised 0-1 coords → pixel coords
        let px = item.x * screen_width as f32;
        let py = item.y * screen_height as f32;
        let pw = item.w * screen_width as f32;
        let ph = item.h * screen_height as f32;

        Detection {
            id: format!("{}-{}-{}", item.label, i, ts),
            pattern_name: item.label,
            matched_text: item.redacted,
            severity: severity_from_str(&item.severity),
            source: DetectionSource::Screen,
            bbox: Some(BoundingBox {
                x: px, y: py, width: pw, height: ph,
                screen_width, screen_height,
            }),
            timestamp_ms: ts,
        }
    }).collect()
}

// ---------------------------------------------------------------------------
// Overlay window management
// ---------------------------------------------------------------------------

fn get_or_create_overlay(app: &AppHandle) -> anyhow::Result<tauri::WebviewWindow> {
    if let Some(w) = app.get_webview_window("overlay") {
        return Ok(w);
    }

    let (screen_w, screen_h) = app
        .primary_monitor()
        .ok()
        .flatten()
        .map(|m| { let s = m.size(); (s.width, s.height) })
        .unwrap_or((1920, 1080));

    let overlay = WebviewWindowBuilder::new(app, "overlay", WebviewUrl::App("/overlay".into()))
        .title("Axiom Overlay")
        .transparent(true)
        .decorations(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .resizable(false)
        .inner_size(screen_w as f64, screen_h as f64)
        .position(0.0, 0.0)
        .focused(false)
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

        let flag       = Arc::clone(&state.scanning);
        let handle     = app.clone();
        let model      = state.model.clone();
        let ollama_url = state.ollama_url.clone();

        thread::spawn(move || {
            eprintln!("[Axiom] Starting VLM scan loop — model={model} url={ollama_url}");

            while *flag.lock().unwrap() {
                let monitors = match Monitor::all() {
                    Ok(m) => m,
                    Err(e) => { eprintln!("[Axiom] monitors: {e}"); thread::sleep(Duration::from_secs(2)); continue; }
                };

                let mut all_det: Vec<Detection> = Vec::new();

                for mon in &monitors {
                    let sw = mon.width().unwrap_or(1920);
                    let sh = mon.height().unwrap_or(1080);

                    // 1. Capture
                    let rgba = match mon.capture_image() {
                        Ok(i) => i,
                        Err(e) => { eprintln!("[Axiom] capture: {e}"); continue; }
                    };

                    // 2. Encode as PNG → base64
                    let img = image::DynamicImage::ImageRgba8(rgba);
                    let mut png_bytes: Vec<u8> = Vec::new();
                    if let Err(e) = img.write_to(
                        &mut std::io::Cursor::new(&mut png_bytes),
                        image::ImageFormat::Png,
                    ) {
                        eprintln!("[Axiom] PNG encode: {e}"); continue;
                    }
                    let b64 = B64.encode(&png_bytes);

                    // 3. Call VLM
                    eprintln!("[Axiom] Sending {:.1}KB frame to VLM ({model})…", png_bytes.len() as f32 / 1024.0);
                    let raw_response = match call_ollama(&ollama_url, &model, &b64) {
                        Ok(r) => r,
                        Err(e) => { eprintln!("[Axiom] VLM call failed: {e}"); continue; }
                    };
                    eprintln!("[Axiom] VLM raw response: {}", &raw_response.chars().take(400).collect::<String>());

                    // 4. Parse → detections
                    let mut hits = parse_vlm_response(&raw_response, sw, sh);
                    eprintln!("[Axiom] Parsed {} detection(s) from VLM", hits.len());
                    all_det.append(&mut hits);
                }

                // 5. Clipboard (regex fallback — fast, no image needed)
                if let Ok(cb) = get_clipboard_text() {
                    all_det.append(&mut scan_clipboard_for_pii(&cb));
                }

                if !all_det.is_empty() {
                    let snippet: String = all_det.iter()
                        .map(|d| format!("[{}] {}", d.pattern_name, d.matched_text))
                        .collect::<Vec<_>>()
                        .join(", ");

                    let payload = ScanResult { detections: all_det, raw_text_snippet: snippet };
                    eprintln!("[Axiom] Emitting {} detection(s)", payload.detections.len());
                    let _ = handle.emit_to("main", "scan_result", &payload);
                    let _ = handle.emit_to("overlay", "scan_result", &payload);
                }

                // VLM inference is slower; poll every 3 seconds
                thread::sleep(Duration::from_secs(3));
            }

            let _ = handle.emit_to("overlay", "clear_overlay", ());
        });

        Ok(())
    }

    #[tauri::command]
    pub async fn stop_scanning(state: State<'_, AppState>) -> Result<(), String> {
        *state.scanning.lock().map_err(|e| e.to_string())? = false;
        Ok(())
    }

    #[tauri::command]
    pub async fn set_overlay_visible(
        app: AppHandle,
        state: State<'_, AppState>,
        visible: bool,
    ) -> Result<(), String> {
        *state.overlay_active.lock().map_err(|e| e.to_string())? = visible;
        if visible {
            let overlay = get_or_create_overlay(&app).map_err(|e| e.to_string())?;
            overlay.show().map_err(|e| e.to_string())?;
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

    /// Returns the active Ollama model name and endpoint for display in the UI.
    #[tauri::command]
    pub async fn get_model_info(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({
            "model": state.model,
            "ollama_url": state.ollama_url,
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
            commands::get_model_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Axiom");
}