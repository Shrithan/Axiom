// src-tauri/src/lib.rs  (Admin app)
// Axiom Admin Console
// SQLite removed; all reads/writes go through firebase_uploader.py subprocess.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use tauri::State;

// ─── DATA STRUCTURES ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Employee {
    pub id: String,
    pub name: String,
    pub email: String,       // stores the username from Firestore
    pub department: String,
    pub status: String,
    pub last_seen: u64,
    pub total_scans: u32,
    pub total_detections: u32,
    pub risk_score: u8,
    pub avatar_initials: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityLog {
    pub id: String,
    pub employee_id: String,
    pub employee_name: String,
    pub department: String,
    pub file_name: String,
    pub detection_count: u32,
    pub highest_severity: String,
    pub timestamp: u64,
    pub redacted: bool,
    pub pii_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub severity: String,
    pub enabled: bool,
    pub detection_count: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmployeePatch {
    pub status: Option<String>,
    pub department: Option<String>,
}

// ─── FIREBASE SUBPROCESS ──────────────────────────────────────

pub struct FirebaseProcess {
    pub child:  Child,
    pub stdin:  ChildStdin,
    pub stdout: BufReader<ChildStdout>,
}

// ─── STATE MANAGEMENT ─────────────────────────────────────────

pub struct AdminState {
    pub rules:    Mutex<Vec<PolicyRule>>,
    pub firebase: Mutex<Option<FirebaseProcess>>,
}

impl Default for AdminState {
    fn default() -> Self {
        Self {
            rules:    Mutex::new(default_rules()),
            firebase: Mutex::new(None),
        }
    }
}

// ─── FIREBASE HELPERS ─────────────────────────────────────────

fn resolve_script(rel_path: &str) -> std::path::PathBuf {
    let mut base = std::env::current_dir().unwrap_or_default();
    if base.ends_with("src-tauri") { base.pop(); }
    base.join(rel_path)
}

fn spawn_firebase() -> anyhow::Result<FirebaseProcess> {
    let mut child = Command::new("python3")
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
            if !err.is_empty() { anyhow::bail!("Firebase init error: {err}"); }
        }
        if resp.get("ready").and_then(|r| r.as_bool()).unwrap_or(false) { break; }
    }

    Ok(FirebaseProcess { child, stdin, stdout })
}

/// Ensure the Firebase subprocess is running, then send a request and read one response.
fn fb_call(state: &AdminState, req: serde_json::Value) -> Result<serde_json::Value, String> {
    let mut guard = state.firebase.lock().map_err(|e| e.to_string())?;
    if guard.is_none() {
        let proc = spawn_firebase().map_err(|e| e.to_string())?;
        *guard = Some(proc);
    }
    let proc = guard.as_mut().unwrap();

    let mut out = serde_json::to_string(&req).map_err(|e| e.to_string())?;
    out.push('\n');
    proc.stdin.write_all(out.as_bytes()).map_err(|e| e.to_string())?;
    proc.stdin.flush().map_err(|e| e.to_string())?;

    let mut resp_line = String::new();
    loop {
        resp_line.clear();
        if proc.stdout.read_line(&mut resp_line).map_err(|e| e.to_string())? == 0 {
            return Err("Firebase subprocess closed unexpectedly".into());
        }
        let t = resp_line.trim();
        if t.is_empty() { continue; }
        return serde_json::from_str(t).map_err(|e| e.to_string());
    }
}

fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─── Firestore doc → Employee ──────────────────────────────────

fn doc_to_employee(v: &serde_json::Value) -> Employee {
    let s = |key: &str| v[key].as_str().unwrap_or("").to_string();
    let u = |key: &str| v[key].as_u64().unwrap_or(0);
    Employee {
        id:               s("id"),
        name:             s("name"),
        email:            s("username"),   // username stored as email in frontend
        department:       s("department"),
        status:           s("status"),
        last_seen:        u("last_seen"),
        total_scans:      u("total_scans") as u32,
        total_detections: u("total_detections") as u32,
        risk_score:       u("risk_score") as u8,
        avatar_initials:  s("avatar_initials"),
    }
}

// ─── Firestore doc → ActivityLog ──────────────────────────────

fn doc_to_activity(v: &serde_json::Value) -> ActivityLog {
    let s = |key: &str| v[key].as_str().unwrap_or("").to_string();
    let pii_types: Vec<String> = v["pii_types"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    ActivityLog {
        id:               s("id"),
        employee_id:      s("employee_id"),
        employee_name:    s("employee_name"),
        department:       s("department"),
        file_name:        s("file_name"),
        detection_count:  v["detection_count"].as_u64().unwrap_or(0) as u32,
        highest_severity: s("highest_severity"),
        timestamp:        v["timestamp"].as_u64().unwrap_or(0),
        redacted:         v["redacted"].as_bool().unwrap_or(false),
        pii_types,
    }
}

// ─── COMMANDS ─────────────────────────────────────────────────

pub mod commands {
    use super::*;
    use tauri::State;

    #[tauri::command]
    pub fn list_employees(state: State<'_, AdminState>) -> Vec<Employee> {
        let req = serde_json::json!({ "id": format!("le-{}", timestamp_ms()), "op": "list_employees" });
        match fb_call(&state, req) {
            Ok(resp) => resp["employees"].as_array()
                .map(|arr| arr.iter().map(doc_to_employee).collect())
                .unwrap_or_default(),
            Err(e) => { eprintln!("[Admin] list_employees error: {e}"); Vec::new() }
        }
    }

    #[tauri::command]
    pub fn add_employee(
        state: State<'_, AdminState>,
        name: String, username: String, pass: String, dept: String,
    ) -> Result<(), String> {
        let id       = format!("e_{}", timestamp_ms());
        let initials = name.split_whitespace()
            .filter_map(|w| w.chars().next())
            .take(2)
            .collect::<String>()
            .to_uppercase();

        let req = serde_json::json!({
            "id":  format!("ae-{}", timestamp_ms()),
            "op":  "add_employee",
            "data": {
                "id": id, "name": name, "username": username, "password": pass,
                "department": dept, "status": "active",
                "last_seen": 0, "total_scans": 0, "total_detections": 0,
                "risk_score": 0, "avatar_initials": initials,
            }
        });

        let resp = fb_call(&state, req)?;
        if resp["ok"].as_bool().unwrap_or(false) {
            Ok(())
        } else {
            Err(resp["error"].as_str().unwrap_or("Add employee failed").to_string())
        }
    }

    #[tauri::command]
    pub fn list_activity(
        state: State<'_, AdminState>,
        employee_id: Option<String>,
    ) -> Vec<ActivityLog> {
        let req = serde_json::json!({
            "id":          format!("la-{}", timestamp_ms()),
            "op":          "list_activity",
            "employee_id": employee_id,
        });
        match fb_call(&state, req) {
            Ok(resp) => resp["logs"].as_array()
                .map(|arr| arr.iter().map(doc_to_activity).collect())
                .unwrap_or_default(),
            Err(e) => { eprintln!("[Admin] list_activity error: {e}"); Vec::new() }
        }
    }

    #[tauri::command]
    pub fn export_activity_csv(
        state: State<'_, AdminState>,
        employee_id: Option<String>,
    ) -> String {
        let logs = list_activity(state, employee_id);
        let mut csv = String::from(
            "id,employee_id,employee_name,department,file_name,\
             detection_count,highest_severity,timestamp,redacted,pii_types\n",
        );
        for l in logs {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                l.id, l.employee_id, l.employee_name, l.department, l.file_name,
                l.detection_count, l.highest_severity, l.timestamp, l.redacted,
                l.pii_types.join(";"),
            ));
        }
        csv
    }

    #[tauri::command]
    pub fn list_rules(state: State<'_, AdminState>) -> Vec<PolicyRule> {
        state.rules.lock().unwrap().clone()
    }

    #[tauri::command]
    pub fn toggle_rule(id: String, state: State<'_, AdminState>) -> Result<PolicyRule, String> {
        let mut rules = state.rules.lock().unwrap();
        let rule = rules.iter_mut().find(|r| r.id == id)
            .ok_or_else(|| format!("Rule {} not found", id))?;
        rule.enabled = !rule.enabled;
        Ok(rule.clone())
    }

    #[tauri::command]
    pub fn set_rule_severity(
        id: String, severity: String, state: State<'_, AdminState>,
    ) -> Result<PolicyRule, String> {
        let valid = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
        if !valid.contains(&severity.as_str()) {
            return Err(format!("Invalid severity: {}", severity));
        }
        let mut rules = state.rules.lock().unwrap();
        let rule = rules.iter_mut().find(|r| r.id == id)
            .ok_or_else(|| format!("Rule {} not found", id))?;
        rule.severity = severity;
        Ok(rule.clone())
    }

    #[tauri::command]
    pub fn update_employee(
        state: State<'_, AdminState>,
        id: String,
        patch: EmployeePatch,
    ) -> Result<Employee, String> {
        let mut patch_map = serde_json::Map::new();
        if let Some(s) = patch.status     { patch_map.insert("status".into(),     serde_json::Value::String(s)); }
        if let Some(d) = patch.department { patch_map.insert("department".into(), serde_json::Value::String(d)); }

        let req = serde_json::json!({
            "id":      format!("ue-{}", timestamp_ms()),
            "op":      "update_employee",
            "doc_id":  id,
            "patch":   patch_map,
        });
        let resp = fb_call(&state, req)?;
        if resp["ok"].as_bool().unwrap_or(false) {
            Ok(doc_to_employee(&resp["employee"]))
        } else {
            Err(resp["error"].as_str().unwrap_or("Update failed").to_string())
        }
    }

    #[tauri::command]
    pub fn remove_employee(
        state: State<'_, AdminState>,
        id: String,
    ) -> Result<(), String> {
        let req = serde_json::json!({
            "id":     format!("re-{}", timestamp_ms()),
            "op":     "remove_employee",
            "doc_id": id,
        });
        let resp = fb_call(&state, req)?;
        if resp["ok"].as_bool().unwrap_or(false) { Ok(()) }
        else { Err(resp["error"].as_str().unwrap_or("Remove failed").to_string()) }
    }

    /// Policy rules are kept in-memory in the admin process (not persisted to Firestore).
    /// Extend this to add a "rules" collection if persistence is needed.
    #[tauri::command]
    pub fn add_rule(
        rule: PolicyRule, state: State<'_, AdminState>,
    ) -> Result<PolicyRule, String> {
        let mut rules = state.rules.lock().unwrap();
        rules.push(rule.clone());
        Ok(rule)
    }

    #[tauri::command]
    pub fn delete_rule(id: String, state: State<'_, AdminState>) -> Result<(), String> {
        let mut rules = state.rules.lock().unwrap();
        rules.retain(|r| r.id != id);
        Ok(())
    }
}

// ─── RUNTIME CONFIGURATION ────────────────────────────────────

pub fn run() {
    tauri::Builder::default()
        .manage(AdminState::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::list_employees,
            commands::add_employee,
            commands::update_employee,
            commands::remove_employee,
            commands::list_activity,
            commands::export_activity_csv,
            commands::list_rules,
            commands::toggle_rule,
            commands::set_rule_severity,
            commands::add_rule,
            commands::delete_rule,
        ])
        .run(tauri::generate_context!())
        .expect("error running Axiom Admin");
}

fn default_rules() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            id: "r1".into(), name: "Social Security Number".into(),
            category: "PII".into(), pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
            severity: "CRITICAL".into(), enabled: true, detection_count: 0,
            description: "Matches US SSN format XXX-XX-XXXX".into(),
        },
        PolicyRule {
            id: "r2".into(), name: "Credit Card Number".into(),
            category: "FINANCIAL".into(),
            pattern: r"\b(?:4[0-9]{12}|5[1-5][0-9]{14})\b".into(),
            severity: "CRITICAL".into(), enabled: true, detection_count: 0,
            description: "Matches Visa and Mastercard patterns".into(),
        },
    ]
}