//! Retained admin prototype boundary. Enterprise management is deferred.
//! No cloud subprocess, credentials, employee fixture data or unenforced policies.
const DEFERRED: &str = "Enterprise management is deferred. Configure V1 policies in employee Local Rules.";

#[tauri::command]
fn list_employees() -> Result<Vec<serde_json::Value>, String> {
    Err(DEFERRED.into())
}

#[tauri::command]
fn list_activity(employee_id: Option<String>) -> Result<Vec<serde_json::Value>, String> {
    let _ = employee_id;
    Err(DEFERRED.into())
}

#[tauri::command]
fn list_rules() -> Result<Vec<serde_json::Value>, String> {
    Err(DEFERRED.into())
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![list_employees, list_activity, list_rules])
        .run(tauri::generate_context!())
        .expect("error running Axiom Admin prototype");
}
