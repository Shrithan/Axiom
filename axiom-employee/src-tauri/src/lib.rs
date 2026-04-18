//! Local privacy engine and macOS background runtime.
use std::io::Write;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;
mod background;
#[cfg(target_os = "macos")]
mod browser;
mod engine;

#[tauri::command]
async fn agent_request(
    app: tauri::AppHandle,
    request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let result = engine::execute(&app, &request)?;
        if request["op"] == "save_rules" {
            app.state::<std::sync::Arc<background::Agent>>()
                .policy_changed();
        }
        Ok(result)
    })
    .await
    .map_err(|_| "Local worker failed")?
}

#[tauri::command]
async fn save_protected(
    app: tauri::AppHandle,
    mut request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    request["op"] = serde_json::json!("export");
    let output = agent_request(app.clone(), request).await?;
    tauri::async_runtime::spawn_blocking(move || {
        let extension = output["extension"].as_str().ok_or("Invalid export")?;
        let text = output["text"].as_str().ok_or("Invalid export")?;
        let selection = app
            .dialog()
            .file()
            .set_file_name(format!("document.protected.{extension}"))
            .add_filter("Protected output", &[extension])
            .blocking_save_file();
        let Some(selection) = selection else {
            return Ok(serde_json::json!({"saved": false, "warnings": []}));
        };
        let path = selection.as_path().ok_or("Unsupported save location")?;
        // A derivative never overwrites the original (or any existing file).
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| "Choose a new filename; existing files are never overwritten")?;
        file.write_all(text.as_bytes())
            .map_err(|_| "Unable to save protected output")?;
        Ok(serde_json::json!({"saved": true, "warnings": output["warnings"]}))
    })
    .await
    .map_err(|_| "Save operation failed")?
}

#[tauri::command]
fn agent_status(
    app: tauri::AppHandle,
    agent: tauri::State<'_, std::sync::Arc<background::Agent>>,
) -> serde_json::Value {
    let mut status = agent.status();
    #[cfg(target_os = "macos")]
    {
        if let Some(bridge) = app.try_state::<std::sync::Arc<browser::BrowserBridge>>() {
            status["browser"] = bridge.status();
        }
    }
    status
}
#[tauri::command]
fn agent_configure(
    settings: background::Settings,
    agent: tauri::State<'_, std::sync::Arc<background::Agent>>,
) -> Result<serde_json::Value, String> {
    agent.update(settings)
}
#[tauri::command]
async fn agent_review(
    id: String,
    agent: tauri::State<'_, std::sync::Arc<background::Agent>>,
) -> Result<serde_json::Value, String> {
    let agent = agent.inner().clone();
    tauri::async_runtime::spawn_blocking(move || agent.review(&id))
        .await
        .map_err(|_| "Review failed")?
}
#[tauri::command]
async fn agent_choose_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        Ok(app
            .dialog()
            .file()
            .blocking_pick_folder()
            .and_then(|p| p.as_path().map(|p| p.to_string_lossy().into_owned())))
    })
    .await
    .map_err(|_| "Folder selection failed")?
}
#[tauri::command]
fn agent_copy_example() -> Result<(), String> {
    background::copy_example()
}
#[tauri::command]
fn agent_quit(app: tauri::AppHandle, agent: tauri::State<'_, std::sync::Arc<background::Agent>>) {
    agent.shutdown();
    app.exit(0);
}

#[cfg(target_os = "macos")]
#[tauri::command]
async fn browser_configure(
    settings: serde_json::Value,
    bridge: tauri::State<'_, std::sync::Arc<browser::BrowserBridge>>,
) -> Result<serde_json::Value, String> {
    let bridge = bridge.inner().clone();
    tauri::async_runtime::spawn_blocking(move || bridge.configure(settings))
        .await
        .map_err(|_| "Browser configuration failed")?
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn browser_configure(settings: serde_json::Value) -> Result<serde_json::Value, String> {
    let _ = settings;
    Err("Native browser bridge currently requires macOS".into())
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let agent =
                background::Agent::new(app.handle().clone()).map_err(std::io::Error::other)?;
            app.manage(agent.clone());
            background::install_tray(app.handle())?;
            agent.start();
            #[cfg(target_os = "macos")]
            {
                match browser::BrowserBridge::new(app.handle().clone(), agent.clone()) {
                    Ok(bridge) => { app.manage(bridge); }
                    Err(_) => agent.source("browser", "unavailable", Some("Browser bridge initialization failed; check local browser configuration")),
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Keep native protection alive. Quit is available in UI and tray.
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            agent_request,
            save_protected,
            agent_status,
            agent_configure,
            agent_review,
            agent_choose_folder,
            agent_copy_example,
            agent_quit,
            browser_configure
        ])
        .build(tauri::generate_context!())
        .expect("error building Axiom local agent");
    app.run(|handle, event| {
        #[cfg(target_os = "macos")]
        if matches!(event, tauri::RunEvent::Reopen { .. }) {
            if let Some(window) = handle.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
        if matches!(event, tauri::RunEvent::Exit) {
            #[cfg(target_os = "macos")]
            {
                if let Some(bridge) = handle.try_state::<std::sync::Arc<browser::BrowserBridge>>() {
                    bridge.shutdown();
                }
            }
            handle
                .state::<std::sync::Arc<background::Agent>>()
                .shutdown();
        }
    });
}
