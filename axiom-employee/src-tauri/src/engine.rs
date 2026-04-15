//! Bounded shared bridge to the Phase 1 local engine. No content logging.
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tauri::Manager;

pub fn execute(
    app: &tauri::AppHandle,
    request: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    execute_cancelable(app, request, || false)
}
pub fn execute_cancelable(
    app: &tauri::AppHandle,
    request: &serde_json::Value,
    canceled: impl Fn() -> bool,
) -> Result<serde_json::Value, String> {
    let development =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/agent_ipc.py");
    let script = if development.exists() {
        development
    } else {
        app.path()
            .resource_dir()
            .map_err(|_| "Resource directory unavailable")?
            .join("scripts/agent_ipc.py")
    };
    // Finder launches have a minimal PATH and may otherwise select Apple's
    // Python without the installed parsers. Explicit configuration wins.
    let mut candidates =
        vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.venv/bin/python")];
    #[cfg(target_os = "macos")]
    candidates.extend([
        std::path::PathBuf::from("/opt/homebrew/bin/python3"),
        std::path::PathBuf::from("/usr/local/bin/python3"),
    ]);
    let python = select_python(std::env::var("AXIOM_PYTHON").ok(), &candidates, |p| {
        p.is_file()
    });
    run_worker(&python, &script, request, Duration::from_secs(30), canceled)
}

fn select_python(
    explicit: Option<String>,
    candidates: &[std::path::PathBuf],
    exists: impl Fn(&Path) -> bool,
) -> String {
    if let Some(value) = explicit {
        return value;
    }
    candidates
        .iter()
        .find(|p| exists(p))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "python3".into())
}

fn run_worker(
    python: &str,
    script: &Path,
    request: &serde_json::Value,
    timeout: Duration,
    canceled: impl Fn() -> bool,
) -> Result<serde_json::Value, String> {
    let raw = serde_json::to_vec(request).map_err(|_| "Invalid request")?;
    if raw.len() > 30 * 1024 * 1024 {
        return Err("Request exceeds limits".into());
    }
    if canceled() {
        return Err("Local processing canceled".into());
    }
    let mut command = Command::new(python);
    command
        .arg(script)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|_| "Python runtime unavailable. Set AXIOM_PYTHON to your local interpreter.")?;
    let mut stdin = child.stdin.take().ok_or("IPC unavailable")?;
    let stdout = child.stdout.take().ok_or("IPC unavailable")?;
    let writer = std::thread::spawn(move || stdin.write_all(&raw));
    let reader = std::thread::spawn(move || {
        let mut bytes = vec![];
        stdout
            .take(32 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let mut expired = false;
    loop {
        if canceled() || Instant::now() >= deadline {
            expired = true;
            break;
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => (),
            Err(_) => {
                expired = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if expired {
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
        }
        let _ = child.kill();
    }
    let _ = child.wait();
    // Kill remaining descendants before joining readers (the trusted worker normally has none).
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }
    let written = writer.join().map_err(|_| "IPC write failed")?;
    let output = reader
        .join()
        .map_err(|_| "IPC read failed")?
        .map_err(|_| "IPC read failed")?;
    if expired {
        return Err("Local processing canceled or exceeded its execution limit".into());
    }
    written.map_err(|_| "IPC write failed")?;
    if output.len() > 32 * 1024 * 1024 {
        return Err("Worker output exceeds limits".into());
    }
    let response: serde_json::Value =
        serde_json::from_slice(&output).map_err(|_| "Invalid local worker response")?;
    if let Some(error) = response.get("error").and_then(|e| e.as_str()) {
        return Err(error.to_string());
    }
    response
        .get("result")
        .cloned()
        .ok_or("Missing local worker result".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn script(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("axiom-worker-{name}-{}.py", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }
    #[test]
    fn explicit_interpreter_wins() {
        assert_eq!(
            select_python(
                Some("configured-python".into()),
                &["local-python".into()],
                |_| true
            ),
            "configured-python"
        );
    }
    #[test]
    fn local_environment_precedes_system_path() {
        assert_eq!(
            select_python(
                None,
                &["local-python".into(), "homebrew-python".into()],
                |_| true
            ),
            "local-python"
        );
    }
    #[test]
    fn missing_environment_uses_available_candidate() {
        assert_eq!(
            select_python(
                None,
                &["missing-python".into(), "homebrew-python".into()],
                |p| p == Path::new("homebrew-python")
            ),
            "homebrew-python"
        );
        assert_eq!(select_python(None, &[], |_| false), "python3");
    }
    #[test]
    fn worker_timeout_is_bounded() {
        let p = script("timeout", "import time;time.sleep(10)");
        let start = Instant::now();
        assert!(run_worker(
            "python3",
            &p,
            &serde_json::json!({}),
            Duration::from_millis(80),
            || false
        )
        .is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn paused_work_never_spawns() {
        assert!(run_worker(
            "missing-interpreter",
            Path::new("missing"),
            &serde_json::json!({}),
            Duration::from_secs(1),
            || true
        )
        .unwrap_err()
        .contains("canceled"));
    }
    #[test]
    fn malformed_worker_is_isolated() {
        let p = script("malformed", "import sys;sys.stdin.read();print('invalid')");
        assert!(run_worker(
            "python3",
            &p,
            &serde_json::json!({}),
            Duration::from_secs(1),
            || false
        )
        .is_err());
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn valid_worker_response() {
        let p = script(
            "valid",
            "import sys;sys.stdin.read();print('{\"result\":{\"action\":\"ALLOW\"}}')",
        );
        assert_eq!(
            run_worker(
                "python3",
                &p,
                &serde_json::json!({}),
                Duration::from_secs(1),
                || false
            )
            .unwrap()["action"],
            "ALLOW"
        );
        std::fs::remove_file(p).unwrap();
    }
}
