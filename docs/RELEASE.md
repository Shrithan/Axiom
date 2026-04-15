# Experimental source release

Axiom is ready to share as an **experimental macOS local privacy prototype**.
It is not a production DLP product or a universal Gmail attachment blocker.
The admin app is a disconnected interface prototype. The employee app is functional.

## Fresh checkout setup

Install Node 22.12 or newer, Python 3.10 or newer, Rust stable, and Xcode Command Line Tools on macOS. From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r axiom-employee/scripts/requirements.txt
npm ci --prefix axiom-employee
npm ci --prefix axiom-admin
AXIOM_PYTHON="$PWD/.venv/bin/python" npm --prefix axiom-employee run tauri dev
```

Keep the terminal running. Documents → Import → Scan works without enabling background monitoring. Policies controls the actual local rules. Settings enables selected-folder and clipboard monitoring. No folder is selected by default. Closing the window leaves the agent running; use Quit Axiom to stop it.

For a release app:

```sh
.venv/bin/python scripts/verify.py --native
```

The app is produced at `axiom-employee/src-tauri/target/release/bundle/macos/Axiom.app`. Python remains an external prerequisite; this is an unsigned development build, not a self-contained installer. Launch the built app with the configured interpreter:

```sh
AXIOM_PYTHON="$PWD/.venv/bin/python" ./axiom-employee/src-tauri/target/release/bundle/macos/Axiom.app/Contents/MacOS/axiom
```

Run that command from the repository root. Closing the terminal may stop a terminal-launched app. The desktop bridge also searches checkout-local virtualenvs and common Homebrew Python paths.

For Chrome setup, follow [the extension instructions](../browser-extension/README.md). The native host and app must use the same data directory. Run the popup from Chrome's extension toolbar; opening popup.html as a normal tab is not an equivalent test. Reload both the extension and the opted-in site after an update.

## Automated verification

```sh
.venv/bin/python scripts/verify.py
.venv/bin/python scripts/verify.py --native
```

The first command runs Python, extension, UI tests and both frontend builds. `--native` adds Rust tests and the macOS release app build. Checks stop at the first failure. They do not register a host, change normal agent settings, grant site access or send email. Native filesystem tests need macOS event access. GitHub Actions repeats the full command on macOS; remote CI has not run until the repository is pushed.

## Five-minute use-case test

Use fictional content only. Create a TXT file containing `Project Penguin; contact sam@example.com`.

1. In Policies, add an enabled Keyword rule for `Penguin` with REDACT. In Documents, import the TXT and scan. Check findings, concealed matched values, and the protected preview. Export to a new path and check that the original is unchanged and protected text contains neither matched value.
2. Change that rule to BLOCK and scan again. Output must be withheld. Switch to another section and back: selection/results should persist.
3. Open a newly created text-based PDF containing the same fictional content in Documents. Expect real findings and a TXT derivative, not a layout-preserving redacted PDF. Image-only PDFs need OCR, which is unsupported. An unavailable parser must be reported separately from a malformed file.
4. Enable clipboard protection, then copy the fictional text. Check actual replacement/clearing and the metadata activity outcome. Clipboard polling is not instantaneous interception of every paste.
5. For browser BLOCK/ALLOW/WARN/REDACT receipt tests, follow the isolated [local harness](../browser-extension/README.md#reproduce-the-receipt-demo). Check server receipts, not just the UI label. Restore the normal host registration after the demo.

Gmail is a separate manual check: enable the guard for Gmail, reload Gmail, and drop an ordinary fictional file onto a compose window. Expect all file drops to be withheld, including harmless files. Paperclip, Drive and Send are unsupported. Actual Gmail verification remains outstanding; do not advertise selective Gmail scanning.

## Troubleshooting

- **File unavailable / reference expired:** activity stores metadata, with only bounded in-memory review references. After restart, expiration, deletion, or path changes, import the original through Documents. The audit log intentionally cannot recover original file contents.
- **Malformed PDF:** retry a known text PDF. Missing PyMuPDF is a runtime configuration problem; install requirements in the interpreter selected by `AXIOM_PYTHON`. Encrypted, malformed and image-only inputs are unsupported, with explicit errors. No OCR or repair is performed.
- **Protection paused / folders unavailable:** open Settings, select existing safe folders, save, then resume. A valid manual document scan does not require folders to be monitored.
- **Chrome disconnected:** keep the native app running, rerun the native host installer for this checkout, and verify both use the same data directory. Temporary demo registrations must be restored. Site opt-in and reload are required.

## Local verification — October 15, 2026

- 109 employee Python, 7 native-host Python, 27 extension JS, 18 UI and 36 Rust tests passed: **197 total**.
- Both frontend production builds, the extension build and the macOS release app build passed. The complete `verify.py --native` command exited successfully.
- Both Python suites also passed from a freshly extracted source archive.
- The archive contains source/docs/assets only; dependency directories, runtime state, build outputs, native launchers and unused model binaries were checked as excluded.
- The native filesystem test needed normal OS access; it passed outside the restrictive command sandbox.
- CI is configured but has not executed on GitHub. No upload, commit, host registration or app settings change was performed in this release-preparation pass.

## Publishable claims and remaining checks

Verified locally: the local policy engine, supported extraction/export behavior, regression suites, native app build, document scanning/export and persistent interface state. Historical browser receipt evidence is linked in the root README. Live Gmail drag/drop and the latest Chrome Open Axiom navigation have not been verified. Hardware animation profiling, OS reduced-motion interaction and a fresh-machine installation remain unverified. Do not describe these as passed.

The source snapshot is imported on top of the repository’s existing main history. New import commits use April 15, 2026 author and committer dates at the owner’s request; verification dates describe when checks actually ran. No license grant has been invented: the owner must choose a license before describing the project as open source. The existing scenic artwork and any reused assets also need appropriate redistribution rights. Public source visibility alone does not grant reuse rights.

## Package source

```sh
python3 scripts/package_source.py
```

This creates `releases/axiom-experimental-source.tar.gz` and a SHA-256 sidecar. The archive omits node_modules, Python environments, Rust outputs, generated extension builds, local state, machine-specific native launchers, secrets-file extensions, editor caches and unused legacy model binaries. The active runtime does not use the legacy model directory. Original files are preserved in the working folder. Archive packaging is not a guarantee that arbitrary future source edits contain no secrets; inspect new files before publishing.

Suggested repository description: **Experimental macOS privacy agent with local document scanning, clipboard protection and opt-in browser form enforcement. React + Tauri + Python.**

See [interface screenshots](immersive/README.md) and [security reporting](../SECURITY.md).
