# Phase 2: Background Privacy Agent

Implemented on macOS, 2026-10-01, building on the existing Phase 1 engine. This workspace has no `.git` directory; no commit or remote update was made.

## Current capability and verification

| Area | Status | Actual behavior |
| --- | --- | --- |
| Background lifecycle | WORKING | Closing the window hides it; threads continue. App reopening restores it. Explicit Quit joins sources and worker and exits. Persistent pause/resume clears pending work and cancels generation-stale scans. |
| Clipboard | WORKING | NSPasteboard text changes, one-second checks, COPY context, safe version-checked replacement or clearing. ALLOW/WARN leave content alone. No raw history. |
| Files | WORKING | Native notify/FSEvents for selected folders, create/modify/move-in events, supported formats, shared engine, review and protected export. Originals are untouched. |
| Application context | WORKING with attribution limit | NSWorkspace foreground name/bundle ID sampled on clipboard changes. This is the foreground app at observation time, not guaranteed proof of the original copying app. It is not persisted in activity. |
| Tray/menu bar | IMPLEMENTED; manual verification incomplete | Tauri tray title Axiom ●/○, actual active/paused menu text, Open, Activity, Pause/Resume, Quit. Compiles and installs during native launch. Automation cannot inspect this system menu surface, so tray clicks were not verified. |
| Notifications | PARTIALLY VERIFIED | Opt-in, generic metadata-only notifications, ten-second global cooldown, failures surfaced in health. A native event dispatched without a delivery error. Visible OS banner delivery was not independently observed. No notification-click Review callback; use Activity or tray Recent Activity. |
| Existing scanner/rules/export | WORKING | Shared Phase 1 extraction, detectors, policy and transformations. Native review/export and existing organization rules verified. |
| Browser/email/send/upload/print/screen share | ARCHITECTURE ONLY | ContentEvent accepts boundary actions; BoundaryAdapter describes before-send/upload/attach contracts. There are no application interception adapters or claimed external blocks. |
| Signed policy provider | ARCHITECTURE ONLY | PolicyProvider protocol; existing LocalStore supplies current policies. No signed bundle ingestion. |
| Login autostart/control plane | DEFERRED | Start manually. No enterprise authentication, remote policy distribution, MDM, cloud console or central telemetry. |

## Architecture

```text
                  Native Tauri background agent
                   /                         \
       FSEvents selected folders       NSPasteboard text changes
       create / modify / move-in       + NSWorkspace foreground context
                   \                         /
                    normalized ContentEvent
                             |
              bounded queue (64 pending, clipboard priority)
                             |
                      one cancellable worker
                             |
               confined file read / transient clipboard text
                             |
                  existing Python Service / Pipeline
              extraction -> detection -> policy -> transformation
                             |
                  source-specific action enforcement
                 /                            \
      file: review or warning          clipboard: replace / clear
          original untouched             stale version checks
                 \                            /
               SQLite whitelisted activity metadata
                             |
        Dashboard / Activity / Documents / Local Rules / Settings
```

Native implementation: `axiom-employee/src-tauri/src/background/{mod,queue,sources,files,clipboard,platform}.rs`. Shared bounded Python worker bridge: `src-tauri/src/engine.rs`. Python event contracts: `scripts/axiom_agent/events.py`; activity store: `activity.py`. Background operations added to existing `service.py`, without duplicating detector/policy code. React background views use `src/agent/Background.tsx`; native events update the UI without interval polling.

ContentEvent carries ID, timestamp, source, action, content type, transient file path, application name/ID and destination context. Background destinations are **UNSPECIFIED**. A COPY or file save does not prove external disclosure. Destination-conditioned EXTERNAL policies therefore do not automatically match unspecified background context. Filesystem sources never emit fictional OPEN events. Manual scanner contexts remain user supplied.

## Start and demonstrate

Install the existing Python parser dependencies in a local environment, then from `axiom-employee`:

```sh
AXIOM_PYTHON="$PWD/.venv/bin/python" npm run tauri dev
```

Or build `npm run tauri -- build --debug --bundles app`. The development macOS app is `src-tauri/target/debug/bundle/macos/Axiom.app`. Scripts are bundled; Python/parser libraries still need installation. Set AXIOM_PYTHON to the interpreter if launching outside a configured shell. AXIOM_DATA_DIR optionally selects an isolated local data directory.

Default protection and text clipboard monitoring are enabled. Notifications default off. **No folders are monitored until explicitly selected.** Settings permits up to 16 canonical existing folders, rejecting disk/home/temporary roots and the agent data directory. Use a specific temporary subfolder for demonstrations. macOS may request access to selected Documents/Desktop/Downloads locations and notifications. No Full Disk Access, Accessibility, screen recording, camera or microphone requests are introduced.

1. In Local Rules, create Project Penguin: Keyword `penguin`, HIGH, REDACT, MASK or REDACT transformation, enabled, Any destination and Any event.
2. In Settings use **Copy Project Penguin example**, or copy `Project Penguin launches Friday.` from another local editor. Wait at least two seconds and paste. Expected: `Project ███████ launches Friday.`. No manual scan is involved.
3. Settings -> monitored folders: add an existing test directory. Create `acquisition.txt` there containing `Project Penguin launches November 3.` and `Contact john@example.com.`.
4. Activity/Documents should show a real file event and both policies. Click Review document, inspect the protected preview, and export a new derivative. Do not overwrite the original.
5. Close the main window and repeat copying/saving. Reopen via Dock/app launch or tray Open Axiom. Protection continues while hidden.
6. Pause protection; both source states become paused and events copied/saved while paused are not scanned. Resume starts new monitoring and baselines the current clipboard. It does not retroactively crawl existing files or inspect the clipboard copied during pause.
7. Quit Axiom through Settings or tray, or normal macOS Quit. Re-launch to resume the saved configuration.

## Source-specific decisions

| Decision | Clipboard COPY | File create/modify | Axiom export |
| --- | --- | --- | --- |
| ALLOW | Leave unchanged | No intervention | Create requested derivative |
| WARN | Leave unchanged; activity and optional notification | Activity and optional notification | Permit derivative with warning |
| REDACT | Replace text after version/generation checks | REVIEW_REQUIRED; offer derivative | Transform extracted output |
| BLOCK | Clear pasteboard after version/generation checks | BOUNDARY_NOT_INTERCEPTED; original still usable in other apps | Withhold output |

A clipboard poll is not an atomic paste gate. A user/app may paste before detection completes. NSPasteboard has no compare-and-swap transaction; version checks reduce races but cannot eliminate simultaneous external writes. Non-text formats and items are not analyzed. Text is bounded to 2M characters/bytes; a protected replacement or clear drops other pasteboard representations of that same item, preventing the original rich text from surviving alongside protected plain text. Clipboard unavailable/oversized events expose a source error rather than pretending protection happened.

File BLOCK is a policy decision, **not an OS file/send lock**. No automatic original edits, deletes, quarantine or covert derivative generation. Review reads the current file again and reruns policy; references are in-memory, expire after restart or after the last 100 file events, and require that the file still be inside configured folders. Extraction coverage and native-format export limitations from Phase 1 still apply.

## Bounds, privacy and security review

- File events use a 700 ms per-path quiet period, a 1,024-entry bounded debounce map, and bounded native callback channel. SHA-256 fingerprints suppress same-content rescans in a policy/configuration generation; hash cache is bounded to 1,024 paths and memory only. Hidden filenames, unsupported formats and `.protected.` derivatives are ignored.
- One queued worker; pending capacity 64, coalesced file paths and newest clipboard events, clipboard priority, dropped-event diagnostics. At most one background parser process. Manual explicit scans can run separately.
- Clipboard tracks NSPasteboard changeCount and Axiom's own writes. Copying the original again at a new version is protected again; it is never bypassed by content-only deduplication. Stale/pause outcomes never overwrite newer clipboard text.
- Worker JSON input <=30 MiB, output <=32 MiB, wall timeout 30 seconds, pause/shutdown cancellation, bounded pipes, subprocess process group cleanup on Unix, stderr discarded. Phase 1 parser/regex limits remain intact. No arbitrary policy execution or runtime download.
- File resolution checks supported regular files, canonical configured-root containment, <=20 MiB and stable size/mtime; Unix descriptor traversal rejects symlinks in every path component, including canonicalize/open races. Original file descriptors are read only. Protected saves use create-new and reject existing destinations.
- A per-data-directory process lock prevents two agents racing the same clipboard under normal startup. Settings use private, uniquely named create-new temporary files and atomic rename. Invalid/unavailable persisted configuration starts paused and surfaces an error.
- Activity SQLite has private file permissions and whitelisted metadata: timestamp, generated event ID, source/event, selected policies/severity/action, document type, count, actual outcome. No raw clipboard values, content, detections, filenames, paths, domains or application identifiers. Configured folder paths are intentionally stored in settings. Local rule patterns/names are organization configuration, not harvested content.
- Maximum 2,000 activity records, latest 200 displayed; counts cover retained records from today. DELETE journaling avoids an unbounded WAL; concurrent connections use a five-second lock timeout. Manual Phase 1 JSONL audit remains separate and bounded.
- No cloud runtime dependencies, telemetry, remote fonts or external inference calls. Native UI uses CSP connect-src self; browser development mode calls only its loopback local service. No universal network firewall or enterprise tamper resistance is claimed.
- No new broad OS permissions. Notification errors, worker failures and watcher/clipboard errors are generic, content-free health information. Malformed documents are isolated; processing continues.

## Automated validation

```sh
cd axiom-employee
python3 -m unittest discover -s tests -v
cargo test --offline --manifest-path src-tauri/Cargo.toml --lib
npm run build
cargo check --offline --manifest-path src-tauri/Cargo.toml
npm run tauri -- build --debug --bundles app
```

**95 tests passed: 69 Python + 26 Rust.** All original 43 Phase 1 tests remain unchanged and passing; 26 new Python tests exercise normalization, shared background policy actions, Penguin integration, original-file preservation, malformed inputs, privacy, concurrency and retention. Rust covers 8 clipboard tests, 8 queue/debounce tests, 5 filesystem tests, 4 worker tests and a real macOS FSEvents create test. The FSEvents test needs normal OS access: it failed in the restricted command sandbox but passed outside it, as did the full native suite. Do not substitute a mocked watcher and call it native verification.

## Actual native verification, 2026-10-01

- Launched final Axiom.app; active clipboard/file source status, real counts and no fabricated integrations.
- Existing Project Penguin rule persisted from Phase 1. Real system clipboard redacted with expected seven block characters, a matching Activity entry, and no feedback loop.
- Closed main window, saved acquisition.txt in a configured temporary subfolder. Axiom automatically emitted FILE_CREATED with Penguin and email matches; byte comparison confirmed the source unchanged.
- Reopened hidden app using native app launch action; later closed-window file creation also incremented real activity.
- Paused: both sources paused; new file/copy produced no additional activity. Pasting fictional example remained unchanged. Resumed: file modification and new copy were detected and protected.
- Review on an automatically observed file opened the existing scanner with two real findings and protected preview. Native export produced the protected text derivative now preserved as `axiom-employee/examples/phase2-acquisition.protected.txt`.
- Copied example from TextEdit while Axiom window was hidden; pasted back into TextEdit as `Project ███████ launches Friday.`. Activity recorded CLIPBOARD_REPLACED.
- Enabled notifications for a test file; processing completed with no dispatch/delivery error reported. Visible OS banner and notification-click review are not verified/provided.
- Read actual activity SQLite and manual audit: fictional clipboard sentence, fixture email, acquisition filename and test directory path absent. Rule names retained as intended.
- Dedicated quiet process samples: CPU 0.0% in both; cumulative CPU time moved from 1.38 to 1.41 seconds (0.03 seconds). This is a development observation, not a fleet benchmark.
- `lsof -nP -a -p <native PID> -i` found no network sockets for the native process. Static review confirms self-only UI connections and no external processing endpoints. This is a point-in-time observation, not an OS firewall guarantee.
- Malformed PDF generated a controlled error and content-free health message; other files continued to scan. Failed parsing now records UNASSESSED, rather than implying an ALLOW decision.
- Settings -> Quit Axiom terminated the measured process; a subsequent process lookup returned no process. Notifications were restored off after the test.
- The native menu-bar system surface was unavailable to UI automation; tray labels/actions are implemented and compiled but manual tray interaction remains unverified.

## Recommended Phase 3

Implement one real boundary adapter, such as a browser extension/native messaging bridge that controls an actual upload and supplies verifiable destination context. Package a reproducible Python runtime, isolate parsing more strongly, improve extraction coverage, and verify native-format sanitization before enterprise deployment. Signed local organization policy bundles and policy authenticity should precede a central control plane. Continue reporting observed decisions separately from actual enforcement.

## Runtime correction, 2026-10-02

Finder's minimal PATH could select Apple's Python without PyMuPDF, causing valid PDFs to be reported as malformed. Native runtime selection now honors AXIOM_PYTHON first, then a repository .venv, then standard macOS Homebrew Python locations, and finally PATH. Missing parser imports now have a distinct dependency/setup error. Failed activity rows no longer offer an unusable Review button. Added three runtime selection tests and one missing-parser regression test. The supplied onboarding PDF was checked locally without printing its text.
