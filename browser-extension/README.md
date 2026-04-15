# Axiom Chrome browser boundary

**Gmail has a conservative block-all file-drop guard.** It withholds every file drag-and-drop on a freshly loaded, opted-in Gmail page. It does not selectively inspect/allow attachments; paperclip, Drive and sending remain unsupported. The popup states these limits explicitly.

Development MV3 extension for **opted-in standard HTML POST multipart file-upload forms on macOS**. It holds selected files before page input/change handlers, evaluates the initial form destination in the running native agent, and releases assessed bytes only after policy authorization. Arbitrary AJAX/fetch/XHR, drag-and-drop, direct custom File APIs, browser redirects, email, printing and screen sharing are outside coverage. This is not an enterprise network firewall.

## Install and run

From the repository root, install the employee Python requirements and Node/Tauri prerequisites described in the root README. Then:

```sh
npm --prefix browser-extension run build
python3 browser-extension/native/install.py
npm --prefix axiom-employee run tauri -- build --bundles app
```

Launch `axiom-employee/src-tauri/target/release/bundle/macos/Axiom.app` through Finder. Keep the native agent running. In Chrome:

1. Open `chrome://extensions`, turn on Developer mode, choose **Load unpacked**, and select `browser-extension/dist`.
2. Confirm the extension ID is `hdllggekmmgdgkkhblemoecomiemhphk`.
3. Visit a site, open the Axiom extension popup, choose **Enable form gate on this site**, and approve access to that specific site. Reload it before selecting files.
4. The popup must report **Connected to local Axiom Agent**. Native Axiom → Settings displays the connection and editable domain classifications.
5. Select files. Close the held-file notice, then use the form's upload button. Axiom evaluates the actual form action and submitter overrides.

No site access is granted automatically. Chrome host permissions apply to a hostname across ports. HTTPS is required for normal sites; localhost HTTP is suitable for this development harness. Files selected before reloading an opted-in page are outside coverage. Uninstall through Chrome and remove `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.axiom.browser.json` to unregister the host. The generated launcher points to this checkout, so moving it requires rerunning the installer.

`install.py --browser chromium` registers Chromium instead; Chromium has not been independently exercised here. The bridge runtime is implemented/tested on macOS. Windows/Linux support is deferred. Python is not bundled into the app. The host itself uses only Python's standard library; the agent interpreter needs the parser requirements. Do not register a Native Messaging host for the HTTP/manual-scanner development server—it is not the native agent.

## Reproduce the receipt demo

Use a fresh isolated directory. This does not edit existing employee rules:

```sh
python3 browser-extension/harness/setup_demo.py
python3 browser-extension/native/install.py --data-dir /private/tmp/axiom-phase3-demo/data
python3 browser-extension/harness/server.py
```

Quit the existing native Axiom instance, then launch the native agent in another terminal:

```sh
AXIOM_DATA_DIR=/private/tmp/axiom-phase3-demo/data \
  ./axiom-employee/src-tauri/target/release/bundle/macos/Axiom.app/Contents/MacOS/axiom
```

Opt in and reload both `http://external.localhost:8877` and `http://internal.localhost:8877`. Select `/private/tmp/axiom-phase3-demo/fixtures/acquisition.txt`, which contains fictional Project Penguin text. External must BLOCK with no server request; internal must ALLOW and deliver 65 bytes. `/stats` returns only counts and SHA-256 hashes. `agenda.txt` allows externally; `warning.txt` asks for consent; `contact.txt` asks to send a protected TXT derivative. Selecting acquisition + agenda externally blocks the whole operation. Stop the agent and retry: no selected bytes may be released.

The server binds only to `127.0.0.1`, holds receipt metadata in memory, retains at most 200 file hashes per host, and stores no uploaded bodies or filenames. These origins are both physically local; their differing classifications prove policy context, not remote transmission. The extension and agent have no harness-specific enforcement code.

After the demo, quit the isolated agent, rerun `python3 browser-extension/native/install.py` without `--data-dir`, and launch the app normally to use `~/.axiom-local`. Host and agent must use the same data directory. Stop the harness with Ctrl-C. The isolated fixture directory can be removed when no longer needed.

## Verification

```sh
python3 -m unittest discover -s axiom-employee/tests
cargo test --manifest-path axiom-employee/src-tauri/Cargo.toml
python3 -m unittest discover -s browser-extension/tests -p 'test_*.py'
npm --prefix browser-extension test
npm --prefix browser-extension run build
```

Rust filesystem tests require normal macOS access. JS content tests use a controlled DOM fixture to exercise the gate and races; real Chrome/server verification is documented separately. `harness/benchmark.py --data-dir ...` measures private bridge assessment only and never submits files or commits upload activity.

See [Phase 3 architecture, security limits and real verification](../docs/PHASE3.md).

## Gmail drag-and-drop stopgap

After rebuilding or updating the extension, reload Axiom at `chrome://extensions`, then reload Gmail. In the Axiom popup, enable the Gmail file-drop guard if Gmail site access has not already been granted. Test with an ordinary fictional file: a drop should show **Gmail file drop blocked**, with no attachment appearing. All file drops are withheld, including harmless files. Text-only drops remain available.

The guard stops capture-phase drag/drop events before Gmail page handlers and never reads file contents, uploads a test body, calls the detector or writes a fake policy-block audit record. It is not a Gmail-specific selective privacy adapter. Already uploaded attachments are unaffected. It does not protect paperclip/Drive attachment paths or Send, and is not a network/tamper-resistant guarantee. The capture logic is covered by automated DOM tests; the actual Gmail file-drop path still needs a fictional-file manual verification. Do not use real sensitive files to establish that proof.
