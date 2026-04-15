> This is the historical Phase 1 implementation record. See [PHASE2.md](PHASE2.md) for current background-agent architecture, tests and native verification.

# V1 implementation record

## Repository audit before implementation

The provided checkout contains two independent applications, `axiom-employee` and
`axiom-admin`, using React 19, TypeScript, Vite and Tauri 2/Rust. Python workers provided
PDF/Office extraction and redaction. There were no existing automated test files or
AGENTS.md instructions. This filesystem snapshot has no Git metadata.

Employee UI and Rust code were large monoliths: detection/reporting, clipboard regex,
macOS AppleScript application discovery, Gemma model startup, process management,
redaction and Firebase upload were coupled. PDF/Word/Excel parsing was real, rather than
entirely simulated. Several UI indicators represented loading/demo assumptions instead
of policy decisions. The Gemma loader used `from_pretrained` without offline-only
controls. The redactor performed raw-value replacements and had no independent policy
layer. Clipboard detection had separate logic from file detection. This did not provide
a common extensible enforcement pipeline.

The admin console had useful management UI components, but its rules lived in process
memory and were not consumed by employee scanning. Employee records and activity logs
used a duplicated Python Firebase adapter. Both adapters included embedded authentication
credentials. Root documentation described a different single HTML simulation and did
not reflect this code. Frontend CSS fetched Google fonts. Unused MediaPipe WASM/model
assets added approximately 49 MiB to the public frontend bundle.

Available tools included Python and all required local parsers, Node/npm/pnpm, Rust and
macOS build prerequisites. Frontend dependencies were absent and Rust crates needed
downloading. Cloud-dependent runtime paths were not executed. Initial baseline builds
were not available before installing dependencies; the preserved admin frontend also
had an unused TypeScript import that failed strict compilation.

## Implementation sequence and boundaries

1. Inventory and inspect both application stacks, entry points, UIs, parser/redactor
   code, cloud adapters, manifests/configuration, model assets and documentation.
2. Preserve React/Vite/Tauri, the employee dark palette/sidebar/background, parser
   library choices, admin UI components and offline model artifacts.
3. Establish normalized content and pluggable detectors, an independent context-aware
   policy engine, deterministic transformations and minimized local storage.
4. Connect actual file imports, rule CRUD, findings, protected preview, audit and export
   to one operation boundary. Use a local Python worker in both desktop IPC and browser
   mode. Remove cloud upload/model startup and brittle OS interception from the active path.
5. Add automated extraction/engine/enforcement/boundary tests, then verify builds and
   the native document import/save workflow. Clearly retire disconnected admin behavior.

The active employee implementation is modular: `models.py`, `extraction.py`,
`detectors.py`, `policy.py`, `transformation.py`, `pipeline.py`, `storage.py`, `service.py`.
`agent_ipc.py` is the local JSON process boundary. `local_server.py` hosts the built app
on loopback with Host/Origin/token checks and a bounded parser subprocess. The Tauri
bridge runs the same operations off its UI thread and uses a native save dialog.

The original employee UI was refactored because its tightly coupled data model and
commands could not accurately represent policy-enforced output. Its visual foundation
and application stack are retained. Unused employee CSS and runtime dependencies were
removed. The admin UI is retained, but its backend now explicitly rejects deferred
enterprise operations instead of fetching cloud data or serving fake policy fixtures.
The cloud worker entry points contain only an explicit retirement message.

## Verification

- **43 automated tests passed** using `python3 -m unittest discover -s tests -v`.
- Penguin and email extraction/detection/policy/transformation passed for real generated
  PDF, DOCX, XLSX, CSV and TXT files.
- Meaningful edge cases: malformed/empty/unsupported documents, image-only PDFs, archive
  limits/macros, invalid/pathological regexes, Unicode offsets, Luhn/SSN/phone/IP false
  positives, disabled policies, context selection, precedence/ties, overlap union,
  masking/replacement/removal, and policy changes at export time.
- Persistence tests inspect audit contents to ensure values/names/paths are absent.
  No-network tests prevent socket use in the core engine. IPC tests generate and verify
  an actual protected artifact. HTTP boundary tests check rejected Host/Origin/token,
  oversized requests and the parser subprocess timeout.
- Employee and admin `npm run build` passed; both Rust backends passed `cargo check`.
- Employee `npm run tauri -- build --debug --no-bundle` passed. A development macOS
  `Axiom.app` bundle was also built with `--debug --bundles app`.
- Browser UI verification: created Project Penguin in Local Rules, imported the real
  example file and saw two findings with the correct rules, protected preview and
  export response. The in-app browser did not expose a verifiable download event, so
  browser filesystem saving is not claimed as tested.
- **Native UI verification:** launched the built macOS app, created/persisted the
  Penguin rule, imported `examples/project-penguin.txt` using the native file picker,
  scanned it and saved `examples/project-penguin.protected.txt` through the native save
  dialog. Reading the saved file confirmed both protected spans, matching the preview.
  `penguin-desktop.jpg` records this UI result.
- Native scripts were present in the bundle resource directory. A separate runtime
  remains required; deployment to a clean machine and signing/notarization are not tested.
- Active employee code was searched for network clients/logging: fetch targets are
  same-origin local API paths. Firebase workers contain no network/authentication code.
- Git diff review/commit/push could not run: the provided workspace is not a Git checkout.
  Source/configuration/lockfiles were inspected directly instead.

## Intentionally deferred

PDF/Office layout-preserving output, exhaustive hidden-content coverage, local OCR,
semantic models, background OS interception, automatic destination attribution,
enterprise administration/authentication, signed policy distribution, parser OS
sandboxing and standalone runtime packaging. Original files remain unchanged. BLOCK
only governs protected outputs through Axiom, and local policy storage is not tamper
resistant. Recommended next work is reproducible runtime packaging and stronger parser
isolation/coverage before connecting a clipboard or browser adapter to ContentEvent.
