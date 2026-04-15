# Phase 3 — real browser boundary enforcement

Verified on macOS with **real Google Chrome**, the unpacked MV3 extension, the running release Tauri app, Chrome Native Messaging, and a separate receiving HTTP server on 2026-10-02. This phase establishes destination-aware enforcement for opted-in standard HTML POST multipart file-upload forms. It does not establish universal browser DLP.

## Architecture and reuse

```text
Chrome file input / standard form submission
  → isolated document_start content gate
  → extension MV3 service worker
  → exact-origin Chrome Native Messaging host (framed stdio)
  → authenticated same-user private Unix socket
  → native Axiom BrowserBridge
  → existing bounded Python worker / Service
  → Pipeline.scan → existing extractors, detectors, rules and transformations
  → bound decision / fresh authorization
  → held, canceled, or native multipart submission of assessed bytes
  → existing metadata-only ActivityStore
```

No detector, parser or policy logic is duplicated in the extension. The browser creates `ContentEvent` context with source `browser`, action `UPLOAD`, source application Chrome, classified destination and normalized domain. The same local policy provider and Python pipeline serve manual scans, background sources and browser evaluation. The Phase 2 queue/worker stays intact; synchronous browser decisions run in a separate serial bridge lane because the initiating form requires a reply. Both lanes use the same bounded engine subprocess implementation. No cloud/admin control plane or model is added.

The MV3 service worker owns the native port and bounds pending calls to four. Content scripts register only for user-granted sites, at document start in the isolated world, including frames whose origins independently match grants. The popup gives native connection status, current-site classification, site opt-in and Open Axiom. There is no page `postMessage` bridge, external extension messaging handler, detector code, storage of page contents, or direct network API.

The installer registers host `com.axiom.browser` for exactly `chrome-extension://hdllggekmmgdgkkhblemoecomiemhphk/`. A fixed public manifest key supplies a stable extension ID; it is not a secret or enterprise signature. Native stdio uses four-byte little-endian JSON lengths. The small Python host forwards to `browser.sock` with the local credential and performs no arbitrary document path reads or shell commands. Socket/token permissions are 0600, the native bridge verifies the connecting OS user and token, and both boundaries enforce message sizes and strict operation schemas. No browser-facing HTTP agent port is added.

## Events, destination and action semantics

File input `input`/`change` events are captured before page handlers. The gate snapshots File objects, synchronously empties the input, stops propagation and temporarily disables the held input's required constraint. It intercepts normal submit-button clicks, Enter and submit events. At submission it reads bounded immutable file bytes, hashes them, and evaluates the form's actual action, including submitter action/method/enctype/target overrides. Direct page `.submit()` cannot recover held selected bytes from the emptied inputs. Page reset clears held selections.

Classification uses the initial upload destination origin, never page title or a manual employee-UI destination selector. Only origin is forwarded; paths, queries, fragments and credentials are excluded. Configurable INTERNAL, PARTNER and PUBLIC hostname lists support exact domains and complete-label subdomains. The longest matching domain wins. Unlisted destinations are EXTERNAL; `company.com.attacker.example` cannot match `company.com`. IP literals match exactly. Case, trailing dots and IDNA names are normalized. Invalid hostnames and conflicting exact domain classifications are rejected. Browser settings are local and editable in the native employee Settings view.

| Decision | Implemented browser behavior |
|---|---|
| ALLOW | Fresh authorization, then native form serialization of the exact assessed byte snapshot. |
| WARN | Explicit Cancel/Continue; Continue authorizes and releases assessed originals. |
| REDACT | Explicit consent to replace small TXT uploads with protected TXT derivatives. Originals remain unchanged. |
| REDACT for PDF/DOCX/XLSX/CSV or oversized derivatives | `UPLOAD_REVIEW_REQUIRED`; intercepted original upload stays blocked. Open the scanner for derivative review. |
| BLOCK | Clear held selection, prevent form release, show policy/destination and commit `UPLOAD_BLOCKED`. |
| Parser error / unsupported file | `UNASSESSED`, not ALLOW; selected bytes remain unreleased. |
| Agent stopped, disabled, paused or transport timeout | Fail closed for the intercepted operation; useful unavailable notice. |

BLOCK dominates other selected files. If no BLOCK exists but any selected file cannot be assessed, the combined operation is UNASSESSED. No automatic partial upload occurs. Bound replies include request ID, destination origin, file count, byte sizes and SHA-256 values. The native bridge retains only decision metadata plus a random receipt, at most 64 decisions for 60 seconds. Authorization checks the live protection generation and current policy/settings revision. Content scripts recheck selection versions and form context after asynchronous work and immediately before synchronous native serialization. Duplicate submits are suppressed. WARN cancellation and replacing a pending warning notice cancel the old operation.

`UPLOAD_ALLOWED`, `UPLOAD_WARNED` and `UPLOAD_REDACTED` mean the browser gate released a submission. They do **not** independently prove server receipt; network/server failure can follow. Native Activity does not claim universal send blocking. Metadata commits may be lost if Chrome/agent closes at that instant; durable delivery acknowledgements and crash recovery are deferred. When the agent is stopped there is no live agent in which to persist an unavailable event; browser feedback remains explicit.

## Actual receipt verification

The harness is an ordinary multipart receiving server, not a special extension adapter or an employee-UI simulation. Both test hostnames resolve to loopback; they exercise differing destination policies without sending fictional test data off the machine. The agent had default built-ins plus a normal keyword policy matching `penguin`, restricted to `UPLOAD` and `EXTERNAL`. No production employee rules were changed.

| Real Chrome operation | Server observation |
|---|---|
| Project Penguin → EXTERNAL | No request, zero bytes. Browser displayed the named BLOCK policy. |
| Same 65-byte file → INTERNAL | One request, 65 bytes, original SHA-256 exactly matched. |
| Ordinary agenda → EXTERNAL | One additional request, 35 bytes, matching original hash. |
| Agent stopped, protected upload retried | Counters stayed unchanged; browser displayed Agent unavailable. |
| TXT email REDACT, Continue chosen | Server received a 95-byte derivative with expected protected hash, not the original hash. |
| WARN, Continue chosen | Server received the exact 25-byte original; Activity recorded UPLOAD_WARNED. |
| Ordinary + Project Penguin together → EXTERNAL | Entire operation blocked; external counters remained three requests / 155 bytes. |

The protected original's SHA-256 is `0dd3f89addf85939ba2576524d9c56cc24fb9cfe68e57b93a97c9838e2fdbea5`; it appears only in the INTERNAL receipts. The file was read back unchanged. See [receipt snapshots and benchmark samples](phase3/receipts.json). Chrome displayed the real extension ID and connected status; native Activity displayed both destination classifications, policies, action and actual gate outcome. Open Axiom from the extension reached native Activity. Settings displayed the configured domain lists.

Phase 2 live regressions also passed: copying a fictional valid SSN caused `CLIPBOARD_CLEARED`; creating a TXT file with a fictional email in a watched directory caused `REVIEW_REQUIRED`. The watched original remained unchanged. Original Phase 1 and Phase 2 tests are preserved.

## Security, privacy and limits

Required extension permissions are `nativeMessaging`, `scripting` and `activeTab`; HTTP/HTTPS host access is optional and site-specific. No automatic `<all_urls>` grant, cookies, history, downloads, bookmarks or broad tabs collection is requested. Chrome permissions apply to the granted hostname across ports. Enabling arbitrary real sites exposes their DOM to the content script, so the user chooses those grants explicitly.

Runtime protected content stays in transient local extension/native worker memory. There is no persistent scan cache or upload staging file. Garbage collection is not secure memory erasure. Activity accepts a strict metadata whitelist: event/time, policy identifiers/names/severity/action, document type, detection count, destination hostname/class and gate outcome. It excludes file names/paths, hashes, full URLs, matched values, original/protected text and request bodies. Local policy configuration necessarily contains user-defined patterns; that is distinct from retaining detected document values. The test activity SQLite database was searched for the fictional memo sentence, email, SSN and filenames; none were present. Native process output and host logging contained no protected bodies. The harness stores only bounded receipt counts/hashes in memory and no filenames/bodies.

Source/CSP inspection confirms the extension communicates through Native Messaging only; its CSP has `connect-src 'none'`. The agent uses framed local subprocess IPC and a private Unix socket, not an external endpoint. Server counters showed only the allowed submissions. This verification did not include a system-wide packet capture of every Chrome process; other installed extensions and browser services are outside Axiom's runtime claim.

Coverage limits are material:

- Only freshly loaded, opted-in pages and standard POST multipart forms are covered. Files selected before injection, ungranted cross-origin frames, opaque/sandboxed frames and custom upload widgets are outside the proved boundary.
- Arbitrary AJAX/fetch/XHR, drag-and-drop, File System Access APIs, blobs/custom JS, preexisting page copies of data, and hostile alternate paths are not generally enforced. A page can disrupt or remove UI. This is not a tamper-resistant boundary against a compromised browser or same-user process.
- Classification binds the **initial form destination**. HTTP 307/308 redirects, downstream server forwarding and destination trustworthiness are not controlled. An INTERNAL receiver can forward data after receipt. No universal network egress guarantee is claimed.
- Native submission intentionally bypasses page submit handlers; applications requiring those handlers are unsupported. Compatibility with every site/CSP/custom element has not been established. HTTPS/localhost secure contexts supply the hashing API; unsupported contexts fail closed.
- ALLOW depends on the existing extractor/detector coverage. PDF image text/annotations and Office hidden/embedded surfaces remain subject to Phase 1 limitations. Native-format sanitization and OCR are deferred.
- Employees can disable the unpacked extension or edit local policies. Signed deployment, managed extension policy, tamper resistance, authentication and enterprise provisioning are deferred.
- macOS Chrome was exercised. Chromium registration exists but was not independently verified; Linux/Windows native browser support is deferred. Native bridge initialization failure is isolated from the other background sources.

## Performance and validation

Five assessments of a 10,500-byte fictional TXT document through the actual private bridge took **68.9–99.7 ms** round trip, with **4–5 ms** inside the Python pipeline. These measurements exclude Chrome file reading, Native Messaging stdio overhead, user consent and server submission. They are not large-file throughput or memory benchmarks. The bridge is serial, uses the existing 30-second bounded worker, and caps combined input at 20 MiB / ten files, framed requests at 30 MiB, and responses at 1 MiB. Safe TXT derivatives are capped at 512 KiB combined. Busy, oversized, stale or timed-out work cannot silently release a file.

Final suite: **174 tests: 109 employee Python + 36 Rust + 7 native-host Python + 22 extension JS**. The baseline was 99 tests, so 75 tests were added. Coverage includes hostname/suffix/IDNA settings, destination policies, multi-file precedence, parser failure, hashes/sizes/schema/path rejection, derivative limits, audit privacy, framing/auth/outcome authorization, duplicate submits, changed selections/destinations, policy invalidation, warning confirmation/cancellation, reset and disconnected agents. JS gate tests use a controlled DOM fixture; the separate real Chrome/server results above establish actual receipt behavior. Rust FSEvents requires normal macOS access outside a restrictive command sandbox. React, release Tauri app and unpacked extension builds passed. No `.git` directory exists in this checkout; nothing was committed or pushed.

## Status and next phase

**Working:** macOS Chrome integration, opt-in form gates, actual initial-destination classification, existing local policies, ALLOW/WARN/BLOCK, small TXT derivative consent, multi-file block, unavailable-agent fail closed, privacy Activity, native settings/status, clipboard/filesystem regressions.

**Partially working:** browser protection covers the stated form subset; REDACT supports safe TXT only; native Activity confirms gate release rather than delivery; connection status uses a 20-second heartbeat and 60-second freshness bound; extraction covers the existing supported text surfaces.

**Architecture only:** the broader ContentEvent model still accommodates SEND/ATTACH/PRINT/SCREEN_SHARE and future adapters, without implementing those boundaries. Admin organization distribution remains a disconnected prototype.

**Deferred:** arbitrary uploads/drop/custom widgets, redirect enforcement, native-format sanitization/OCR, email/print/screen-share adapters, Windows/Linux, independently verified Chromium, durable transaction audit, managed signed installation/tamper resistance and login autostart.

Recommended Phase 4: reproducible packaged Python/native-host/extension installation, managed signed policy delivery and extension deployment, stronger parser isolation, durable boundary acknowledgements, and a narrowly tested custom-upload adapter with explicit redirect handling. Expand proof of enforced boundaries before extending product claims.

Setup and repeatable demo instructions: [browser extension README](../browser-extension/README.md).

After verification, the receiving server was stopped, the isolated agent was quit, and the native host was restored to the normal `~/.axiom-local` configuration. The final release app was launched normally; the installed Chrome popup and native Settings both showed connected. Existing employee policies and folder settings were preserved. Only the two loopback fixture sites were granted extension access during testing.

### Gmail drag-and-drop follow-up

A user confirmed that drag-and-drop into Gmail proceeded despite site access being granted. This path bypassed the standard-form adapter. A conservative Gmail guard now captures file dragenter/dragover/drop events at document start and withholds **every file drop**, without reading contents or releasing a synthetic attachment. It allows text-only drops. This is a block-all unsupported-path guard, not selective policy-backed Gmail protection. Paperclip, Drive attachments, existing uploads and sending remain outside coverage. No fake native UPLOAD_BLOCKED activity is recorded, because the guard does not perform a policy assessment.

The extension popup separates site access/native connectivity from actual coverage, labels Gmail's guard explicitly and lists its unsupported paths. The rebuilt extension was reloaded in the user's active Chrome profile; Gmail was reloaded; the live popup displayed the new guard and limitations. Automated tests verify capture cancellation, withholding without policy/audit claims, and text-only drop behavior. A real Gmail file-drop receipt/non-receipt test has not been performed after this change; use a fictional file for that manual verification.

Five new extension tests pass, bringing the latest total to **179** (109 employee Python, 36 Rust, seven host Python and 27 extension JS). The earlier 174-test real multipart verification remains the evidence for selective policy enforcement.
