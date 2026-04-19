# Axiom immersive scroll interface

Implemented October 14, 2026. Existing dusk palette, bundled landscape, system typography and privacy backend retained.

## Architecture and navigation

`FixedSidebar` and global protection controls stay in the fixed left column. One `ScrollViewport` contains seven persistent `Chapter` sections: overview, activity, documents, browser, clipboard, policies and settings. There is no page-key remount or route replacement. Scanner data/results, file input selection, comparison, filters, browser draft and rule drafts remain mounted while navigating.

`useScrollNavigation` / `scrollController` focus stable section anchors and use native smooth `scrollIntoView`. Reduced-motion navigation is immediate. IntersectionObserver tracks a height-derived reading line and a separate visibility lane. ResizeObserver recalculates that line when window height changes. Legacy dashboard/rules/scan/audit requests map to mounted anchors. Native `axiom-navigate` listeners remain in the single shared `useAgent` hook. No wheel interception, scroll-jacking, snap requirement, duplicate polling or per-section backend subscriptions.

## Motion by chapter

| Chapter | Centerpiece | Meaning |
|---|---|---|
| Overview | Sculptural core with three-dimensional tumble, asymmetric deformation, internal moving light, dashed orbital motion and floating source cards | Actual source states and event IDs; paused core is subdued |
| Activity | Color-coded recorded event nodes, traveling connection light, expanding metadata; quiet rings when empty | Latest five matching real records; filters drive both stream and table |
| Documents | Document outline, scan beam, grouped pipeline nodes, result highlights | Real reading / request pending / completed / error states; no invented sub-stage progress or percentages; BLOCK output is explicitly withheld |
| Browser | Idle boundary, one recorded packet, return or approved branch | Actual recorded upload outcomes; no fabricated traffic, no universal browser protection claim |
| Clipboard | Synthetic Project Penguin text and sequential mask glyphs through a detection field | Explicitly labeled illustration; never real clipboard content; real metadata shown separately |
| Policies | Animated detector/event/destination constraints leading to configured action | One actual rule; enabled/disabled states and validated saved changes; no invented dependencies or precedence |
| Settings | Connected device/core/source nodes | Actual agent, source and worker states; idle is not a parser-health guarantee |

Chapters enter once. Individual centerpieces and dividers pause independently when offscreen, including when their long parent chapter remains visible. Window blur/hidden state pauses motion, and reduced-motion CSS disables it while retaining static information. SVG/CSS only; no new animation framework, canvas/WebGL context or JavaScript frame loop.

## Validation

197 tests passed: 109 engine Python, 36 Rust, seven native-host Python, 27 extension JavaScript, 18 new frontend tests. Frontend tests cover native aliases, forward/reverse tracking, resize, cleanup, independent offscreen gating, reduced-motion navigation, malformed targets, no fake browser packets/release claims, clipboard privacy, disabled rule semantics, BLOCK visualization and bounded finding rendering.

React production build succeeded. Final release Tauri application bundle built and launched. Native interaction checks confirmed persistent unsaved policy drafts, persistent file selection, real scanning with two findings, protected comparison and export, and activity-filter persistence. The exported fictional TXT omitted both the email and protected keyword. Natural keyboard scrolling traversed sections with automatic sidebar updates. Compact layouts were inspected; wide tables become labeled vertical cards and the global protection control remains visible.

Background engine/extension enforcement code was not rewritten. Original Phase 1–3 tests pass. Native event navigation is wired and regression-tested; the final live extension-driven navigation check was not completed before the user requested wrap-up. An existing native-host wrapper was found pointing at an old demo directory and restored to the normal default data directory using the existing installer, with the same extension ID/permissions. No additional site access was granted.

The isolated native test instance was quit and its shell confirmed exit 0. The final app was launched with normal configuration and showed its pre-existing paused state. Production policies and folder settings were not edited. Existing invalid/unavailable monitored folders still require selecting valid folders and saving Settings.

## Performance and limitations

Repeated identical agent-status payloads do not trigger status rerenders. Finding lists render 50 rows per page and retain access to all findings; decision lookup uses a memoized map. Activity data remains bounded by the existing 200-record query. No animated per-row blur. Local background approximately 192 KiB. Final frontend bundle: 277.08 kB JavaScript / 85.98 kB gzip, 48.62 kB CSS / 11.56 kB gzip. Hardware CPU/GPU utilization was not profiled. OS reduced-motion preference was not toggled live; its navigation/static behavior is covered by tests and CSS inspection. Physical trackpad feel was not measured.

macOS screenshot automation became unreliable for foreground/tiling controls and timed out on Dock access. Some captures were taken in a preceding native build before the final offscreen optimization; final visible styling is the same. The desktop mid-scroll image is labeled as such, not a minimum-window verification. Browser upload end-to-end receipt tests were not repeated for this frontend-only change; prior Phase 3 evidence remains the enforcement proof.

## Screenshots

Screenshots contain actual isolated fixture metadata and explicitly labeled synthetic illustrations. No fabricated activity was inserted.

- [Overview](screenshots/overview.png)
- [Activity](screenshots/activity.png)
- [Documents](screenshots/documents.png)
- [Browser](screenshots/browser.png)
- [Clipboard](screenshots/clipboard.png)
- [Policies](screenshots/policies.png)
- [Settings](screenshots/settings.png)
- [Protected document comparison](screenshots/document-comparison.png)
- [Desktop mid-scroll](screenshots/browser-scroll-desktop.png)

## Reproduce

Run `npm --prefix axiom-employee run test:ui` and `npm --prefix axiom-employee run build`. Build the native bundle with `npm --prefix axiom-employee run tauri -- build --bundles app`. Launch `axiom-employee/src-tauri/target/release/bundle/macos/Axiom.app`.
