# Axiom Dusk redesign

Implemented October 13, 2026. Existing React/Tauri app, no privacy-engine changes.

## Implementation

Three-zone overview; locally bundled dusk landscape; system serif/sans typography; shared live agent state; reusable inline SVG icons and animated translucent SVG sculpture. All seven navigation sections restyled. Metadata-only activity search/source filters/details; document import, findings, explicit local reveal, original/protected comparison and native export; existing rule validation and native source controls retained. Settings grouped by protection, notifications, monitored folders, browser and diagnostics. Native window minimum 760 × 560.

## Validation

179 existing tests passed: 109 engine Python, 36 Rust, seven native-host Python, 27 extension JavaScript. React production build and release Tauri app bundle succeeded. Native app launched. Isolated live tests passed pause/resume, fictional TXT extraction/email detection/masking, comparison, native derivative export (original email absent), policy save and enable toggle persistence, folder monitoring with real REVIEW_REQUIRED event, and fictional clipboard CLIPBOARD_REPLACED event. Captured all major pages and native 1440 × 920, roughly 760 × 950, 760 × 560 and macOS Fill layouts; corrected minimum-height sidebar control overflow. Normal app restored afterward with existing paused state preserved. Normal configuration reports unavailable configured folders; no production policies/folder settings changed.

Chrome extension and native bridge code/permissions unchanged. Extension and native-host regression tests passed. A fresh live Chrome connection check was started but not completed when the user requested wrap-up. No new browser upload end-to-end test claimed.

## Performance and limitations

No added animation package, external runtime image/font requests, WebGL context or JavaScript animation-frame loop. Background WebP approximately 192 KiB; final frontend JavaScript 260.87 kB / 81.28 kB gzip, CSS 21.96 kB / 5.99 kB gzip. SVG/CSS ambient motion pauses on document hidden/window blur; reduced-motion media rules disable animations/transitions. Lists use finite entrance animation, not per-row blur. CPU/GPU numbers were not instrumented. Reduced-motion behavior was checked in source, not by changing the OS preference live. Orb is a layered vector interpretation, not the reference's physically rendered 3D object. Narrow layouts use vertical scrolling and move the activity column beneath the hero. Native window decorations retained. Document exports remain extracted-text/CSV derivatives, not original-layout reconstruction. Gmail coverage remains the separate all-file-drop stopgap, not universal/selective Gmail protection.

## Asset provenance

`axiom-employee/public/assets/dusk-lake.webp` was generated using the built-in imagegen tool for this project, then locally converted to WebP. It is not a copied stock photo or the reference screenshot. Prompt: cinematic photographic alpine mountain lake at dusk; jagged Dolomite-like mountains layered in smoky blue haze; dark pine forest silhouettes; still water reflecting muted peach horizon light; deep navy/charcoal foreground, lavender sky; open center for an interface overlay; no interface, orb, text, logos, people, buildings or watermark. No runtime network dependency.

## Screenshots

Screenshots show real isolated test data, never fabricated dashboard events.

- [activity](screenshots/activity.png) — 2880 × 1840 capture pixels
- [browser](screenshots/browser.png) — 2880 × 1840 capture pixels
- [clipboard](screenshots/clipboard.png) — 2880 × 1840 capture pixels
- [document-comparison](screenshots/document-comparison.png) — 2880 × 1840 capture pixels
- [documents](screenshots/documents.png) — 2880 × 1840 capture pixels
- [overview-desktop](screenshots/overview-desktop.png) — 3024 × 1900 capture pixels
- [overview-laptop](screenshots/overview-laptop.png) — 2880 × 1840 capture pixels
- [overview-live](screenshots/overview-live.png) — 2880 × 1840 capture pixels
- [overview-minimum](screenshots/overview-minimum.png) — 1522 × 1122 capture pixels
- [overview-small](screenshots/overview-small.png) — 1522 × 1900 capture pixels
- [policies](screenshots/policies.png) — 2880 × 1840 capture pixels
- [settings](screenshots/settings.png) — 2880 × 1840 capture pixels
