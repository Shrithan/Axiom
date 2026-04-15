# Axiom employee agent

This is the functional macOS background privacy agent: React/Vite UI, Tauri desktop bridge and
Python extraction → detection → policy → transformation engine.

See [Phase 2 architecture and verification](../docs/PHASE2.md) and [the repository README](../README.md) for setup, the Project Penguin walkthrough,
policy precedence, privacy/storage details and current limitations.

The working organization configuration interface is **Local Rules** inside this app.
Browser mode: build with `npm run build`, then run `python3 scripts/local_server.py`
using an interpreter with `scripts/requirements.txt` installed. Open
`http://127.0.0.1:8765`. Desktop mode: set `AXIOM_PYTHON` to that interpreter and run
`npm run tauri dev`.

`npm run test` uses the `python3` on PATH; when using a virtualenv run
`.venv/bin/python -m unittest discover -s tests -v` instead.

Native-only background sources: selected-folder FSEvents and text NSPasteboard monitoring. Closing the window keeps protection running; Settings/tray Quit stops it. No folders are watched by default, notifications default off, and login autostart is deferred. Browser mode has no background interception.

The UI now uses seven persistent scroll chapters. Sidebar clicks and native navigation events scroll and focus sections without resetting scanner state or unsaved rule drafts. See [motion architecture and verification](../docs/immersive/README.md). Frontend tests: `npm run test:ui`.
