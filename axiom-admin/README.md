# Axiom admin prototype

The original React/Vite/Tauri management UI is retained for future control-plane work.
Firebase synchronization and credentials have been removed. The UI explicitly reports
that enterprise management is deferred; legacy admin rule fixtures do not enforce
employee scans.

For functional V1 organization configuration, use **Local Rules** in the employee app.
See [the repository README](../README.md) for the actual pipeline and limitations.

Build this retained prototype with `npm install` and `npm run build`; check its native
backend with `cargo check --manifest-path src-tauri/Cargo.toml`. This is not a functioning
enterprise management service or a source of enforced employee policies.
