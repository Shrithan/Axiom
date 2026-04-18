# Contributing

Follow [release setup and verification](docs/RELEASE.md). Keep extraction, detection, policy decisions and enforcement outcomes distinct. Add focused regressions for behavior changes; use fictional fixtures. Do not log matches, document bodies, filenames or paths in persisted audit records.

For browser changes, test actual receiver receipts in addition to controlled DOM tests. Do not claim support for an upload mechanism unless its bytes are withheld and the supported policy outcomes are verified. Preserve explicit unsupported and disconnected states.

Run `.venv/bin/python scripts/verify.py --native` on macOS before proposing a release. Explain any checks that could not run. Avoid committing generated outputs, native host launchers, credentials, real documents, local policies or runtime state. A license has not yet been selected by the owner.
