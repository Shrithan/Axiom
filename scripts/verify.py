#!/usr/bin/env python3
"""Run release checks without changing the user's agent configuration."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', help='Include macOS Rust tests and release app build')
    args = parser.parse_args()
    checks = [
        [sys.executable, '-m', 'unittest', 'discover', '-s', 'axiom-employee/tests'],
        [sys.executable, '-m', 'unittest', 'discover', '-s', 'browser-extension/tests', '-p', 'test_*.py'],
        ['npm', '--prefix', 'browser-extension', 'test'],
        ['npm', '--prefix', 'browser-extension', 'run', 'build'],
        ['npm', '--prefix', 'axiom-employee', 'run', 'test:ui'],
        ['npm', '--prefix', 'axiom-employee', 'run', 'build'],
        ['npm', '--prefix', 'axiom-admin', 'run', 'build'],
    ]
    if args.native:
        if sys.platform != 'darwin':
            parser.error('--native currently requires macOS')
        checks += [
            ['cargo', 'test', '--manifest-path', 'axiom-employee/src-tauri/Cargo.toml', '--lib'],
            ['npm', '--prefix', 'axiom-employee', 'run', 'tauri', '--', 'build', '--bundles', 'app'],
        ]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    for command in checks:
        print('\nCHECK: ' + ' '.join(command), flush=True)
        result = subprocess.run(command, cwd=ROOT, env=env)
        if result.returncode:
            print('FAILED: fix this check before publishing.', file=sys.stderr)
            return result.returncode
    print('\nAll requested checks passed. Live browser enforcement and installation require manual checks in docs/RELEASE.md.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
