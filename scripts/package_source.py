#!/usr/bin/env python3
"""Create a source archive, excluding local runtimes, caches and build outputs."""
import argparse
import hashlib
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.venv', 'venv', 'node_modules', 'target', 'dist', 'dist-ssr',
            '__pycache__', '.pnpm-store', '.axiom-local', '.vscode', '.idea',
            'legacy-model-assets', 'releases', '.aws', '.codex', '.agents'}
TOP_LEVEL = {'README.md', 'Readme', '.gitignore', '.github', 'axiom-employee',
             'axiom-admin', 'browser-extension', 'docs', 'scripts', 'SECURITY.md',
             'CONTRIBUTING.md', 'LICENSE', 'LICENSE.md'}


def source_files(directory):
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or path.name in EXCLUDED:
            continue
        if directory == ROOT and path.name not in TOP_LEVEL:
            continue
        if path.name.startswith('.env') or path.name == '.DS_Store':
            continue
        if path.suffix in {'.pyc', '.log', '.local', '.pem', '.key', '.p12', '.pfx'}:
            continue
        if path.relative_to(ROOT).as_posix() == 'browser-extension/native/axiom-native-host':
            continue
        if path.relative_to(ROOT).as_posix() == 'axiom-employee/src-tauri/models':
            continue  # Unused OCR assets; the active extractor has no OCR support.
        if path.is_dir():
            yield from source_files(path)
        elif path.is_file():
            yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'releases' / 'axiom-experimental-source.tar.gz')
    args = parser.parse_args()
    output = args.output.resolve()
    files = list(source_files(ROOT))
    if output in files:
        parser.error('Output must not replace a source file')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, 'w:gz') as archive:
        for path in files:
            archive.add(path, arcname='axiom/' + path.relative_to(ROOT).as_posix(), recursive=False)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(f'{digest}  {output.name}\n')
    print(f'{len(files)} source files; {output.stat().st_size / 1024 / 1024:.2f} MiB\n{output}\nSHA256 {digest}')


if __name__ == '__main__':
    main()
