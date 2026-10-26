#!/usr/bin/env python3
"""Fixture reproducibility: identical sources must produce byte-identical PE
fixtures, so a regression cannot hide behind a changing input binary."""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

APPS_DIRECTORY = Path(sys.argv[1])
OPTIONAL_MODE = os.environ.get("RECOMP_OPTIONAL") == "1"


def build(destination: Path) -> Path:
    subprocess.run(["sh", str(APPS_DIRECTORY / "build.sh"), str(destination)], check=True,
                   stdout=subprocess.DEVNULL)
    manifest = destination / "fixtures.sha256"
    assert manifest.exists(), "fixtures.sha256 was not produced"
    return manifest


def read_manifest(path: Path) -> dict:
    entries = {}
    for line in path.read_text().splitlines():
        digest, _, name = line.partition("  ")
        entries[name] = digest
    return entries


def main() -> int:
    if shutil.which("x86_64-w64-mingw32-gcc") is None:
        if OPTIONAL_MODE:
            print("SKIP (RECOMP_OPTIONAL=1): mingw-w64 x86_64 compiler not available")
            return 0
        print("ERROR: mingw-w64 x86_64 compiler is required", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        first = read_manifest(build(root / "first"))
        second = read_manifest(build(root / "second"))

        if set(first) != set(second):
            print(f"FAIL: fixture sets differ: {sorted(first)} vs {sorted(second)}", file=sys.stderr)
            return 1

        mismatches = [name for name in first if first[name] != second[name]]
        if mismatches:
            for name in mismatches:
                print(f"FAIL: {name} is not reproducible ({first[name]} != {second[name]})", file=sys.stderr)
            return 1

        print(f"PASS: {len(first)} fixtures are byte-for-byte reproducible")
    return 0


if __name__ == "__main__":
    sys.exit(main())
