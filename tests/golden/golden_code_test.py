#!/usr/bin/env python3
"""The generated C++ must not change while the lifter moves onto the IR.

Moving the lifter from writing C++ text to building statements and rendering them
is a refactor, and a refactor of a compiler is only trustworthy if its output is
pinned. This compares the generated guest.cpp for every fixture against digests
captured before the work started.

A change here is not automatically a bug -- but it must be a deliberate one, with
the baseline regenerated and the reason recorded, never a side effect.
"""

import hashlib
import pathlib
import subprocess
import sys
import tempfile

CLI = sys.argv[1]
FIXTURES = pathlib.Path(sys.argv[2])
BASELINE = pathlib.Path(sys.argv[3])

PASSES = []
FAILURES = []


def main():
    expected = {}
    for line in BASELINE.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, digest, size = line.split()
        expected[name] = (digest, int(size))
    if not expected:
        print("FAIL: the golden baseline is empty", file=sys.stderr)
        return 1

    checked = 0
    for fixture in sorted((FIXTURES / "bin").glob("*.exe")):
        if fixture.name not in expected:
            continue
        with tempfile.TemporaryDirectory() as workspace:
            result = subprocess.run(
                [CLI, "translate", str(fixture), "--target", "macos-arm64", "--output", workspace],
                text=True, capture_output=True)
            guest = pathlib.Path(workspace) / "guest.cpp"
            if result.returncode != 0 or not guest.exists():
                FAILURES.append(f"{fixture.name}: translate failed: {(result.stdout + result.stderr)[:160]}")
                continue
            body = guest.read_bytes()
            digest = hashlib.sha256(body).hexdigest()
            wanted_digest, wanted_size = expected[fixture.name]
            if digest != wanted_digest:
                FAILURES.append(
                    f"{fixture.name}: generated code changed ({len(body)} bytes, expected {wanted_size}). "
                    "If this is deliberate, regenerate tests/golden/generated_code.sha256 and say why.")
            else:
                PASSES.append(f"{fixture.name}: byte-identical")
            checked += 1

    print(f"checked {checked} fixtures against the golden baseline")
    for line in PASSES:
        print("PASS " + line)
    for line in FAILURES:
        print("FAIL " + line, file=sys.stderr)
    print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
