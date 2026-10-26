#!/usr/bin/env python3
"""End-to-end regression: real x86-64 PE fixtures recompile to native binaries
that run and produce verified output."""

import json
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CLI, APPS_DIRECTORY, RUNTIME_DIRECTORY = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])

EXPECTED_OUTPUT = {
    "arith": ["arith:start", "primes<200=46", "fib(20)=6765", "gcd(1071,462)=21", "arith:done"],
    "tictactoe": ["tictactoe:start", "result=draw moves=9", "tictactoe:done"],
    "snake": ["snake:start", "snake:done"],
}


def build_fixtures(destination: Path) -> bool:
    if shutil.which("x86_64-w64-mingw32-gcc") is None:
        return False
    subprocess.run(["sh", str(APPS_DIRECTORY / "build.sh"), str(destination)], check=True)
    return True


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fixture_binaries = root / "bin"
        if not build_fixtures(fixture_binaries):
            print("SKIP: mingw-w64 x86_64 compiler not available")
            return 0

        for name, expected in EXPECTED_OUTPUT.items():
            executable = fixture_binaries / f"{name}.exe"
            project = root / f"project-{name}"

            translated = subprocess.run(
                [CLI, "translate", str(executable), "--target", "macos-arm64", "--output", str(project), "--json"],
                text=True, capture_output=True)
            assert translated.returncode == 0, translated.stderr
            assert json.loads(translated.stdout)["status"] == "ok", translated.stdout

            built = subprocess.run([CLI, "build", str(project), "--json"], text=True, capture_output=True)
            assert built.returncode == 0, built.stderr
            guest = project / "recomp-guest"
            assert guest.exists(), "generated executable is missing"

            if platform.machine().lower() in ("arm64", "aarch64"):
                description = subprocess.run(["file", str(guest)], text=True, capture_output=True, check=True)
                assert "arm64" in description.stdout.lower(), description.stdout

            execution = subprocess.run([CLI, "run", str(project)], text=True, capture_output=True)
            assert execution.returncode == 0, execution.stderr
            for fragment in expected:
                assert fragment in execution.stdout, f"{name}: missing {fragment!r} in {execution.stdout!r}"

            verification = subprocess.run([CLI, "verify", str(project), "--json"], text=True, capture_output=True)
            if verification.returncode == 0:
                assert json.loads(verification.stdout)["status"] == "pass", verification.stdout
            else:
                assert "not built" in verification.stderr or "not built" in verification.stdout, verification.stderr

            print(f"PASS {name}: {len(execution.stdout)} bytes of verified output")
    return 0


if __name__ == "__main__":
    sys.exit(main())
