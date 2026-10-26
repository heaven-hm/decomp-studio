#!/usr/bin/env python3
"""End-to-end regression: every positive fixture must recompile to a native
binary, run, and pass differential verification against the original x86-64 code.

This test cannot silently pass. If a mandatory toolchain is missing it fails
(unless RECOMP_OPTIONAL=1); if verification is unavailable, incomplete, or
reports anything other than an exact match, it fails.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CLI = sys.argv[1]
APPS_DIRECTORY = Path(sys.argv[2])
OPTIONAL_MODE = os.environ.get("RECOMP_OPTIONAL") == "1"

# Fixtures that must recompile, execute and verify.
FIXTURES = [
    ("arith", "arithmetic, recursion, flags"),
    ("tictactoe", "minimax game"),
    ("snake", "deterministic simulation"),
    ("aliasing", "register aliasing"),
    ("eflags", "EFLAGS"),
    ("calls", "calling conventions and indirect calls"),
    ("memory", "memory addressing"),
    ("flagprobe", "per-operation flag semantics"),
    ("wide", "64-bit arithmetic and shifts"),
]

EXPECTED_OUTPUT = {
    "arith": ["arith:start", "primes<200=46", "fib(20)=6765", "gcd(1071,462)=21", "arith:done"],
    "tictactoe": ["tictactoe:start", "result=draw moves=9", "tictactoe:done"],
    "snake": ["snake:start", "snake:done"],
    "aliasing": ["aliasing:start", "zero_extend=1", "aliasing:done"],
    "eflags": ["eflags:start", "flags_checksum=", "eflags:done"],
    "calls": ["calls:start", "sum8=36", "factorial(12)=479001600", "table_dispatch=", "calls:done"],
    "memory": ["memory:start", "table_checksum=", "memory:done"],
    "flagprobe": ["add ", "imul ", "shln "],
    "wide": ["wide:start", "roll=", "wide:done"],
}


def fail(message: str) -> None:
    print("FAIL: " + message, file=sys.stderr)
    raise SystemExit(1)


def build_fixtures(destination: Path) -> None:
    if shutil.which("x86_64-w64-mingw32-gcc") is None:
        if OPTIONAL_MODE:
            print("SKIP (RECOMP_OPTIONAL=1): mingw-w64 x86_64 compiler not available")
            raise SystemExit(0)
        fail("mingw-w64 x86_64 compiler is required; install it or set RECOMP_OPTIONAL=1")
    subprocess.run(["sh", str(APPS_DIRECTORY / "build.sh"), str(destination)], check=True,
                   stdout=subprocess.DEVNULL)


def run_cli(arguments) -> subprocess.CompletedProcess:
    return subprocess.run([CLI, *arguments], text=True, capture_output=True)


def verify_fixture(name: str, executable: Path, project: Path) -> str:
    translated = run_cli(["translate", str(executable), "--target", "macos-arm64",
                          "--output", str(project), "--json"])
    if translated.returncode != 0:
        fail(f"{name}: translate failed: {translated.stderr.strip()}")
    if json.loads(translated.stdout).get("status") != "ok":
        fail(f"{name}: translate did not report ok: {translated.stdout}")

    built = run_cli(["build", str(project), "--json"])
    if built.returncode != 0:
        fail(f"{name}: build failed: {built.stderr.strip()}")

    guest = project / "recomp-guest"
    if not guest.exists():
        fail(f"{name}: generated executable is missing")

    if platform.machine().lower() in ("arm64", "aarch64"):
        description = subprocess.run(["file", str(guest)], text=True, capture_output=True, check=True)
        if "arm64" not in description.stdout.lower():
            fail(f"{name}: generated executable is not arm64: {description.stdout.strip()}")

    execution = run_cli(["run", str(project)])
    if execution.returncode != 0:
        fail(f"{name}: the translated binary failed to run: {execution.stderr.strip()}")
    if not execution.stdout.strip():
        fail(f"{name}: the translated binary produced no output")
    for fragment in EXPECTED_OUTPUT[name]:
        if fragment not in execution.stdout:
            fail(f"{name}: expected output fragment {fragment!r} was not produced")

    verification = run_cli(["verify", str(project), "--json"])
    if verification.returncode != 0:
        detail = verification.stdout.strip() or verification.stderr.strip()
        if "not built" in detail:
            fail(f"{name}: verification backend is unavailable; verification is mandatory ({detail})")
        fail(f"{name}: verification failed: {detail}")

    report = json.loads(verification.stdout)
    if report.get("status") != "pass":
        fail(f"{name}: verification status is {report.get('status')!r}, not 'pass'")
    if not report.get("reference_completed"):
        fail(f"{name}: the reference execution did not complete")
    if not report.get("candidate_completed"):
        fail(f"{name}: the candidate execution did not complete")
    if not report.get("outputs_match"):
        fail(f"{name}: candidate output differs from the reference")
    if report.get("unsupported_mnemonics"):
        fail(f"{name}: translation reported unsupported mnemonics: {report['unsupported_mnemonics']}")
    if report.get("executed_instructions", 0) <= 0:
        fail(f"{name}: the reference executed no instructions")

    return f"{name}: {len(execution.stdout)} bytes, {report['executed_instructions']} reference instructions, VERIFIED"


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fixture_binaries = root / "bin"
        build_fixtures(fixture_binaries)

        for name, description in FIXTURES:
            executable = fixture_binaries / f"{name}.exe"
            if not executable.exists():
                fail(f"{name}: fixture was not built ({description})")
            print("PASS " + verify_fixture(name, executable, root / f"project-{name}"))

        print(f"PASS: {len(FIXTURES)} fixtures recompiled, executed and verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
