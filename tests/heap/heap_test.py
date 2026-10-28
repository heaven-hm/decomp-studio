#!/usr/bin/env python3
"""Guest heap regression, checked by value.

Why this is not a differential test, unlike the other fixture tests.

Recomp Studio verifies a translation by running the original machine code under
Unicorn with the same Win32 shims as the runtime, then comparing output. That
assumption does not currently hold: the reference's shim emulation models four
symbols (GetStdHandle, WriteFile, ReadFile, ExitProcess) and the runtime
implements 63, so any guest that calls anything else gets a null result from the
reference and a real one from the candidate.

That used to be invisible, because the reference returned 0 for an unmodelled
import and the comparison simply failed with a confusing divergence. It now
stops and reports `reference does not model <library>!<symbol>`, which this test
asserts, so the gap cannot silently look like a translation bug.

The heap is the case that exposed it. HeapFree was a no-op and HeapAlloc only
bumped a pointer, so a guest that allocates and frees in a loop consumed the
region until allocations returned null. The fixture pushes 200 MB through a
128 MB region; the old allocator died around round 128.

This test cannot silently pass: the expected values are literals, and a missing
toolchain fails unless RECOMP_OPTIONAL=1.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CLI = sys.argv[1]
APPS_DIRECTORY = Path(sys.argv[2])
OPTIONAL_MODE = os.environ.get("RECOMP_OPTIONAL") == "1"

FIXTURE = "heap"

EXPECTED_LINES = [
    "heap:start",
    "heap_handle_nonzero=1",
    "rounds_completed=200",          # 200 MB through a 128 MB region
    "heap_checksum=1533866663046942392",
    "small_checksum=5564290431150879872",
    "heap:done",
]

PASSES = []
FAILURES = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSES.append(name)
    else:
        FAILURES.append(f"{name}: {detail}")


def run_cli(arguments) -> subprocess.CompletedProcess:
    return subprocess.run([CLI, *arguments], text=True, capture_output=True)


def build_fixtures(destination: Path) -> None:
    if shutil.which("x86_64-w64-mingw32-gcc") is None:
        if OPTIONAL_MODE:
            print("SKIP (RECOMP_OPTIONAL=1): mingw-w64 x86_64 compiler not available")
            raise SystemExit(0)
        print("ERROR: mingw-w64 x86_64 compiler is required", file=sys.stderr)
        raise SystemExit(1)
    subprocess.run(["sh", str(APPS_DIRECTORY / "build.sh"), str(destination)], check=True,
                   stdout=subprocess.DEVNULL)


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fixtures = root / "bin"
        build_fixtures(fixtures)
        executable = fixtures / f"{FIXTURE}.exe"
        if not executable.exists():
            print(f"FAIL {FIXTURE}: fixture was not built", file=sys.stderr)
            return 1

        census = run_cli(["coverage", str(executable), "--json"])
        check("coverage/exit", census.returncode == 0, census.stderr.strip())
        if census.returncode == 0:
            report = json.loads(census.stdout)
            check("coverage/complete", report["unsupported_instructions"] == 0,
                  f"{report['unsupported_instructions']} unsupported: "
                  f"{[e['mnemonic'] for e in report['unsupported']]}")

        project = root / "project"
        translated = run_cli(["translate", str(executable), "--target", "macos-arm64",
                              "--output", str(project), "--json"])
        check("translate/exit", translated.returncode == 0,
              (translated.stderr or translated.stdout).strip())
        built = run_cli(["build", str(project), "--json"])
        check("build/exit", built.returncode == 0, (built.stderr or built.stdout).strip())

        execution = run_cli(["run", str(project)])
        check("run/exit", execution.returncode == 0,
              f"exit {execution.returncode}: {execution.stderr.strip()}")
        produced = execution.stdout.splitlines()
        for index, expected in enumerate(EXPECTED_LINES):
            actual = produced[index] if index < len(produced) else "<missing>"
            check(f"value/{expected.split('=')[0]}", actual == expected,
                  f"expected {expected!r}, got {actual!r}")
        check("value/line-count", len(produced) == len(EXPECTED_LINES),
              f"expected {len(EXPECTED_LINES)} lines, got {len(produced)}")

        # The reference now runs the heap fixture, because it dispatches through
        # the runtime's own shims and starts from the same guest state. That is a
        # stronger claim than the one this test used to pin, so it is pinned the
        # stronger way: the comparison must actually detect a behavioural change.
        # A pass on its own proves nothing, so the run below is checked against a
        # deliberately corrupted candidate as well.
        verification = run_cli(["verify", str(project), "--json"])
        check("verify/exit", verification.returncode == 0,
              "the heap fixture no longer verifies; the reference shares the runtime's shims")
        try:
            payload = json.loads(verification.stdout)
            check("verify/reference-completes", payload["reference_completed"] is True,
                  "the reference did not complete the heap fixture")
            check("verify/verified", payload["status"] == "pass",
                  "the heap fixture did not verify")
            check("verify/outputs-match", payload["outputs_match"] is True,
                  "the reference and candidate outputs differ")
            check("verify/compared-something",
                  payload["executed_instructions"] > 1000,
                  f"only {payload['executed_instructions']} reference instructions executed")
        except json.JSONDecodeError:
            check("verify/json", False, verification.stdout[:200])

        diagnosis = run_cli(["verify", str(project)]).stdout
        # The pass line used to read "VERIFY: PASS (identical output)", and this checked
        # for that phrase. It was removed because it UNDERSTATES the gate: output
        # agreement alone is not a pass, and a reader who sees it reasonably concludes it
        # is. The verdict name is the honest summary, so that is what is checked now.
        check("verify/reports-verdict", "verdict: " in diagnosis,
              f"the run does not report a verdict: {diagnosis.strip()[:200]}")

        # It must stay out of the differential suite, where it would fail for
        # the reference's reason and look like a regression.
        end_to_end = (APPS_DIRECTORY.parent.parent / "end-to-end" / "recompile_test.py").read_text()
        check("suite/not-differential", f'("{FIXTURE}",' not in end_to_end,
              f"{FIXTURE} is listed in the differential fixture suite, but the reference does "
              "not model the heap shims")

    for name in PASSES:
        print(f"PASS {name}")
    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"FAILED: {len(FAILURES)} heap check(s) failed", file=sys.stderr)
        return 1
    print(f"PASS: {len(PASSES)} heap checks (by value; the reference cannot model the heap)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
