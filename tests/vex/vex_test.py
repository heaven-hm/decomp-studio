#!/usr/bin/env python3
"""VEX (AVX) encoding regression, checked by value.

Why this test is not differential, unlike every other fixture test here.

Recomp Studio verifies a translation by executing the original machine code
under Unicorn and comparing output byte for byte. That works for the SSE, x87
and integer instruction sets, but not for VEX/AVX: Unicorn does not emulate it
faithfully. Unicorn's own tracker says so —

  * issue #1074, "[x86_64] incorrect emulation of most VEX instructions",
    https://github.com/unicorn-engine/unicorn/issues/1074 — names vpxor;
  * PR #1658, "Fail when VEX.L is set in SSE instructions (AVX is not supported)",
    https://github.com/unicorn-engine/unicorn/pull/1658 — "YMM isn't supported
    in qemu upstream at all".

Measured on this machine (Unicorn 2.1.4), for the fixture below:

  value                       this program (SDM)   Unicorn reference
  vmulsd upper half           4.5 (merged)         0 (not merged)
  vpxor checksum              6175760664974581504  -6300853929389498616

The first is the SDM rule `DEST[127:64] := SRC1[127:64]`, which QEMU itself
implements in ops_sse.h's SSE_HELPER_S. The second is arithmetic on inputs whose
result bytes are all 0xff, so it is computable by hand. In both cases the
translation is right and the reference is wrong.

So this test asserts the values the SDM requires, and asserts that the fixture
lifts completely. It deliberately does NOT claim differential verification, and
it checks that the fixture is absent from the differential suite rather than
letting a known-bad reference fail there.

This test cannot silently pass: a missing toolchain fails (unless
RECOMP_OPTIONAL=1), and every expected value is a literal.
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

FIXTURE = "vex"

# Every line the fixture prints, with the value the Intel SDM requires. These are
# literals on purpose: a regression has to change a number here, not silently
# change what "correct" means.
EXPECTED_LINES = [
    "vex:start",
    "vmulsd_lo=0",
    "vmulsd_hi_x2=0",          # src1's upper half is zero (see the fixture note)
    "vaddsd_lo=3",
    "vaddsd_hi_x2=0",
    "vmovdqu_checksum=-1810799853885296360",
    "vpxor_checksum=6175760664974581504",
    "vcvtsi2sd=-1234",
    "vex:done",
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

        # 1. It must lift completely, or nothing below can run.
        census = run_cli(["coverage", str(executable), "--json"])
        check("coverage/exit", census.returncode == 0, census.stderr.strip())
        if census.returncode == 0:
            report = json.loads(census.stdout)
            check("coverage/complete", report["unsupported_instructions"] == 0,
                  f"{report['unsupported_instructions']} unsupported: "
                  f"{[e['mnemonic'] for e in report['unsupported']]}")
            check("coverage/walked", report["total_instructions"] > 0,
                  "the census walked no instructions")

        # 2. It must translate and build.
        project = root / "project"
        translated = run_cli(["translate", str(executable), "--target", "macos-arm64",
                              "--output", str(project), "--json"])
        check("translate/exit", translated.returncode == 0,
              (translated.stderr or translated.stdout).strip())
        built = run_cli(["build", str(project), "--json"])
        check("build/exit", built.returncode == 0, (built.stderr or built.stdout).strip())

        # 3. The values must be the ones the SDM requires.
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

        # 4. The fixture must stay out of the differential suite, because the
        #    reference cannot adjudicate it. If someone adds it there, the suite
        #    would fail for the reference's reason and look like a regression.
        end_to_end = (APPS_DIRECTORY.parent.parent / "end-to-end" / "recompile_test.py").read_text()
        check("suite/not-differential", f'("{FIXTURE}",' not in end_to_end,
              f"{FIXTURE} is listed in the differential fixture suite, but Unicorn cannot "
              "verify VEX; see the module docstring")

    for name in PASSES:
        print(f"PASS {name}")
    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"FAILED: {len(FAILURES)} VEX check(s) failed", file=sys.stderr)
        return 1
    print(f"PASS: {len(PASSES)} VEX checks (by value; differential verification unavailable)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
