#!/usr/bin/env python3
"""Coverage census regression.

`coverage` classifies every recovered instruction without aborting, so a program
the lifter cannot translate still produces a complete, accurate diagnostic
instead of a single line. These checks are cross-checked against two commands
that must agree with it:

  * `analyze`    - must report the same recovered function/instruction counts,
                   proving the census walks the same instruction set;
  * `translate`  - must succeed exactly when the census reports 100% coverage,
                   and must fail when it reports anything unsupported.

That pairing is what stops the census from lying in either direction: a census
that over-reports would contradict a successful translation, and one that
under-reports would contradict a failed translation.

This test cannot silently pass. A missing mandatory toolchain fails (unless
RECOMP_OPTIONAL=1).
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

# Fixtures the lifter supports completely: the census must report 100% coverage
# and translation must succeed.
FULLY_COVERED = [
    ("arith", "PE32+ arithmetic, flags and recursion"),
    ("pe32_abi", "PE32 calling conventions and address wrapping"),
]

# Fixture that contains x87, which the lifter does not implement: the census must
# name it and translation must refuse the image.
UNSUPPORTED_FIXTURE = "unsupported_instruction"
EXPECTED_UNSUPPORTED_MNEMONICS = {"fld1", "fstp"}

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


def census(executable: Path, name: str):
    """Return (json_report, text_output); records a failure and returns None if unusable."""
    result = run_cli(["coverage", str(executable), "--json"])
    if result.returncode != 0:
        check(f"{name}/coverage-exit", False, f"coverage exited {result.returncode}: {result.stderr.strip()}")
        return None
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        check(f"{name}/coverage-json", False, f"coverage --json did not emit JSON: {error}: {result.stdout[:200]!r}")
        return None
    text = run_cli(["coverage", str(executable)])
    if text.returncode != 0:
        check(f"{name}/coverage-text-exit", False, f"text coverage exited {text.returncode}")
        return None
    return report, text.stdout


def analyze(executable: Path):
    result = run_cli(["analyze", str(executable), "--json"])
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def check_fully_covered(name: str, description: str, executable: Path, root: Path) -> None:
    outcome = census(executable, name)
    if outcome is None:
        return
    report, text = outcome

    check(f"{name}/zero-unsupported", report["unsupported_instructions"] == 0,
          f"expected 0 unsupported instructions, got {report['unsupported_instructions']} "
          f"({[entry['mnemonic'] for entry in report['unsupported']]})")
    check(f"{name}/full-coverage", report["coverage_percent"] == 100.0,
          f"expected 100% coverage, got {report['coverage_percent']}")
    check(f"{name}/no-classes", report["unsupported_class_count"] == 0,
          f"expected no unsupported classes, got {report['unsupported_class_count']}")
    check(f"{name}/lifted-equals-total",
          report["lifted_instructions"] == report["total_instructions"],
          f"lifted {report['lifted_instructions']} != total {report['total_instructions']}")
    check(f"{name}/walked-something", report["total_instructions"] > 0,
          "the census reported no instructions at all")

    analyzed = analyze(executable)
    if analyzed is None:
        check(f"{name}/analyze-agrees", False, "analyze failed on a supported fixture")
    else:
        check(f"{name}/analyze-instructions-agree",
              analyzed["instruction_count"] == report["total_instructions"],
              f"analyze says {analyzed['instruction_count']} instructions, "
              f"coverage says {report['total_instructions']}")
        check(f"{name}/analyze-functions-agree",
              analyzed["function_count"] == report["function_count"],
              f"analyze says {analyzed['function_count']} functions, "
              f"coverage says {report['function_count']}")

    # A complete census must correspond to a translation that is actually accepted.
    translated = run_cli(["translate", str(executable), "--target", "macos-arm64",
                          "--output", str(root / f"project-{name}"), "--json"])
    check(f"{name}/translate-accepted", translated.returncode == 0,
          f"census claimed full coverage but translate failed: "
          f"{(translated.stderr or translated.stdout).strip()}")

    # The human-readable form must carry the same numbers as the machine form.
    for label, value in (("total", report["total_instructions"]),
                         ("lifted", report["lifted_instructions"]),
                         ("unsupported", report["unsupported_instructions"])):
        check(f"{name}/text-agrees-{label}", str(value) in text,
              f"text output does not mention the {label} count {value}")
    check(f"{name}/text-complete-marker", "complete" in text.lower(),
          "text output does not report complete coverage")

    PASSES.append(f"{name}/fully-covered ({description})")


def check_unsupported(executable: Path, root: Path) -> None:
    name = UNSUPPORTED_FIXTURE
    outcome = census(executable, name)
    if outcome is None:
        return
    report, text = outcome

    check(f"{name}/has-unsupported", report["unsupported_instructions"] > 0,
          "the census reported no unsupported instructions for an x87 fixture")
    check(f"{name}/below-full", report["coverage_percent"] < 100.0,
          f"expected coverage below 100%, got {report['coverage_percent']}")
    check(f"{name}/classes-nonempty", report["unsupported_class_count"] > 0,
          "no unsupported classes were reported")
    check(f"{name}/class-count-matches-list",
          report["unsupported_class_count"] == len(report["unsupported"]),
          f"class count {report['unsupported_class_count']} != listed {len(report['unsupported'])}")

    total_occurrences = sum(entry["occurrences"] for entry in report["unsupported"])
    check(f"{name}/occurrences-sum", total_occurrences == report["unsupported_instructions"],
          f"class occurrences sum to {total_occurrences}, "
          f"unsupported count is {report['unsupported_instructions']}")
    check(f"{name}/parts-sum-to-whole",
          report["lifted_instructions"] + report["unsupported_instructions"] == report["total_instructions"],
          f"{report['lifted_instructions']} + {report['unsupported_instructions']} "
          f"!= {report['total_instructions']}")

    occurrences = [entry["occurrences"] for entry in report["unsupported"]]
    check(f"{name}/sorted-descending", occurrences == sorted(occurrences, reverse=True),
          f"classes are not sorted by frequency: {occurrences}")

    reported = {entry["mnemonic"] for entry in report["unsupported"]}
    missing = EXPECTED_UNSUPPORTED_MNEMONICS - reported
    check(f"{name}/names-x87", not missing,
          f"census did not name {sorted(missing)}; it named {sorted(reported)}")

    for entry in report["unsupported"]:
        check(f"{name}/reason-{entry['mnemonic']}",
              entry["mnemonic"] in entry["reason"] and entry["first_address"].startswith("0x")
              and entry["first_function"].startswith("0x"),
              f"class entry is not self-describing: {entry}")

    # The census must not under-report: a binary it flags must be refused.
    translated = run_cli(["translate", str(executable), "--target", "macos-arm64",
                          "--output", str(root / f"project-{name}"), "--json"])
    check(f"{name}/translate-refused", translated.returncode != 0,
          "the census reported unsupported instructions but translate succeeded")

    for entry in report["unsupported"]:
        check(f"{name}/text-lists-{entry['mnemonic']}", entry["mnemonic"] in text,
              f"text output does not list {entry['mnemonic']}")

    PASSES.append(f"{name}/unsupported-reported ({report['unsupported_class_count']} classes)")


def check_argument_handling() -> None:
    missing_argument = run_cli(["coverage"])
    check("args/requires-image", missing_argument.returncode != 0,
          "coverage without an image must fail")

    with tempfile.TemporaryDirectory() as temporary:
        absent = Path(temporary) / "does-not-exist.exe"
        result = run_cli(["coverage", str(absent)])
        check("args/missing-file", result.returncode != 0,
              "coverage on a nonexistent image must fail")
        check("args/missing-file-diagnostic", bool((result.stderr + result.stdout).strip()),
              "coverage on a nonexistent image must explain why")


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fixture_binaries = root / "bin"
        build_fixtures(fixture_binaries)

        for name, description in FULLY_COVERED:
            executable = fixture_binaries / f"{name}.exe"
            if not executable.exists():
                if name.startswith("pe32_") and OPTIONAL_MODE:
                    print(f"SKIP (RECOMP_OPTIONAL=1): {name} needs the i686 toolchain")
                    continue
                FAILURES.append(f"{name}: fixture was not built ({description})")
                continue
            check_fully_covered(name, description, executable, root)

        unsupported = fixture_binaries / f"{UNSUPPORTED_FIXTURE}.exe"
        if unsupported.exists():
            check_unsupported(unsupported, root)
        else:
            FAILURES.append(f"{UNSUPPORTED_FIXTURE}: negative fixture was not built")

        check_argument_handling()

    for name in PASSES:
        print(f"PASS {name}")
    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"FAILED: {len(FAILURES)} coverage check(s) failed", file=sys.stderr)
        return 1
    print(f"PASS: {len(PASSES)} coverage census checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
