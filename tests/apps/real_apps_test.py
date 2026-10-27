#!/usr/bin/env python3
"""End-to-end regression over the genuine Windows applications.

Every other fixture test in this repository runs on binaries this project builds
itself. This one runs on real, third-party Windows executables: it puts each
through the whole pipeline — recover, classify, translate, build, run, verify —
and prints a PASS/FAIL line per application, so the state of the real corpus is
visible in the suite rather than only in a report.

The corpus lives outside the repository and is not redistributable, so when it
is absent this test prints SKIP and exits 0. Set RECOMP_APPS_DIR to point at it,
or pass the directory as the second argument.

Two things it will not do, deliberately:

* It will not treat a program as passing because it ran. An application passes
  only when `verify` reports `pass`, which requires the reference execution to
  complete and the outputs to match.
* It will not fail merely because an application is still unsupported. The
  baseline records where each one is today; the test fails when an application
  gets *worse* (its unsupported-instruction count rises, or a stage that used to
  succeed stops succeeding) and reports when one gets better, so progress and
  regressions are both visible without inventing a green result.

Usage: real_apps_test.py <cli> <apps-dir> <baseline.json> [extra-app ...]
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CLI = sys.argv[1]
BASELINE_PATH = Path(sys.argv[2])
EXTRA_APPS = [Path(argument) for argument in sys.argv[3:]]
# Read from the environment rather than argv so an unset variable cannot collapse
# into a missing argument and shift the rest. An unset variable must mean "no
# corpus", not "the repository root", or the test would quietly run the project's
# own fixtures and call that the real-application corpus.
_APPS_ENVIRONMENT = os.environ.get("RECOMP_APPS_DIR", "").strip()
APPS_DIRECTORY = Path(_APPS_ENVIRONMENT) if _APPS_ENVIRONMENT else None

# Translating and compiling a real application is genuinely slow, so those stages get a
# generous budget. Running one is not: the corpus applications are small, and a
# translated binary that has not finished in two minutes is a signal worth having rather
# than something to wait out. The same budget applies to verification, which executes the
# program a second time through the emulator.
STAGE_TIMEOUT_SECONDS = int(os.environ.get("RECOMP_STAGE_TIMEOUT", "900"))
RUN_TIMEOUT_SECONDS = int(os.environ.get("RECOMP_RUN_TIMEOUT", "120"))
BUILD_INSTRUCTION_LIMIT = int(os.environ.get("RECOMP_BUILD_MAX_INSTRUCTIONS", "200000"))

PASSES = []
FAILURES = []
IMPROVEMENTS = []


def run_cli(arguments, timeout=STAGE_TIMEOUT_SECONDS):
    """Run the CLI, reporting a timeout or a signal as a distinct outcome."""
    try:
        return subprocess.run([CLI, *arguments], text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(arguments, 124, "", f"timed out after {timeout}s")


def discover():
    found = []
    if APPS_DIRECTORY is not None and APPS_DIRECTORY.is_dir():
        found.extend(sorted(path for path in APPS_DIRECTORY.rglob("*.exe")))
    found.extend(path for path in EXTRA_APPS if path.is_file())
    return found


def measure(executable: Path, project: Path):
    """Run one application through the pipeline and return its status record."""
    record = {
        "path": str(executable),
        "sha256": None,
        "unsupported_instructions": None,
        "unsupported_classes": None,
        "first_unsupported": None,
        "missing_imports": None,
        "translated": False,
        "built": False,
        "run_exit_code": None,
        "verify": None,
        "note": "",
    }

    coverage = run_cli(["coverage", str(executable), "--json"])
    if coverage.returncode != 0:
        record["note"] = "coverage failed: " + (coverage.stderr or coverage.stdout).strip()[:160]
        return record
    census = json.loads(coverage.stdout)
    record["unsupported_instructions"] = census["unsupported_instructions"]
    record["unsupported_classes"] = census["unsupported_class_count"]
    if census["unsupported"]:
        record["first_unsupported"] = census["unsupported"][0]["mnemonic"]

    imports = run_cli(["imports", str(executable), "--json"])
    if imports.returncode == 0:
        record["missing_imports"] = json.loads(imports.stdout)["missing_count"]

    translated = run_cli(["translate", str(executable), "--target", "macos-arm64",
                          "--output", str(project), "--json"])
    if translated.returncode != 0:
        record["note"] = (translated.stderr or translated.stdout).strip().splitlines()[0][:160]
        return record
    record["translated"] = True

    # Building a 2,000,000-instruction image takes far longer than a regression
    # suite should, and it is a compile-time cost rather than a correctness
    # signal, so oversized projects are reported as translate-only instead of
    # being silently dropped.
    total = census["total_instructions"]
    if total > BUILD_INSTRUCTION_LIMIT:
        record["note"] = f"translate-only: {total} instructions exceeds the build limit"
        return record

    built = run_cli(["build", str(project), "--json"])
    if built.returncode != 0:
        record["note"] = "build failed: " + (built.stderr or built.stdout).strip().splitlines()[0][:160]
        return record
    record["built"] = True

    executed = run_cli(["run", str(project)], timeout=RUN_TIMEOUT_SECONDS)
    record["run_exit_code"] = executed.returncode
    if executed.returncode == 124:
        record["note"] = f"run did not finish within {RUN_TIMEOUT_SECONDS}s"

    verified = run_cli(["verify", str(project), "--json"], timeout=RUN_TIMEOUT_SECONDS)
    if verified.returncode == 0:
        record["verify"] = json.loads(verified.stdout)["status"]
    else:
        record["verify"] = "fail"
        record["note"] = (verified.stdout or verified.stderr).strip().splitlines()[-1][:160]
    return record


def main() -> int:
    applications = discover()
    if not applications:
        where = APPS_DIRECTORY if APPS_DIRECTORY is not None else "<RECOMP_APPS_DIR unset>"
        print(f"SKIP: no applications found under {where}; "
              "set RECOMP_APPS_DIR to the directory holding the Windows corpus")
        return 0

    baseline = {}
    if BASELINE_PATH.exists():
        baseline = json.loads(BASELINE_PATH.read_text()).get("applications", {})

    records = []
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        print(f"{'application':<28}{'unsupp':>8}{'imports':>9}  {'translate':<10}{'build':<7}{'run':<6}{'verify':<8}note")
        for executable in applications:
            project = root / executable.stem
            started = time.monotonic()
            record = measure(executable, project)
            record["seconds"] = round(time.monotonic() - started, 1)
            records.append(record)
            key = executable.name
            print(f"{key:<28}{str(record['unsupported_instructions']):>8}"
                  f"{str(record['missing_imports']):>9}  "
                  f"{('yes' if record['translated'] else 'NO'):<10}"
                  f"{('yes' if record['built'] else ('-' if not record['translated'] else 'NO')):<7}"
                  f"{str(record['run_exit_code'] if record['built'] else '-'):<6}"
                  f"{str(record['verify'] if record['built'] else '-'):<8}{record['note'][:48]}")

            previous = baseline.get(key)
            if previous is None:
                continue
            # A regression is getting worse, never merely being incomplete.
            if (previous.get("unsupported_instructions") is not None
                    and record["unsupported_instructions"] is not None
                    and record["unsupported_instructions"] > previous["unsupported_instructions"]):
                FAILURES.append(
                    f"{key}: unsupported instructions rose from "
                    f"{previous['unsupported_instructions']} to {record['unsupported_instructions']}")
            elif (previous.get("unsupported_instructions") is not None
                    and record["unsupported_instructions"] is not None
                    and record["unsupported_instructions"] < previous["unsupported_instructions"]):
                IMPROVEMENTS.append(
                    f"{key}: unsupported instructions fell from "
                    f"{previous['unsupported_instructions']} to {record['unsupported_instructions']}")
            for stage in ("translated", "built"):
                if previous.get(stage) and not record[stage]:
                    FAILURES.append(f"{key}: {stage} used to succeed and now does not")
            if previous.get("verify") == "pass" and record["verify"] != "pass":
                FAILURES.append(f"{key}: verification used to pass and now reports {record['verify']!r}")
            # A program that never ran cannot be verified, whatever the backend says.
            if record["verify"] == "pass" and not record["built"]:
                FAILURES.append(f"{key}: verify reported pass for a project that was never built")

    if os.environ.get("RECOMP_WRITE_BASELINE") == "1":
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(json.dumps({
            "note": ("Recorded state of the real-application corpus. The test fails when an "
                     "application gets worse: a higher unsupported-instruction count, a stage that "
                     "used to succeed failing, or a verification that used to pass no longer "
                     "passing. Improvements are reported, not failed. Regenerate with "
                     "RECOMP_WRITE_BASELINE=1."),
            "applications": {
                Path(record["path"]).name: {
                    "unsupported_instructions": record["unsupported_instructions"],
                    "missing_imports": record["missing_imports"],
                    "translated": record["translated"],
                    "built": record["built"],
                    "verify": record["verify"],
                } for record in records
            },
        }, indent=2) + "\n")
        print(f"wrote baseline to {BASELINE_PATH}")

    passing = [r for r in records if r["verify"] == "pass"]
    translating = [r for r in records if r["translated"]]
    print()
    print(f"{len(records)} applications: {len(translating)} translate, "
          f"{len([r for r in records if r['built']])} build, {len(passing)} verify")
    for record in passing:
        PASSES.append(Path(record["path"]).name)

    for name in PASSES:
        print(f"PASS {name}")
    for improvement in IMPROVEMENTS:
        print(f"IMPROVED {improvement}")
    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"FAILED: {len(FAILURES)} regression(s) in the real-application corpus", file=sys.stderr)
        return 1
    if not baseline:
        print(f"NOTE: no baseline at {BASELINE_PATH}; this run only reports")
    print("PASS: no regressions across the real-application corpus")
    return 0


if __name__ == "__main__":
    sys.exit(main())
