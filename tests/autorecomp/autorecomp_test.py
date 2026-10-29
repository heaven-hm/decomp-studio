#!/usr/bin/env python3
"""autorecomp regression.

`autorecomp` runs the whole pipeline — detect, inspect, recover, classify,
check imports, translate, build, and optionally run and verify — with progress,
a log file and a repair loop.

The most important check here is the honesty one: a program that builds and then
fails to run must NOT be reported as a completed port. An earlier revision of
this command printed "AUTORECOMP COMPLETE" and exited 0 while `run` and `verify`
had both failed, because only thrown exceptions were recorded and those two
steps report failure by returning a status rather than throwing.

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

GOOD_FIXTURE = "arith"
FAILING_FIXTURE = "unsupported_import"

REQUIRED_FIELDS = {
    "status", "target", "output", "build_and_run", "repair", "function_count",
    "instruction_count", "unsupported_instructions", "unsupported_class_count",
    "missing_imports", "built", "run_exit_code", "verified", "repaired", "log",
}

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


def analyze(executable: Path):
    result = run_cli(["analyze", str(executable), "--json"])
    return json.loads(result.stdout) if result.returncode == 0 else None


def check_success_path(executable: Path, root: Path) -> None:
    output = root / "good-buildrun"
    result = run_cli(["autorecomp", str(executable), "--output", str(output), "--buildrun", "--json"])
    check("good/exit", result.returncode == 0, f"exited {result.returncode}: {result.stderr.strip()}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        check("good/json", False, f"did not emit JSON: {error}: {result.stdout[:200]!r}")
        return

    missing_fields = REQUIRED_FIELDS - set(payload)
    check("good/fields", not missing_fields, f"missing fields {sorted(missing_fields)}")
    check("good/status", payload["status"] == "ok", f"status is {payload['status']!r}")
    check("good/target-detected", payload["target"] in ("macos-arm64", "macos-x86_64", "linux-arm64", "linux-x86_64"),
          f"unexpected detected target {payload['target']!r}")
    check("good/built", payload["built"] is True, "did not report a built executable")
    check("good/ran", payload["run_exit_code"] == 0, f"run exit code {payload['run_exit_code']}")
    check("good/verified", payload["verified"] is True, "did not verify the translated program")
    check("good/no-unsupported", payload["unsupported_instructions"] == 0,
          f"{payload['unsupported_instructions']} unsupported instructions")
    check("good/no-missing-imports", payload["missing_imports"] == 0,
          f"{payload['missing_imports']} missing imports")

    analyzed = analyze(executable)
    if analyzed is None:
        check("good/analyze-agrees", False, "analyze failed on the fixture")
    else:
        check("good/function-count", payload["function_count"] == analyzed["function_count"],
              f"autorecomp {payload['function_count']} vs analyze {analyzed['function_count']}")
        check("good/instruction-count", payload["instruction_count"] == analyzed["instruction_count"],
              f"autorecomp {payload['instruction_count']} vs analyze {analyzed['instruction_count']}")

    log = Path(payload["log"])
    check("good/log-exists", log.exists(), f"no log at {log}")
    if log.exists():
        text = log.read_text()
        for fragment in ("recomp-studio autorecomp", "detect host and target", "translate to host source",
                         "build native executable", "run native executable", "verify against the reference"):
            check(f"good/log-has-{fragment.split()[0]}", fragment in text, f"log does not mention {fragment!r}")
        check("good/log-result", "result: ok" in text, "log does not record the final result")
    PASSES.append("good/build-and-run-verified")


def check_build_only(executable: Path, root: Path) -> None:
    output = root / "build-only"
    result = run_cli(["autorecomp", str(executable), "--output", str(output), "--json"])
    check("buildonly/exit", result.returncode == 0, f"exited {result.returncode}: {result.stderr.strip()}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        check("buildonly/json", False, result.stdout[:200])
        return
    check("buildonly/mode", payload["build_and_run"] is False, "did not record build-only mode")
    check("buildonly/built", payload["built"] is True, "build-only did not build")
    # Without --buildrun the program is deliberately not run, so verification is
    # not attempted and must not be claimed.
    check("buildonly/not-verified", payload["verified"] is False,
          "build-only must not claim verification")
    check("buildonly/run-not-attempted", payload["run_exit_code"] is None,
          "build-only should not have run the program")
    PASSES.append("buildonly/builds-without-running")


def check_translation_failure(executable: Path, root: Path) -> None:
    result = run_cli(["autorecomp", str(executable), "--output", str(root / "unsupported"), "--buildrun", "--json"])
    payload = json.loads(result.stdout)
    check("translation-failure/exit", result.returncode != 0, "unsupported instruction unexpectedly passed")
    check("translation-failure/no-run-exit", payload["run_exit_code"] is None,
          f"run not reached but exit code is {payload['run_exit_code']!r}")
    check("translation-failure/not-built", payload["built"] is False, "unsupported instruction produced a build")


def check_failure_is_reported(executable: Path, root: Path) -> None:
    """The honesty check: a program that runs and fails is not a completed port."""
    output = root / "failing"
    result = run_cli(["autorecomp", str(executable), "--output", str(output), "--buildrun", "--json"])
    check("fail/exit", result.returncode != 0, "a failed port must exit non-zero")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        check("fail/json", False, result.stdout[:200])
        return
    check("fail/status", payload["status"] == "error", f"status is {payload['status']!r}, expected 'error'")
    check("fail/verified", payload["verified"] is False, "a failed port must not claim verification")
    check("fail/run-nonzero", payload["run_exit_code"] != 0, "expected a non-zero program exit code")
    check("fail/error-field", bool(payload.get("error")), "no error field explaining the failure")
    check("fail/missing-imports", payload["missing_imports"] > 0,
          "the fixture imports MessageBoxA, which has no shim")
    PASSES.append("fail/failure-reported-honestly")


def check_argument_handling() -> None:
    check("args/requires-image", run_cli(["autorecomp"]).returncode != 0,
          "autorecomp without an image must fail")
    with tempfile.TemporaryDirectory() as temporary:
        absent = Path(temporary) / "does-not-exist.exe"
        result = run_cli(["autorecomp", str(absent), "--output", str(Path(temporary) / "out"), "--json"])
        check("args/missing-file", result.returncode != 0, "autorecomp on a nonexistent image must fail")
        try:
            payload = json.loads(result.stdout)
            check("args/missing-file-json", payload["status"] == "error" and bool(payload.get("error")),
                  f"unexpected payload {payload}")
        except json.JSONDecodeError:
            check("args/missing-file-json", False, "a failed run must still emit JSON with --json")
        alias = run_cli(["autorecomp", str(absent), "--output", str(Path(temporary) / "alias"),
                         "--autorepair", "--buildrun", "--json"])
        try:
            payload = json.loads(alias.stdout)
            check("args/autorepair-alias", payload.get("repair") is True and payload.get("build_and_run") is True,
                  f"requested flags were not enabled: {payload}")
        except json.JSONDecodeError:
            check("args/autorepair-alias", False, f"alias was rejected: {alias.stderr.strip()}")


def check_repair_diagnosis(executable: Path, root: Path) -> None:
    output = root / "repair-unimplemented-import"
    result = run_cli(["autorecomp", str(executable), "--output", str(output), "--autorepair", "--buildrun",
                      "--budget", "1", "--json"])
    report = output / "reports" / "harness" / "iteration-1.json"
    check("repair/fails", result.returncode != 0, "unsupported import must not be verified")
    if not report.exists():
        check("repair/report", False, "repair did not write an iteration report")
        return
    payload = json.loads(report.read_text())
    check("repair/no-fake-divergence", payload["diverged"] is False and
          "first control-flow divergence" not in payload["diagnosis"], payload["diagnosis"])
    # The diagnosis must name the import the fixture actually lacks, and that symbol
    # tracks unsupported_import.c -- it was MessageBoxA until the Win32 window surface was
    # implemented. The check is on the CAUSE (a named, unimplemented import), not on which
    # side reached it first: the reference shares the shim table, so both sides lack it and
    # either may report it.
    check("repair/actual-diagnosis", "shell32.dll!ShellExecuteA" in payload["diagnosis"],
          payload["diagnosis"])


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fixture_binaries = root / "bin"
        build_fixtures(fixture_binaries)

        good = fixture_binaries / f"{GOOD_FIXTURE}.exe"
        failing = fixture_binaries / f"{FAILING_FIXTURE}.exe"
        unsupported = fixture_binaries / "unsupported_instruction.exe"
        if good.exists():
            check_success_path(good, root)
            check_build_only(good, root)
        else:
            FAILURES.append(f"{GOOD_FIXTURE}: fixture was not built")
        if failing.exists():
            check_failure_is_reported(failing, root)
            check_repair_diagnosis(failing, root)
        else:
            FAILURES.append(f"{FAILING_FIXTURE}: fixture was not built")
        if unsupported.exists():
            check_translation_failure(unsupported, root)
        else:
            FAILURES.append("unsupported_instruction: fixture was not built")
        check_argument_handling()

    for name in PASSES:
        print(f"PASS {name}")
    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"FAILED: {len(FAILURES)} autorecomp check(s) failed", file=sys.stderr)
        return 1
    print(f"PASS: {len(PASSES)} autorecomp checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
