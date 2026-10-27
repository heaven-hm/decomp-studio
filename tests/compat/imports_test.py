#!/usr/bin/env python3
"""Import compatibility report regression.

`imports` answers the question instruction coverage cannot: whether the
program's operating-system surface exists. A binary can be at 100% instruction
coverage and still stop on its first call into an unimplemented DLL.

The report reads the calling-convention table in `runtime/win32_abi.hpp`, while
the runtime dispatches through its own table in `runtime/recomp_runtime.cpp`. If
those two ever drift apart the report would claim an import works when it does
not, so this test parses both and requires them to agree exactly. That check is
the reason the "implemented" count can be trusted at all.

This test cannot silently pass. A missing mandatory toolchain fails (unless
RECOMP_OPTIONAL=1).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CLI = sys.argv[1]
APPS_DIRECTORY = Path(sys.argv[2])
REPOSITORY_ROOT = Path(sys.argv[3])
OPTIONAL_MODE = os.environ.get("RECOMP_OPTIONAL") == "1"

PASSES = []
FAILURES = []

# Fixture whose imports are all shimmed.
FULLY_SHIMMED = ("arith", 3)
# Fixture that calls user32!MessageBoxA, which has no shim.
UNSUPPORTED_FIXTURE = "unsupported_import"
EXPECTED_MISSING = ("user32.dll", "MessageBoxA")


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


def report(executable: Path, name: str):
    result = run_cli(["imports", str(executable), "--json"])
    if result.returncode != 0:
        check(f"{name}/exit", False, f"imports exited {result.returncode}: {result.stderr.strip()}")
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        check(f"{name}/json", False, f"imports --json did not emit JSON: {error}")
        return None
    text = run_cli(["imports", str(executable)])
    if text.returncode != 0:
        check(f"{name}/text-exit", False, f"text imports exited {text.returncode}")
        return None
    return payload, text.stdout


def inspect_import_count(executable: Path):
    result = run_cli(["inspect", str(executable), "--json"])
    if result.returncode != 0:
        return None
    return json.loads(result.stdout).get("import_count")


def check_fully_shimmed(executable: Path) -> None:
    name, expected_imports = FULLY_SHIMMED
    outcome = report(executable, name)
    if outcome is None:
        return
    payload, text = outcome

    check(f"{name}/import-count", payload["import_count"] == expected_imports,
          f"expected {expected_imports} imports, got {payload['import_count']}")
    check(f"{name}/nothing-missing", payload["missing_count"] == 0,
          f"expected no missing imports, got {payload['missing']}")
    check(f"{name}/all-implemented", payload["implemented_count"] == payload["import_count"],
          f"implemented {payload['implemented_count']} of {payload['import_count']}")
    check(f"{name}/percent", payload["implemented_percent"] == 100.0,
          f"expected 100.00%, got {payload['implemented_percent']}")
    check(f"{name}/text-complete", "complete" in text.lower(),
          "text output does not report complete compatibility")
    PASSES.append(f"{name}/fully-shimmed")


def check_unsupported(executable: Path) -> None:
    name = UNSUPPORTED_FIXTURE
    outcome = report(executable, name)
    if outcome is None:
        return
    payload, text = outcome

    check(f"{name}/has-missing", payload["missing_count"] > 0,
          "reported no missing imports for a fixture that calls MessageBoxA")
    check(f"{name}/below-complete", payload["implemented_percent"] < 100.0,
          f"expected under 100%, got {payload['implemented_percent']}")
    check(f"{name}/counts-add-up",
          payload["implemented_count"] + payload["missing_count"] == payload["import_count"],
          f"{payload['implemented_count']} + {payload['missing_count']} != {payload['import_count']}")
    check(f"{name}/library-counts-add-up",
          sum(entry["imports"] for entry in payload["libraries"]) == payload["import_count"],
          "per-library import counts do not sum to the total")
    check(f"{name}/library-missing-add-up",
          sum(entry["missing"] for entry in payload["libraries"]) == payload["missing_count"],
          "per-library missing counts do not sum to the total")

    reported = {(entry["library"], entry["symbol"]) for entry in payload["missing"]}
    check(f"{name}/names-unshimmed", EXPECTED_MISSING in reported,
          f"expected {EXPECTED_MISSING} in the missing list, got {sorted(reported)}")

    library, symbol = EXPECTED_MISSING
    check(f"{name}/text-lists-missing", f"{library}!{symbol}" in text,
          f"text output does not list {library}!{symbol}")
    PASSES.append(f"{name}/unsupported-reported ({payload['missing_count']} missing)")


def check_agrees_with_inspect(executables) -> None:
    for name, executable in executables:
        outcome = report(executable, f"{name}-inspect")
        if outcome is None:
            continue
        payload, _ = outcome
        count = inspect_import_count(executable)
        check(f"{name}/inspect-agrees", count == payload["import_count"],
              f"inspect says {count} imports, imports says {payload['import_count']}")
        PASSES.append(f"{name}/inspect-agrees")


def check_shim_tables_agree() -> None:
    """The report's 'implemented' set must be the runtime's real shim set."""
    header = REPOSITORY_ROOT / "runtime" / "win32_abi.hpp"
    runtime = REPOSITORY_ROOT / "runtime" / "recomp_runtime.cpp"
    if not header.exists() or not runtime.exists():
        check("shim-tables/present", False, f"cannot find {header} or {runtime}")
        return

    declared = set(re.findall(r'\{"([^"]+)",\s*"([^"]+)",\s*\d+,\s*(?:true|false)\}',
                              header.read_text()))
    # The implementation table's third field is a function name; the ABI table's
    # is a digit, which is what distinguishes the two shapes. Matching only
    # `win32_` names would silently stop checking anything a differently named
    # shim family added, which is exactly the drift this guards against.
    implemented = set(re.findall(r'\{"([^"]+)",\s*"([^"]+)",\s*[A-Za-z_][A-Za-z0-9_]*\}',
                                 runtime.read_text()))

    check("shim-tables/non-empty", len(declared) > 0 and len(implemented) > 0,
          f"parsed {len(declared)} declared and {len(implemented)} implemented shims")
    only_declared = sorted(declared - implemented)
    only_implemented = sorted(implemented - declared)
    check("shim-tables/declared-are-implemented", not only_declared,
          f"declared in win32_abi.hpp but not implemented in the runtime: {only_declared}")
    check("shim-tables/implemented-are-declared", not only_implemented,
          f"implemented in the runtime but missing from win32_abi.hpp: {only_implemented}")
    PASSES.append(f"shim-tables/agree ({len(declared)} shims)")


def check_argument_handling() -> None:
    check("args/requires-image", run_cli(["imports"]).returncode != 0,
          "imports without an image must fail")
    with tempfile.TemporaryDirectory() as temporary:
        absent = Path(temporary) / "does-not-exist.exe"
        result = run_cli(["imports", str(absent)])
        check("args/missing-file", result.returncode != 0,
              "imports on a nonexistent image must fail")
        check("args/missing-file-diagnostic", bool((result.stderr + result.stdout).strip()),
              "imports on a nonexistent image must explain why")


def main() -> int:
    check_shim_tables_agree()
    check_argument_handling()

    with tempfile.TemporaryDirectory() as temporary:
        fixture_binaries = Path(temporary) / "bin"
        build_fixtures(fixture_binaries)

        fully = fixture_binaries / f"{FULLY_SHIMMED[0]}.exe"
        if fully.exists():
            check_fully_shimmed(fully)
        else:
            FAILURES.append(f"{FULLY_SHIMMED[0]}: fixture was not built")

        unsupported = fixture_binaries / f"{UNSUPPORTED_FIXTURE}.exe"
        if unsupported.exists():
            check_unsupported(unsupported)
        else:
            FAILURES.append(f"{UNSUPPORTED_FIXTURE}: negative fixture was not built")

        pairs = [(name, path) for name, path in
                 ((FULLY_SHIMMED[0], fully), (UNSUPPORTED_FIXTURE, unsupported)) if path.exists()]
        check_agrees_with_inspect(pairs)

    for name in PASSES:
        print(f"PASS {name}")
    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"FAILED: {len(FAILURES)} import compatibility check(s) failed", file=sys.stderr)
        return 1
    print(f"PASS: {len(PASSES)} import compatibility checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
