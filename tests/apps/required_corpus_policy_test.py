#!/usr/bin/env python3
"""Guard the required real-application corpus policy."""

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REAL_APPS = ROOT / "tests" / "apps" / "real_apps_test.py"


def main() -> int:
    environment = os.environ.copy()
    environment.pop("RECOMP_APPS_DIR", None)
    environment["RECOMP_REQUIRE_APPS"] = "1"
    result = subprocess.run(
        [sys.executable, str(REAL_APPS), "/bin/false", str(ROOT / "missing-baseline.json")],
        env=environment,
        text=True,
        capture_output=True,
    )
    if result.returncode != 1 or "requires a real corpus" not in result.stderr:
        print("FAIL: required corpus mode did not reject an absent corpus", file=sys.stderr)
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        return 1
    print("PASS: required corpus mode rejects an absent corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
