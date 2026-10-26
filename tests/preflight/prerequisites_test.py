#!/usr/bin/env python3
"""Preflight: verify the tools the required test suite depends on are present.

Set RECOMP_OPTIONAL=1 to downgrade missing toolchains to a warning (local
development without mingw-w64). In CI this must stay unset so a missing
dependency fails the build instead of silently skipping coverage.
"""

import os
import shutil
import subprocess
import sys

CLI = sys.argv[1]
OPTIONAL_MODE = os.environ.get("RECOMP_OPTIONAL") == "1"

REQUIRED_TOOLS = {
    "x86_64-w64-mingw32-gcc": "compiles the x86-64 PE fixtures used by the end-to-end tests",
}
OPTIONAL_TOOLS = {
    "i686-w64-mingw32-gcc": "compiles the 32-bit PE fixtures used by the PE32 regression tests",
    "clang++": "compiles generated host projects (the CLI also honours RECOMP_CC)",
    "file": "reports the produced executable's architecture",
}


def main() -> int:
    missing_required = []
    for tool, purpose in REQUIRED_TOOLS.items():
        if shutil.which(tool) is None:
            missing_required.append(f"{tool} ({purpose})")

    for tool, purpose in OPTIONAL_TOOLS.items():
        status = "present" if shutil.which(tool) else "absent"
        print(f"optional  {tool:<26} {status:<8} {purpose}")

    if missing_required:
        message = "missing required tool(s): " + "; ".join(missing_required)
        if OPTIONAL_MODE:
            print("WARNING (RECOMP_OPTIONAL=1): " + message)
        else:
            print("ERROR: " + message, file=sys.stderr)
            print("Install mingw-w64, or set RECOMP_OPTIONAL=1 to skip toolchain tests locally.", file=sys.stderr)
            return 1

    result = subprocess.run([CLI, "--version", "--json"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: recomp-studio is not runnable: {result.stderr}", file=sys.stderr)
        return 1
    print(f"preflight ok: {result.stdout.strip()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
