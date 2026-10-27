#!/usr/bin/env python3
"""Preflight: verify the tools the required test suite depends on are present.

Set RECOMP_OPTIONAL=1 to downgrade missing toolchains to a warning (local
development without mingw-w64). In CI this must stay unset so a missing
dependency fails the build instead of silently skipping coverage.
"""

import json
import os
import shutil
import subprocess
import sys

CLI = sys.argv[1]
OPTIONAL_MODE = os.environ.get("RECOMP_OPTIONAL") == "1"

REQUIRED_TOOLS = {
    "x86_64-w64-mingw32-gcc": "compiles the x86-64 (PE32+) fixtures used by the end-to-end tests",
    "i686-w64-mingw32-gcc": "compiles the x86 (PE32) fixtures used by the end-to-end tests",
}
OPTIONAL_TOOLS = {
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

    # `doctor` reports the optional upstream components the integration plan names.
    # It must report them from the artifact each installs, not from a command name:
    # macOS ships a text editor called `xed` in /usr/bin, so a name probe claims
    # Intel XED is present when it is not.
    doctor = subprocess.run([CLI, "doctor", "--json"], text=True, capture_output=True)
    if doctor.returncode != 0:
        print("FAIL: doctor --json did not succeed", file=sys.stderr)
        return 1
    try:
        reported = json.loads(doctor.stdout)
    except json.JSONDecodeError:
        print(f"FAIL: doctor --json is not JSON: {doctor.stdout[:200]}", file=sys.stderr)
        return 1
    for component in ("llvm", "xed", "remill"):
        if component not in reported:
            print(f"FAIL: doctor does not report the {component} state", file=sys.stderr)
            return 1
        print(f"upstream  {component:<26} {'present' if reported[component] else 'absent'}")
    if reported["xed"] and not any(
            os.path.exists(path) for path in (
                "/opt/homebrew/include/xed/xed-interface.h",
                "/usr/local/include/xed/xed-interface.h",
                "/usr/include/xed/xed-interface.h")):
        print("FAIL: doctor reports Intel XED present but no xed-interface.h exists; "
              "the probe is matching a command name, and /usr/bin/xed is a text editor",
              file=sys.stderr)
        return 1

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
