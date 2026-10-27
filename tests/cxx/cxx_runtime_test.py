#!/usr/bin/env python3
"""The C++ runtime, checked by value.

A GCC-built Windows program reaches libstdc++ through C++ member functions, and a
member function passes `this` in ECX rather than on the stack. The recompiler
modelled every imported function as cdecl or stdcall, so a member function's
arguments were read one stack slot late: `operator<<(int)` was handed `this`
where the number should have been, and printed the address of the string literal
written immediately before it. Every line of output here is an expected value, so
that failure cannot return silently.

Checked by value rather than differentially, and deliberately so: the reference
models four Windows imports and none of libstdc++, so it cannot run this program
at all. Reporting differential verification for it would be reporting something
untrue.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CLI = sys.argv[1]
FIXTURES = Path(sys.argv[2])
OPTIONAL_MODE = os.environ.get("RECOMP_OPTIONAL") == "1"
CXX = os.environ.get("CXX32", "i686-w64-mingw32-g++")

EXPECTED = """cxx:start
short_size=3
short_value=abc
long_size=46
long_value=a string long enough to leave the local buffer
copy_matches=1
assigned_value=abc
member_value=42
member_string=counter=seven
stream_int=4242
cxx:done
"""

PASSES = []
FAILURES = []


def check(name, condition, detail=""):
    if condition:
        PASSES.append(name)
    else:
        FAILURES.append(f"{name}: {detail}")


def run_cli(arguments):
    return subprocess.run([CLI, *arguments], text=True, capture_output=True)


def main():
    if shutil.which(CXX) is None:
        if OPTIONAL_MODE:
            print(f"SKIP (RECOMP_OPTIONAL=1): {CXX} is not installed")
            return 0
        print(f"FAIL: {CXX} is required to build the C++ fixture", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)
        executable = workspace / "cxxruntime.exe"
        built = subprocess.run(
            [CXX, "-O2", "-fno-asynchronous-unwind-tables", "-fno-stack-protector",
             "-Wl,--no-insert-timestamp", "-Wl,--subsystem,console",
             "-o", str(executable), str(FIXTURES / "cxxruntime.cpp")],
            text=True, capture_output=True)
        if built.returncode != 0:
            print("FAIL: could not build the C++ fixture\n" + built.stderr[:800], file=sys.stderr)
            return 1

        project = workspace / "project"
        translated = run_cli(["translate", str(executable), "--target", "macos-arm64",
                              "--output", str(project)])
        check("c++ fixture translates", translated.returncode == 0,
              (translated.stdout + translated.stderr)[:200])
        if translated.returncode != 0:
            for line in PASSES:
                print("PASS " + line)
            for line in FAILURES:
                print("FAIL " + line, file=sys.stderr)
            return 1

        compiled = run_cli(["build", str(project)])
        check("c++ fixture builds", compiled.returncode == 0,
              (compiled.stdout + compiled.stderr)[:200])
        if compiled.returncode != 0:
            for line in PASSES:
                print("PASS " + line)
            for line in FAILURES:
                print("FAIL " + line, file=sys.stderr)
            return 1

        # The program reads nothing, so it terminates on its own.
        guest = project / "recomp-guest"
        executed = subprocess.run([str(guest)], text=True, capture_output=True, timeout=120)
        check("c++ fixture runs", executed.returncode == 0,
              f"exit {executed.returncode}: {executed.stderr[-300:]}")
        check("c++ fixture output matches exactly", executed.stdout == EXPECTED,
              "expected:\n" + EXPECTED + "actual:\n" + executed.stdout)

    for line in PASSES:
        print("PASS " + line)
    for line in FAILURES:
        print("FAIL " + line, file=sys.stderr)
    print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
