#!/usr/bin/env python3
"""A registered atexit handler is kept, and its non-execution is reported.

The runtime accepted the registration and reported success without keeping the
handler, so a program that registered one produced neither the handler's output nor a
diagnostic -- the worst of both. The handler is now registered and, because neither
side executes handlers yet, every one that will not run is named on stderr.

This builds a real Windows executable that registers two handlers and requires both
to be named. When execution is implemented, this test changes to require the output
instead -- and the diagnostic disappearing is what will show it happened.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

CLI = sys.argv[1]
FIXTURES = pathlib.Path(sys.argv[2])
OPTIONAL = "--optional" in sys.argv
CXX = shutil.which("x86_64-w64-mingw32-gcc")

EXPECTED = ["atexit:start", "atexit:registered"]


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def main():
    if CXX is None:
        if OPTIONAL:
            print("SKIP (RECOMP_OPTIONAL=1): x86_64-w64-mingw32-gcc is not installed")
            return 0
        return fail("x86_64-w64-mingw32-gcc is required to build the fixture")

    with tempfile.TemporaryDirectory() as workspace:
        workspace = pathlib.Path(workspace)
        executable = workspace / "atexit.exe"
        built = subprocess.run(
            [CXX, "-O2", "-fno-asynchronous-unwind-tables", "-fno-stack-protector",
             "-Wl,--no-insert-timestamp", "-Wl,--subsystem,console",
             "-o", str(executable), str(FIXTURES / "atexit.c")],
            text=True, capture_output=True)
        if built.returncode != 0:
            return fail("could not build the fixture\n" + built.stderr[:800])

        project = workspace / "project"
        translated = subprocess.run(
            [CLI, "translate", str(executable), "--target", "macos-arm64", "--output", str(project)],
            text=True, capture_output=True)
        if translated.returncode != 0:
            return fail("translate failed: " + (translated.stderr or translated.stdout)[:400])
        built_project = subprocess.run([CLI, "build", str(project), "--json"],
                                       text=True, capture_output=True)
        if built_project.returncode != 0:
            return fail("build failed: " + (built_project.stderr or built_project.stdout)[:400])

        execution = subprocess.run([str(project / "recomp-guest")], text=True, capture_output=True)
        produced = [line for line in execution.stdout.splitlines() if line.strip()]
        if produced != EXPECTED:
            return fail(f"unexpected output\n  expected: {EXPECTED}\n  produced: {produced}")

        # The registration is real, so the handlers are known by name. Reporting them
        # is what replaced silently pretending the registration had worked.
        reported = [line for line in execution.stderr.splitlines() if "atexit handler at" in line]
        if len(reported) < 2:
            return fail(f"registered handlers were not reported; stderr was:\n{execution.stderr[:400]}")
        if not all("did not run" in line for line in reported):
            return fail("a handler was reported without saying it did not run")

        # And the differential reference must agree, which it only can if it runs them
        # through the same path.
        verification = subprocess.run([CLI, "verify", str(project), "--json"],
                                      text=True, capture_output=True)
        report = json.loads(verification.stdout)
        if report.get("status") != "pass":
            return fail(f"verification status is {report.get('status')!r}, not 'pass'")

        print(f"PASS atexit registration kept and non-execution reported ({len(reported)} handlers)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
