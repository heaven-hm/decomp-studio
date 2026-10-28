#!/usr/bin/env python3
"""A missing RECOMP_STDIN_FILE must not prevent the guest from starting."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    cli = Path(sys.argv[1])
    fixtures = Path(sys.argv[2]) / "bin" / "arith.exe"
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        built = subprocess.run(
            [str(cli), "autorecomp", str(fixtures), "--output", str(project)],
            text=True,
            capture_output=True,
        )
        if built.returncode != 0:
            print(built.stdout + built.stderr, file=sys.stderr)
            return 1

        environment = os.environ.copy()
        environment["RECOMP_STDIN_FILE"] = str(project / "missing-input.txt")
        # The runner has a Perl-based timeout supervisor.  Its own process and
        # the generated guest must not fail merely because a parent supplied a
        # locale this host does not have (C.UTF-8 is common on Linux but absent
        # from several macOS installations).
        environment["LC_ALL"] = "C.UTF-8"
        environment["LANG"] = "C.UTF-8"
        environment["LC_CTYPE"] = "C.UTF-8"
        environment["RECOMP_RUN_TIMEOUT"] = "5"
        executed = subprocess.run(
            [str(cli), "run", str(project)],
            text=True,
            capture_output=True,
            env=environment,
        )
        if executed.returncode != 0 or "arith:done" not in executed.stdout:
            print(executed.stdout + executed.stderr, file=sys.stderr)
            return 1
        if "could not be opened" not in executed.stderr:
            print("missing stdin warning was not reported", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
