#!/usr/bin/env python3
"""Compare an original executable with a rebuilt executable as separate processes.

This is deliberately outside the C++ guest runtime. It provides an independent
process-level oracle for deterministic command-line fixtures and native hosts.
It does not claim register, memory, graphics, audio, or gameplay equivalence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_one(path: Path, cwd: Path, stdin: bytes, timeout: float) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [str(path)],
            cwd=cwd,
            input=stdin,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        if isinstance(stdout, str):
            stdout = stdout.encode()
        if isinstance(stderr, str):
            stderr = stderr.encode()
        return {
            "completed": False,
            "timed_out": True,
            "exit_code": None,
            "stdout": stdout,
            "stderr": stderr,
        }
    except OSError as error:
        return {
            "completed": False,
            "timed_out": False,
            "exit_code": None,
            "stdout": b"",
            "stderr": str(error).encode(),
        }
    return {
        # A signal is not a terminal program result. Treating two processes that
        # were both killed as equivalent would turn an interrupted run into a
        # false verification.
        "completed": completed.returncode >= 0,
        "timed_out": False,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def serialise_run(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "completed": result["completed"],
        "timed_out": result["timed_out"],
        "exit_code": result["exit_code"],
        "stdout_bytes": len(result["stdout"]),
        "stderr_bytes": len(result["stderr"]),
        "stdout_sha256": digest(result["stdout"]),
        "stderr_sha256": digest(result["stderr"]),
        "stderr_preview": result["stderr"].decode("utf-8", "replace")[:4096],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--stdin", type=Path, help="read deterministic input from this file")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    reference = args.reference.resolve()
    candidate = args.candidate.resolve()
    cwd = args.cwd.resolve()
    stdin = args.stdin.read_bytes() if args.stdin else b""
    reference_run = run_one(reference, cwd, stdin, args.timeout)
    candidate_run = run_one(candidate, cwd, stdin, args.timeout)
    completed = reference_run["completed"] and candidate_run["completed"]
    outputs_match = (
        completed
        and reference_run["stdout"] == candidate_run["stdout"]
        and reference_run["stderr"] == candidate_run["stderr"]
    )
    exit_codes_match = (
        completed and reference_run["exit_code"] == candidate_run["exit_code"]
    )
    verified = completed and outputs_match and exit_codes_match
    if verified:
        verdict = "VERIFIED_PROCESS_OUTPUT"
    elif not completed:
        verdict = "INCOMPLETE"
    else:
        verdict = "DIVERGED"
    report: dict[str, Any] = {
        "verdict": verdict,
        "verified": verified,
        "reference": str(reference),
        "candidate": str(candidate),
        "cwd": str(cwd),
        "timeout_seconds": args.timeout,
        "outputs_match": outputs_match,
        "exit_codes_match": exit_codes_match,
        "scope": ["process exit status", "stdout", "stderr"],
        "excluded": ["registers", "memory", "graphics", "audio", "gameplay state"],
        "reference_run": serialise_run(reference_run),
        "candidate_run": serialise_run(candidate_run),
    }
    output = json.dumps(report, sort_keys=True)
    if args.json:
        print(output)
    else:
        print(f"verdict: {verdict}")
        print(f"reference completed: {'yes' if reference_run['completed'] else 'no'}")
        print(f"candidate completed: {'yes' if candidate_run['completed'] else 'no'}")
        print(f"stdout match: {'yes' if outputs_match else 'no'}")
        print(f"stderr match: {'yes' if reference_run['stderr'] == candidate_run['stderr'] else 'no'}")
        print(f"exit code match: {'yes' if exit_codes_match else 'no'}")
        print("scope: process exit status, stdout and stderr only")
    return 0 if verified else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
