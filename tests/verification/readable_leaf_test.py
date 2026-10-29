#!/usr/bin/env python3
"""Compile a PE32 leaf, reconstruct it, build the emitted source and compare it."""
import json
import pathlib
import subprocess
import sys
import tempfile

cli, fixture = sys.argv[1:]

def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True)

with tempfile.TemporaryDirectory(prefix="recomp-readable-") as directory:
    root = pathlib.Path(directory)
    binary = root / "leaf.exe"
    project = root / "project"
    run("i686-w64-mingw32-gcc", "-O2", "-nostdlib", "-ffreestanding",
        "-fno-asynchronous-unwind-tables", "-fno-stack-protector",
        "-Wl,--no-insert-timestamp", "-Wl,-e,recomp_entry", "-Wl,--subsystem,console",
        "-o", str(binary), fixture, "-lkernel32", "-lgcc")
    translated = json.loads(run(cli, "translate", str(binary), "--output", str(project),
                                "--source-style", "readable", "--json").stdout)
    assert translated["high_level_functions"] >= 1
    assert "High-level reconstruction" in (project / "guest.cpp").read_text()
    faithful = root / "faithful"
    fallback = json.loads(run(cli, "translate", str(binary), "--output", str(faithful),
                              "--json").stdout)
    assert fallback["high_level_functions"] == 0
    assert "High-level reconstruction" not in (faithful / "guest.cpp").read_text()
    run(cli, "build", str(project), "--json")
    result = json.loads(run(cli, "verify", str(project), "--json").stdout)
    assert result["verdict"] == "VERIFIED", result
    assert result["reference_completed"] and result["candidate_completed"]
    assert result["checkpoints_compared"] > 0 and result["state_match"]
