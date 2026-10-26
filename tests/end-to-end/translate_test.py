#!/usr/bin/env python3
"""A real PE fixture produces and executes an ARM64 host binary."""

import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path


cli, fixture_builder = sys.argv[1:]
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    subprocess.run([sys.executable, fixture_builder, str(root)], check=True)
    project = root / "generated"
    translated = subprocess.run([cli, "translate", str(root / "x64-fixture.exe"), "--target", "macos-arm64", "--output", str(project), "--json"], text=True, capture_output=True)
    assert translated.returncode == 0, translated.stderr
    assert json.loads(translated.stdout)["status"] == "ok"
    built = subprocess.run([cli, "build", str(project), "--json"], text=True, capture_output=True)
    assert built.returncode == 0, built.stderr
    guest = project / "build" / "recomp-guest"
    output = subprocess.run([str(guest)], text=True, capture_output=True)
    assert output.returncode == 0, output.stderr
    assert json.loads(output.stdout) == {"status": "ok", "return_value": 42}
    inspected = subprocess.run(["file", str(guest)], text=True, capture_output=True, check=True)
    assert "arm64" in inspected.stdout.lower() or platform.machine().lower() != "arm64"
