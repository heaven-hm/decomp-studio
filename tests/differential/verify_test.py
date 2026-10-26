#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    subprocess.run([sys.executable, sys.argv[2], str(root)], check=True)
    project = root / "verified"
    assert subprocess.run([sys.argv[1], "translate", str(root / "x86-fixture.exe"), "--target", "macos-arm64", "--output", str(project)], capture_output=True).returncode == 0
    assert subprocess.run([sys.argv[1], "build", str(project)], capture_output=True).returncode == 0
    result = subprocess.run([sys.argv[1], "verify", str(project), "--json"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"status": "pass", "reference_return_value": 42, "native_return_value": 42}
