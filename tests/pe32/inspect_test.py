#!/usr/bin/env python3
"""CLI inspection works on binary PE fixtures of both Windows CPU widths."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


binary = sys.argv[1]
fixture_builder = Path(sys.argv[2])
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    subprocess.run([sys.executable, str(fixture_builder), str(root)], check=True)
    for filename, expected_format, expected_arch in [
        ("x86-fixture.exe", "PE32", "x86"),
        ("x64-fixture.exe", "PE32+", "x64"),
    ]:
        path = root / filename
        result = subprocess.run([binary, "inspect", str(path), "--json"],
                                check=False, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["status"] == "ok"
        assert report["format"] == expected_format
        assert report["architecture"] == expected_arch
        assert report["entry_rva"] == "0x00001000"
        assert report["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
