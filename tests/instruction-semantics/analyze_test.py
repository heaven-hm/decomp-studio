#!/usr/bin/env python3
"""Analysis must decode actual bytes from PE32 and PE32+ fixture code."""

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
    for name, architecture in [("x86-fixture.exe", "x86"), ("x64-fixture.exe", "x64")]:
        result = subprocess.run([binary, "analyze", str(root / name), "--json"],
                                capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["status"] == "ok"
        assert report["architecture"] == architecture
        assert report["function_count"] == 1
        assert report["instruction_count"] == 3
        assert report["instructions"] == ["mov", "add", "ret"]
