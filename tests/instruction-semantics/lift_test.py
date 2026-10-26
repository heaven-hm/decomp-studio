#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    subprocess.run([sys.executable, sys.argv[2], str(root)], check=True)
    result = subprocess.run([sys.argv[1], "lift", str(root / "x86-fixture.exe"), "--json"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert [item["opcode"] for item in report["operations"]] == ["write_register", "arithmetic_with_eflags", "return"]
    assert [item["width"] for item in report["operations"]] == [32, 32, 32]
