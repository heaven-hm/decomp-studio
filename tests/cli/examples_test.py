#!/usr/bin/env python3
import json
import subprocess
import sys

result = subprocess.run([sys.argv[1], "examples", "list", "--json"], text=True, capture_output=True)
assert result.returncode == 0, result.stderr
profiles = {entry["name"]: entry for entry in json.loads(result.stdout)["profiles"]}
assert profiles["fixture-x86"]["status"] == "supported"
assert profiles["fixture-x64"]["status"] == "supported"
assert profiles["tictactoe-ai"]["status"] == "blocked"
assert profiles["putty-plink"]["status"] == "blocked"
