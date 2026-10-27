#!/usr/bin/env python3
"""Public CLI contract: machine-readable version output."""

import json
import subprocess
import sys


result = subprocess.run([sys.argv[1], "--version", "--json"], check=False,
                        capture_output=True, text=True)
assert result.returncode == 0, result.stderr
payload = json.loads(result.stdout)
assert payload == {"status": "ok", "version": "0.5.0"}, payload
