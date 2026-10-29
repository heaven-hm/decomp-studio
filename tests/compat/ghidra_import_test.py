import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    binary = root / "input.exe"
    export = root / "functions.txt"
    binary.write_bytes(b"fixture binary")
    export.write_text('# export\n00401000 | 0012 | 002 | __cdecl | - | name"quoted\n')
    result = subprocess.run([sys.argv[1], str(binary), str(export), "12.2"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert data["export_sha256"] == hashlib.sha256(export.read_bytes()).hexdigest()
    assert data["binary_export_association"] == "unverified"
    assert data["functions"][0]["name"] == 'name"quoted'
    assert data["functions"][0]["body_bytes"] == 12
    assert data["functions"][0]["references"] == 2
    export.write_text("invalid | line\n")
    result = subprocess.run([sys.argv[1], str(binary), str(export), "12.2"], capture_output=True, text=True)
    assert result.returncode != 0 and not result.stdout
