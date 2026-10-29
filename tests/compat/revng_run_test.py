import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="revng test ") as directory:
    root = pathlib.Path(directory)
    binary = root / "game input.exe"
    binary.write_bytes(b"fixture")
    fake = root / "fake revng"
    fake.write_text("#!/bin/sh\n[ \"$1 $2 $3\" = 'quick artifact emit-c-as-single-file' ] || exit 9\n"
                    "[ \"$5\" = '-o' ] || exit 10\nprintf 'artifact' > \"$6\"\n")
    fake.chmod(0o755)
    output = root / "analysis output"
    result = subprocess.run([sys.argv[1], str(fake), str(binary), str(output)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    manifest = json.loads((output / "analysis-provenance.json").read_text())
    assert manifest["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert manifest["artifact_sha256"] == hashlib.sha256(b"artifact").hexdigest()
    assert manifest["binary_artifact_association"] == "unverified"
    result = subprocess.run([sys.argv[1], str(fake), str(binary), str(output)], capture_output=True, text=True)
    assert result.returncode != 0
    fake.write_text("#!/bin/sh\nprintf changed > \"$4\"\nprintf artifact > \"$6\"\n")
    changed = root / "changed"
    result = subprocess.run([sys.argv[1], str(fake), str(binary), str(changed)], capture_output=True, text=True)
    assert result.returncode != 0 and "input binary changed" in result.stderr
    assert not (changed / "analysis-provenance.json").exists()
    failed = root / "failed"
    result = subprocess.run([sys.argv[1], "/bin/false", str(binary), str(failed)], capture_output=True, text=True)
    assert result.returncode != 0 and not (failed / "analysis-provenance.json").exists()
