import pathlib
import shutil
import hashlib
import json
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    binary = root / "game.exe"
    binary.write_bytes(b"fixture")
    scripts = root / "scripts"
    scripts.mkdir()
    (scripts / "ExportFunctions.java").write_text("untrusted exporter")
    output = root / "output"
    run = subprocess.run([sys.argv[1], "/bin/true", str(scripts), str(binary), str(output)],
                         capture_output=True, text=True)
    assert run.returncode != 0
    assert "does not match pinned" in run.stderr
    assert not output.exists(), "untrusted script must not create output"
    if len(sys.argv) > 2 and sys.argv[2]:
        shutil.copy(pathlib.Path(sys.argv[2]) / "tools/ghidra/ExportFunctions.java", scripts)
        (scripts / "DecompileAll.java").write_text("untrusted decompiler")
        run = subprocess.run([sys.argv[1], "/bin/true", str(scripts), str(binary), str(output), "--decompile"],
                             capture_output=True, text=True)
        assert run.returncode != 0 and "decompiler script does not match pinned" in run.stderr
        assert not output.exists(), "untrusted decompiler must not create output"
        shutil.copy(pathlib.Path(sys.argv[2]) / "tools/ghidra/DecompileAll.java", scripts)
        fake = root / "fake-headless"
        fake.write_text("#!/bin/sh\nprintf 'function export' > \"$1/game_functions.txt\"\nprintf 'pseudocode' > \"$1/game_decompiled.c\"\n")
        fake.chmod(0o755)
        run = subprocess.run([sys.argv[1], str(fake), str(scripts), str(binary), str(output), "--decompile"],
                             capture_output=True, text=True)
        assert run.returncode == 0, run.stderr
        provenance = json.loads((output / "analysis-provenance.json").read_text())
        assert provenance["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
        assert provenance["function_export_sha256"] == hashlib.sha256(b"function export").hexdigest()
        assert provenance["decompiled_sha256"] == hashlib.sha256(b"pseudocode").hexdigest()
        assert provenance["binary_export_association"] == "unverified"
        other = root / "changed-output"
        fake.write_text("#!/bin/sh\nprintf 'function export' > \"$1/game_functions.txt\"\nprintf changed > \"$4\"\n")
        run = subprocess.run([sys.argv[1], str(fake), str(scripts), str(binary), str(other)],
                             capture_output=True, text=True)
        assert run.returncode != 0 and "input binary changed" in run.stderr
        assert not (other / "analysis-provenance.json").exists()
    run = subprocess.run([sys.argv[1]], capture_output=True, text=True)
    assert run.returncode == 2 and "usage:" in run.stderr
