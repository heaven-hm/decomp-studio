import pathlib
import shutil
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
    run = subprocess.run([sys.argv[1]], capture_output=True, text=True)
    assert run.returncode == 2 and "usage:" in run.stderr
