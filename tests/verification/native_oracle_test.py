#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts" / "native_oracle.py"


def write_program(path: Path, output: str, exit_code: int) -> None:
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"sys.stdout.write({output!r})\n"
        f"sys.exit({exit_code})\n"
    )
    path.chmod(0o755)


def run(reference: Path, candidate: Path) -> tuple[int, dict]:
    result = subprocess.run(
        [sys.executable, str(ORACLE), "--reference", str(reference),
         "--candidate", str(candidate), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, json.loads(result.stdout)


with tempfile.TemporaryDirectory(prefix="decomp-studio-native-oracle-") as directory:
    root = Path(directory)
    reference = root / "reference.py"
    candidate = root / "candidate.py"
    write_program(reference, "same output\n", 7)
    write_program(candidate, "same output\n", 7)
    code, report = run(reference, candidate)
    assert code == 0, report
    assert report["verdict"] == "VERIFIED_PROCESS_OUTPUT", report
    assert report["scope"] == ["process exit status", "stdout", "stderr"], report

    write_program(candidate, "different output\n", 7)
    code, report = run(reference, candidate)
    assert code == 1, report
    assert report["verdict"] == "DIVERGED", report
    assert report["outputs_match"] is False, report

print("native oracle: passed independent process and divergence checks")
