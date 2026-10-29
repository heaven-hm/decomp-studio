#!/usr/bin/env python3
"""Compile a PE32 leaf, reconstruct it with the hybrid source mode, and prove
that the delivered source is the source that was built and verified."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

cli, fixture = sys.argv[1:]

def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True)

with tempfile.TemporaryDirectory(prefix="recomp-readable-") as directory:
    root = pathlib.Path(directory)
    binary = root / "leaf.exe"
    project = root / "project"
    run("i686-w64-mingw32-gcc", "-O2", "-nostdlib", "-ffreestanding",
        "-fno-asynchronous-unwind-tables", "-fno-stack-protector",
        "-Wl,--no-insert-timestamp", "-Wl,-e,recomp_entry", "-Wl,--subsystem,console",
        "-o", str(binary), fixture, "-lkernel32", "-lgcc")

    hybrid = json.loads(run(cli, "translate", str(binary), "--output", str(project),
                            "--source-mode", "hybrid", "--source-quality", "human-readable",
                            "--json").stdout)
    assert hybrid["source_mode"] == "hybrid", hybrid
    assert hybrid["source_quality"] == "human-readable", hybrid
    assert hybrid["high_level_functions"] >= 1, hybrid
    assert hybrid["unresolved_functions"] == 0, hybrid
    guest_source = (project / "guest.cpp").read_text()
    assert "Source classification: high-level verified" in guest_source
    assert "Source classification: low-level fallback" in guest_source

    # The delivered source must be the source the manifest describes.
    manifest = json.loads((project / "recomp-source-manifest.json").read_text())
    listed = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    assert "guest.cpp" in listed
    for name, digest in listed.items():
        actual = hashlib.sha256((project / name).read_bytes()).hexdigest()
        assert actual == digest, name

    # The per-function map must carry the same classification the report claims.
    source_map = json.loads((project / "recomp-source-map.json").read_text())
    assert source_map["source_mode"] == "hybrid"
    assert source_map["census"]["high_level_verified"] == hybrid["high_level_functions"]
    assert source_map["census"]["low_level_fallback"] == hybrid["low_level_fallback_functions"]
    verified = [record for record in source_map["functions"]
                if record["classification"] == "high-level verified"]
    assert verified, source_map["functions"][:3]
    for record in verified:
        assert record["recognizer"], record
        assert record["evidence"], record

    # --source-style readable is the alias for the same recognition.
    styled = root / "styled"
    alias = json.loads(run(cli, "translate", str(binary), "--output", str(styled),
                           "--source-style", "readable", "--json").stdout)
    assert alias["high_level_functions"] == hybrid["high_level_functions"]

    # Default mode stays machine-level: no function is presented as high-level.
    faithful = root / "faithful"
    fallback = json.loads(run(cli, "translate", str(binary), "--output", str(faithful),
                              "--json").stdout)
    assert fallback["source_mode"] == "low-level"
    assert fallback["high_level_functions"] == 0
    assert "Source classification: high-level verified" not in (faithful / "guest.cpp").read_text()

    # The quality gate fails closed before writing any file.
    refused = root / "refused"
    gate = subprocess.run([cli, "translate", str(binary), "--output", str(refused),
                           "--source-mode", "low-level", "--source-quality", "human-readable",
                           "--json"], text=True, capture_output=True)
    assert gate.returncode != 0, gate.stdout
    assert "human-readable" in (gate.stdout + gate.stderr)
    assert not (refused / "guest.cpp").exists()

    run(cli, "build", str(project), "--json")
    build_manifest = json.loads((project / "recomp-build-manifest.json").read_text())
    assert build_manifest["executable"]["sha256"]
    for entry in build_manifest["source_files"]:
        actual = hashlib.sha256((project / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["sha256"], entry["path"]

    result = json.loads(run(cli, "verify", str(project), "--json").stdout)
    assert result["verdict"] == "VERIFIED", result
    assert result["reference_completed"] and result["candidate_completed"]
    assert result["checkpoints_compared"] > 0 and result["state_match"]
