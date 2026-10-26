#!/usr/bin/env python3
"""Negative regression tests.

Every unsupported or malformed input must fail with an explicit, non-zero
result. Nothing may crash the tool, and nothing may be reported as usable.
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

CLI = sys.argv[1]
APPS_DIRECTORY = Path(sys.argv[2])
OPTIONAL_MODE = os.environ.get("RECOMP_OPTIONAL") == "1"

PASSES = []
FAILURES = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSES.append(name)
    else:
        FAILURES.append(f"{name}: {detail}")


def run_cli(arguments) -> subprocess.CompletedProcess:
    return subprocess.run([CLI, *arguments], text=True, capture_output=True)


def expect_error(name: str, arguments, expected_fragment: str = "") -> None:
    result = run_cli(arguments)
    if result.returncode < 0:
        check(name, False, f"terminated by signal {-result.returncode}")
        return
    if result.returncode == 0:
        check(name, False, "expected a non-zero exit code")
        return
    combined = result.stdout + result.stderr
    if expected_fragment and expected_fragment not in combined:
        check(name, False, f"missing diagnostic {expected_fragment!r} in {combined.strip()!r}")
        return
    check(name, True)


def malformed_pe_files(directory: Path):
    empty = directory / "empty.exe"
    empty.write_bytes(b"")

    mz_only = directory / "mz_only.exe"
    mz_only.write_bytes(b"MZ")

    bad_pe_offset = directory / "bad_offset.exe"
    bad_pe_offset.write_bytes(b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0xffffff) + b"\x00" * 64)

    missing_signature = directory / "no_signature.exe"
    buffer = bytearray(b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x40) + b"\x00" * 64)
    missing_signature.write_bytes(bytes(buffer))

    unsupported_magic = directory / "bad_magic.exe"
    image = bytearray(b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x40) + b"\x00" * 64)
    image[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", image, 0x44, 0x8664, 1, 0, 0, 0, 0xf0, 0x0102)
    struct.pack_into("<H", image, 0x58, 0x9999)  # unknown optional-header magic
    unsupported_magic.write_bytes(bytes(image))

    return [empty, mz_only, bad_pe_offset, missing_signature, unsupported_magic]


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)

        for path in malformed_pe_files(root):
            expect_error(f"malformed PE rejected: {path.name}", ["inspect", str(path)])
            expect_error(f"malformed PE not translated: {path.name}",
                         ["translate", str(path), "--output", str(root / (path.stem + "-out"))])

        # A directory is not an executable.
        expect_error("directory input rejected", ["translate", str(APPS_DIRECTORY), "--output", str(root / "dir-out")])

        # Unsupported instruction class (x87).
        unsupported = APPS_DIRECTORY / "bin" / "unsupported_instruction.exe"
        if unsupported.exists():
            expect_error("unsupported instruction reported",
                         ["translate", str(unsupported), "--output", str(root / "unsupported-out")],
                         "unsupported instruction")
        else:
            check("unsupported instruction fixture present", False, "run tests/fixtures/apps/build.sh")

        # Unsupported import: translation succeeds, execution must fail explicitly.
        unsupported_import = APPS_DIRECTORY / "bin" / "unsupported_import.exe"
        if unsupported_import.exists():
            project = root / "import-out"
            translated = run_cli(["translate", str(unsupported_import), "--output", str(project)])
            check("unsupported import still translates", translated.returncode == 0, translated.stderr)
            built = run_cli(["build", str(project)])
            check("unsupported import still builds", built.returncode == 0, built.stderr)
            executed = run_cli(["run", str(project)])
            combined = executed.stdout + executed.stderr
            check("unsupported import fails at run time", executed.returncode != 0, "expected non-zero exit")
            check("unsupported import is named", "MessageBoxA" in combined, combined.strip())
            verified = run_cli(["verify", str(project), "--json"])
            check("unsupported import does not verify", verified.returncode != 0, verified.stdout)
        else:
            check("unsupported import fixture present", False, "run tests/fixtures/apps/build.sh")

        # 32-bit PE32 input: detected, and refused (until x86 lifting is enabled).
        pe32 = APPS_DIRECTORY / "bin" / "pe32_arith.exe"
        if pe32.exists():
            inspected = run_cli(["inspect", str(pe32), "--json"])
            check("PE32 is detected", inspected.returncode == 0 and '"x86"' in inspected.stdout, inspected.stdout)
            expect_error("PE32 is refused explicitly",
                         ["translate", str(pe32), "--output", str(root / "pe32-out")])
        elif shutil.which("i686-w64-mingw32-gcc") is None and OPTIONAL_MODE:
            print("SKIP (RECOMP_OPTIONAL=1): no i686 toolchain for the PE32 fixture")
        else:
            check("PE32 fixture present", False, "i686-w64-mingw32-gcc must build pe32_arith.exe")

    for line in PASSES:
        print("PASS " + line)
    for line in FAILURES:
        print("FAIL " + line, file=sys.stderr)
    print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
