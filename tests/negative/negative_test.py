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


def build_fixtures(destination: Path) -> None:
    """Build the fixtures this test needs, instead of reading a stale in-place bin/.

    The in-place tests/fixtures/apps/bin/ is gitignored and was previously read
    directly, so a fixture that changed meaning (x87 stopped being unsupported
    once the x87 core landed) left a stale binary behind and failed this test for
    a reason unrelated to the code under test. Building here removes the trap.
    """
    if shutil.which("x86_64-w64-mingw32-gcc") is None:
        if OPTIONAL_MODE:
            print("SKIP (RECOMP_OPTIONAL=1): mingw-w64 x86_64 compiler not available")
            raise SystemExit(0)
        print("ERROR: mingw-w64 x86_64 compiler is required", file=sys.stderr)
        raise SystemExit(1)
    subprocess.run(["sh", str(APPS_DIRECTORY / "build.sh"), str(destination)], check=True,
                   stdout=subprocess.DEVNULL)


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fixture_binaries = root / "fixtures"
        build_fixtures(fixture_binaries)

        for path in malformed_pe_files(root):
            expect_error(f"malformed PE rejected: {path.name}", ["inspect", str(path)])
            expect_error(f"malformed PE not translated: {path.name}",
                         ["translate", str(path), "--output", str(root / (path.stem + "-out"))])

        # A directory is not an executable.
        expect_error("directory input rejected", ["translate", str(APPS_DIRECTORY), "--output", str(root / "dir-out")])

        # Unsupported instruction class (RDMSR: a model-specific register read).
        unsupported = fixture_binaries / "unsupported_instruction.exe"
        if unsupported.exists():
            expect_error("unsupported instruction reported",
                         ["translate", str(unsupported), "--output", str(root / "unsupported-out")],
                         "unsupported instruction")
        else:
            check("unsupported instruction fixture present", False, "build.sh did not produce it")

        # Unsupported import: translation succeeds, execution must fail explicitly.
        unsupported_import = fixture_binaries / "unsupported_import.exe"
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
            check("unsupported import fixture present", False, "build.sh did not produce it")

        # 32-bit PE32 input: the machine type must be reported as x86, not x86_64.
        pe32 = fixture_binaries / "pe32_arith.exe"
        if pe32.exists():
            inspected = run_cli(["inspect", str(pe32), "--json"])
            check("PE32 is detected as x86",
                  inspected.returncode == 0 and '"architecture":"x86"' in inspected.stdout, inspected.stdout)
        elif shutil.which("i686-w64-mingw32-gcc") is None and OPTIONAL_MODE:
            print("SKIP (RECOMP_OPTIONAL=1): no i686 toolchain for the PE32 fixture")
        else:
            check("PE32 fixture present", False, "i686-w64-mingw32-gcc must build pe32_arith.exe")

        # A managed image. The native code in one is a CLR launcher stub, so
        # recovering functions from it reports complete coverage of a program
        # that was never read. This is the same class of failure as a packed
        # input and must be refused the same way, with the cause named.
        if pe32.exists():
            data = bytearray(pe32.read_bytes())
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            optional = pe_offset + 24
            # Directory 14 (CLR runtime header): the count is a 4-byte field at
            # optional+92 on PE32, then fifteen 8-byte entries.
            struct.pack_into("<II", data, optional + 96 + 14 * 8, 0x2000, 0x48)
            managed = fixture_binaries / "managed_dotnet.exe"
            managed.write_bytes(bytes(data))

            # Detection names the format before the PE reader is consulted, so the
            # report says what the file is rather than only that it was refused.
            inspected = run_cli(["inspect", str(managed)])
            check("managed image is reported by inspect",
                  "managed .NET" in inspected.stdout and "dotnet-clr" in inspected.stdout,
                  inspected.stdout[:200])

            for command in ("coverage", "analyze"):
                result = run_cli([command, str(managed)])
                combined = result.stdout + result.stderr
                check(f"managed image is refused by {command}", result.returncode != 0, combined.strip()[:120])
                # The cause is that the code is IL, not machine code. Check the
                # substance rather than a fixed wording.
                check(f"managed refusal names the cause ({command})",
                      "managed .NET" in combined and "IL bytecode" in combined, combined.strip()[:200])

            translated = run_cli(["translate", str(managed), "--output", str(fixture_binaries / "managed-out")])
            combined = translated.stdout + translated.stderr
            check("managed image is refused by translate", translated.returncode != 0, combined.strip()[:120])
            check("managed translate refusal names the cause",
                  "managed .NET" in combined and "IL bytecode" in combined, combined.strip()[:200])

    for line in PASSES:
        print("PASS " + line)
    for line in FAILURES:
        print("FAIL " + line, file=sys.stderr)
    print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
