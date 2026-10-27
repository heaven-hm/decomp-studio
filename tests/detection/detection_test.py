#!/usr/bin/env python3
"""Detection must be deterministic, evidenced, and honest about uncertainty.

A detector that guesses is worse than one that admits it does not know, because a
wrong answer sends the reader to the wrong capability. So this pins:

  1. real files are identified correctly, with the architecture;
  2. every detection records the evidence it used, so it can be checked;
  3. a format that is recognised but unsupported is refused with a reason that
     names the format and the missing capability;
  4. byte sequences that are not identifiable are reported as unrecognised rather
     than being forced into the nearest format.

Files synthesised here are labelled as such: they carry the magic a real file of
that format carries, and nothing else. They test the detector, not a decompiler.
"""

import json
import pathlib
import struct
import subprocess
import sys
import tempfile

CLI = sys.argv[1]
FIXTURES = pathlib.Path(sys.argv[2])

PASSES = []
FAILURES = []


def check(name, condition, detail=""):
    if condition:
        PASSES.append(name)
    else:
        FAILURES.append(f"{name}: {detail}")


def inspect(path):
    result = subprocess.run([CLI, "inspect", str(path), "--json"], text=True, capture_output=True)
    try:
        return json.loads(result.stdout), result
    except json.JSONDecodeError:
        return None, result


def write_two_delay_import_pe(path):
    """Write a minimal PE32 whose delay directory names two DLLs."""
    body = bytearray(0x600)
    body[0:2] = b"MZ"
    struct.pack_into("<I", body, 0x3C, 0x80)
    body[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", body, coff, 0x14C, 1, 0, 0, 0, 0xE0, 0x010F)
    optional = coff + 20
    struct.pack_into("<H", body, optional, 0x10B)
    struct.pack_into("<I", body, optional + 16, 0x1000)
    struct.pack_into("<I", body, optional + 28, 0x400000)
    struct.pack_into("<I", body, optional + 32, 0x1000)
    struct.pack_into("<I", body, optional + 36, 0x200)
    struct.pack_into("<I", body, optional + 56, 0x2000)
    struct.pack_into("<I", body, optional + 60, 0x200)
    struct.pack_into("<H", body, optional + 68, 3)
    struct.pack_into("<I", body, optional + 92, 16)
    struct.pack_into("<II", body, optional + 96 + 13 * 8, 0x1000, 96)

    section = optional + 0xE0
    body[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", body, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", body, section + 36, 0x40000040)

    # Two 32-byte IMAGE_DELAYLOAD_DESCRIPTOR records followed by a zero record.
    struct.pack_into("<IIIIIIII", body, 0x200, 1, 0x1080, 0, 0x10C0, 0x10A0, 0, 0, 0)
    struct.pack_into("<IIIIIIII", body, 0x220, 1, 0x1090, 0, 0x10D0, 0x10B0, 0, 0, 0)
    body[0x280:0x28A] = b"first.dll\0"
    body[0x290:0x29B] = b"second.dll\0"
    struct.pack_into("<II", body, 0x2A0, 0x10E0, 0)
    struct.pack_into("<II", body, 0x2B0, 0x10F0, 0)
    body[0x2E0:0x2E8] = b"\0\0First\0"
    body[0x2F0:0x2F9] = b"\0\0Second\0"
    path.write_bytes(body)


def main():
    with tempfile.TemporaryDirectory() as workspace:
        workspace = pathlib.Path(workspace)

        # 1. A real PE fixture, which this build can lift.
        pe = FIXTURES / "bin" / "arith.exe"
        if pe.exists():
            payload, result = inspect(pe)
            check("pe/is-inspected", result.returncode == 0, (result.stdout + result.stderr)[:160])
            check("pe/is-not-refused-as-foreign", "detected:" not in result.stdout,
                  "a native PE was reported as an unsupported format")
        else:
            check("pe/fixture-present", False, f"{pe} is missing; build the fixtures")

        delay_pe = workspace / "two-delay-imports.exe"
        write_two_delay_import_pe(delay_pe)
        payload, result = inspect(delay_pe)
        delay_names = {entry["name"] for entry in (payload or {}).get("imports", [])
                       if entry.get("delay")}
        check("pe/all-delay-descriptors-read",
              result.returncode == 0 and (payload or {}).get("delay_imports") == 2 and
              delay_names == {"first.dll!First", "second.dll!Second"},
              result.stdout[:400] + result.stderr[:160])

        # A real .NET assembly, if the corpus is available.
        dotnet = pathlib.Path("/Users/haseeb-mir/Downloads/recomp-apps/TicTacToe/TicTacToe.exe")
        if dotnet.exists():
            payload, result = inspect(dotnet)
            check("dotnet/is-detected", payload is not None and payload.get("runtime") == "dotnet-clr",
                  result.stdout[:200])
            check("dotnet/is-refused", result.returncode != 0, "a managed image was not refused")
            check("dotnet/reason-names-il",
                  payload is not None and "IL bytecode" in payload.get("reason", ""),
                  (payload or {}).get("reason", "")[:160])

        # 2. ELF, synthesised: magic plus a 64-bit little-endian x86-64 machine.
        elf = workspace / "synthetic.elf"
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2      # 64-bit
        header[5] = 1      # little-endian
        struct.pack_into("<H", header, 18, 0x3E)
        elf.write_bytes(bytes(header))
        payload, result = inspect(elf)
        check("elf/is-detected", payload is not None and payload.get("container") == "elf", result.stdout[:200])
        check("elf/architecture-read", payload is not None and payload.get("architecture") == "x86_64",
              (payload or {}).get("architecture", ""))
        check("elf/is-refused", result.returncode != 0, "an ELF binary was not refused")
        check("elf/reason-names-elf", payload is not None and "ELF" in payload.get("reason", ""),
              (payload or {}).get("reason", "")[:160])

        # Mach-O, synthesised: 64-bit little-endian, arm64.
        macho = workspace / "synthetic.macho"
        body = bytearray(32)
        struct.pack_into("<I", body, 0, 0xFEEDFACF)
        struct.pack_into("<I", body, 4, 0x0100000C)
        macho.write_bytes(bytes(body))
        payload, result = inspect(macho)
        check("macho/is-detected", payload is not None and payload.get("container") == "macho", result.stdout[:200])
        check("macho/architecture-read", payload is not None and payload.get("architecture") == "arm64",
              (payload or {}).get("architecture", ""))

        # A JVM class file, synthesised: the magic plus a version.
        class_file = workspace / "Synthetic.class"
        class_file.write_bytes(b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52))
        payload, result = inspect(class_file)
        check("jvm/is-detected", payload is not None and payload.get("container") == "class-file",
              result.stdout[:200])
        check("jvm/is-refused", result.returncode != 0, "a class file was not refused")
        check("jvm/reason-names-bytecode",
              payload is not None and "bytecode" in payload.get("reason", ""),
              (payload or {}).get("reason", "")[:160])

        # CPython bytecode, synthesised: the .pyc magic.
        pyc = workspace / "synthetic.pyc"
        pyc.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x0d\x0d" + b"\x00" * 8)
        payload, result = inspect(pyc)
        check("cpython/is-detected",
              payload is not None and payload.get("container") == "cpython-bytecode", result.stdout[:200])
        check("cpython/is-refused", result.returncode != 0, "CPython bytecode was not refused")

        # A script.
        script = workspace / "synthetic.sh"
        script.write_text("#!/bin/sh\necho hello\n")
        payload, result = inspect(script)
        check("script/is-detected", payload is not None and payload.get("container") == "script",
              result.stdout[:200])

        # 3. Evidence is always recorded, and confidence is reported.
        for name, path in (("elf", elf), ("macho", macho), ("class", class_file), ("pyc", pyc)):
            payload, result = inspect(path)
            check(f"{name}/confidence-reported",
                  payload is not None and payload.get("confidence") in ("certain", "probable", "uncertain"),
                  result.stdout[:160])
            check(f"{name}/summary-present",
                  payload is not None and bool(payload.get("summary")), result.stdout[:160])

        # 4. Bytes that match nothing must not be forced into a format.
        unknown = workspace / "synthetic.bin"
        unknown.write_bytes(bytes(range(64)))
        payload, result = inspect(unknown)
        check("unknown/is-not-forced", payload is not None and payload.get("container") == "unknown",
              result.stdout[:200])
        check("unknown/is-refused", result.returncode != 0, "unrecognised bytes were accepted")
        check("unknown/reason-is-honest",
              payload is not None and "not recognised" in payload.get("reason", ""),
              (payload or {}).get("reason", "")[:160])

    for line in PASSES:
        print("PASS " + line)
    for line in FAILURES:
        print("FAIL " + line, file=sys.stderr)
    print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
