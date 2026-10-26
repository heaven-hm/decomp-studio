#!/usr/bin/env python3
"""Build minimal real PE32 and PE32+ files containing supplied machine code."""

from pathlib import Path
import struct
import sys


def make_pe(path: Path, machine: int, magic: int, code: bytes) -> None:
    pe_offset, raw_offset, raw_size = 0x80, 0x200, 0x200
    optional_size = 0xE0 if magic == 0x10B else 0xF0
    image = bytearray(raw_offset + raw_size)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset:pe_offset + 4] = bytes((0x50, 0x45, 0, 0))
    struct.pack_into("<HHIIIHH", image, pe_offset + 4, machine, 1, 0, 0, 0,
                     optional_size, 0x0102)
    optional = pe_offset + 24
    struct.pack_into("<H", image, optional, magic)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    if magic == 0x10B:
        struct.pack_into("<I", image, optional + 28, 0x400000)
        struct.pack_into("<I", image, optional + 92, 16)
    else:
        struct.pack_into("<Q", image, optional + 24, 0x140000000)
        struct.pack_into("<I", image, optional + 108, 16)
    struct.pack_into("<I", image, optional + 32, 0x1000)
    struct.pack_into("<I", image, optional + 36, 0x200)
    struct.pack_into("<I", image, optional + 56, 0x2000)
    struct.pack_into("<I", image, optional + 60, raw_offset)
    section = optional + optional_size
    image[section:section + 8] = bytes((0x2E, 0x74, 0x65, 0x78, 0x74, 0, 0, 0))
    struct.pack_into("<IIIIIIHHI", image, section + 8, len(code), 0x1000,
                     raw_size, raw_offset, 0, 0, 0, 0, 0x60000020)
    image[raw_offset:raw_offset + len(code)] = code
    path.write_bytes(image)


if __name__ == "__main__":
    destination = Path(sys.argv[1])
    destination.mkdir(parents=True, exist_ok=True)
    code = bytes((0xB8, 0x28, 0, 0, 0, 0x05, 0x02, 0, 0, 0, 0xC3))
    make_pe(destination / "x86-fixture.exe", 0x014C, 0x10B, code)
    make_pe(destination / "x64-fixture.exe", 0x8664, 0x20B, code)
    branch_code = bytes((0x72, 0x00, 0xC3))
    make_pe(destination / "branch-x64-fixture.exe", 0x8664, 0x20B, branch_code)
    rex_code = bytes((0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xC4, 0x28, 0xC3))
    make_pe(destination / "rex-x64-fixture.exe", 0x8664, 0x20B, rex_code)
    unsupported_code = bytes((0xCC,))
    make_pe(destination / "unsupported-x64-fixture.exe", 0x8664, 0x20B, unsupported_code)
