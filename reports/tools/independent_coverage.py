#!/usr/bin/env python3
"""Independent instruction-coverage ground truth for Recomp Studio.

This tool is deliberately NOT built on the project's C++ code.  It re-implements,
from reading the project's sources, three things:

  1. A PE loader (own parser, no pefile) that maps sections by RVA, honours the
     image base / entry point, and reproduces the project's read_rva() semantics.
  2. Function recovery (recursive descent) ported from
     core/discovery/function_discovery.cpp so the reachable instruction set is
     comparable with the project's own numbers.
  3. A model of the mnemonics the lifter accepts, extracted by hand from
     core/semantics/x86_64_lifter.cpp (line ranges cited in LIFTER_EVIDENCE
     below), including the operand-dependent conditions.

The *decoder* is the Capstone Python bindings (a different build of Capstone
from the one the project links: wheel 5.0.7 vs Homebrew dylib 5.0.3).

Outputs a mnemonic histogram and the set of mnemonics the lifter rejects, plus
the address of the first rejection in the project's own translation order
(ascending function entry, then ascending instruction address).

Usage:
  independent_coverage.py <image> [--json OUT.json] [--limit N]
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass, field

try:
    import capstone
except ImportError:  # pragma: no cover
    print("FATAL: capstone python bindings unavailable", file=sys.stderr)
    sys.exit(2)


# --------------------------------------------------------------------------
# 1. PE loader (own parser; semantics mirrored from core/binary/pe.cpp)
# --------------------------------------------------------------------------

IMAGE_SCN_MEM_EXECUTE = 0x20000000

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_BASERELOC = 5
DIR_TLS = 9


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def end_virtual_address(self) -> int:
        # pe.hpp:24-25 -> VA + max(virtual_size, raw_size)
        return self.virtual_address + max(self.virtual_size, self.raw_size)

    @property
    def is_executable(self) -> bool:
        return (self.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0


@dataclass
class ImportedSymbol:
    import_address_table_rva: int
    library_name: str
    symbol_name: str


@dataclass
class ExportedSymbol:
    rva: int
    name: str


class PortableExecutable:
    """Minimal PE32/PE32+ reader mirroring core/binary/pe.cpp."""

    def __init__(self, path: str) -> None:
        with open(path, "rb") as handle:
            self.file_bytes = handle.read()
        self.path = path
        self.sections: list[Section] = []
        self.imports: list[ImportedSymbol] = []
        self.exports: list[ExportedSymbol] = []
        self.base_relocations: list[tuple[int, int]] = []
        self.tls_callback_rvas: list[int] = []
        self._parse()

    # -- helpers ---------------------------------------------------------
    def _u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.file_bytes, offset)[0]

    def _u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.file_bytes, offset)[0]

    def _u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.file_bytes, offset)[0]

    def _cstring(self, rva: int, limit: int = 4096) -> str:
        out = bytearray()
        for index in range(limit):
            chunk = self.read_rva(rva + index, 1)
            if chunk[0] == 0:
                break
            out.append(chunk[0])
        return out.decode("latin-1")

    # -- RVA mapping (pe.cpp:54-107) -------------------------------------
    def section_containing(self, rva: int) -> Section | None:
        for section in self.sections:
            if section.virtual_address <= rva < section.end_virtual_address:
                return section
        return None

    def read_rva(self, rva: int, count: int) -> bytes:
        """Identical semantics to PortableExecutable::read_rva (pe.cpp:72-87)."""
        out = bytearray(count)
        section = self.section_containing(rva)
        if section is None:
            if rva < self.size_of_headers and rva + count <= len(self.file_bytes):
                out[:] = self.file_bytes[rva : rva + count]
            return bytes(out)
        delta = rva - section.virtual_address
        if delta >= section.raw_size:
            return bytes(out)
        available = min(count, section.raw_size - delta)
        source = section.raw_offset + delta
        if source + available <= len(self.file_bytes):
            out[:available] = self.file_bytes[source : source + available]
        return bytes(out)

    def read_u16(self, rva: int) -> int:
        return struct.unpack_from("<H", self.read_rva(rva, 2))[0]

    def read_u32(self, rva: int) -> int:
        return struct.unpack_from("<I", self.read_rva(rva, 4))[0]

    def read_u64(self, rva: int) -> int:
        return struct.unpack_from("<Q", self.read_rva(rva, 8))[0]

    def executable_sections(self) -> list[Section]:
        return [s for s in self.sections if s.is_executable]

    # -- parsing (pe.cpp:134-297) ----------------------------------------
    def _parse(self) -> None:
        data = self.file_bytes
        if len(data) < 0x40 or data[0:2] != b"MZ":
            raise ValueError("not a DOS MZ executable")
        pe_offset = self._u32(0x3C)
        if pe_offset + 24 > len(data) or self._u32(pe_offset) != 0x00004550:
            raise ValueError("missing PE signature")

        coff = pe_offset + 4
        self.machine = self._u16(coff)
        section_count = self._u16(coff + 2)
        optional_header_size = self._u16(coff + 16)
        characteristics = self._u16(coff + 18)
        self.is_dynamic_library = (characteristics & 0x2000) != 0
        optional = coff + 20
        magic = self._u16(optional)
        if magic == 0x10B:
            self.is_64_bit = False
        elif magic == 0x20B:
            self.is_64_bit = True
        else:
            raise ValueError("unsupported PE optional header magic")

        self.entry_point_rva = self._u32(optional + 16)
        self.subsystem = self._u16(optional + 68)
        if self.is_64_bit:
            self.image_base = self._u64(optional + 24)
            self.size_of_image = self._u32(optional + 56)
            self.size_of_headers = self._u32(optional + 60)
            self.size_of_code = self._u32(optional + 4)
        else:
            self.image_base = self._u32(optional + 28)
            self.size_of_image = self._u32(optional + 56)
            self.size_of_headers = self._u32(optional + 60)
            self.size_of_code = self._u32(optional + 4)

        table = optional + optional_header_size
        for index in range(section_count):
            offset = table + index * 40
            name = data[offset : offset + 8].split(b"\x00")[0].decode("latin-1")
            self.sections.append(
                Section(
                    name=name,
                    virtual_size=self._u32(offset + 8),
                    virtual_address=self._u32(offset + 12),
                    raw_size=self._u32(offset + 16),
                    raw_offset=self._u32(offset + 20),
                    characteristics=self._u32(offset + 36),
                )
            )

        dir_count_offset = optional + 108 if self.is_64_bit else optional + 92
        dir_offset = optional + 112 if self.is_64_bit else optional + 96
        dir_count = min(self._u32(dir_count_offset), 16)
        directories = [
            (self._u32(dir_offset + i * 8), self._u32(dir_offset + i * 8 + 4))
            for i in range(dir_count)
        ]

        def directory(index: int) -> tuple[int, int]:
            return directories[index] if index < len(directories) else (0, 0)

        self._parse_imports(directory(DIR_IMPORT)[0])
        self._parse_exports(directory(DIR_EXPORT)[0])
        self._parse_relocations(*directory(DIR_BASERELOC))
        self._parse_tls(directory(DIR_TLS)[0])

    def _parse_imports(self, import_rva: int) -> None:
        if import_rva == 0:
            return
        pointer_size = 8 if self.is_64_bit else 4
        ordinal_flag = 0x8000000000000000 if self.is_64_bit else 0x80000000
        descriptor = import_rva
        while True:
            original_first_thunk = self.read_u32(descriptor)
            name_rva = self.read_u32(descriptor + 12)
            first_thunk = self.read_u32(descriptor + 16)
            if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break
            library = self._cstring(name_rva).lower()
            thunk_rva = original_first_thunk or first_thunk
            slot_rva = first_thunk
            while True:
                value = self.read_u64(thunk_rva) if self.is_64_bit else self.read_u32(thunk_rva)
                if value == 0:
                    break
                if value & ordinal_flag:
                    symbol = "#" + str(value & 0xFFFF)
                else:
                    symbol = self._cstring((value & 0xFFFFFFFF) + 2)
                self.imports.append(ImportedSymbol(slot_rva, library, symbol))
                thunk_rva += pointer_size
                slot_rva += pointer_size
            descriptor += 20

    def _parse_exports(self, export_rva: int) -> None:
        if export_rva == 0:
            return
        name_count = self.read_u32(export_rva + 24)
        address_table = self.read_u32(export_rva + 28)
        name_table = self.read_u32(export_rva + 32)
        ordinal_table = self.read_u32(export_rva + 36)
        for index in range(min(name_count, 100000)):
            name_pointer = self.read_u32(name_table + index * 4)
            ordinal = self.read_u16(ordinal_table + index * 2)
            function_rva = self.read_u32(address_table + ordinal * 4)
            if function_rva != 0:
                self.exports.append(ExportedSymbol(function_rva, self._cstring(name_pointer)))

    def _parse_relocations(self, reloc_rva: int, reloc_size: int) -> None:
        if reloc_rva == 0 or reloc_size == 0:
            return
        position = 0
        while position < reloc_size:
            block_rva = self.read_u32(reloc_rva + position)
            block_size = self.read_u32(reloc_rva + position + 4)
            if block_size < 8:
                break
            entry_count = (block_size - 8) // 2
            for index in range(entry_count):
                entry = self.read_u16(reloc_rva + position + 8 + index * 2)
                reloc_type = entry >> 12
                offset = entry & 0xFFF
                if reloc_type != 0:
                    self.base_relocations.append((block_rva + offset, reloc_type))
            position += block_size

    def _parse_tls(self, tls_rva: int) -> None:
        if tls_rva == 0:
            return
        callbacks_address = (
            self.read_u64(tls_rva + 24) if self.is_64_bit else self.read_u32(tls_rva + 12)
        )
        if callbacks_address == 0:
            return
        callbacks_rva = (
            callbacks_address - self.image_base
            if callbacks_address >= self.image_base
            else callbacks_address
        )
        for index in range(64):
            callback = (
                self.read_u64(callbacks_rva + index * 8)
                if self.is_64_bit
                else self.read_u32(callbacks_rva + index * 4)
            )
            if callback == 0:
                break
            self.tls_callback_rvas.append(callback - self.image_base)

    @property
    def architecture_name(self) -> str:
        return "x86_64" if self.is_64_bit else "x86"


# --------------------------------------------------------------------------
# 2. Decoder (Capstone Python bindings)
# --------------------------------------------------------------------------


@dataclass
class Operand:
    kind: str  # "reg" | "imm" | "mem"
    size: int
    reg: str = ""
    imm: int = 0


@dataclass
class Insn:
    address: int
    size: int
    mnemonic: str  # raw capstone mnemonic
    text: str
    operands: list[Operand] = field(default_factory=list)
    raw: bytes = b""


class Decoder:
    def __init__(self, is_64_bit: bool) -> None:
        mode = capstone.CS_MODE_64 if is_64_bit else capstone.CS_MODE_32
        self.md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.md.detail = True
        self.cache: dict[int, Insn | None] = {}

    def decode(self, image: PortableExecutable, rva: int) -> Insn | None:
        cached = self.cache.get(rva)
        if cached is not None or rva in self.cache:
            return cached
        if not image.section_containing(rva) or not self._contains_code(image, rva):
            self.cache[rva] = None
            return None
        code = image.read_rva(rva, 16)
        insn = next(self.md.disasm(code, image.image_base + rva, count=1), None)
        if insn is None:
            self.cache[rva] = None
            return None
        operands: list[Operand] = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_REG:
                operands.append(Operand("reg", op.size, self.md.reg_name(op.reg)))
            elif op.type == capstone.x86.X86_OP_IMM:
                operands.append(Operand("imm", op.size, imm=op.imm))
            elif op.type == capstone.x86.X86_OP_MEM:
                operands.append(Operand("mem", op.size))
            else:
                operands.append(Operand("other", op.size))
        decoded = Insn(
            address=insn.address,
            size=insn.size,
            mnemonic=insn.mnemonic,
            text=(insn.mnemonic + " " + insn.op_str).strip(),
            operands=operands,
            raw=bytes(insn.bytes),
        )
        self.cache[rva] = decoded
        return decoded

    @staticmethod
    def _contains_code(image: PortableExecutable, rva: int) -> bool:
        for section in image.executable_sections():
            if section.virtual_address <= rva < section.end_virtual_address:
                return True
        return False


# --------------------------------------------------------------------------
# 3. Function recovery (port of core/discovery/function_discovery.cpp:96-196)
# --------------------------------------------------------------------------

CONDITIONAL_BRANCHES_DISCOVERY = {
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
    "jp", "jnp", "jl", "jge", "jle", "jg",
    "jrcxz", "jecxz", "loop", "loope", "loopne",
}
TERMINATORS = {"ret", "retf", "iret", "iretd", "iretq", "hlt", "ud2", "int3"}
MAXIMUM_INSTRUCTIONS = 2_000_000
RELOC_HIGHLOW = 3
RELOC_DIR64 = 10


@dataclass
class RecoveredFunction:
    entry: int
    instructions: dict[int, Insn] = field(default_factory=dict)
    block_starts: set[int] = field(default_factory=set)
    tail_call_targets: set[int] = field(default_factory=set)


class FunctionDiscovery:
    def __init__(self, image: PortableExecutable, decoder: Decoder) -> None:
        self.image = image
        self.decoder = decoder
        self.functions: dict[int, RecoveredFunction] = {}
        self.entry_sources: collections.Counter = collections.Counter()

    def contains_code(self, rva: int) -> bool:
        return self.decoder._contains_code(self.image, rva)

    def _direct_branch_target(self, insn: Insn) -> int | None:
        if not insn.operands:
            return None
        if insn.operands[0].kind != "imm":
            return None
        return insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF

    def discover(self) -> None:
        image = self.image
        pending_entries: list[int] = []
        if image.entry_point_rva != 0 and self.contains_code(image.entry_point_rva):
            pending_entries.append(image.image_base + image.entry_point_rva)
            self.entry_sources["entry_point"] += 1
        for exported in image.exports:
            if self.contains_code(exported.rva):
                pending_entries.append(image.image_base + exported.rva)
                self.entry_sources["export"] += 1
        for rva in image.tls_callback_rvas:
            if self.contains_code(rva):
                pending_entries.append(image.image_base + rva)
                self.entry_sources["tls_callback"] += 1
        for rva, reloc_type in image.base_relocations:
            if reloc_type == RELOC_DIR64:
                target = image.read_u64(rva)
            elif reloc_type == RELOC_HIGHLOW:
                target = image.read_u32(rva)
            else:
                continue
            if target >= image.image_base and self.contains_code(
                (target - image.image_base) & 0xFFFFFFFF
            ):
                pending_entries.append(target)
                self.entry_sources["base_relocation"] += 1

        known_entries = set(pending_entries)
        recovered = 0

        while pending_entries:
            entry = pending_entries.pop()
            entry_rva = (entry - image.image_base) & 0xFFFFFFFF
            if not self.contains_code(entry_rva) or entry in self.functions:
                continue
            function = RecoveredFunction(entry)
            function.block_starts.add(entry)
            pending_blocks = [entry]
            visited_blocks: set[int] = set()
            while pending_blocks and recovered < MAXIMUM_INSTRUCTIONS:
                address = pending_blocks.pop()
                while True:
                    address_rva = (address - image.image_base) & 0xFFFFFFFF
                    if (
                        not self.contains_code(address_rva)
                        or address in function.instructions
                        or address in visited_blocks
                    ):
                        break
                    visited_blocks.add(address)
                    insn = self.decoder.decode(image, address_rva)
                    if insn is None or insn.size == 0:
                        break
                    function.instructions[address] = insn
                    recovered += 1

                    next_address = address + insn.size
                    if insn.mnemonic == "call":
                        target = self._direct_branch_target(insn)
                        if target is not None and self.contains_code(
                            (target - image.image_base) & 0xFFFFFFFF
                        ):
                            if target not in known_entries:
                                known_entries.add(target)
                                pending_entries.append(target)
                        address = next_address
                        continue
                    if insn.mnemonic in CONDITIONAL_BRANCHES_DISCOVERY:
                        target = self._direct_branch_target(insn)
                        if target is not None and self.contains_code(
                            (target - image.image_base) & 0xFFFFFFFF
                        ):
                            function.block_starts.add(target)
                            pending_blocks.append(target)
                        address = next_address
                        continue
                    if insn.mnemonic == "jmp":
                        target = self._direct_branch_target(insn)
                        if target is not None and self.contains_code(
                            (target - image.image_base) & 0xFFFFFFFF
                        ):
                            if target in known_entries:
                                function.tail_call_targets.add(target)
                            else:
                                function.block_starts.add(target)
                                pending_blocks.append(target)
                        break
                    if insn.mnemonic in TERMINATORS:
                        break
                    address = next_address
            self.functions[entry] = function


# --------------------------------------------------------------------------
# 4. Lifter model
# --------------------------------------------------------------------------
# Extracted by reading core/semantics/x86_64_lifter.cpp.  Line ranges cited in
# LIFTER_EVIDENCE; every entry below is justified by a specific branch there.

LIFTER_EVIDENCE = {
    "revision": "core/semantics/x86_64_lifter.cpp @ working tree, mtime 2026-10-27 06:05:48",
    "prefix stripping": "x86_64_lifter.cpp:254-259 (rep/repe/repne/lock stripped)",
    "string ops": "x86_64_lifter.cpp:94-102 + 286-297",
    "128-bit vector moves": "x86_64_lifter.cpp:299-304",
    "movss/movsd vector": "x86_64_lifter.cpp:305-309",
    "movd/movq vector": "x86_64_lifter.cpp:310-326",
    "vector bitwise": "x86_64_lifter.cpp:104-110 + 327-337",
    "paddd/psubd/pcmpeqd": "x86_64_lifter.cpp:338-346",
    "pshufd": "x86_64_lifter.cpp:347-353",
    "punpck{l,h}{dq,qdq}": "x86_64_lifter.cpp:354-363",
    "ldmxcsr/stmxcsr": "x86_64_lifter.cpp:365-376 (one memory operand required)",
    "cvtdq2ps": "x86_64_lifter.cpp:378-392",
    "cpuid": "x86_64_lifter.cpp:393",
    "prefetch*": "x86_64_lifter.cpp:394-396",
    "bt/bts/btr/btc": "x86_64_lifter.cpp:397-417",
    "nop*/endbr*/pause": "x86_64_lifter.cpp:419-421",
    "mov/movabs": "x86_64_lifter.cpp:423-427",
    "movzx": "x86_64_lifter.cpp:428-437",
    "movsx/movsxd": "x86_64_lifter.cpp:438-449",
    "lea": "x86_64_lifter.cpp:450-454",
    "xchg": "x86_64_lifter.cpp:455-463",
    "arithmetic add/sub/adc/sbb/and/or/xor": "x86_64_lifter.cpp:72-79 + 465-473",
    "cmp": "x86_64_lifter.cpp:474-479",
    "test": "x86_64_lifter.cpp:480-485",
    "inc/dec/neg/not": "x86_64_lifter.cpp:486-499",
    "shrd/shld": "x86_64_lifter.cpp:500-510",
    "shl/sal/shr/sar/rol/ror/rcl/rcr": "x86_64_lifter.cpp:81-88 + 511-520",
    "imul": "x86_64_lifter.cpp:522-546",
    "mul": "x86_64_lifter.cpp:547-552",
    "div/idiv": "x86_64_lifter.cpp:553-558",
    "cdq/cqo/lahf/sahf/cwde/cdqe": "x86_64_lifter.cpp:559-587",
    "push/pop/leave": "x86_64_lifter.cpp:589-611",
    "set<cc>": "x86_64_lifter.cpp:51-70 + 613-618",
    "cmov<cc>": "x86_64_lifter.cpp:51-70 + 619-624",
    "call": "x86_64_lifter.cpp:626-643",
    "jmp": "x86_64_lifter.cpp:644-665",
    "conditional jumps": "x86_64_lifter.cpp:90-92 + 666-676",
    "ret/retf": "x86_64_lifter.cpp:677-689",
    "int3/hlt/ud2/ud1/ud0": "x86_64_lifter.cpp:690-694",
    "vpxor/vandps/vpor": "x86_64_lifter.cpp:696-708",
    "addsd/subsd/mulsd/divsd/addss/subss/mulss/divss": "x86_64_lifter.cpp:709-729",
    "cvtsi2sd": "x86_64_lifter.cpp:730-738",
    "cvttsd2si": "x86_64_lifter.cpp:739-747",
    "cvtsd2ss": "x86_64_lifter.cpp:748-752",
    "cvtss2sd": "x86_64_lifter.cpp:753-757",
    "bsr/bsf": "x86_64_lifter.cpp:758-770",
    "xadd/cmpxchg": "x86_64_lifter.cpp:771-790",
    "reject": "x86_64_lifter.cpp:247-250 + 791",
    "census keying": ("census() at x86_64_lifter.cpp:838-875 aggregates on the RAW "
                      "instruction.mnemonic, while the throw path record_unsupported "
                      "(line 791) reports the prefix-STRIPPED mnemonic"),
}

# sha256 of the lifter revision this model was extracted from. The tool prints
# the live hash so a stale model is visible instead of silent.
LIFTER_SOURCE = "core/semantics/x86_64_lifter.cpp"
LIFTER_SHA256 = "3561e1ff3fb0796f05cb625c68fe3a53e0cde925f0b71d1f238d5fac4c200e28"

CONDITION_CODES = {
    "o", "no", "b", "c", "nae", "ae", "nb", "nc", "e", "z", "ne", "nz",
    "be", "na", "a", "nbe", "s", "ns", "p", "pe", "np", "po", "l", "nge",
    "ge", "nl", "le", "ng", "g", "nle",
}
STRING_OPERATION_SIZES = {
    "movsb": 1, "movsw": 2, "movsd": 4, "movsq": 8,
    "stosb": 1, "stosw": 2, "stosd": 4, "stosq": 8,
    "lodsb": 1, "lodsw": 2, "lodsd": 4, "lodsq": 8,
    "scasb": 1, "scasw": 2, "scasd": 4, "scasq": 8,
    "cmpsb": 1, "cmpsw": 2, "cmpsd": 4, "cmpsq": 8,
}
VECTOR_BITWISE = {
    "xorps", "xorpd", "pxor", "andps", "andpd", "pand", "orps", "orpd", "por",
}
ARITHMETIC = {"add", "sub", "adc", "sbb", "and", "or", "xor"}
SHIFTS = {"shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr"}
LIFTER_CONDITIONAL_BRANCHES = {
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
    "jp", "jnp", "jl", "jge", "jle", "jg",
}
UNCONDITIONAL_SIMPLE = {
    "movzx", "movsx", "movsxd", "lea", "xchg", "cmp", "test", "inc", "dec",
    "neg", "not", "imul", "mul", "div", "idiv", "cdq", "cqo", "lahf", "sahf",
    "cwde", "cdqe", "push", "pop", "leave", "call", "jmp", "ret", "retf",
    "int3", "hlt", "ud2", "ud1", "ud0", "ldmxcsr", "stmxcsr", "cpuid",
    "prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2", "prefetchw",
    "endbr64", "endbr32", "pause", "mov", "movabs", "cvttsd2si",
}
VECTOR_128_MOVES = {"movaps", "movups", "movdqa", "movdqu", "movapd", "movupd"}
VECTOR_BINARY_TWO_XMM = {"paddd", "psubd", "pcmpeqd", "punpckldq", "punpckhdq",
                         "punpcklqdq", "punpckhqdq"}
SCALAR_ARITH = {"addsd", "subsd", "mulsd", "divsd", "addss", "subss", "mulss", "divss"}


def normalize_mnemonic(mnemonic: str) -> str:
    """Port of x86_64_lifter.cpp:254-259."""
    text = mnemonic
    if text.startswith("rep "):
        text = text[4:]
    elif text.startswith("repe "):
        text = text[5:]
    elif text.startswith("repne "):
        text = text[6:]
    if text.startswith("lock "):
        text = text[5:]
    return text


def is_vector_register(name: str) -> bool:
    return len(name) > 3 and name.startswith("xmm") and name[3:].isdigit()


class LifterModel:
    """Decides, per instruction, whether x86_64_lifter.cpp would accept it."""

    def __init__(self) -> None:
        self.rejection_reasons: collections.Counter = collections.Counter()

    def accepts(self, insn: Insn) -> bool:
        m = normalize_mnemonic(insn.mnemonic)
        ops = insn.operands
        n = len(ops)
        op0_xmm = n > 0 and ops[0].kind == "reg" and is_vector_register(ops[0].reg)
        op1_xmm = n > 1 and ops[1].kind == "reg" and is_vector_register(ops[1].reg)
        any_xmm = op0_xmm or op1_xmm

        # L286-297 string operations (movsd/cmpsd excluded when op0 is xmm)
        if m in STRING_OPERATION_SIZES and not (
            m in ("movsd", "cmpsd") and n > 0 and op0_xmm
        ):
            return True
        # L299-304 128-bit vector moves
        if m in VECTOR_128_MOVES and n == 2 and any_xmm:
            return True
        # L305-309 movss/movsd with a vector operand
        if m in ("movss", "movsd") and n == 2 and any_xmm:
            return True
        # L310-326 movd/movq with a vector operand
        if m in ("movd", "movq") and n == 2 and any_xmm:
            return True
        # L327-337 vector bitwise (op0 must be xmm)
        if m in VECTOR_BITWISE and n == 2 and op0_xmm:
            return True
        # L338-346 paddd/psubd/pcmpeqd, both xmm
        if m in ("paddd", "psubd", "pcmpeqd") and n == 2 and op0_xmm and op1_xmm:
            return True
        # L347-353 pshufd
        if m == "pshufd" and n == 3 and op0_xmm and op1_xmm:
            return True
        # L354-363 punpck{l,h}{dq,qdq}, both xmm
        if m in ("punpckldq", "punpckhdq", "punpcklqdq", "punpckhqdq") and n == 2 and op0_xmm and op1_xmm:
            return True
        # L365-376 MXCSR load/store: exactly one memory operand
        if m in ("ldmxcsr", "stmxcsr") and n == 1 and ops[0].kind == "mem":
            return True
        # L378-392 cvtdq2ps
        if m == "cvtdq2ps" and n == 2 and op0_xmm:
            return True
        # L393 cpuid
        if m == "cpuid":
            return True
        # L394-396 prefetch*
        if m in ("prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2", "prefetchw"):
            return True
        # L397-417 bt/bts/btr/btc: 2 operands, op0 a GPR
        if m in ("bt", "bts", "btr", "btc") and n == 2 and ops[0].kind == "reg" and not op0_xmm:
            return True
        # L419-421 nop*, endbr*, pause
        if m == "nop" or m.startswith("nop") or m in ("endbr64", "endbr32", "pause"):
            return True
        # L423-427 mov/movabs
        if m in ("mov", "movabs"):
            return True
        # L428-449 movzx / movsx / movsxd
        if m in ("movzx", "movsx", "movsxd"):
            return True
        # L450-463 lea / xchg
        if m in ("lea", "xchg"):
            return True
        # L465-473 arithmetic (exactly 2 operands)
        if m in ARITHMETIC and n == 2:
            return True
        # L474-485 cmp / test
        if m in ("cmp", "test"):
            return True
        # L486-499 inc/dec/neg/not
        if m in ("inc", "dec", "neg", "not"):
            return True
        # L500-510 shrd/shld (3 operands)
        if m in ("shrd", "shld") and n == 3:
            return True
        # L511-520 shifts
        if m in SHIFTS:
            return True
        # L522-587 multiply / divide / sign-extend family
        if m in ("imul", "mul", "div", "idiv", "cdq", "cqo", "lahf", "sahf", "cwde", "cdqe"):
            return True
        # L589-611 push / pop / leave
        if m in ("push", "pop", "leave"):
            return True
        # L613-624 set<cc> / cmov<cc>
        if m.startswith("set") and m[3:] in CONDITION_CODES:
            return True
        if m.startswith("cmov") and m[4:] in CONDITION_CODES:
            return True
        # L626-665 call / jmp
        if m in ("call", "jmp"):
            return True
        # L666-676 conditional jumps (note: NOT jrcxz/jecxz/loop*)
        if m in LIFTER_CONDITIONAL_BRANCHES and m[1:] in CONDITION_CODES:
            return True
        # L677-694 ret / retf / traps
        if m in ("ret", "retf", "int3", "hlt", "ud2", "ud1", "ud0"):
            return True
        # L696-708 AVX 3-operand bitwise
        if m in ("vpxor", "vandps", "vpor") and n == 3 and op0_xmm:
            return True
        # L709-729 scalar float/double arithmetic
        if m in SCALAR_ARITH and n == 2 and op0_xmm:
            return True
        # L730-738 cvtsi2sd
        if m == "cvtsi2sd" and n == 2 and op0_xmm:
            return True
        # L739-747 cvttsd2si
        if m == "cvttsd2si" and n == 2:
            return True
        # L748-757 cvtsd2ss / cvtss2sd
        if m in ("cvtsd2ss", "cvtss2sd") and n == 2 and op0_xmm:
            return True
        # L758-770 bsr/bsf
        if m in ("bsr", "bsf") and n == 2:
            return True
        # L771-790 xadd / cmpxchg
        if m in ("xadd", "cmpxchg") and n == 2:
            return True
        return False

    def rejection_reason(self, insn: Insn) -> str:
        m = normalize_mnemonic(insn.mnemonic)
        ops = insn.operands
        if m in STRING_OPERATION_SIZES:
            return "string op with xmm operand (movsd/cmpsd SSE2 form)"
        if m in VECTOR_128_MOVES:
            return "128-bit vector move without xmm operand"
        if m in ("movss", "movsd", "movd", "movq"):
            return "vector move without xmm operand"
        if m in VECTOR_BITWISE:
            return "vector bitwise without xmm destination"
        if m in VECTOR_BINARY_TWO_XMM:
            return "packed integer op requires two xmm registers"
        if m == "pshufd":
            return "pshufd requires 3 operands with two xmm registers"
        if m in ("bt", "bts", "btr", "btc"):
            return "bit test with non-register destination"
        if m in ARITHMETIC:
            return "arithmetic op without exactly 2 operands"
        if m in ("shrd", "shld"):
            return "double shift without exactly 3 operands"
        if m in ("vpxor", "vandps", "vpor"):
            return "AVX bitwise without xmm destination or 3 operands"
        if m in SCALAR_ARITH:
            return "scalar float op without xmm destination"
        if m in ("cvtsi2sd", "cvtsd2ss", "cvtss2sd"):
            return "conversion without xmm destination"
        if m == "cvttsd2si":
            return "cvttsd2si without 2 operands"
        if m in ("bsr", "bsf", "xadd", "cmpxchg"):
            return "instruction without exactly 2 operands"
        return "mnemonic not dispatched by the lifter"


# --------------------------------------------------------------------------
# 5. Reporting
# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--json", dest="json_path", default="")
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--first-unsupported", action="store_true",
                        help="also print the first rejected instruction in project order")
    args = parser.parse_args()

    image = PortableExecutable(args.image)
    decoder = Decoder(image.is_64_bit)
    discovery = FunctionDiscovery(image, decoder)
    discovery.discover()

    lifter = LifterModel()
    histogram: collections.Counter = collections.Counter()
    raw_histogram: collections.Counter = collections.Counter()
    unsupported: collections.Counter = collections.Counter()
    unsupported_by_addr: dict[str, str] = {}
    unsupported_reasons: collections.Counter = collections.Counter()
    total = 0
    unique_addresses: set[int] = set()

    first_unsupported: tuple[int, int, str, str] | None = None
    for entry in sorted(discovery.functions):
        function = discovery.functions[entry]
        for address in sorted(function.instructions):
            insn = function.instructions[address]
            total += 1
            unique_addresses.add(address)
            m = normalize_mnemonic(insn.mnemonic)
            histogram[m] += 1
            raw_histogram[insn.mnemonic] += 1
            if not lifter.accepts(insn):
                unsupported[m] += 1
                unsupported_reasons[lifter.rejection_reason(insn)] += 1
                unsupported_by_addr[f"0x{address:x}"] = m
                if first_unsupported is None:
                    first_unsupported = (entry, address, m, insn.text)

    # Prefix-carrying mnemonics: the census keys on the raw mnemonic while the
    # throw path reports the stripped one, so a prefixed unsupported instruction
    # would be classified under a different name by the two code paths.
    prefixed_unsupported = {
        raw: count
        for raw, count in raw_histogram.items()
        if raw != normalize_mnemonic(raw) and normalize_mnemonic(raw) in unsupported
    }

    lifter_hash = "unavailable"
    if os.path.exists(LIFTER_SOURCE):
        with open(LIFTER_SOURCE, "rb") as handle:
            lifter_hash = hashlib.sha256(handle.read()).hexdigest()

    print(f"image:                {image.path}")
    print(f"architecture:         {image.architecture_name} (machine=0x{image.machine:04x})")
    print(f"image_base:           0x{image.image_base:x}")
    print(f"entry_point_rva:      0x{image.entry_point_rva:x}")
    print(f"executable sections:  {', '.join(s.name for s in image.executable_sections())}")
    print(f"imports parsed:       {len(image.imports)}")
    print(f"exports parsed:       {len(image.exports)}")
    print(f"base relocations:     {len(image.base_relocations)}")
    print(f"tls callbacks:        {len(image.tls_callback_rvas)}")
    print(f"entry sources:        {dict(discovery.entry_sources)}")
    print(f"functions recovered:  {len(discovery.functions)}")
    print(f"instructions:         {total} (unique addresses {len(unique_addresses)})")
    print(f"distinct mnemonics:   {len(histogram)}")
    print(f"unsupported instrs:   {sum(unsupported.values())}")
    print(f"unsupported mnemonics:{len(unsupported)}")
    print(f"lifter revision:      {LIFTER_SOURCE} sha256 {lifter_hash}")
    print(f"lifter model pinned:  {LIFTER_SHA256}"
          + ("  (MATCH)" if lifter_hash == LIFTER_SHA256 else "  (DIFFERS - model may be stale)"))
    print(f"prefixed unsupported: {prefixed_unsupported if prefixed_unsupported else 'none'}"
          "  (would be keyed differently by census vs abort path)")

    print("\n=== TOP UNSUPPORTED MNEMONICS BY COUNT ===")
    for rank, (mnemonic, count) in enumerate(unsupported.most_common(args.top), start=1):
        print(f"{rank:2d}. {mnemonic:<16} {count:7d}")

    print("\n=== FULL UNSUPPORTED MNEMONIC SET (count desc) ===")
    for mnemonic, count in unsupported.most_common():
        print(f"{mnemonic:<24} {count}")

    print("\n=== REJECTION REASONS ===")
    for reason, count in unsupported_reasons.most_common():
        print(f"{count:7d}  {reason}")

    print("\n=== FULL MNEMONIC HISTOGRAM (count desc) ===")
    for mnemonic, count in histogram.most_common():
        print(f"{mnemonic:<24} {count}")

    if first_unsupported is not None:
        entry, address, mnemonic, text = first_unsupported
        print("\n=== FIRST REJECTED INSTRUCTION (project translation order) ===")
        print(f"function entry 0x{entry:x}  instruction 0x{address:x}  {text}")
    else:
        print("\n=== FIRST REJECTED INSTRUCTION ===\nnone (fully covered)")

    if args.json_path:
        payload = {
            "image": image.path,
            "architecture": image.architecture_name,
            "image_base": image.image_base,
            "entry_point_rva": image.entry_point_rva,
            "functions": len(discovery.functions),
            "instructions": total,
            "unique_instruction_addresses": len(unique_addresses),
            "histogram": dict(histogram.most_common()),
            "raw_histogram": dict(raw_histogram.most_common()),
            "unsupported": dict(unsupported.most_common()),
            "unsupported_reasons": dict(unsupported_reasons.most_common()),
            "unsupported_by_address": unsupported_by_addr,
            "first_unsupported": (
                {
                    "function_entry": f"0x{first_unsupported[0]:x}",
                    "address": f"0x{first_unsupported[1]:x}",
                    "mnemonic": first_unsupported[2],
                    "text": first_unsupported[3],
                }
                if first_unsupported
                else None
            ),
            "prefixed_unsupported": prefixed_unsupported,
            "lifter_source": LIFTER_SOURCE,
            "lifter_source_sha256": lifter_hash,
            "lifter_source_sha256_pinned": LIFTER_SHA256,
            "lifter_source_matches_pin": lifter_hash == LIFTER_SHA256,
            "lifter_evidence": LIFTER_EVIDENCE,
        }
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=False)
        print(f"\nJSON written to {args.json_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
