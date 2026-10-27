#!/usr/bin/env python3
"""Second-opinion cross-checks for independent_coverage.py.

Two checks, neither of which reuses the project's C++ code:

  A. PE parse: my own parser (independent_coverage.PortableExecutable) versus
     pefile, for machine / image base / entry point / section RVA mapping.
  B. Decoder: my Capstone-based decode versus LLVM's disassembler
     (llvm-objdump) at the same virtual addresses, over a sample of
     instructions taken from my own recovered instruction stream.

Usage:
  crosscheck_decoder.py <image> [--sample N]
"""

from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from independent_coverage import (  # noqa: E402
    Decoder,
    FunctionDiscovery,
    PortableExecutable,
    normalize_mnemonic,
)

LLVM_OBJDUMP = "/opt/homebrew/opt/llvm/bin/llvm-objdump"


def check_pefile(image: PortableExecutable) -> bool:
    try:
        import pefile  # type: ignore
    except ImportError:
        print("CHECK A (pefile): SKIPPED - pefile not installed")
        return False
    pe = pefile.PE(image.path, fast_load=False)
    ok = True
    pairs = [
        ("machine", image.machine, pe.FILE_HEADER.Machine),
        ("image_base", image.image_base, pe.OPTIONAL_HEADER.ImageBase),
        ("entry_point_rva", image.entry_point_rva, pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        ("size_of_headers", image.size_of_headers, pe.OPTIONAL_HEADER.SizeOfHeaders),
        ("section_count", len(image.sections), pe.FILE_HEADER.NumberOfSections),
    ]
    for name, mine, theirs in pairs:
        status = "OK" if mine == theirs else "DIFF"
        if mine != theirs:
            ok = False
        print(f"CHECK A {name:<18} mine={mine!r:<20} pefile={theirs!r:<20} {status}")
    for index, section in enumerate(pe.sections):
        mine = image.sections[index]
        their_name = section.Name.split(b"\x00")[0].decode("latin-1")
        fields = [
            ("name", mine.name, their_name),
            ("virtual_address", mine.virtual_address, section.VirtualAddress),
            ("virtual_size", mine.virtual_size, section.Misc_VirtualSize),
            ("raw_offset", mine.raw_offset, section.PointerToRawData),
            ("raw_size", mine.raw_size, section.SizeOfRawData),
        ]
        for field, a, b in fields:
            if a != b:
                ok = False
                print(f"CHECK A section[{index}].{field}: mine={a!r} pefile={b!r} DIFF")
    print(f"CHECK A (pefile structural comparison): {'PASS' if ok else 'FAIL'}")
    return ok


def llvm_mnemonics(image: PortableExecutable) -> dict[int, tuple[str, int | None]]:
    """LLVM's decode, in Intel syntax so mnemonics are directly comparable.

    Instruction lengths are derived from consecutive addresses inside a
    section, which is sound because llvm-objdump dumps a section linearly.
    """
    output = subprocess.run(
        [LLVM_OBJDUMP, "-d", "--no-show-raw-insn", "--x86-asm-syntax=intel", image.path],
        capture_output=True, text=True, check=True,
    ).stdout
    texts: dict[int, str] = {}
    pattern = re.compile(r"^\s*([0-9a-f]+):\s+(.+?)\s*$")
    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            texts[int(match.group(1), 16)] = match.group(2).strip()

    table: dict[int, tuple[str, int | None]] = {}
    base = image.image_base
    for section in image.sections:
        start = base + section.virtual_address
        end = start + max(section.virtual_size, section.raw_size)
        inside = sorted(address for address in texts if start <= address < end)
        for index, address in enumerate(inside):
            size = inside[index + 1] - address if index + 1 < len(inside) else None
            table[address] = (texts[address], size)
    return table


def normalize_text(text: str) -> str:
    """Collapse syntax-only differences between the two printers.

    * whitespace/case
    * llvm-objdump appends a symbol annotation, e.g. "call 0x1400 <.text+0x10>"
    * capstone prints immediates in decimal where llvm prints hex ("1" vs "0x1")
    """
    text = text.lower().replace("\t", " ")
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s*<[^>]*>$", "", text).strip()
    text = re.sub(r"0x([0-9a-f]+)", lambda m: str(int(m.group(1), 16)), text)
    return text


def check_decoder(image: PortableExecutable, sample: int) -> bool:
    decoder = Decoder(image.is_64_bit)
    discovery = FunctionDiscovery(image, decoder)
    discovery.discover()

    addresses: list[int] = []
    for entry in sorted(discovery.functions):
        for address in sorted(discovery.functions[entry].instructions):
            addresses.append(address)
    if not addresses:
        print("CHECK B (llvm-objdump): SKIPPED - no instructions recovered")
        return False

    stride = max(1, len(addresses) // sample)
    chosen = addresses[::stride][:sample]

    llvm = llvm_mnemonics(image)
    mnemonic_agree = 0
    text_agree = 0
    missing = 0
    size_disagreements = 0
    size_compared = 0
    disagreements: collections.Counter = collections.Counter()
    text_disagreements: collections.Counter = collections.Counter()
    for address in chosen:
        insn = decoder.cache.get(address - image.image_base)
        if insn is None:
            continue
        entry = llvm.get(address)
        if entry is None:
            missing += 1
            continue
        theirs, their_size = entry
        their_mnemonic = theirs.split()[0]
        if normalize_mnemonic(insn.mnemonic) == normalize_mnemonic(their_mnemonic):
            mnemonic_agree += 1
        else:
            disagreements[(insn.mnemonic, their_mnemonic)] += 1
        if normalize_text(insn.text) == normalize_text(theirs):
            text_agree += 1
        else:
            text_disagreements[(normalize_text(insn.text), normalize_text(theirs))] += 1
        # An independent decode of the same bytes at the same address must
        # consume the same number of bytes.
        if their_size is not None:
            size_compared += 1
            if insn.size != their_size:
                size_disagreements += 1

    total = mnemonic_agree + sum(disagreements.values())
    print(f"CHECK B sample size: {len(chosen)} instructions")
    print(f"CHECK B mnemonic agreement: {mnemonic_agree}/{total}")
    print(f"CHECK B full-text agreement: {text_agree}/{total}")
    print(f"CHECK B length mismatches:   {size_disagreements}/{size_compared}")
    print(f"CHECK B not in llvm-objdump map: {missing}")
    for (mine, theirs), count in disagreements.most_common(20):
        print(f"CHECK B   mine={mine!r:<20} llvm={theirs!r:<20} x{count}")
    print("CHECK B text-only differences (same mnemonic/length, printer style):")
    for (mine, theirs), count in text_disagreements.most_common(12):
        print(f"CHECK B   mine={mine!r}\nCHECK B   llvm={theirs!r}  x{count}")
    ratio = mnemonic_agree / total if total else 0.0
    text_ratio = text_agree / total if total else 0.0
    passed = ratio >= 0.99 and size_disagreements == 0
    print(f"CHECK B (llvm-objdump mnemonic agreement {ratio:.4%}, text {text_ratio:.4%}): "
          f"{'PASS' if passed else 'FAIL'}")
    return passed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--sample", type=int, default=400)
    args = parser.parse_args()

    image = PortableExecutable(args.image)
    print(f"image: {args.image}\n")
    a = check_pefile(image)
    print()
    b = check_decoder(image, args.sample)
    print()
    print(f"OVERALL: {'PASS' if (a and b) else 'FAIL'}")
    return 0 if (a and b) else 1


if __name__ == "__main__":
    sys.exit(main())
