#!/usr/bin/env python3
"""Compare two store logs per instruction.

Usage: compare_store_logs.py <reference.log> <candidate.log>

Produced by RECOMP_REF_STORE_LOG and RECOMP_STORE_LOG. Grouping by instruction
rather than comparing line by line is what removes the granularity question: the
reference reports a 16-byte store as two 8-byte writes, so a line-by-line
comparison reports a divergence for every vector store.


The reference reports a 16-byte store as two 8-byte writes, so comparing the logs
line by line reports a divergence for every vector store. Grouping by instruction
and comparing the set of byte ranges each instruction wrote removes the question
of how either side chose to chunk them.
"""
import sys
from collections import defaultdict


def load(path):
    groups = []          # [(instruction, [(address, width), ...]), ...] in order
    current = None
    for line in open(path):
        parts = line.split()
        if not parts:
            continue
        # A leading 's' marks a store a shim performed. The reference cannot log
        # those -- its shim writes to guest_memory with a host memcpy, which the
        # emulator never observes -- so they are skipped rather than reported as
        # stores the reference failed to make.
        if parts[0].startswith("s"):
            continue
        instruction = parts[0]
        address, width = int(parts[1], 16), int(parts[3])
        if current is None or current[0] != instruction:
            current = (instruction, [])
            groups.append(current)
        current[1].append((address, width))
    return groups


def merge(ranges):
    """The set of byte ranges written, as (start, end) with adjacent ranges joined."""
    spans = sorted((a, a + w) for a, w in ranges)
    out = []
    for start, end in spans:
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def main():
    reference = load(sys.argv[1])
    candidate = load(sys.argv[2])
    # The candidate logs the entry sentinel push, which the reference writes with
    # uc_mem_write rather than by executing an instruction.
    if candidate and candidate[0][0] == "0":
        candidate = candidate[1:]
    print(f"reference: {len(reference)} instructions that store")
    print(f"candidate: {len(candidate)} instructions that store")
    differing = 0
    for index in range(min(len(reference), len(candidate))):
        r_instr, r_ranges = reference[index]
        c_instr, c_ranges = candidate[index]
        if r_instr != c_instr:
            print(f"instruction streams diverge at store group {index}: "
                  f"reference 0x{r_instr} candidate 0x{c_instr}")
            break
        r_merged, c_merged = merge(r_ranges), merge(c_ranges)
        if r_merged != c_merged:
            differing += 1
            if differing <= 5:
                print(f"0x{r_instr}: ranges differ")
                print(f"   reference: {[(hex(a), hex(b)) for a, b in r_merged]}")
                print(f"   candidate: {[(hex(a), hex(b)) for a, b in c_merged]}")
    print(f"instructions whose written ranges differ: {differing}")


if __name__ == "__main__":
    main()
