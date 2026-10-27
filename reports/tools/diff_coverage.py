#!/usr/bin/env python3
"""Diff `recomp-studio coverage --json` against the independent ground truth.

Usage:
  diff_coverage.py <coverage.json> <ground-truth.json>

Reports:
  * headline totals (total / lifted / unsupported / class count)
  * classes the tool lists that the independent model does not  (over-reporting)
  * classes the independent model lists that the tool does not  (under-reporting)
  * per-class count differences
  * the first unsupported site, cross-checked
Exit code 0 when the two agree exactly, 1 otherwise.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    coverage = json.load(open(sys.argv[1]))
    truth = json.load(open(sys.argv[2]))

    tool_classes = {entry["mnemonic"]: entry["occurrences"] for entry in coverage["unsupported"]}
    mine = dict(truth["unsupported"])

    print(f"coverage json : {sys.argv[1]}")
    print(f"ground truth  : {sys.argv[2]}")
    print()

    # ---- headline totals -------------------------------------------------
    headline = [
        ("total_instructions", coverage["total_instructions"], truth["instructions"]),
        ("unsupported_instructions", coverage["unsupported_instructions"], sum(mine.values())),
        ("unsupported_class_count", coverage["unsupported_class_count"], len(mine)),
        ("function_count", coverage["function_count"], truth["functions"]),
        ("lifted_instructions", coverage["lifted_instructions"],
         truth["instructions"] - sum(mine.values())),
    ]
    all_ok = True
    for name, a, b in headline:
        ok = a == b
        all_ok &= ok
        print(f"{'OK  ' if ok else 'DIFF'} {name:<26} coverage={a:<9} independent={b}")
    print()

    # ---- class-set differences -------------------------------------------
    over = sorted(set(tool_classes) - set(mine))
    under = sorted(set(mine) - set(tool_classes))
    print(f"classes only in coverage (over-reporting): {len(over)}")
    for name in over:
        print(f"    {name:<22} coverage={tool_classes[name]}")
    print(f"classes only in independent model (under-reporting): {len(under)}")
    for name in under:
        print(f"    {name:<22} independent={mine[name]}")
    print()

    # ---- per-class count differences -------------------------------------
    count_diffs = [
        (name, tool_classes[name], mine[name])
        for name in sorted(set(tool_classes) & set(mine))
        if tool_classes[name] != mine[name]
    ]
    print(f"per-class occurrence-count differences: {len(count_diffs)}")
    for name, a, b in count_diffs:
        print(f"    {name:<22} coverage={a:<7} independent={b}")
    print()

    # ---- first site ------------------------------------------------------
    first = truth.get("first_unsupported")
    if first:
        print("first unsupported site (independent, project translation order):")
        print(f"    address={first['address']}  mnemonic={first['mnemonic']}")
        print(f"    function={first['function_entry']}")
        target = int(first["address"], 16)
        matches = [e for e in coverage["unsupported"] if int(e["first_address"], 16) == target]
        if matches:
            print(f"    coverage reports the same first site for class {matches[0]['mnemonic']!r}")
        else:
            print("    coverage does NOT report this address as any class's first site")
            all_ok = False
        earliest = min(coverage["unsupported"], key=lambda e: int(e["first_address"], 16))
        print(f"    earliest first-site across all classes: {earliest['mnemonic']} @ "
              f"{earliest['first_address']}")
        if int(earliest["first_address"], 16) != target:
            print("    NOTE: coverage's earliest first-site differs from the predicted abort site")
            all_ok = False
    print()

    verdict = "AGREE EXACTLY" if (all_ok and not over and not under and not count_diffs) else "MISMATCH"
    print(f"RESULT: {verdict}")
    return 0 if verdict == "AGREE EXACTLY" else 1


if __name__ == "__main__":
    sys.exit(main())
