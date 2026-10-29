#!/usr/bin/env python3
"""Prove the heap comparison detects a corruption that never reaches stdout.

The verification gate compares the pages the guest WROTE, not just the 68 KiB of stack and
image it used to. Coverage is not detection: a comparison that runs and finds nothing is
indistinguishable from one that cannot see the difference at all. This test injects a
one-byte difference into a heap store and asserts that `verify` reports it -- a change
that deliberately does NOT alter stdout, so the output comparison cannot be what catches
it.

The mutation goes into the GENERATED PROJECT's copy of the runtime, never the source tree.
A test that edits a tracked source file to prove something cannot run in parallel with
anything else and leaves the tree dirty if it crashes.

Usage: heap_corruption_test.py <cli> <fixtures-dir> <scratch-dir>
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile

CLI = sys.argv[1]
FIXTURES = pathlib.Path(sys.argv[2])
SCRATCH = pathlib.Path(sys.argv[3])

FAILURES = []
PASSES = []

# One heap store, changed by one bit. The heap base is where the runtime places it, and the
# width is pinned to 4 so exactly one store is affected.
MUTATION = """  static bool mutated = false;
  if (address >= 0x160000000ull && address < 0x168000000ull && width == 4 && !mutated) {
    mutated = true;
    auto flipped = static_cast<std::uint32_t>(value) ^ 1u;
    std::memcpy(guest_memory + address, &flipped, sizeof(flipped));
    mark_guest_page_dirty(address);
    return;
  }
"""


def check(name, condition, detail=""):
    (PASSES if condition else FAILURES).append(name)
    if not condition:
        print(f"FAIL {name}: {detail}", file=sys.stderr)


def verify(project):
    result = subprocess.run([CLI, "verify", str(project), "--json"], text=True, capture_output=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def main():
    fixture = FIXTURES / "bin" / "heap.exe"
    if not fixture.exists():
        print(f"SKIP: {fixture} is not built")
        return 77
    SCRATCH.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=SCRATCH) as workspace:
        project = pathlib.Path(workspace) / "project"
        translated = subprocess.run(
            [CLI, "translate", str(fixture), "--target", "macos-arm64", "--output", str(project)],
            text=True, capture_output=True)
        check("translate", translated.returncode == 0, translated.stderr[:200])

        clean = verify(project) if (project / "recomp-guest").exists() else None
        if clean is None:
            built = subprocess.run([CLI, "build", str(project)], text=True, capture_output=True)
            check("build", built.returncode == 0, built.stderr[:200])
            clean = verify(project)
        check("clean/verifies", clean is not None and clean.get("status") == "pass",
              f"the unmutated fixture did not verify: {clean}")
        check("clean/compares-heap-pages", clean is not None and clean.get("dirty_pages_compared", 0) > 0,
              f"no heap pages were compared, so this test proves nothing: {clean}")

        # Patch the PROJECT's copy of the runtime, not the repository's.
        runtime = project / "recomp_runtime.hpp"
        text = runtime.read_text()
        anchor = "  std::memcpy(guest_memory + address, &value, static_cast<std::size_t>(width));\n  mark_guest_page_dirty(address);"
        check("mutation/anchor-found", text.count(anchor) == 1,
              "the store funnel moved; this test needs updating rather than deleting")
        if text.count(anchor) != 1:
            return 1
        runtime.write_text(text.replace(anchor, MUTATION + anchor, 1))

        rebuilt = subprocess.run([CLI, "build", str(project), "--allow-modified-sources"],
                                 text=True, capture_output=True)
        check("mutation/builds", rebuilt.returncode == 0, rebuilt.stderr[:300])

        corrupted = verify(project)
        # This check was FAILING for a reason worth keeping: the unmutated fixture itself
        # reported DIVERGED on a page inside its own LOADED IMAGE, which each side's loader
        # writes, so the run never reached a clean baseline. The image region is now excluded
        # for that reason and the corruption is caught by the ordinary digest comparison -- a
        # page BOTH sides dirty, compared byte for byte.
        check("corrupt/not-verified",
              corrupted is not None and corrupted.get("status") != "pass",
              f"a one-byte heap corruption was NOT detected: {corrupted}")
        check("corrupt/memory-disagrees",
              corrupted is not None and corrupted.get("memory_match") is False,
              f"the verdict failed but not on memory: {corrupted}")
        check("corrupt/names-the-page",
              corrupted is not None and "page" in (corrupted.get("memory_diagnosis") or ""),
              f"the diagnosis does not name the page that differs: {corrupted}")
        # The corruption must NOT have changed stdout, or this proves only that the output
        # comparison works -- which was never in doubt.
        check("corrupt/output-unchanged",
              corrupted is not None and corrupted.get("outputs_match") is True,
              f"the mutation changed the output, so it does not test the heap comparison: {corrupted}")

    print(f"{len(PASSES)} checks passed")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} heap-corruption check(s)", file=sys.stderr)
        return 1
    print("PASS: a heap corruption that never reaches stdout is detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
