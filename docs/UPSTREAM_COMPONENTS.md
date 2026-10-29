# Upstream components

What this project uses from other projects, under what licence, and by what integration
mechanism. Every entry states the mechanism because **the mechanism is what determines the
obligation**: adapting source into the core is not the same act as invoking a program.

The authoritative inventory is `tools.lock.json`; the authoritative attribution record is
`THIRD_PARTY_NOTICES.md`. This document explains the reasoning behind both.

## The licence position, in one table

| component | licence | used how | in the core? |
|---|---|---|---|
| Capstone | BSD-3-Clause | linked, instruction decoding | **yes** |
| LLVM / clang++ | Apache-2.0 with LLVM exception | invoked to compile the generated project | no |
| CMake / Ninja | BSD-3-Clause / Apache-2.0 | build | no |
| Remill | Apache-2.0 | **semantics adapted**, with attribution | **yes** (attributed) |
| igi-recomp | MIT | **shims adapted**, with attribution | **yes** (attributed) |
| project-igi-browser | MIT | **shims and one lifter technique adapted** | **yes** (attributed) |
| hisahi/scanf | MIT | vendored | **yes** (attributed) |
| **PCRecomp** | **MIT** | Ghidra scripts driven as an external process | no |
| Ghidra | Apache-2.0 | **external process** | no |
| Unicorn | **GPL-2.0** | linked into the test/verification tooling | **not in the shipped core** |
| radare2 | **LGPL-3.0-only** | not integrated | no |
| LIEF, Zydis, angr, Z3, Frida | Apache-2.0 / MIT / BSD-2 / MIT / wxWindows | optional, `required=false` | no |

`tools.lock.json` marks each entry `required`. **Unicorn is `required=false` and radare2 is
`required=false`, and that is a licensing decision, not a technical one**: a copyleft
dependency must not become load-bearing for the shipped artifact.

## The two integration mechanisms, and why they are different

### Adaptation (source enters the core)

Permitted only for permissive licences, and only with attribution that names the upstream
file and the exact commit. `THIRD_PARTY_NOTICES.md` records, for each adaptation:

- upstream repository and **exact commit**;
- the **source file**;
- **copyright holder**;
- **licence**, with the licence text reproduced under `third_party/`;
- **what was modified** -- in every case the semantics are re-expressed against this
  project's `GuestContext` rather than copied verbatim.

Examples with their recorded commits: Remill's `lib/Arch/X86/Semantics/MMX.cpp` at
`56918a8c2554088e93389e97d292f4035286506c` for the `PINSRW`/`PEXTRW` lane model; igi-recomp's
`shim/src/kernel32.c` at `278eaf6394f7f42c7de6cffef2cf982154f59899` for `GetLocalTime`;
project-igi-browser's `host/kernel32.c` for the console and heap adapters.

### The primary foundation, verified

**PCRecomp is MIT** (`LICENSE`: "MIT License, Copyright (c) 2026 sp00nz"), and its purpose is
this project's purpose: "every tool, runtime, and hard-won trick from our PC static
recompilation projects... make it run again -- on Windows 11, or natively on Linux with no
emulator and no Wine" ([README](https://github.com/sp00nznet/pcrecomp)). It is the directive's
primary foundation and its licence permits integration.

The optional CMake setting `RECOMP_PCRECOMP_SOURCE` builds PCRecomp's actual
`win32hle_selftest.c` and `gdi_selftest.c` against its runtime sources at revision
`a85ea970f9e0640ab6546d2ca7a01fccb132973d`. It requires clean upstream tools and runtime sources,
SDL2 and SDL2_ttf. Configure with `-DRECOMP_PCRECOMP_SOURCE=/path/to/pcrecomp`,
build the `pcrecomp_win32hle_selftest` and `pcrecomp_gdi_selftest` targets, then
run `ctest -R '^pcrecomp_' --output-on-failure` from that build directory.
These upstream tests exercise its guest calls, callbacks and GDI rendering;
they do not run Recomp Studio generated code. PCRecomp owns a separate guest
address space and global register file, whereas Recomp Studio uses `GuestContext`.
The memory, callback and thread contracts must be bridged before that runtime can
serve Recomp Studio guests.

With `i686-w64-mingw32-gcc` and Python Capstone installed, the optional
`pcrecomp_pe32_fixture` test also compiles the project's arithmetic fixture to
PE32, runs PCRecomp's generator, builds its generated C with `win32hle`, and
checks the native output. It uses the original PE as the upstream host's image
input. When Unicorn is enabled, `pcrecomp_pe32_unicorn_reference` also executes
the original PE under Recomp Studio's Unicorn reference and compares its output
byte for byte with PCRecomp's native program. The two paths use
different runtime implementations, but the reference is emulated rather than
native Windows. Neither test establishes game support or high-level source
reconstruction.

**Its own NOTICE demonstrates the file-level rule this document insists on.** The repository
carries a `LICENSES/` directory and a `NOTICE` that lists each exception by PATH:
`tools/assets/is3extract.py` (the PKWARE DCL explode section) is a Python port of zlib's
`contrib/blast/blast.c`, Mark Adler, under the **zlib licence**, and "everything else is MIT".
So even in a permissively licensed repository, **the licence of the FILE is what governs a
copy** -- which is why this project records the source file and not just the repository.

### Invocation (a program runs, its output is read)

Ghidra is a JVM application, so `apps/cli/ghidra_run.cpp` spawns `analyzeHeadless` and
`apps/cli/ghidra_import.cpp` parses its output. **This is not a claim that process isolation
removes the obligation.** What it changes is the nature of the obligation: the project
distributes no Ghidra code and links nothing from it, so the Apache-2.0 notice requirement
attaches to the tool the user installs, not to this source tree. That distinction is real
but narrow, and it is recorded here rather than relied on silently.

## What is deliberately NOT used

- **rev.ng** -- assigned high-level source reconstruction by the directive. `revng-run`
  invokes the documented `quick artifact emit-c-as-single-file` command as an external
  process, renders it using `revng ptml --plain`, and records input and output hashes.
  It preserves both the raw YAML artifact and rendered analysis text, and
  marks its association and behavior unverified. The adapter has been tested against a
  controlled stand-in; no rev.ng executable is installed here, so actual PE support and
  output remain untested. No rev.ng code is linked into the core. Its license informs
  the integration mechanism:

  **rev.ng is GPLv2, and its own README says why**: "rev.ng depends on certain on GPLv2
  components (in particular, QEMU), so the project is GPLv2-licensed as a whole"
  ([revng-c README](https://github.com/revng/revng-c/blob/253558ba63dee23b850461ad3110b6cfa5295906/README.md)).
  The core repository is listed as GPL-2.0 on
  [github.com/revng/revng](https://github.com/revng/revng). The decompiler was open-sourced
  in March 2024 ([rev.ng blog](https://rev.ng/blog/open-sourcing-renvg-decompiler-ui-closed-beta)),
  so it IS available -- it is the LICENCE, not availability, that decides the mechanism.

  **It therefore cannot be linked into this core.** If it is used, it must be invoked as an
  external process, exactly as Ghidra is, and with the same caveat recorded above: that
  changes the nature of the obligation, it does not remove it.

  **AND THE FILE-LEVEL WARNING THE DIRECTIVE GIVES IS CONCRETE HERE, not hypothetical:**
  `revng-c` also ships a `LICENSE.mit`
  ([file](https://github.com/revng/revng-c/blob/8706fd845912a7ceda9f98d1f187dc14335b6734/LICENSE.mit))
  covering files contributed under MIT. So a file copied out of that repository could be
  MIT while the repository as a whole is GPLv2, and the licence of the FILE is what governs
  a copy. Any future rev.ng integration must check per file, not per repository.
- **Wine** -- the directive suggests Wine as an API provider. Wine's `msvcrt` is
  **LGPL-2.1+**, which cannot be copied into this core. The project implements its own CRT
  surface and used MIT `hisahi/scanf` where a scanner was needed.
- **QEMU, Box64, FEX, DARWIN, Proton** -- GPL or otherwise out of scope for linking; none is
  integrated.

## Rules this project follows

1. **Check the licence before copying, per file.** A repository's `LICENSE` does not
   necessarily cover every file in it.
2. **Copyleft code does not enter the core.** If a capability needs a GPL/LGPL component, it
   is either invoked as an external process or not used, and the reason is recorded.
3. **Every adaptation is attributed with its commit.** An adaptation whose provenance cannot
   be established is not landed.
4. **`THIRD_PARTY_NOTICES.md` is updated in the same commit as the adaptation**, not later.
5. **No claim that "it is only a tool" settles the question.** The mechanism is described,
   and the obligation it creates is stated.

`ghidra-run` also accepts `--decompile`, which invokes PCRecomp's pinned
`tools/ghidra/DecompileAll.java` in the same analysis session and reports the
resulting `_decompiled.c` path. This is Ghidra pseudocode for investigation;
it is not a compilable reconstruction or behavioral verification.
The run writes `analysis-provenance.json` with hashes of the input and emitted
artifacts, and refuses to write that record if the input hash changes during
the run. These hashes record observed files; they do not authenticate Ghidra or
prove that an export was derived from that binary.
