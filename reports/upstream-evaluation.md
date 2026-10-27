# Upstream evaluation — mature binary-lifting / recompilation projects

**Task:** task-2 (STEP 3 + STEP 4 of the project brief)
**Author:** teammate `upstream-eval`
**Date of evidence collection:** 2026-10-27 (all dates below are as reported by GitHub on that date)
**Deliverable scope:** this file only. No code, test, build or runtime file was modified by this task.

**Question answered:** given a pipeline that already decodes with Capstone, verifies with
Unicorn and generates host code with `clang++`, which mature upstream projects — if any —
should Recomp Studio adopt for the Windows PE32/PE32+ x86/x64 → native macOS ARM64 MVP, and
which must be explicitly refused?

---

## 1. Baseline: what already works and must not be replaced without proof

| Existing component | Where it is used | Evidence it is load-bearing |
| --- | --- | --- |
| Capstone (BSD-3-Clause) | x86/x86-64 decoding in discovery and the repair harness | [`../core/discovery/function_discovery.cpp`](../core/discovery/function_discovery.cpp) (`cs_open`, `cs_disasm`, `cs_option(CS_OPT_DETAIL)`), [`../core/harness/repair_harness.cpp`](../core/harness/repair_harness.cpp); required by [`../CMakeLists.txt`](../CMakeLists.txt) (fatal error if absent) |
| Unicorn (GPL-2.0) | reference execution for differential verification | [`../core/verification/differential_harness.cpp`](../core/verification/differential_harness.cpp) (`uc_open(UC_ARCH_X86, UC_MODE_64/32)`, `UC_HOOK_CODE` trace hook); optional via `RECOMP_ENABLE_UNICORN` |
| LLVM / `clang++` (Apache-2.0 with LLVM exception) | host code generation for the emitted C++ | [`../core/pipeline.hpp`](../core/pipeline.hpp), [`../ARCHITECTURE.md`](../ARCHITECTURE.md); invoked as a compiler, not linked as a library |
| Differential verification contract | byte-identical stdout **and** identical executed-address trace | [`../README.md`](../README.md) ("Verification and the repair harness"), [`../ARCHITECTURE.md`](../ARCHITECTURE.md) ("Verification") |

Per the brief, none of these may be swapped out without demonstrating that the replacement
is technically better. Nothing in this report proposes removing any of them.

---

## 2. Decision table

Legend — **Adopt**: add for the MVP PoC. **Adopt-later**: keep on a shortlist behind a
concrete trigger. **Reject**: do not integrate.

| # | Project | Purpose | Guest → host | Licence | Maintenance status | Cost on macOS ARM64 | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | [capstone-engine/capstone](https://github.com/capstone-engine/capstone) | Disassembly framework, 20+ architectures incl. x86/x86-64 | decode only (no lifting/execution) | BSD-3-Clause ([LICENSES/LICENSE_BSD_3_CLAUSE.txt](https://github.com/capstone-engine/capstone/blob/next/LICENSES/LICENSE_BSD_3_CLAUSE.txt); repo also ships `LICENSE_LLVM.TXT`) | 5.0.9 released 2026-05-28, 6.0.0-Alpha11 (pre-release) 2026-09-21, last push 2026-10-24, not archived ([releases](https://github.com/capstone-engine/capstone/releases)) | already integrated; Homebrew bottle 5.0.9 for Apple Silicon ([formula](https://formulae.brew.sh/formula/capstone)) | **Keep** (in use, tested) |
| 2 | [unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn) | CPU emulator framework (x86/x86-64 among many) | emulate only | GPL-2.0 (confirmed by [Homebrew metadata](https://formulae.brew.sh/formula/unicorn): "GPL-2.0-only AND GPL-2.0-or-later") | 2.1.4 released 2025-09-09, last push 2026-10-18, not archived | already integrated, optional behind `RECOMP_ENABLE_UNICORN`; Homebrew bottle 2.1.4 Apple Silicon | **Keep** (verification only) |
| 3 | [llvm/llvm-project](https://github.com/llvm/llvm-project) | Compiler infrastructure; host codegen | any → native host triple (arm64/x86_64/wasm) | Apache-2.0 with LLVM exceptions ([LICENSE.TXT](https://github.com/llvm/llvm-project/blob/main/LICENSE.TXT); GitHub reports `NOASSERTION`) | llvmorg-23.1.4 released 2026-10-20, last push 2026-10-26, not archived | already used as the `clang++` toolchain; no in-process dependency needed | **Keep as-is** — do not link `libLLVM` |
| 4 | [zyantific/zydis](https://github.com/zyantific/zydis) | x86/x86-64 decoder + encoder with per-instruction CPU/FPU flag-access metadata | decode only | MIT (GitHub metadata; README badge) | v4.1.1 released 2025-02-16, last push 2026-07-27, not archived ([releases](https://github.com/zyantific/zydis/releases)) | Homebrew bottle 4.1.1, MIT, Apple Silicon ([formula](https://formulae.brew.sh/formula/zydis)); no third-party deps, C11, no `malloc`, "tested on Windows, macOS, FreeBSD, Linux and UEFI" ([README](https://github.com/zyantific/zydis/blob/master/README.md)) | **Adopt (PoC)** — see §4 |
| 5 | [intelxed/xed](https://github.com/intelxed/xed) | Intel X86 Encoder Decoder library | decode/encode only | Apache-2.0 (GitHub metadata) | v2026.08.23 released 2026-08-24, last push 2026-08-24, not archived | build is `./mfile.py` + `mbuild`, i.e. a bespoke Python build system, no CMake, no Homebrew formula ([README](https://github.com/intelxed/xed/blob/main/README.md)) | **Reject** — redundant with Capstone/Zydis, awkward build |
| 6 | [lifting-bits/remill](https://github.com/lifting-bits/remill) | Lifts machine code to LLVM bitcode | x86/amd64 (incl. AVX/AVX512), AArch64, SPARC32/64 → LLVM IR; AArch32 underway | Apache-2.0 ([LICENSE](https://github.com/lifting-bits/remill/blob/master/LICENSE)) | v6.0.1 released 2026-04-21; last commit 2026-08-27 (`56918a8c`); not archived | superbuild of LLVM 15+, Intel XED v2025.06.08, glog, googletest; README: "supported on Linux … also works on macOS, experimental support for Windows" ([README](https://github.com/lifting-bits/remill/blob/master/README.md)) | **Reject for MVP** — would replace the whole verified lifter; adopt-later as a semantics oracle only |
| 7 | [lifting-bits/mcsema](https://github.com/lifting-bits/mcsema) | Binary lifting framework (CFG recovery + remill) | x86/amd64/aarch64/sparc32/64 → LLVM bitcode | **AGPL-3.0** (GitHub metadata) | **archived**; last release v3.0.26 on 2021-04-01; last commit 2022-04-26 (`26368053`) | CFG recovery "relies on IDA Pro" ([README](https://github.com/lifting-bits/mcsema/blob/master/README.md)) — commercial dependency | **Reject** — unmaintained, AGPL, IDA Pro |
| 8 | [revng/revng](https://github.com/revng/revng) | Binary analysis framework + decompiler (QEMU lifter, LLVM passes) | x86, x86-64, i386, ARM, AArch64, MIPS, S390X → LLVM IR → C ([features](https://rev.ng/features)) | **GPL-2.0** as a whole (QEMU); individual files MIT ([README license section](https://github.com/revng/revng/blob/develop/README.md), GitHub metadata `GPL-2.0`) | no releases; last commit 2026-10-22; not archived | "rev.ng can only run on Linux x86-64. However, you can run it on Windows using WSL and on macOS via Docker" ([docs](https://docs.rev.ng/user-manual/initial-setup/)) | **Reject** — cannot run natively on macOS ARM64; GPL-2.0 whole-project |
| 9 | [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | SRE framework with decompiler; headless batch mode | many guests (x86/x64/ARM/AArch64/MIPS/…) → P-code/C | Apache-2.0 (GitHub metadata) | Ghidra_12.2_build released 2026-10-22; last push 2026-10-26; not archived | Java 25 JDK, ~1 GB install, macOS 10.13+; macOS ARM 64-bit supported "with user-built native binaries" ([GettingStarted.md](https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/GettingStarted.md)) | **Adopt-later** — offline function-discovery oracle, never a linked dependency |
| 10 | [lief-project/LIEF](https://github.com/lief-project/LIEF) | Parse/modify PE, ELF, MachO, COFF | PE parsing only (no lifting) | Apache-2.0 (GitHub metadata) | 1.0.0 released 2026-07-12; last push 2026-10-26; not archived | Homebrew bottle 1.0.0 Apple Silicon, pulls `fmt`, `spdlog`, `tl-expected` ([formula](https://formulae.brew.sh/formula/lief)) | **Reject for MVP** — the hand-rolled PE parser works and is tested; adopt-later only on a concrete PE gap |
| 11 | [winehq/wine](https://gitlab.winehq.org/wine/wine) | Windows API implementation (loader + DLLs), dynamic | runs Windows PE on the host — **not a recompiler** | LGPL-2.1-or-later ([LICENSE via the official GitHub mirror](https://github.com/wine-mirror/wine/blob/master/LICENSE)) | active — mirror commit `f343ca60` 2026-10-26; Wine 11 stable line (2026-01) | on Apple Silicon, Wine is an x86-64 program run under Rosetta 2 ([The Register, 2026-01-15](https://www.theregister.com/software/2026/01/15/wine-11-runs-windows-apps-in-linux-macos-better-than-ever/5087238)); Rosetta is being retired after macOS 27 ([Apple](https://support.apple.com/en-us/102527)) | **Reject** — wrong direction (emulation/compat layer, no native ARM64 output) and host-constraint violation |
| 12 | [HenryKun55/igi-recomp](https://github.com/HenryKun55/igi-recomp) | Single-game static recompiler: IGI.exe x86 PE32 → portable C, runs natively on macOS | guest x86 → C (runtime header notes "the same code runs on arm64 and on the Vita's ARMv7") | MIT (GitHub metadata) | no releases; created 2026-10-02, last push 2026-10-14; not archived | not a library — no stable API to integrate; already listed as a design reference in [`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md) | **Reject as a component** — keep as design reference |
| 13 | [M-HT/SR](https://github.com/M-HT/SR) | Per-game static recompiler for DOS and Windows x86 games; emits x86/`llasm`/x64 assembler → LLVM IR | guest x86 → Windows x86/x64, Linux x86/x64/arm/arm64/riscv64, macOS x64/arm64 | MIT, plus a GPLv2-or-later / LGPLv2.1-or-later offer for use in GPL projects ([README](https://github.com/M-HT/SR/blob/master/README.md)) | latest tag `septerra_v1.04.0.13` on 2026-05-30; last push 2026-08-27; not archived | requires hand-written per-executable information and ships game-specific C; no reusable lifting library | **Reject as a component** — keep as design reference (its `llasm`/LLVM-IR direction is the interesting part) |
| 14 | [N64Recomp](https://github.com/N64Recomp/N64Recomp), [Zelda64Recomp](https://github.com/Zelda64Recomp/Zelda64Recomp) (already listed in THIRD_PARTY_NOTICES) | per-title recompilers | guest MIPS → C | MIT | not re-evaluated here | n/a | **No change** — already design references only |

---

## 3. Explicitly NOT integrated, and why

- **remill** — build weight (LLVM 15+ superbuild, XED, glog, gtest) and, decisively, it is a
  *replacement* for the layer that is already verified end-to-end: it lifts to LLVM bitcode
  and expects its own runtime, and it supplies neither Windows PE loading, nor control-flow
  recovery, nor Win32 shims. Adopting it for the MVP would trade a working, tested lifter for
  an unproven one.
- **mcsema** — archived, last release 2021-04-01, last commit 2022-04-26, **AGPL-3.0**
  (a licence conflict with an Apache-2.0 tool intended for commercial and noncommercial
  distribution), and its CFG recovery depends on **IDA Pro**, i.e. a commercial tool.
- **revng** — the whole project is GPL-2.0 (QEMU-based), and upstream states it runs only on
  Linux x86-64, with macOS reachable only through Docker. That violates the
  "no Windows or x86 hosts, must build on Apple Silicon" constraint.
- **Ghidra as a dependency** — JDK 25 plus a ~1 GB distribution and user-built native
  components is disproportionate for the MVP, and it is a *Java analysis tool*, not a C/C++
  library. It stays on the shortlist as an **offline oracle** for function discovery.
- **LIEF** — Apache-2.0 and healthy, but it duplicates [`../core/binary/pe.cpp`](../core/binary/pe.cpp),
  which is already implemented and covered by fixtures. Replacing a working parser is exactly
  what the brief forbids; revisit only when a concrete PE feature is missing.
- **Wine** — the wrong direction: Wine is a dynamic Windows API implementation that runs the
  original PE, so it produces no native ARM64 code from the guest. On Apple Silicon it is an
  x86-64 program that depends on Rosetta 2, which Apple has announced will be retired after
  macOS 27.
- **XED** — redundant (Capstone already decodes; Zydis is the smaller second decoder) and its
  `mfile.py`/`mbuild` build system has no CMake support and no Homebrew formula.
- **igi-recomp and M-HT/SR as components** — both are excellent *references*, and both are
  already credited in [`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md), but neither
  offers a reusable lifting library: igi-recomp is one game's pipeline, M-HT/SR requires
  hand-written per-executable information.
- **`libLLVM` linked in-process** — unnecessary: `clang++` is already invoked as an external
  compiler, which keeps the recompiler's own build light.

---

## 4. STEP 4 — the one component to integrate for a proof of concept

### Recommendation: **Zydis** ([github.com/zyantific/zydis](https://github.com/zyantific/zydis)), MIT, as an optional *analysis-phase* decoder-metadata provider.

It is the smallest genuinely useful addition: one library, no third-party dependencies, a
Homebrew bottle for Apple Silicon, an MIT licence compatible with this project's Apache-2.0,
and it is not a competitor to any existing component — it is additive.

### 4.1 The exact capability gap it fills

**Gap A — per-flag access metadata (the important one).** The top item on the project's own
roadmap is *backward flag liveness* ([`../ARCHITECTURE.md`](../ARCHITECTURE.md), "Advanced
roadmap" §1, attributed to igi-recomp). Implementing it requires knowing, per instruction,
**which** flags are read, which are written, and whether a written flag is *defined* or
*undefined*. Capstone's detail API cannot express that: `cs_regs_access()` reports `rflags` as
a single all-or-nothing register.

First-hand probe run for this report (Capstone 5.0.3 on this host, Apple Silicon, via
`cs_regs_access`):

```
add    rax,rbx   read=rax,rbx      write=rflags,rax
cmp    rax,rbx   read=rax,rbx      write=rflags
je     +5        read=rflags       write=
inc    rax       read=rax          write=rflags,rax
shl    eax,1     read=eax          write=rflags,eax
adc    rax,rbx   read=rflags,rax,rbx  write=rflags,rax
mul    rbx       read=rax,rbx      write=rax,rdx,rflags
lahf             read=rflags       write=ah
```

So Capstone says "*some* flags are written" but not *which*, and not whether the value is
defined. Zydis v4 exposes exactly that: `ZydisDecodedInstruction.cpu_flags` points at a
`ZydisAccessedFlags` whose masks cover *tested*, *modified*, *set to 0*, *set to 1* and
*undefined*, guarded by the `ZYDIS_ATTRIB_CPUFLAG_ACCESS` attribute
([`include/Zydis/DecoderTypes.h`](https://github.com/zyantific/zydis/blob/master/include/Zydis/DecoderTypes.h),
[`src/Decoder.c`](https://github.com/zyantific/zydis/blob/master/src/Decoder.c),
[porting guide v3→v4](https://github.com/zyantific/zydis/blob/master/assets/porting-guide-v3-v4.md)).
This matters in practice here, not in theory: the project's own
[`../CHANGELOG.md`](../CHANGELOG.md) already lists "undefined shift/rotate flags" as a fixed
bug — the precise case where "written" and "written with a defined value" must be
distinguished.

**Gap B — an independent decoder for cross-checking discovery.** Discovery currently trusts a
single decoder for instruction length and branch classification
([`../core/discovery/function_discovery.cpp`](../core/discovery/function_discovery.cpp)). A
second, independent decoder makes decode disagreements a test-visible signal instead of a
silent CFG error. This is a *test-time* benefit only.

### 4.2 Integration cost

- **Dependency:** Homebrew bottle `zydis` 4.1.1 for Apple Silicon, MIT
  ([formula](https://formulae.brew.sh/formula/zydis)); alternatively a CMake source build with
  no third-party dependencies, C11, no `malloc`, thread-safe
  ([README](https://github.com/zyantific/zydis/blob/master/README.md)).
- **Build-system change:** one optional CMake option mirroring the existing Unicorn pattern in
  [`../CMakeLists.txt`](../CMakeLists.txt) (`RECOMP_ENABLE_UNICORN`, lines 7–9 and 34–49) —
  e.g. `RECOMP_ENABLE_ZYDIS`, defaulting to off. Zydis must never become a hard requirement.
- **Code change:** one adapter behind the existing `discovery::DecodedInstruction`
  ([`../core/discovery/function_discovery.hpp`](../core/discovery/function_discovery.hpp));
  Capstone remains the decoder, Zydis supplies flag metadata (and, in tests, the decode
  cross-check). No change to the lifter's public interface, the runtime, or generated code.
- **Licence impact:** none — MIT is compatible with Apache-2.0, and unlike Unicorn
  (GPL-2.0, already isolated behind `RECOMP_ENABLE_UNICORN`) it adds no copyleft obligation.
- **Runtime impact:** zero — Zydis is used only by the recompiler's analysis phase and is not
  linked into the generated program.

### 4.3 The equivalent-correctness test it must pass before replacing anything

Zydis may only *supplement* Capstone until all of the following pass; only Gate D permits a
replacement, and even then Capstone stays as the cross-check oracle.

- **Gate A — decode equivalence.** Over all 11 fixture PEs, plus every byte of each `.text`
  section as a robustness corpus, Zydis and Capstone must agree on: instruction length,
  terminator/branch classification, operand count and kinds, and register/immediate values.
  Every disagreement is reported (never silently tolerated) and adjudicated by executing the
  disputed bytes under the existing Unicorn reference.
- **Gate B — flag-metadata correctness.** In a debug mode, for every instruction the lifter
  emits, the flags the generated code *reads* must be a superset of the flags Zydis reports as
  tested/read, and every flag read must have been defined by an earlier write unless Zydis
  marks it undefined. Verified by comparing the current eager-flag lifter against the
  liveness lifter **bit-for-bit on the guest EFLAGS value at every instruction boundary**.
- **Gate C — end-to-end equivalence.** All 11 fixtures must still produce byte-identical
  stdout **and** an identical executed-address trace against the Unicorn reference — the
  existing `verify` contract ([`../README.md`](../README.md), [`../ARCHITECTURE.md`](../ARCHITECTURE.md)).
  This is the acceptance criterion; any speed-up from flag liveness is a secondary metric and
  must be measured before/after with the same command and dataset.
- **Gate D — replacement (only if A–C pass).** Zydis may then take over discovery decoding,
  with Capstone retained as the independent cross-check. If any gate fails, the option is
  turned off and the pipeline is unchanged.

**Rollback:** the feature is off by default and touches no runtime or generated code, so
removing it restores the current verified pipeline exactly.

---

## 5. Unverified, uncertain, or environment-specific

1. **Wine's own documentation is unreachable from here.** `gitlab.winehq.org` and
   `www.winehq.org` sit behind bot protection (Anubis / CAPTCHA), so Wine's `LICENSE` and
   release notes were read from the official GitHub mirror
   ([wine-mirror/wine](https://github.com/wine-mirror/wine/blob/master/LICENSE)) and press
   coverage. The exact Wine 11 release date (2026-01-15) comes from press coverage, not from
   winehq.org — treat it as **unverified**.
2. **remill on macOS ARM64** — the README says it "also works on macOS" but names Ubuntu 22.04
   as the tested platform; no build was attempted here, so remill v6 buildability on Apple
   Silicon is **unverified**.
3. **Zydis is not currently installed on this host.** `/opt/homebrew/include/Zydis` is a
   dangling symlink to `../Cellar/zydis/4.1.1/include/Zydis`, whose Cellar entry is absent
   (only a leftover `/opt/homebrew/lib/cmake/Zydis` link remains). The PoC therefore starts
   with `brew install zydis`. The flag-metadata API was verified from upstream sources, not
   from a local build.
4. **Capstone on this host is 5.0.3** (Homebrew stable upstream is 5.0.9); the `cs_regs_access`
   probe in §4.1 was run against 5.0.3.
5. **Ghidra installation route** — `https://formulae.brew.sh/cask/ghidra` returns 404, so the
   commonly cited `brew install --cask ghidra` path is **unverified**; the JDK 25, macOS
   10.13+ and user-built-native-components requirements come from the stable
   `GettingStarted.md`.
6. **M-HT/SR licence** — MIT per its README, with an additional GPLv2+/LGPLv2.1+ offer;
   GitHub's licence detector reports no licence for the repository (no root licence file
   detected). The README statement is the source used here.
7. **igi-recomp's produced binary architecture** — the README says it runs natively on macOS
   and `runtime/include/recomp.h` notes the code runs on arm64; the actual architecture of its
   build output was **not** verified.
8. **Repo-internal claims were taken from the repository's own documentation**
   ([`../README.md`](../README.md), [`../ARCHITECTURE.md`](../ARCHITECTURE.md)) and from the
   source files cited in §1; this task did not re-run the regression suite, so the project's
   "implemented, verified" statuses are reported as documented, not independently re-confirmed
   here.

---

## 6. Bottom line

Of fourteen candidates, exactly **one** is worth adding for the MVP proof of concept:
**Zydis (MIT, no dependencies, Homebrew bottle for Apple Silicon)** as an optional
analysis-phase provider of per-instruction CPU-flag access metadata and as a second decoder
for test-time cross-checking. Everything heavier or more invasive — remill, mcsema, revng,
Ghidra-as-a-dependency, LIEF, Wine, XED, and the two per-game recompilers as components — is
explicitly refused, with Capstone, Unicorn and `clang++` left untouched because they are
already working and tested.
