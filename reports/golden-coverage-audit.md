# Golden-coverage audit — is the IR-migration safety net adequate?

**Scope.** `tests/golden/golden_code_test.py` + `tests/golden/generated_code.sha256` as the safety net
for moving `core/semantics/x86_64_lifter.cpp` onto the architecture-neutral IR in `core/ir/`.
**Branch.** `feature/x86-x64-arm64-mvp`
**CLI under test.** `build/recomp-studio`, sha256 `2392ab759dddf0c4bcb729195196589b06296c88122072bc813056f7d9c39f52`
**Golden run at audit time.** `22 passed, 0 failed` (exit 0) — the net is green, so every weight below is
measured on the same output the net pins.

**Verdict.** The net is *green and meaningful, but not adequate*. It pins 24,518 statements from 22
hand-written fixtures; a single real binary (IGI.EXE) produces **422,653** statements, 17.2× as many.
**66 of the lifter's 178 `emit()` sites are provably unreachable from every pinned fixture** (41 of them
are live in a real binary), and the harness **passes vacuously** if the fixture binaries disappear.

---

## 1. Method

```bash
# authoritative statement census, per image (the product's own counter)
./build/recomp-studio coverage <exe>

# generated code for every fixture and for the real binaries
./build/recomp-studio translate <exe> --target macos-arm64 --output /tmp/gc/<name>

# the net itself
python3 tests/golden/golden_code_test.py ./build/recomp-studio tests/fixtures/apps \
        tests/golden/generated_code.sha256
```

* **Statements** = the `ir statements:` figure from `coverage`. It reconciles *exactly* with the
  pre-existing baseline in `reports/ir-migration-surface.md` §2.2: the 22 pinned fixtures sum to
  **24,518**, which is the number that report used. (A `guest.cpp` line parser run alongside agrees to
  within +1.2 %, the residual being multi-line statements grouped into one.)
* **Instructions** = `trace_instruction(...) // <mnemonic> <operands>` comment lines in the generated
  `guest.cpp`. One trace line per lifted instruction, so this is exact and is the denominator for all
  mnemonic frequencies.
* **Mnemonic** = first token of the trace comment.
* **`emit()` sites** = every `emit(...)` call in `core/semantics/x86_64_lifter.cpp`, mapped to the
  `if (...)` conditions that guard them by a brace/paren-aware scan of `emit_instruction()`
  (178 sites; 146 carry a mnemonic guard). This is syntax-derived, not text-heuristic — see §4.1.

Corpora: **22 pinned fixtures** (24,518 stmts) · **Tetris.exe** (real, 32-bit) ·
**IGI.EXE** (real, 32-bit, 1.35 MB, Jun 2002).

---

## 2. What is *not* covered — scale

| corpus | functions | instructions | IR statements | distinct mnemonics |
|---|---:|---:|---:|---:|
| 22 pinned fixtures | 97 | 11,830 | **24,518** | **153** |
| `Tetris.exe` | 495 | 11,455 | 26,286 | 54 |
| `igi.exe` | 3,370 | 191,337 | **422,653** | **137** |
| IGI vs fixtures | 34.7× | 16.2× | **17.2×** | 0.90× |

The fixtures are *mnemonically broader* than either real binary (153 distinct mnemonics vs 137/54) —
they were written to sweep the ISA. But they are **16–17× smaller in instance mass**, and breadth on
mnemonic *names* is not breadth on operand shapes: `mov` appears 4,686 times in fixtures and 44,090
times in IGI, and the encoding variants (segment overrides, SIB, disp32, 32-bit vs 64-bit addressing)
are not the same set.

`unsupported_instruction.exe` is not pinned (it fails under `strict` lifting: `unsupported instruction
'rdmsr' at 0x1400010be`), so it contributes 0 of the 24,518.

Per-fixture census (reproducible with `coverage`): aliasing 805 · arith 1,461 · bitops 817 · byteops 884 ·
calls 1,088 · eflags 938 · flagprobe 946 · heap 790 · memory 965 · packed 4,249 · pe32_abi 823 ·
pe32_arith 1,527 · pe32_simd_convert 1,239 · simd_convert 1,129 · snake 1,136 · teb32 735 ·
tictactoe 1,050 · unsupported_import 199 · vecmove 771 · vex 832 · wide 916 · x87 1,218. **Sum = 24,518.**

---

## 3. Mnemonic coverage table

Real-binary corpus (Tetris ∪ IGI) = **202,792 instruction instances, 146 distinct mnemonics**.
Covered by ≥1 fixture: 188,961 instances (**93.18 %**). **Not covered by any fixture: 13,831 instances
(6.82 %) across 78 mnemonics.** Those 78 mnemonics account for 16,019 of the 250,237 instruction-attributable
statements generated in the real corpus (**6.40 %**).

Ranked by frequency in the real binaries (IGI / Tetris split shown):

| # | mnemonic | instr (real) | stmts (real) | IGI | Tetris |
|---:|---|---:|---:|---:|---:|
| 1 | `fmul` | 5,161 | 5,177 | 5,161 | 0 |
| 2 | `fadd` | 1,780 | 1,791 | 1,780 | 0 |
| 3 | `fcomp` | 1,598 | 3,196 | 1,598 | 0 |
| 4 | `fsub` | 1,533 | 1,540 | 1,533 | 0 |
| 5 | `jl` | 555 | 680 | 555 | 0 |
| 6 | `fild` | 516 | 520 | 516 | 0 |
| 7 | `fst` | 358 | 364 | 358 | 0 |
| 8 | `leave` | 356 | 712 | 72 | 284 |
| 9 | `fxch` | 312 | 316 | 312 | 0 |
| 10 | `not` | 224 | 228 | 220 | 4 |
| 11 | `fcom` | 215 | 215 | 215 | 0 |
| 12 | `fdiv` | 194 | 202 | 194 | 0 |
| 13 | `repne` | 190 | 190 | 190 | 0 |
| 14 | `fdivr` | 186 | 196 | 186 | 0 |
| 15 | `fsubr` | 121 | 124 | 121 | 0 |
| 16 | `jae` | 117 | 134 | 107 | 10 |
| 17 | `jbe` | 59 | 73 | 56 | 3 |
| 18 | `wait` | 34 | 4 | 34 | 0 |
| 19 | `sahf` | 31 | 31 | 31 | 0 |
| 20 | `jns` | 22 | 25 | 15 | 7 |
| 21 | `xchg` | 19 | 19 | 18 | 1 |
| 22 | `fld1` | 18 | 19 | 18 | 0 |
| 23 | `fiadd` | 13 | 13 | 13 | 0 |
| 24 | `fdivrp` | 11 | 22 | 11 | 0 |
| 25 | `fldz` | 11 | 12 | 11 | 0 |
| 26 | `stosd` | 11 | 11 | 11 | 0 |
| 27 | `bsr` | 9 | 9 | 9 | 0 |
| 28 | `fscale` | 9 | 9 | 9 | 0 |
| 29 | `seta` | 9 | 9 | 0 | 9 |
| 30 | `frndint` | 8 | 8 | 8 | 0 |
| 31 | `setg` | 8 | 8 | 8 | 0 |
| 32 | `setl` | 8 | 8 | 8 | 0 |
| 33 | `fidiv` | 7 | 8 | 7 | 0 |
| 34 | `fsubrp` | 7 | 14 | 7 | 0 |
| 35 | `stosb` | 6 | 6 | 6 | 0 |
| 36 | `fptan` | 6 | 6 | 6 | 0 |
| 37 | `f2xm1` | 5 | 5 | 5 | 0 |
| 38 | `fprem` | 5 | 6 | 5 | 0 |
| 39 | `setge` | 5 | 5 | 5 | 0 |
| 40 | `fisub` | 5 | 5 | 5 | 0 |
| 41 | `repe` | 4 | 4 | 3 | 1 |
| 42 | `loopne` | 4 | 4 | 4 | 0 |
| 43 | `les` | 4 | 4 | 4 | 0 |
| 44 | `pushfd` | 4 | 4 | 1 | 3 |
| 45 | `bsf` | 4 | 4 | 4 | 0 |
| 46 | `fldl2e` | 4 | 4 | 4 | 0 |
| 47 | `popfd` | 4 | 4 | 2 | 2 |
| 48 | `setae` | 4 | 4 | 0 | 4 |
| 49 | `cpuid` | 4 | 4 | 0 | 4 |
| 50 | `fstpnce` | 3 | 6 | 3 | 0 |
| 51 | `fldenv` | 3 | 3 | 1 | 2 |
| 52 | `setle` | 3 | 3 | 3 | 0 |
| 53 | `repz` | 3 | 6 | 0 | 3 |
| 54 | `stosw` | 2 | 2 | 2 | 0 |
| 55 | `fimul` | 2 | 2 | 2 | 0 |
| 56 | `fnclex` | 2 | 2 | 2 | 0 |
| 57 | `fldpi` | 2 | 2 | 2 | 0 |
| 58 | `fxam` | 2 | 2 | 2 | 0 |
| 59 | `xlatb` | 2 | 2 | 2 | 0 |
| 60 | `cwde` | 2 | 2 | 2 | 0 |
| 61 | `lcall` | 2 | 4 | 2 | 0 |
| 62 | `cmpsb` | 2 | 2 | 2 | 0 |
| 63 | `cmpsd` | 2 | 2 | 2 | 0 |
| 64 | `lodsd` | 2 | 2 | 2 | 0 |
| 65 | `scasb` | 2 | 2 | 2 | 0 |
| 66 | `scasd` | 2 | 2 | 2 | 0 |
| 67 | `fxsave` | 2 | 2 | 0 | 2 |
| 68 | `fxrstor` | 2 | 2 | 0 | 2 |
| 69 | `fninit` | 2 | 2 | 0 | 2 |
| 70 | `enter` | 1 | 3 | 1 | 0 |
| 71 | `fldln2` | 1 | 1 | 1 | 0 |
| 72 | `jp` | 1 | 1 | 1 | 0 |
| 73 | `fnsave` | 1 | 1 | 1 | 0 |
| 74 | `frstor` | 1 | 1 | 1 | 0 |
| 75 | `fnstenv` | 1 | 1 | 1 | 0 |
| 76 | `aaa` | 1 | 1 | 1 | 0 |
| 77 | `movsw` | 1 | 1 | 1 | 0 |
| 78 | `fcmovu` | 1 | 1 | 1 | 0 |

**Reading of the table.** The gap is not uniformly spread — it is an **x87-shaped hole**.
Of the 13,831 uncovered instructions, **12,124 (87.7 %)** are x87 — and those same mnemonics are
**13,768 of the 16,019 uncovered statements (85.9 %)**. The `x87.exe` fixture covers only **18**
x87 mnemonics and, crucially, only the **register-form / pop-form** ones (`faddp`, `fmulp`, `fsubp`,
`fdivp`, `fld`, `fstp`, `fistp`, `fcompp`, `fabs`, `fchs`, `fsqrt`, `fsin`, `fcos`, `fpatan`, `fyl2x`,
`fldcw`, `fnstcw`, `fnstsw`). Real 32-bit code overwhelmingly uses the **memory-operand** forms
(`fmul dword ptr [...]`, `fadd dword ptr [...]`, `fcomp dword ptr [...]`), which the fixture never
emits. 38 x87 mnemonics used by the real binaries are absent from the fixture corpus entirely.

Seven mnemonics are exercised **only by Tetris** and by no other corpus: `cpuid`, `fninit`, `fxrstor`,
`fxsave`, `repz`, `seta`, `setae` — pinning IGI alone would still miss them.

---

## 4. Structural blind spots

These are shapes the golden test **cannot catch even in principle**, because no fixture drives them.

### 4.1 66 `emit()` sites are provably unreachable from the pinned corpus

Method: parse `X86_64Lifter::emit_instruction()` in `core/semantics/x86_64_lifter.cpp`, track brace
scopes, and attach to each `emit()` call the condition text of every enclosing `if (...) {` block.
Extract the `mnemonic == "X"` / `mnemonic.rfind("X", 0)` literals from those conditions. A site whose
guard mnemonics are **all** absent from the fixture mnemonic set can never execute under any fixture.

| | sites |
|---|---:|
| `emit()` sites in the lifter | **178** |
| carrying a mnemonic guard | 146 |
| **reachable by ≥1 pinned fixture** | **78 (53.4 %)** |
| flagged unreachable | 68 |
| minus 2 false positives from prefix guards (`mnemonic.rfind("set",0)`, `"cmov"` — `setb/sete/setne/seto` and `cmovg/…` *are* in fixtures) | −2 |
| **provably unreachable by every fixture** | **66 (45.2 %)** |
| — of those, **reachable by a real binary** (live, untested) | **41** |
| — dead in fixtures *and* both real binaries | 25 |

Split of the 66: **31** are reachable only via IGI, **3** only via Tetris, 7 via either, 25 via neither.

Representative live-untested sites (line numbers in `core/semantics/x86_64_lifter.cpp`):

| line | guard mnemonic(s) | what it emits |
|---:|---|---|
| 745 | `cpuid` | `execute_cpuid(context);` |
| 813 | `xchg` | exchange, register/memory forms |
| 986–987 | `leave` | two statements: `rsp = rbp`, `rbp = pop_guest_stack(context)` |
| 992 | `seta/setae/setg/setge/setl/setle` | `evaluate_condition` write |
| 1136 / 1140 | `pushfd/pushfq`, `popfd/popfq` | eflags push/pop |
| 1248 / 1252 | `bsf`, `bsr` | `bit_scan_forward/reverse` |
| 1264 / 1269 | `cmpxchg`, `xadd` | atomic read-modify-write |
| 1298 | `fild` | `x87_load_integer` |
| 1472 / 1476 | `fxsave`, `fxrstor` | `x87_save_state` / `x87_restore_state` |
| 1525–1536 | `enter` | 7 sites, nested-frame prologue |
| 1541 | `aaa` | BCD adjust |
| 1550–1622 | `fprem`, `f2xm1`, `fscale`, `fldln2`, `fldl2e`, `fldl2t`, `fldlg2`, `fld1`, `fldz`, `fldpi`, `fxch` | x87 transcendental / constant loads |
| 1569 | `lds`, `les`, `lfs`, `lgs`, `lss` | far pointer load |

Direct grep confirmation (`grep -c '// leave' <guest.cpp>`): fixtures **0**, IGI **72**, Tetris **284**.
Same for `// cpuid`: fixtures **0**, IGI **0**, Tetris **4**.

### 4.2 The named `xgetbv` hazard — and it is worse than "not executed"

`core/semantics/x86_64_lifter.cpp:1086` emits **two statements on one line**:

```cpp
if (mnemonic == "xgetbv") {
  emit("context->registers[0] = 0x1ull; context->registers[2] = 0;");
  return;
}
```

Modelling that as two IR statements is correct and **will change the generated bytes**. Verified:
`xgetbv` is absent from the fixture corpus **and** from both real binaries
(`grep -c '// xgetbv'` → 0 in all three; mnemonic-set membership → false in all three).
So this site is exercised by *nothing at all*: the golden test cannot see the change, and neither can
any real-binary check run against these two images. It is the clearest single example of the class, but
§4.1 shows it is one of 66.

Other multi-statement-per-`emit()` sites found by the same scan (all latent byte-change risks):
`:969` (`lahf`/`sahf`, 6 statements), `:1079` (indirect jump, 2), `:1291`, `:1296` (cmpxchg/xadd, 4),
`:1361`, `:1365`, `:1483`, `:1486` (x87 memory operands, 4), `:1393` (x87 reg-reg, 3), `:1517`
(`xlat`, 3), `:1542` (`xlat`, 2), `:1557` (`enter`, loop), `:1568` (`aaa`, 8), `:1629` (x87, 3),
`:1683` (`loop`, 2).

### 4.3 The harness passes **vacuously** when fixtures vanish

```python
for fixture in sorted((FIXTURES / "bin").glob("*.exe")):
    if fixture.name not in expected:
        continue          # <- silently skipped, in both directions
```

Measured:

```
$ python3 tests/golden/golden_code_test.py ./build/recomp-studio /tmp/gc/empty tests/golden/generated_code.sha256
checked 0 fixtures against the golden baseline
0 passed, 0 failed
[exit code: 0]
```

An empty fixture directory **passes**. Renaming one pinned fixture out of the way
(`x87.exe` → `x87_renamed.exe`) gives `21 passed, 0 failed`, exit 0, with no warning that a pinned
fixture is missing. The test never iterates the baseline to find fixtures that should exist but don't.
So corpus *shrinkage* — a deleted `.exe`, a rename, a `build.sh` change that renames an output — silently
reduces the net's coverage while keeping it green. For a refactor whose entire justification is "the
output is pinned", that is the most dangerous property in the file.

### 4.4 It pins bytes, not behaviour, and only for one target

The net compares `sha256(guest.cpp)` for `--target macos-arm64` only. It does not compile the generated
project, does not run it, and does not check any other target. A lifter change that produces identical
text but a broken runtime helper (or vice versa, an unchanged `guest.cpp` with a changed
`recomp_runtime.cpp` — the runtime is *not* pinned at all) is invisible. `recomp_runtime.cpp`,
`recomp_runtime.hpp` and `win32_abi.hpp` are generated next to `guest.cpp` and are not digested.

### 4.5 Silent no-ops

`core/semantics/x86_64_lifter.cpp:1311` — `if (mnemonic == "wait" || mnemonic == "fwait") return;`
emits **nothing**: 34 `wait` instructions in IGI produce 4 statements total (their trace lines only).
That is defensible modelling, but it means "mnemonic appears in the trace" ≠ "mnemonic has an emit site
under test". Any audit that equates the two will overstate coverage; this report does not.

---

## 5. Recommendation — smallest additions that close the largest gaps

Ordered by value per unit of work. Items 1+2 together close **66/66** of the provably unreachable
`emit()` sites.

| # | addition | closes | protects | why |
|---|---|---:|---:|---|
| **1** | **New fixture `x87_mem.c`** — x87 with *memory operands* and comparison/transcendental: `fmul/fadd/fsub/fdiv/fsubr/fdivr` on `dword ptr`/`qword ptr`, `fcom/fcomp`, `fild/fist/fistp/fst`, `fxch`, `f2xm1/fscale/fprem/frndint/fptan/fyl2xp1/fsincos`, `fld1/fldz/fldpi/fldln2/fldl2e/fldl2t/fldlg2`, `fnsave/frstor/fldenv/fnstenv/fnclex/fninit/fxsave/fxrstor/fxam`, `cwd/cqo/cwde` | **24/66** | **13,764 stmts (5.50 % of the real corpus)** | 86 % of the entire uncovered statement mass is x87; `x87.exe` covers only register/pop forms |
| **2** | **New fixture `misc32.c`** — 32-bit control/flag/string shapes: `leave`, `enter`, `jl/jae/jbe/jns/jp`, `seta/setae/setg/setge/setl/setle`, `not`, `sahf`, `bsf/bsr`, `cpuid`, `xchg`, `pushfd/popfd`, `aaa`, `xlatb`, `stosb/stosw/stosd`, `repne/repe/repz`, `loopne`, `cmpsb/cmpsd/lodsd/scasb/scasd/movsw`, `les/lds`, `lcall`, `cmpxchg/xadd`, `tzcnt`, `retf`, `clc/stc/cmc`, `xgetbv` | **42/66** | 2,215 stmts (0.89 %) | closes the non-x87 sites **including the two-statements-on-one-line `xgetbv` hazard (§4.2)**, which nothing currently exercises |
| **3** | **Pin `Tetris.exe` as a second golden artifact** (digest of `guest.cpp`, 26,286 stmts — 1.07× the whole fixture corpus) | — | covers 7 mnemonics no fixture and no other pinned image exercises (`cpuid`, `fxsave`, `fxrstor`, `fninit`, `repz`, `seta`, `setae`) and 3 emit sites closed by Tetris alone | a real 32-bit binary at zero fixture-authoring cost; but see caveat |
| **4** | **Harden the harness** (cheap, highest leverage): fail when `checked != len(expected)`; fail on baseline entries with no corresponding fixture; also digest `recomp_runtime.cpp` / `win32_abi.hpp` | removes §4.3 entirely | — | the net currently cannot detect its own coverage shrinking |

**Smallest sufficient set = items 1 + 4.** Item 1 alone recovers 86 % of the uncovered statement mass and
24 of the 66 blind emit sites; item 4 stops the net from silently losing fixtures. Adding item 2 gets to
66/66 for another ~200 lines of fixture source.

**Caveat on item 3.** A pinned real binary is only reproducible if the `.exe` is checked in and stable.
`igi.exe` (81 MB of `guest.cpp`, 422,653 stmts) is impractical to pin as a digest artifact; Tetris
(224 KB `.exe`, 26,286 stmts) is not. Pinning Tetris also does not fix §4.1 — 61 of the 66 blind sites
are IGI-only and remain blind.

**What none of this fixes.** Even with items 1–4, coverage stays mnemonic-and-shape bounded: 93.18 % of
real-binary *instances* use already-covered mnemonics, but on operand shapes the fixtures do not
reproduce. If the migration's risk is "does the IR round-trip *this* encoding", only a real-binary
differential (translate a real `.exe` before and after the change and diff the two `guest.cpp`) closes
it. That is the strongest available addition and it needs no new fixtures — just a second digest of
IGI/Tetris output captured now, before the refactor lands.

---

## 6. Reproduction appendix

```bash
# 1. net is green at audit time
python3 tests/golden/golden_code_test.py ./build/recomp-studio tests/fixtures/apps \
        tests/golden/generated_code.sha256            # -> 22 passed, 0 failed ; exit 0

# 2. scale (per image)
for f in tests/fixtures/apps/bin/*.exe; do ./build/recomp-studio coverage "$f"; done
./build/recomp-studio coverage /Users/haseeb-mir/Downloads/recomp-apps/tetris/Tetris.exe
./build/recomp-studio coverage /Users/haseeb-mir/Downloads/IGI/igi.exe
#    fixtures sum 24,518 stmts | Tetris 26,286 | IGI 422,653

# 3. generated corpora
for f in tests/fixtures/apps/bin/*.exe; do
  n=$(basename "$f" .exe)
  ./build/recomp-studio translate "$f" --target macos-arm64 --output /tmp/gc/fx_$n
done
./build/recomp-studio translate /Users/haseeb-mir/Downloads/recomp-apps/tetris/Tetris.exe \
    --target macos-arm64 --output /tmp/gc/tetris
./build/recomp-studio translate /Users/haseeb-mir/Downloads/IGI/igi.exe \
    --target macos-arm64 --output /tmp/gc/igi

# 4. mnemonic extraction (per trace comment)
grep -o 'trace_instruction([^)]*); // [a-z0-9]*' /tmp/gc/igi/guest.cpp | awk '{print $NF}' | sort | uniq -c | sort -rn

# 5. vacuous-pass check
mkdir -p /tmp/gc/empty/bin
python3 tests/golden/golden_code_test.py ./build/recomp-studio /tmp/gc/empty \
        tests/golden/generated_code.sha256            # -> "checked 0 fixtures" ; exit 0  <-- blind spot
```

Analysis scripts used for §3 and §4.1 live outside the repo at `/tmp/gc/`
(`emit_sites.py`, `guard_map.py`, `final_numbers.py`, `table.py`, `split.py`); they read
`core/semantics/x86_64_lifter.cpp` and the generated corpora and write only to `/tmp`.

**Files not modified.** This audit is read-only against the repository except for this report. No
fixture, baseline, source or configuration file was changed; no git state-changing command was run.
