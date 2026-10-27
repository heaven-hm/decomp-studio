# Coverage verification — independent decoder ground truth (task-3)

**Owner:** `coverage-audit` (teammate)
**Shared task:** task-3 — independently verify task-1's `coverage` CLI command
**Verdict: VERIFIED**

`./build/recomp-studio coverage` was compared against an independently derived
Capstone-based ground truth on three binaries. On all three, every headline figure, the
complete set of unsupported classes, and every per-class occurrence count match exactly.
`coverage` neither over-reports nor under-reports. The comparison was shown to be
*capable of failing* by a negative control that injected three defects and was correctly
rejected.

**Write scope respected:** only `reports/coverage-verification.md` and `reports/tools/`
were written. No file under `core/`, `apps/`, `runtime/`, `tests/` was modified. The only
non-`reports/` command run was the lead-authorised `cmake --build build`, which regenerates
build artefacts only.

**Lifter revision this report is pinned to:**
`core/semantics/x86_64_lifter.cpp` sha256
`3561e1ff3fb0796f05cb625c68fe3a53e0cde925f0b71d1f238d5fac4c200e28`. The tool prints this
hash and compares it against a pinned constant on every run, so a stale model is visible
rather than silent. It matched at the time of the Phase 2 comparison.

**Compared revision:** commit `9301bbe` ("feat(coverage): report every unsupported
instruction class, not just the first"). The pre-existing `build/recomp-studio` was stale
(06:06) relative to `apps/cli/main.cpp` (06:19:56), so the binary was rebuilt before any
measurement; the rebuild is what produced the numbers below.

---

## 1. Status summary

| Item | State |
| --- | --- |
| Phase 1 — independent ground truth | **DONE** |
| Phase 1 — self-validation of the ground truth | **DONE** (5 checks, all pass) |
| Phase 2 — `coverage` vs independent histogram | **DONE** — 3/3 binaries agree exactly |
| Negative control (does the diff detect defects?) | **PASS** — 3 injected defects detected |
| task-3 | claimed, then completed |

### Headline result

| Image | `coverage` total | independent total | `coverage` unsupported | independent unsupported | classes (tool / indep.) | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `tests/fixtures/apps/bin/arith.exe` | 688 | 688 | 0 | 0 | 0 / 0 | **AGREE EXACTLY** |
| `/tmp/recomp-real/plink.exe` | 164668 | 164668 | 2037 | 2037 | 82 / 82 | **AGREE EXACTLY** |
| `/Users/haseeb-mir/Downloads/IGI/igi.exe` | 51518 | 51518 | 540 | 540 | 33 / 33 | **AGREE EXACTLY** |

Differences found: **zero** classes only in the tool, **zero** classes only in the
independent model, **zero** per-class occurrence-count differences.

---

## 2. Independence statement (read this before trusting the numbers)

* **Independent of the lifter:** yes. Nothing in `reports/tools/` calls into
  `build/recomp-studio`, links the project, or consumes its output. The lifter's accepted
  mnemonic set was re-derived by hand from the source (line ranges in §7) and
  re-implemented in Python as a decision model.
* **Independent of the project's *discovery* code:** it is a separate implementation, but a
  deliberate *port* of `core/discovery/function_discovery.cpp`, because the comparison is
  only meaningful if both sides walk the same reachable instruction set. It was validated to
  be exact (§4.1).
* **Independent of the project's *decoder*: NO — the honest caveat.** The project links
  Homebrew **libcapstone 5.0.3** (`CMakeLists.txt:12-17`); my tool uses the **Capstone
  Python bindings 5.0.7** (bundled wheel). Different builds of the same disassembler
  project, so a Capstone bug would affect both sides identically. I therefore added a
  genuinely independent second decoder — **LLVM via `llvm-objdump`** — and cross-checked the
  decoded stream against it (§4.2). That is the real evidence that the decoded stream is not
  a Capstone artefact.

---

## 3. Exact commands

```sh
# rebuild the stale binary at 9301bbe (lead-authorised)
cmake --build build -j

# independent ground truth (own PE parser + Capstone Python 5.0.7)
python3 reports/tools/independent_coverage.py tests/fixtures/apps/bin/arith.exe \
    --json reports/tools/ground-truth-arith.json > reports/tools/ground-truth-arith.txt
python3 reports/tools/independent_coverage.py /tmp/recomp-real/plink.exe \
    --json reports/tools/ground-truth-plink.json > reports/tools/ground-truth-plink.txt
python3 reports/tools/independent_coverage.py /Users/haseeb-mir/Downloads/IGI/igi.exe \
    --json reports/tools/ground-truth-igi.json > reports/tools/ground-truth-igi.txt

# second-opinion checks
python3 reports/tools/crosscheck_decoder.py /tmp/recomp-real/plink.exe --sample 500
python3 reports/tools/crosscheck_decoder.py tests/fixtures/apps/bin/arith.exe --sample 200

# the tool under test
./build/recomp-studio coverage tests/fixtures/apps/bin/arith.exe --json > reports/tools/coverage-arith.json
./build/recomp-studio coverage tests/fixtures/apps/bin/arith.exe        > reports/tools/coverage-arith.txt
./build/recomp-studio coverage /tmp/recomp-real/plink.exe --json       > reports/tools/coverage-plink.json
./build/recomp-studio coverage /tmp/recomp-real/plink.exe              > reports/tools/coverage-plink.txt
./build/recomp-studio coverage /Users/haseeb-mir/Downloads/IGI/igi.exe --json > reports/tools/coverage-igi.json
./build/recomp-studio coverage /Users/haseeb-mir/Downloads/IGI/igi.exe        > reports/tools/coverage-igi.txt

# the comparison
python3 reports/tools/diff_coverage.py reports/tools/coverage-arith.json reports/tools/ground-truth-arith.json
python3 reports/tools/diff_coverage.py reports/tools/coverage-plink.json reports/tools/ground-truth-plink.json
python3 reports/tools/diff_coverage.py reports/tools/coverage-igi.json   reports/tools/ground-truth-igi.json
```

Input hashes verified before use:

| Image | sha256 | bytes |
| --- | --- | --- |
| `/tmp/recomp-real/plink.exe` | `969f36879d5716aa1a9811f43a6a6510e8f08372dbeb9695b810b9c776f39c75` | 1 036 448 |
| `/Users/haseeb-mir/Downloads/IGI/igi.exe` | `dea34892d417715873ea61d7b2ba5556655f1ad65385104348146f9679915a01` | 1 384 448 |

Both match the hashes supplied in the task and by the lead.

### Artefacts

| File | Purpose |
| --- | --- |
| [`reports/tools/independent_coverage.py`](reports/tools/independent_coverage.py) | Own PE parser + Capstone decode + reachability port + lifter accept/reject model; pins the lifter hash. |
| [`reports/tools/diff_coverage.py`](reports/tools/diff_coverage.py) | The comparison: totals, class-set differences, per-class counts, first site. Exit 1 on any mismatch. |
| [`reports/tools/crosscheck_decoder.py`](reports/tools/crosscheck_decoder.py) | PE parse vs `pefile`; decode vs `llvm-objdump`. |
| `ground-truth-{arith,plink,igi}.{txt,json}` | Raw independent output. |
| `coverage-{arith,plink,igi}.{txt,json}` | Raw `coverage` output. |
| `diff-{arith,plink,igi}.txt` | Raw comparison output. |
| `crosscheck-{arith,plink}.txt` | Raw second-opinion output. |

---

## 4. Validation of the ground truth itself

A histogram is only usable as a reference if the instruction set it is computed over is the
same set the project sees. Five checks, all passing.

### 4.1 Reachability port matches the project exactly

```sh
./build/recomp-studio functions /tmp/recomp-real/plink.exe > /tmp/plink-functions.txt
```

```
mine: 2208 functions   project: 2208 functions
entries only in mine:    0
entries only in project: 0
instruction-count mismatches: 0
block-count mismatches:       0
VERDICT: EXACT MATCH on function set, per-function instruction counts and block counts
```

| Image | Project `analyze` | My tool |
| --- | --- | --- |
| `arith.exe` | 5 functions / 688 instructions | 5 functions / 688 instructions |
| `plink.exe` | 2208 functions / 164668 instructions | 2208 functions / 164668 instructions |
| `igi.exe` | 971 functions / 51518 instructions | 971 functions / 51518 instructions |

The total instruction count exceeds the unique address count (164668 vs 160695 on
`plink.exe`) because a function that is also a `call` target is recovered both as its own
function and as part of its caller's body — the project's documented behaviour, reproduced.

### 4.2 Decode layer validated against LLVM's disassembler

`llvm-objdump -d --no-show-raw-insn --x86-asm-syntax=intel` at the same virtual addresses,
over a stride sample of the recovered stream:

| Image | Sample | Mnemonic agreement | Length mismatches | Full-text agreement |
| --- | --- | --- | --- | --- |
| `plink.exe` | 500 | **500/500 (100.00%)** | **0/500** | 466/500 (93.20%) |
| `arith.exe` | 200 | **200/200 (100.00%)** | **0/200** | 189/200 (94.50%) |

Residual text differences are printer style only, all inspected: `llvm-objdump` appends a
resolved-target comment (`lea rcx, [rip + 739041] # 5369456024`), prints immediates in hex
where Capstone prints decimal (`0x1` vs `1`), renders sign-extended immediates as negative
(`-4` vs `18446744073709551612`), and elides the implicit `1` in `shr eax, 1`. Mnemonics and
instruction lengths — what the histogram depends on — agree 100% with zero exceptions.

### 4.3 PE loader validated against `pefile`

`machine`, `image_base`, `entry_point_rva`, `size_of_headers`, section count, and every
section's `name`/`virtual_address`/`virtual_size`/`raw_offset`/`raw_size` are identical to
`pefile`'s parse for both tested images (`CHECK A ... PASS`). Section mapping is by RVA with
`end_virtual_address = VA + max(virtual_size, raw_size)` and `read_rva` semantics copied
from `core/binary/pe.cpp:54-87`.

### 4.4 The first-rejection prediction reproduces the reported abort

`translate` on `plink.exe` aborts with:

```
error: unsupported instruction 'punpcklbw' at 0x140014590ull
```

My model, iterating functions in ascending entry order and instructions in ascending
address order (the order of `x86_64_lifter.cpp:814` and `:797`), predicts:

```
function entry 0x140014570  instruction 0x140014590  punpcklbw xmm0, xmm0
```

Same mnemonic, same address — and `coverage` independently reports `punpcklbw` with
`first_address: 0x0140014590`, the earliest first-site across all 82 of its classes.

### 4.5 The lifter model is pinned to a specific source revision

`core/semantics/x86_64_lifter.cpp` is modified in the working tree (task-1). It changed at
**06:05:48** while I was extracting the mnemonic set; I detected this from the file mtime,
re-read the file, and corrected the model. The two differences that mattered:

| Change | Effect on the model |
| --- | --- |
| `ldmxcsr`/`stmxcsr` now require exactly one **memory** operand (`:365-376`) instead of being accepted unconditionally | model updated to require `size==1 && kind==mem` |
| `cvtdq2ps` is newly supported (`:378-392`) | added to the model |

These do **not** change any count: every `ldmxcsr` (5) and `stmxcsr` (6) instance in
`plink.exe` is the memory form, and `cvtdq2ps` does not occur in any tested image. Counts
are identical before and after the correction. All line ranges in §7 refer to the pinned
revision.

---

## 5. Phase 2 — `coverage` versus the independent histogram

### 5.1 `arith.exe` — must be fully covered

```sh
$ ./build/recomp-studio coverage tests/fixtures/apps/bin/arith.exe
architecture:   x86_64
functions:      5
instructions:   688
lifted:         688 (100.00%)
unsupported:    0
coverage:       complete — every recovered instruction lifts
[exit code: 0]
```

```sh
$ ./build/recomp-studio coverage tests/fixtures/apps/bin/arith.exe --json
{"status":"ok","architecture":"x86_64","format":"PE32+","function_count":5,
 "total_instructions":688,"lifted_instructions":688,"unsupported_instructions":0,
 "coverage_percent":100.00,"unsupported_class_count":0,"unsupported":[]}
```

Comparison ([`diff-arith.txt`](reports/tools/diff-arith.txt)):

```
OK   total_instructions         coverage=688       independent=688
OK   unsupported_instructions   coverage=0         independent=0
OK   unsupported_class_count    coverage=0         independent=0
OK   function_count             coverage=5         independent=5
OK   lifted_instructions        coverage=688       independent=688
classes only in coverage (over-reporting): 0
classes only in independent model (under-reporting): 0
per-class occurrence-count differences: 0
RESULT: AGREE EXACTLY
```

**`arith.exe` is fully covered, and the tool agrees.** The independent mnemonic histogram
is 30 classes over 688 instructions: `mov 294, lea 73, call 55, add 43, cmp 41, xor 35,
jne 30, sub 28, jmp 14, je 12, and 11, nop 9, push 8, pop 8, ret 4, test 3, imul 3, shr 2,
ja 2, cdqe 2, neg 2, js 1, movabs 1, mul 1, movzx 1, jb 1, div 1, cdq 1, idiv 1, cmovs 1`.

### 5.2 `plink.exe` — the genuine 1 MB PE32+ binary

```sh
$ ./build/recomp-studio coverage /tmp/recomp-real/plink.exe
architecture:   x86_64
functions:      2208
instructions:   164668
lifted:         162631 (98.76%)
unsupported:    2037
classes:        82 distinct unsupported instruction classes

occurrences  mnemonic                    first site
234          pmuludq                     0x0140072408 in 0x01400721e0
160          psrad                       0x0140072433 in 0x01400721e0
132          aesenc                      0x014007d290 in 0x014007d260
124          paddq                       0x0140072422 in 0x01400721e0
110          bswap                       0x0140014693 in 0x0140014680
102          psllq                       0x0140072410 in 0x01400721e0
 97          packssdw                    0x0140072467 in 0x01400721e0
 93          punpcklwd                   0x0140038c1c in 0x0140038bf0
 80          pslld                       0x0140072d63 in 0x0140072a70
 68          psrld                       0x014004c995 in 0x014004c610
 68          psrlq                       0x01400722ec in 0x01400721e0
 58          pmullw                      0x01400723e5 in 0x01400721e0
 53          punpckhwd                   0x0140073339 in 0x0140072a70
 51          pcmpeqb                     0x014005700c in 0x0140056f30
 49          paddw                       0x014001b024 in 0x014001af30
 45          pmaddwd                     0x01400799c8 in 0x0140079690
 45          pshuflw                     0x0140014594 in 0x0140014570
 37          pmovmskb                    0x0140057020 in 0x0140056f30
 37          psrlw                       0x014004c9a2 in 0x014004c610
 33          aesdec                      0x014007d340 in 0x014007d310
 26          pmulhuw                     0x01400723e1 in 0x01400721e0
 21          vmovdqa                     0x01400870b3 in 0x0140086ed0
...
```

(Full text output: [`coverage-plink.txt`](reports/tools/coverage-plink.txt); JSON:
[`coverage-plink.json`](reports/tools/coverage-plink.json).)

Comparison ([`diff-plink.txt`](reports/tools/diff-plink.txt)):

```
OK   total_instructions         coverage=164668    independent=164668
OK   unsupported_instructions   coverage=2037      independent=2037
OK   unsupported_class_count    coverage=82        independent=82
OK   function_count             coverage=2208      independent=2208
OK   lifted_instructions        coverage=162631    independent=162631
classes only in coverage (over-reporting): 0
classes only in independent model (under-reporting): 0
per-class occurrence-count differences: 0

first unsupported site (independent, project translation order):
    address=0x140014590  mnemonic=punpcklbw
    function=0x140014570
    coverage reports the same first site for class 'punpcklbw'
    earliest first-site across all classes: punpcklbw @ 0x0140014590

RESULT: AGREE EXACTLY
```

Every one of the 82 classes and all 2037 occurrences match. This includes the
operand-form-conditioned rejections (`pshufd 2`, `punpckhdq 2`, `punpckldq 2`, `psubd 1`,
`bts 12`, `btr 8`), which are the cases most likely to expose a model error — the two
independent implementations agree on those too.

### 5.3 Negative control — the comparison can actually fail

To show that "AGREE EXACTLY" is not vacuous, three defects were injected into a copy of
`coverage-plink.json` (drop `psrad`, bump `pmuludq` by one, add a phantom class
`fictitious_op`):

```
classes only in coverage (over-reporting): 1
    fictitious_op          coverage=3
classes only in independent model (under-reporting): 1
    psrad                  independent=160
per-class occurrence-count differences: 1
    pmuludq                coverage=235     independent=234
    NOTE: coverage's earliest first-site differs from the predicted abort site
RESULT: MISMATCH
[negative-control exit code: 1]
```

All three defects were detected, including the class-set difference in both directions.
The comparison is sensitive.

---

## 6. The user's ultimate target: `igi.exe` (x86 / PE32)

`coverage` on `igi.exe` reproduces the lead's figures exactly:

```sh
$ ./build/recomp-studio coverage /Users/haseeb-mir/Downloads/IGI/igi.exe
architecture:   x86
functions:      971
instructions:   51518
lifted:         50978 (98.95%)
unsupported:    540
classes:        33 distinct unsupported instruction classes
[exit code: 0]
```

My independent tool on the same binary ([`ground-truth-igi.txt`](reports/tools/ground-truth-igi.txt)):

```
architecture:         x86 (machine=0x014c)
image_base:           0x400000
entry_point_rva:      0xa50f5
executable sections:  .text
imports parsed:       128
entry sources:        {'entry_point': 1}
functions recovered:  971
instructions:         51518 (unique addresses 51382)
distinct mnemonics:   87
unsupported instrs:   540
unsupported mnemonics:33
```

Comparison ([`diff-igi.txt`](reports/tools/diff-igi.txt)):

```
OK   total_instructions         coverage=51518     independent=51518
OK   unsupported_instructions   coverage=540       independent=540
OK   unsupported_class_count    coverage=33        independent=33
OK   function_count             coverage=971       independent=971
OK   lifted_instructions        coverage=50978     independent=50978
classes only in coverage (over-reporting): 0
classes only in independent model (under-reporting): 0
per-class occurrence-count differences: 0

first unsupported site (independent, project translation order):
    address=0x449d58  mnemonic=fmul
    function=0x449d30
    coverage reports the same first site for class 'fmul'
    earliest first-site across all classes: fmul @ 0x0000449d58

RESULT: AGREE EXACTLY
```

### 6.1 x87 dominance — independently confirmed, with one number I cannot reproduce

**Confirmed: x87 dominates the `igi.exe` gap.** The complete 33-class list is below, and
the ranking is x87 from top to bottom.

However, **I cannot reproduce the lead's exact figure of "526 of the 540 are x87"**, and I
want to be precise about why rather than paper over it. My count depends on how `wait` is
classified, and both defensible answers differ from 526:

| Definition | x87 instructions | Share |
| --- | --- | --- |
| mnemonics beginning with `f` | **523** | 96.85% |
| the above **plus `wait`** (0x9B is the x87 WAIT/FWAIT instruction) | **535** | 99.07% |
| lead's figure | 526 | 97.41% |

526 lies between my two values, so the *conclusion* — x87 is overwhelmingly dominant — is
confirmed under either definition. The exact count is not reproducible from my data: the
closest of my two defensible classifications (523) differs by 3, and the one I consider
technically correct (535, counting `wait` as x87) differs by 9. I am reporting my own
numbers rather than adopting 526.

Non-x87 classes in `igi.exe` are only three, totalling 5 instructions:
`std 2`, `cld 2`, `jecxz 1`.

Full unsupported list (33 classes, 540 instructions):

```
fld 154, fmul 107, fstp 95, faddp 54, fnstsw 18, wait 12, fcomp 11, fchs 9, fild 8,
fadd 8, fsub 7, fldcw 6, fcos 6, fst 5, fsin 5, fxch 4, fistp 3, fnstcw 3, fldz 3,
fld1 3, fmulp 3, std 2, cld 2, fcom 2, fsqrt 2, fldln2 1, fyl2x 1, fnclex 1, fdivrp 1,
fldpi 1, jecxz 1, fpatan 1, fdivr 1
```

### 6.2 `jecxz` in `igi.exe` empirically confirms the source-reading divergence

In §7.1(ii) I predicted from reading the source that `jrcxz`/`jecxz`/`loop*` are treated as
conditional branches by `function_discovery.cpp:12-14` but are **absent** from the lifter's
`kConditionalBranches` (`x86_64_lifter.cpp:90-92`), and would therefore be rejected at lift
time. `igi.exe` contains exactly one `jecxz` (`0x4aad19`), and `coverage` reports it as an
unsupported class. The prediction is confirmed on real code.

This is the one item in this report that is a **lifter gap rather than a coverage-tool
defect** — `coverage` reports it correctly. It is listed here because it is a one-line fix
and `igi.exe` is the user's target.

---

## 7. Lifter evidence — line ranges used

The accepted-mnemonic set was read out of
[`core/semantics/x86_64_lifter.cpp`](core/semantics/x86_64_lifter.cpp) by hand, at the
pinned revision. Each group in the model cites its source branch; the mapping is embedded in
the tool as `LIFTER_EVIDENCE` and reproduced in `ground-truth-plink.json` under
`"lifter_evidence"`.

| Group | Lines (pinned revision) |
| --- | --- |
| Prefix stripping (`rep`/`repe`/`repne`/`lock`) | `254-259` |
| Rejection site (`record_unsupported`, throw) | `247-250`, called at `791` |
| String ops (`movs*`/`stos*`/`lods*`/`scas*`/`cmps*`) | table `94-102`, dispatch `286-297` |
| 128-bit vector moves | `299-304` |
| `movss`/`movsd` vector form | `305-309` |
| `movd`/`movq` vector form | `310-326` |
| Vector bitwise | table `104-110`, dispatch `327-337` |
| `paddd`/`psubd`/`pcmpeqd` | `338-346` |
| `pshufd` | `347-353` |
| `punpck{l,h}{dq,qdq}` | `354-363` |
| `ldmxcsr`/`stmxcsr` (one memory operand required) | `365-376` |
| `cvtdq2ps` | `378-392` |
| `cpuid`, `prefetch*` | `393`, `394-396` |
| `bt`/`bts`/`btr`/`btc` | `397-417` |
| `nop*`/`endbr*`/`pause` | `419-421` |
| `mov`/`movabs`, `movzx`, `movsx`/`movsxd`, `lea`, `xchg` | `423-427`, `428-437`, `438-449`, `450-454`, `455-463` |
| Arithmetic `add/sub/adc/sbb/and/or/xor` | table `72-79`, dispatch `465-473` |
| `cmp`, `test` | `474-479`, `480-485` |
| `inc`/`dec`/`neg`/`not` | `486-499` |
| `shrd`/`shld`; shifts | `500-510`; table `81-88`, dispatch `511-520` |
| `imul`, `mul`, `div`/`idiv` | `522-546`, `547-552`, `553-558` |
| `cdq`/`cqo`/`lahf`/`sahf`/`cwde`/`cdqe` | `559-587` |
| `push`/`pop`/`leave` | `589-611` |
| `set<cc>` / `cmov<cc>` | condition codes `51-70`, dispatch `613-618`, `619-624` |
| `call`, `jmp` | `626-643`, `644-665` |
| Conditional jumps | set `90-92`, dispatch `666-676` |
| `ret`/`retf`, `int3`/`hlt`/`ud2`/`ud1`/`ud0` | `677-689`, `690-694` |
| `vpxor`/`vandps`/`vpor` | `696-708` |
| Scalar float/double arithmetic | `709-729` |
| `cvtsi2sd`, `cvttsd2si`, `cvtsd2ss`, `cvtss2sd` | `730-738`, `739-747`, `748-752`, `753-757` |
| `bsr`/`bsf` | `758-770` |
| `xadd`/`cmpxchg` | `771-790` |

### 7.1 Two divergences found while reading

**(i) The census and the abort path key mnemonics differently.** `census()`
(`x86_64_lifter.cpp:838-875`) aggregates on the **raw** `instruction.mnemonic`, while
`record_unsupported` (line `791`) throws a message containing the **prefix-stripped**
mnemonic (`:254-259`). For an unsupported `lock bts`, the census would report the class as
`"lock bts"` while the reason string says `bts`. For all three tested binaries this is
**inert** — I checked: the 11 prefix-carrying mnemonics in `plink.exe` (`lock or 24,
lock xadd 12, lock inc 12, lock and 10, lock add 7, lock dec 3, lock cmpxchg 2,
rep stosq 2, rep stosw 2, rep movsb 1, rep stosb 1`) are all supported, so none reaches the
census. The tool prints `prefixed unsupported: none` on every run so this stays visible.
It is a latent inconsistency, not a current defect: it would surface on a binary that
contains an unsupported prefixed instruction (e.g. `lock bts [mem], 7`), where the class
name and the reason string would disagree.

**(ii) The lifter and discovery disagree about conditional branches.**
`function_discovery.cpp:12-14` treats `jrcxz`/`jecxz`/`loop`/`loope`/`loopne` as
conditional branches, but the lifter's `kConditionalBranches` (`x86_64_lifter.cpp:90-92`)
does **not** include them, so those mnemonics are rejected at lift time. Confirmed
empirically in §6.2 on `igi.exe`.

---

## 8. Actionable findings — where the remaining work is

Ranked for the project's actual targets. `coverage` reports all of these correctly; these
are lifter gaps, not coverage-tool defects.

### 8.1 `igi.exe` (the user's target): one family, one fix

**x87 is 523–535 of the 540 unsupported instructions (96.85%–99.07%).** Nothing else
matters on this binary: the three non-x87 classes total 5 instructions. An x87 stack
implementation (`fld`/`fst`/`fstp`/`fild`/`fistp`, the arithmetic forms `fadd*`/`fsub*`/
`fmul*`/`fdiv*`, the comparison forms `fcom*`/`fnstsw`, and `fldcw`/`fnstcw`) would take
`igi.exe` from 98.95% to ~100%.

Cheap extras on the same binary: `std`/`cld` (2 each, trivial flag writes), `jecxz` (1, add
to the lifter's conditional-branch set), `wait` (12, a no-op prefix).

### 8.2 `plink.exe`: families in priority order

| Instructions | Share | Family |
| --- | --- | --- |
| 1557 | 76.44% | SSE/MMX packed-integer arithmetic, shifts, packs/unpacks, shuffles |
| 195 | 9.57% | AES-NI / PCLMUL |
| 136 | 6.68% | Scalar GPR gaps (`bswap 110`, `bts 12`, `btr 8`, `int 5`, `cwd 1`) |
| 135 | 6.63% | AVX (VEX-encoded; includes the 9 FMA instructions) |
| 12 | 0.59% | SSE compare/convert gaps (`comisd`, `ucomisd`, `cvtdq2pd`, `xgetbv`) |
| 5 | 0.25% | SSE4.2 string compare (`pcmpistri`) |

### 8.3 Cheap wins in already-written handlers

**A. Memory-source forms of already-supported SSE ops are rejected (27 instructions on
`plink.exe`).** The handlers at `:338-346`, `:347-353` and `:354-363` require *both*
operands to be `xmm`, so the common `xmm, m128` form falls through to
`record_unsupported`. Confirmed instances:

```
0x14006860d  pshufd xmm0, xmmword ptr [rdi - 0x90], 0x1b
0x140068616  pshufd xmm1, xmmword ptr [rdi - 0x80], 0xb1
0x140079a43  punpckldq xmm6, xmmword ptr [rip + 0x4b7e5]
0x140079a5b  punpckldq xmm5, xmmword ptr [rip + 0x4b7cd]
0x140079a35  punpckhdq xmm9, xmmword ptr [rip + 0x4b7f2]
0x140079a4f  punpckhdq xmm3, xmmword ptr [rip + 0x4b7d9]
0x1400b3d0d  psubd xmm5, xmmword ptr [rip + 0x1761b]
```

The runtime already has `*_memory` helpers for the vector-bitwise family (`:332-334`), so
the same pattern extends to these handlers.

**B. Memory-destination bit tests are rejected (20 instructions on `plink.exe`).**
`bt`/`bts`/`btr`/`btc` are handled only when operand 0 is a register (`:397-399`), so
`bts dword ptr [rbx], 7` and `btr qword ptr [rbx], 9` are rejected.

**C. `comisd`/`ucomisd` are absent (5 on `plink.exe`).** They are not in the scalar
float/double tables (`:709-729`), which only cover `add/sub/mul/div`.

**D. `bswap` (110 on `plink.exe`) has no handler anywhere in the file** — a one-line win.

**E. `vzeroupper` (3) is semantically a no-op** and can join the ignore list at `:365-396`.

---

## 9. Limitations — stated plainly

1. **Shared disassembler.** My decoder is the Capstone Python bindings 5.0.7; the project
   links libcapstone 5.0.3. Same project, different build. Mitigated by 100% mnemonic and
   instruction-length agreement with `llvm-objdump` over 700 sampled instructions (§4.2),
   but a bug common to both Capstone builds would be invisible to this comparison. This is
   the single most important caveat on the VERIFIED verdict.
2. **Reachability is a port, not a second implementation.** It reproduces the project's
   algorithm rather than independently deriving reachability. It matched the project exactly
   on all functions and per-function counts for all three binaries (§4.1), so it is a valid
   *reference for comparison*; it is not independent evidence that the project's
   reachability is *correct*.
3. **The lifter model is a reading of the source, not the compiled lifter.** It is only as
   current as the pinned hash (which matched at comparison time). It is corroborated by
   reproducing the exact abort site, but the fact that it agrees with `census()` on all
   three binaries is partly a consequence of both being derived from the same source — the
   *decode and reachability* layers are what this verification independently confirms.
4. **The exact "526 x87" figure could not be reproduced** (§6.1). x87 dominance is
   confirmed; the precise count is 523 or 535 depending on `wait`.
5. **Three binaries only.** `plink.exe` and `igi.exe` are real, but the family rankings in
   §8 are specific to those two programs.
6. **No instruction patches applied.** `translate` applies
   `configuration.instruction_patches` before discovery (`core/pipeline.cpp:105`); no config
   file was used, so none were applied, and my tool applies none. A run with patches would
   produce a different instruction stream and therefore a different histogram.
7. **The lifter is a moving target.** It was edited at 06:05:48 during this task (§4.5). Any
   further edit invalidates the model; the tool's pinned-hash check exists to make that
   failure loud rather than silent. Re-run the three `diff_coverage.py` commands after any
   lifter change.
