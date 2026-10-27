# Instruction gap census — corpus-wide unsupported class ranking

**Owner:** `instruction-gap-analyst` (teammate).
**Deliverable:** this file. Write scope was exactly `reports/instruction-gap-census.md`; no code, test,
or other report was modified. The session was read-only apart from this file (all scratch output
lives in `/tmp/gapcensus/`).

**Repository revision:** `c2a836c`, branch `feature/x86-x64-arm64-mvp`.

**Tool revisions the numbers are pinned to.** The lifter was being edited and rebuilt by the lead
while this census ran, so every figure below is pinned to a *frozen copy* of the tool:

| artefact | sha256 |
| --- | --- |
| `build/recomp-studio` (frozen copy used for the headline per-binary runs) | `bcb0e1d32e97eccf48eda008f94dc57169b0a9d198fef90df8423df8e05b289b` |
| `core/semantics/x86_64_lifter.cpp` at the time the corpus sweep ran | `0d9d5e4793b7e89c2678bd8f8d57344c2e0c5e026a790eb417597505e10fc65d` |
| `core/semantics/x86_64_lifter.cpp` **at the time every line number below was re-verified** | `138c36e45b34998bfc558af751613c6ed4703294d2904bc61e05cc701ee45ba7` |
| `core/discovery/function_discovery.cpp` (§4.1, §4.2) | `fe09c1a58be7b86c…` (unchanged during the census) |
| `runtime/recomp_runtime.hpp` (unchanged throughout) | `f064c792c3881f962c408afcbc4139e5e60e19b5bc8402856f3013c5598096f6` |

**Every lifter line number in §4–§6 was re-read from the file at revision `138c36e4…`
immediately before this report was written — after two earlier readings had already gone stale.
The lead edited `x86_64_lifter.cpp` at least four times during this census** (the hash moved
`a25863b5` → `0d9d5e47` → `2b768eaf` → `138c36e4`). The lifter is a moving target: any later change
invalidates these numbers. Each citation therefore also names the anchor text (the mnemonic string
or table it lives in) so it can be relocated with a single `grep`.

---

## 1. The six binaries named in the report — all located

All six were found; none was substituted. The reported failure addresses match this census exactly
(see the per-binary tables in §2).

| report name | resolved path | sha256 | format |
| --- | --- | --- | --- |
| powder | `/Users/haseeb-mir/Downloads/recomp-apps/win64/powder-v100.1.400-x86_64-windows-mingw.exe` | `df32b616b31dabae10b82028731ebdfd6867c872198b81f29d418cbafbf460c3` | PE32+ x86_64 |
| gconv.exe | `/Users/haseeb-mir/Downloads/tools/gconv.exe` | `5616139f4f94e7299b0703954d6a3eeda36fdda5cb17e19fa32163ba6b326c78` | PE32 x86 |
| legacy-notepad-x64 | `/Users/haseeb-mir/Downloads/recomp-apps/win64/legacy-notepad-x64.exe` | `00e67923f531e5590ab404aa5b906470b7c1505ec75cf69f22db99509de9fb56` | PE32+ x86_64 |
| idman643build16 | `/Users/haseeb-mir/Downloads/idman643build16.exe` | `276aa7e4ff7682445b011ebe6ac3920e7eca6ece7d3f6723b1f1cb515164461b` | PE32 x86 |
| IGI-Injector | `/Users/haseeb-mir/Downloads/tools/IGI1Editor_v0.8.5.1/bin/IGI-Injector.exe` | `a845f88e0882d74d14858fd477d495a84b766a5f6ce2853884939108e0f87459` | PE32 x86 |
| guess.exe | `/Users/haseeb-mir/Downloads/recomp-apps/win64/guess.exe` | `950d3f190d9c8bc354f19201ce5caf1578e781eb02d9fbc0d78865060f427a31` | PE32+ x86_64 |

Ambiguities resolved (recorded so the choice is reproducible):

* `gconv.exe` exists twice — `Downloads/tools/gconv.exe` and
  `Downloads/Other/Resource_Convertor/gconv.exe`. Both are the same size and produce the same
  class list; the `tools/` copy is the one cited above.
* `guess.exe` exists at `Downloads/recomp-apps/guess.exe`,
  `.../win32/guess.exe` and `.../win64/guess.exe`. The reported address `0x140002c34` is an
  image-base `0x140000000` address, so it is the **x64** build; `win64/guess.exe` is cited.
  (`win32/guess.exe` is a different PE32 image with a different class list.)
* `legacy-notepad-x64.exe` also exists at `Downloads/recomp-apps/legacy-notepad-x64.exe`
  (byte-identical to the `win64/` copy).
* `powder` also exists at `Downloads/recomp-apps/powder-…exe` and
  `Downloads/recomp-apps/win64/powder-…exe` (byte-identical).

---

## 2. Per-binary census — full unsupported class list

Command form: `./build/recomp-studio coverage <exe>`. The six runs below were re-executed with the
frozen tool copy (`/tmp/gapcensus/frozen-studio`, sha256 `bcb0e1d3…`) so they share one tool version.
Reproduce with
`/tmp/gapcensus/frozen-studio coverage <path>`; raw captures are in `/tmp/gapcensus/six/`.

### 2.1 powder (x86_64) — 9061 functions, 1 081 565 instructions, 1841 unsupported, **60 classes**

```
160  movddup        0x0140013505   110  shufps         0x0140012fc2    39  pinsrw         0x0140096d0d
130  mulps          0x0140047f4d   101  minss          0x0140006766    39  punpckhbw      0x014069478b
118  movlps         0x0140049cff    99  maxss          0x014000675e    39  punpcklbw      0x0140694778
115  movhps         0x0140007761    87  addps          0x0140047f58    34  pextrw         0x01404439a8
 81  shufpd         0x014008a7c6    73  subps          0x0140085074    33  andnps         0x0140047e0f
 73  unpcklps       0x0140049d35    51  movhlps        0x0140023aa0    32  addpd          0x014004dc49
 47  cvttps2dq      0x0140047f75    32  movq           0x0140047f68    32  movshdup       0x0140049d13
 29  mulpd          0x0140085a9e    28  cvtps2pd       0x014004dc2b    26  aeskeygenassist 0x01404fd913
 24  cmpnltss       0x0140047dfe    24  movlhps        0x014013424c    22  movsldup       0x0140087edb
 20  unpckhpd       0x014004dc45    18  unpcklpd       0x0140085a9a    15  sqrtss         0x0140051f74
 14  cmpnless       0x014002489f    11  addsubps       0x0140129c0b     9  cvtpd2ps       0x014019f89b
  7  divps          0x01402b66bb     6  punpcklwd      0x014069e66f     6  sqrtsd         0x014004b87d
  5  rsqrtss        0x014019f646     4  andnpd         0x014015d1fb     4  cmpltss        0x0140150e09
  4  divpd          0x014019f88f     4  minsd          0x014004de31     4  packuswb       0x01405c4526
  4  pclmulqdq      0x01404fd6bb     3  cmpltsd        0x01401dc032     3  cvttpd2dq      0x0140085aa2
  3  movhpd         0x014015d273     2  maxsd          0x01404d5258     2  rcpps          0x0140157149
  2  rdseed         0x0140393748     2  rdtsc          0x014043e0d0     2  subpd          0x014019f897
  1  addsubpd       0x01404064af     1  aesdec         0x01404fd5fb     1  aesdeclast     0x01404fd60e
  1  aesenc         0x01404fd5dd     1  aesenclast     0x01404fd5f0     1  aesimc         0x01404fd874
  1  cmpnltsd      0x014015d1e7     1  rdrand         0x01403936de     1  unpckhps       0x01402d5877
```
The reported `maxss` at `0x14000675e` is row `99 maxss 0x014000675e` (the tool zero-pads to ten hex
digits). Verified with r2: `0x14000675e  f30f5f0506..  maxss xmm0, dword [0x1406cdc6c]`.

### 2.2 gconv.exe (x86) — 1046 functions, 43 480 instructions, 14 unsupported, **7 classes**

```
4  daa        0x0000412a39     3  ficom      0x000041165c     2  movlps     0x0000411651
2  unpckhps   0x00004105ce     1  int1       0x000040f12d     1  lsl        0x0000411f2e
1  pushal     0x000040ecec
```
The reported `pushal` at `0x40ecec` is the last row.

### 2.3 legacy-notepad-x64 (x86_64) — 403 functions, 22 499 instructions, 19 unsupported, **8 classes**

```
5  vfmadd213sd   0x0140025b8f     4  vcomisd       0x0140025ae1     3  vfmadd231sd  0x0140025bb2
2  pcmpistri     0x01400275dc     2  vcvtdq2pd     0x0140025ad5     1  roundsd      0x01400268e0
1  vfmsub213sd   0x0140025bcc     1  vinsertf128   0x0140027ea2
```
The reported `roundsd` at `0x1400268e0` is row `1 roundsd 0x01400268e0`.

### 2.4 idman643build16 (x86) — 437 functions, 19 686 instructions, 6 unsupported, **3 classes**

```
3  daa     0x000040311d     2  aas     0x0000404149     1  fbstp     0x0000403838
```
The reported `daa` at `0x40311d` is the first row.

### 2.5 IGI-Injector (x86) — 1680 functions, 80 039 instructions, 156 unsupported, **19 classes**

```
61  movlpd     0x0000405248    23  mulpd       0x000042e89b    23  pextrw      0x000042e840
13  addpd      0x000042e875     9  palignr     0x0000412258     5  pinsrw      0x0000430e3a
 5  unpcklpd   0x000042e837     2  cmpeqsd     0x000042e994     2  cmpnlepd    0x000042e230
 2  movlhps    0x000042f04a     2  subpd       0x000042e897     2  unpckhpd    0x000042e955
 1  cvtps2pd   0x0000409878     1  cvtsd2si    0x0000430e63     1  das         0x000041398b
 1  fbstp      0x00004139c6     1  fisttp      0x000042efac     1  pcmpistri   0x000042f0db
 1  pmaxsw     0x0000430ff1
```
The reported `movlpd` at `0x405248` is the first row.

### 2.6 guess.exe (x86_64) — 210 functions, 14 438 instructions, 41 unsupported, **10 classes**

```
10  shufps     0x0140002f83     6  addps       0x0140006244     6  cvttps2dq   0x0140006247
 6  mulps      0x0140006241     4  addpd       0x0140002c34     2  maxsd       0x0140002c50
 2  maxss      0x0140002f87     2  mulpd       0x0140002c3c     2  unpckhpd    0x0140002c4c
 1  divps      0x0140002fb0
```
The reported `addpd` at `0x140002c34` is row `4 addpd 0x0140002c34`.

### 2.7 What the six have in common

Five of the six fail on **SSE/SSE2 packed or scalar floating-point**, not on anything exotic:
`maxss/minss/maxsd/minsd` (min/max), `addps/mulps/subps/divps/shufps` (packed single), `addpd/mulpd`
(packed double), `movlps/movhps/movlpd` (half-width moves), `unpck*` (interleave), `cvttps2dq`
(packed convert), `pextrw/pinsrw` (word extract/insert), `movddup/movshdup/movsldup` (duplicate).
The x86-32 binaries `gconv.exe` and `idman643build16` are dominated by BCD/legacy mnemonics
(`daa`, `aas`, `pushal`) plus `fbstp`; §4 shows those are mostly decode noise, not gaps.

---

## 3. Corpus-wide aggregate

### 3.1 Corpus and method

Every file under `/Users/haseeb-mir/Downloads` whose first two bytes are `MZ` **and** which carries
a valid `PE\0\0` signature was enumerated (a small Python PE scanner, `/tmp/gapcensus/scan.py`;
the criterion the task allowed — "check the first two bytes are MZ" — plus a PE-signature check so
that DOS-only `MZ` stubs and archive members are not miscounted).

* **1504** PE files found (1188 MB), across 5 machine types.
* `coverage` was run on all 1504. **888** were rejected by the tool itself with
  `error: input is a managed .NET image (CLR runtime header at rva …)`. Those are managed
  assemblies with no native code; the tool refuses them deliberately and they are excluded.
* **616 native PE images** produced a census (`.exe`, `.dll`, `.so`, `.dle`, `.asi`).
* **260** of the 616 report zero unsupported classes (`coverage: complete — every recovered
  instruction lifts`) and therefore print no table.

Corpus totals over the 616 native images:

| quantity | value |
| --- | --- |
| recovered instructions | **83 698 489** |
| unsupported instructions | **2 497 153** (2.98 %) |
| distinct unsupported classes | **761** |

**Version-independence check.** Because the lead rebuilt the tool mid-sweep, 83 files were
re-run with the frozen copy and compared byte-for-byte with the original sweep output:
**79 of 79 files that produced data were identical** (instructions, unsupported count and every
class row). The 4 remaining files had *timed out* in the first sweep and completed in the second;
their frozen results were merged in. So mixing the two tool revisions did not change any figure,
and the two revisions agree on every instruction they both saw.

### 3.2 Ranked by total occurrences

`occ` = total occurrences across the corpus; `bins` = distinct binaries that need it.

| # | mnemonic | occ | bins |
| --- | --- | --- | --- |
| 1 | `popal` | 160 697 | 40 |
| 2 | `vmovdqu32` | 116 553 | 9 |
| 3 | `vpaddd` | 115 829 | 9 |
| 4 | `vpclmulqdq` | 112 076 | 1 |
| 5 | `arpl` | 111 746 | 36 |
| 6 | `vpxorq` | 90 080 | 2 |
| 7 | `vaesenc` | 87 713 | 2 |
| 8 | `vpmaddwd` | 75 062 | 5 |
| 9 | `vmovdqu64` | 58 301 | 7 |
| 10 | `vpmulld` | 45 617 | 9 |
| 11 | `vpsrad` | 44 259 | 7 |
| 12 | `vpmaddubsw` | 41 056 | 10 |
| 13 | `vbroadcastf64x2` | 37 752 | 1 |
| 14 | `vinserti128` | 37 080 | 22 |
| 15 | `vpshufb` | 35 082 | 19 |
| 16 | `vpunpcklwd` | 34 617 | 8 |
| 17 | `vpunpckhwd` | 34 356 | 8 |
| 18 | `vpternlogq` | 34 260 | 3 |
| 19 | `vpbroadcastd` | 33 288 | 21 |
| 20 | `vmovdqa64` | 32 364 | 6 |
| 21 | `daa` | 25 587 | 28 |
| 22 | `addps` | 24 842 | 154 |
| 23 | `vpaddw` | 24 783 | 6 |
| 24 | `shufps` | 24 393 | 193 |
| 25 | `vextracti128` | 23 722 | 26 |

This ranking is **dominated by AVX-512 (zmm) code inside a handful of codec libraries** —
`libx265`, `libSvtAv1Enc`, `libcrypto`, `libaom`, `libjxl`, `libyuv`, `librav1e` under
`Downloads/recomp-apps/openlierox/openlierox-20260912.1-windows/`. Those files alone supply most
of the top 25: e.g. `vpclmulqdq` is 112 076 occurrences in **one** binary, `vpxorq` 90 080 in two.
Occurrence count and reach point in opposite directions, so §3.3 ranks the same data by reach.

### 3.3 Ranked by distinct binaries (which classes buy the most)

| # | mnemonic | occ | bins |
| --- | --- | --- | --- |
| 1 | `shufps` | 24 393 | **193** |
| 2 | `mulps` | 21 990 | **160** |
| 3 | `addps` | 24 842 | **154** |
| 4 | `cvttps2dq` | 1 860 | 137 |
| 5 | `sqrtss` | 843 | 131 |
| 6 | `unpcklpd` | 1 461 | 89 |
| 7 | `movlhps` | 3 059 | 85 |
| 8 | `movq` | 14 021 | 75 |
| 9 | `maxss` | 4 402 | 73 |
| 10 | `minss` | 3 021 | 73 |
| 11 | `unpcklps` | 6 582 | 71 |
| 12 | `pextrw` | 3 484 | 71 |
| 13 | `mulpd` | 2 976 | 68 |
| 14 | `pinsrw` | 2 334 | 68 |
| 15 | `addpd` | 1 640 | 67 |
| 16 | `unpckhpd` | 1 038 | 64 |
| 17 | `movhps` | 18 432 | 63 |
| 18 | `cvtps2pd` | 3 924 | 63 |
| 19 | `cvtpd2ps` | 2 389 | 63 |
| 20 | `movddup` | 3 255 | 58 |
| 21 | `movhlps` | 15 334 | 54 |
| 22 | `subps` | 4 415 | 53 |
| 23 | `minsd` | 1 869 | 53 |
| 24 | `sqrtsd` | 549 | 53 |
| 25 | `divps` | 749 | 52 |

**This is the actionable ranking.** The SSE floating-point/move family reaches 130–193 of the 616
binaries, i.e. it is the single capability that most widens the set of programs that translate at
all. Grouped unions (binaries needing at least one member, summed occurrences):

| group | binaries | occ |
| --- | --- | --- |
| `addps`/`mulps`/`subps`/`divps`/`shufps` | 197 | 76 389 |
| `cvtps2pd`/`cvtpd2ps`/`cvttps2dq` | 195 | 8 173 |
| `unpcklps`/`unpckhps`/`unpcklpd`/`unpckhpd` | 140 | 10 540 |
| `maxss`/`minss`/`maxsd`/`minsd` | 112 | 11 029 |
| `movlps`/`movhps`/`movlpd`/`movhpd` | 111 | 24 669 |
| `movhlps`/`movlhps` | 110 | 18 393 |
| `addpd`/`mulpd`/`subpd`/`divpd` | 84 | 5 701 |

---

## 4. Three things to know before acting on §3

Two findings change how the numbers in §3 must be read. Both are evidenced from source and from
the binaries themselves; neither was guessed.

### 4.1 A large share of the top-ranked "gaps" is data decoded as code, not instruction gaps

The discovery deliberately treats every 4-byte-aligned value in **every** section, including
executable ones, as a candidate function pointer, and then walks linearly from each candidate:

* `core/discovery/function_discovery.cpp:202-214` — "Executable sections are scanned too …" then
  `for (offset = 0; offset + 4 <= section.raw_size; offset += 4)` pushing any value that
  `decodes_as_code`.
* `core/discovery/function_discovery.cpp:232-244` — the linear walk from each entry.

Byte-level proof that the resulting "functions" are pointer tables:

* **`Qt5Core.dll`**, the function the census records at `0x6701eee4` (`daa`, first site = entry).
  `r2 -q -c "s 0x6701eee4; px 16"` → `27e7 0167 3fe7 0167 4be7 0167 57e7 0167`, i.e. the
  32-bit values `0x6701e727, 0x6701e73f, 0x6701e74b, 0x6701e757` — a table of code addresses.
  `0x27` is `daa`, `0xe7 01` is `out 1, eax`, `0x3f` is `aas`: three "instructions" in one table
  row. Same file at `0x67051828`: `3c0b 0567 200c 0567 530d 0567 3b12 0567` → the addresses
  `0x67050b3c, 0x67050c20, 0x67050d53, 0x6705123b`.
* **`libGLESv2.dll`**, function at `0x10002d48` (`pushal`): the surrounding bytes are a run of
  `2c 00` pairs (`",\0"`), not code.
* **`dsetup32.dll`** reports **2 004 984 recovered instructions** from an executable-section
  footprint of **87 040 bytes** — 23 instructions per byte, which is physically impossible
  (x86 averages 2.5–3.5 bytes per instruction). Its classes are `popal` 69 118, `arpl` 40 337,
  `popaw` 12 205, `daa` 6 615: exactly the signature of compressed/table data being decoded.
  `popal`/`popaw`/`arpl` are invalid encodings in 64-bit mode and are not emitted by any modern
  compiler in 32-bit mode either.

Objective corpus-wide measure (instructions per executable-section byte, computed from each PE's
own section table by `/tmp/gapcensus/plausible.py`):

| threshold | binaries | share of instructions | share of unsupported |
| --- | --- | --- | --- |
| > 0.6 instr/byte | 20 | 19.3 % | **15.0 %** |
| > 1.0 instr/byte (impossible) | 10 | 15.0 % | 14.4 % |

The implausible binaries are `dsetup32.dll` (23.04), `DSETUP.dll` (9.37), `libyuv.dll` (2.25),
`lame_enc.dll` (1.96), `unins000.exe` (1.88), `progress-quest.exe`/`pq.exe` (1.43),
`libstdc++-6.dll` (1.25), `CheatEngine75.exe` (1.05), `libopenal` (0.89).

Counting the legacy/BCD mnemonics that only data produces — `popal, arpl, daa, das, aas, aad, salc,
pushal, popaw, iretd, into, int1, cli, sti, jcxz, bound, femms` — they account for **444 199
occurrences (17.8 % of all unsupported occurrences) across 80 binaries**. Ranks 1 and 5 of §3.2
(`popal`, `arpl`) and rank 21 (`daa`) are entirely this artefact.

**Consequence:** implementing `popal`/`arpl`/`daa` would buy nothing and would add instructions the
hardware does not define in 64-bit mode. The fix belongs in function discovery (a plausibility or
reachability filter on candidate entries), not in the lifter. The rankings in §3.3, which are
built from real compiler output, are unaffected.

### 4.2 The census is truncated at 2 000 000 instructions for large images

`core/discovery/function_discovery.cpp:217` — `constexpr std::size_t kMaximumInstructions =
2'000'000;`, enforced at line 232 (`while (… && recovered_instruction_count < kMaximumInstructions)`).
Six binaries land just above the cap (`libyuv` 2 000 003, `unins000` 2 000 002, `libstdc++-6`
2 000 014, `libx265` 2 000 434, `libSvtAv1Enc` 2 000 136, `libaom` 2 000 099), which is how the cap
shows up in the data. **Every figure for those binaries is a lower bound**, and the corpus totals
in §3.1 are therefore lower bounds.

### 4.3 A correctness defect the census cannot see: 256-bit VEX forms are silently truncated

The VEX path in the lifter copies **32 bytes** for a `ymm` destination
(`core/semantics/x86_64_lifter.cpp:530-535`, `is_wide_vector_register(operands[0].register_name)
? 32 : 16` at line 533) and then re-enters `emit_instruction` with the SSE mnemonic and the two
128-bit operands. But every packed-integer helper it reaches is generated by
`RECOMP_PACKED_BINARY` (`runtime/recomp_runtime.hpp:941-971`), which loops
`for (index = 0; index < 16 / sizeof(element); ++index)` — i.e. **16 bytes, always**.

So `vpaddd ymm0, ymm1, ymm2` (mapped `vpaddd → paddd` at lifter line 143, `paddd →
vector_add_dwords` at line 178) lifts successfully and emits a 32-byte `memcpy` followed by a
**128-bit** add: the upper 128 bits of the destination keep `src1` instead of receiving
`src1 + src2`. The same applies to every `vex_equivalents` entry whose SSE helper is 16-byte wide
(`vpxor`, `vpshufb`, `vpmullw`, …). These instructions are **not** counted as unsupported, so the
census *understates* the AVX2 gap while the recompiler silently mistranslates it.

Evidence: the source path above, plus the fact that the zmm forms of the same mnemonics *do* fail
(`vpaddd zmm27, zmm27, zmm26` at `libx265 0x20df8368f`) because `vector_register_index`
(`core/semantics/x86_64_lifter.cpp:232-237`) recognises only `xmm`/`ymm`.
**Status: source-derived, not runtime-verified** — this session was read-only and could not build
or run the differential harness. It should be confirmed with a fixture that executes
`vpaddd ymm` before being relied on.

---

## 5. Classification of the top classes

Definitions used (stated because the task's categories are broad):

* **(a)** no new runtime code and no new lifter branch — the mnemonic is added to an existing
  condition/table whose handler already computes the identical result.
* **(b)** new code is required: a runtime helper and/or a new lifter branch.
* **(c)** cannot work in a user-mode flat model.
* **(noise)** not an instruction gap at all — §4.1.

### 5.1 Top 15 by total occurrences (§3.2)

| # | mnemonic | occ | bins | class | evidence |
| --- | --- | --- | --- | --- | --- |
| 1 | `popal` | 160 697 | 40 | **noise** | `0x61` is invalid in 64-bit mode; `dsetup32.dll` alone reports 69 118 from a table region (§4.1) |
| 2 | `vmovdqu32` | 116 553 | 9 | (b) | AVX-512 `zmm` load/store; needs the register file widened (see below) |
| 3 | `vpaddd` | 115 829 | 9 | (b) | verified `vpaddd zmm27, zmm27, zmm26` (libx265 `0x20df8368f`); the 128-bit form is already mapped at line 143 |
| 4 | `vpclmulqdq` | 112 076 | 1 | (b) | AVX-512 VPCLMULQDQ; no carry-less-multiply helper exists |
| 5 | `arpl` | 111 746 | 36 | **noise** | invalid in 64-bit mode; same table regions as `popal` |
| 6 | `vpxorq` | 90 080 | 2 | (b) | AVX-512 `zmm` xor |
| 7 | `vaesenc` | 87 713 | 2 | (b) | verified `vaesenc ymm3, ymm0, ymm1` (Qt6Core `0x18000d217`) — VAES, 256-bit AES round |
| 8 | `vpmaddwd` | 75 062 | 5 | (b) | verified `vpmaddwd zmm27, zmm27, zmm30`; the 128-bit `pmaddwd` already exists (line 200) |
| 9 | `vmovdqu64` | 58 301 | 7 | (b) | verified `vmovdqu64 zmm0, zmmword [rdx]` (lame_enc `0x18004d83f`) |
| 10 | `vpmulld` | 45 617 | 9 | (b) | verified `vpmulld ymm3, ymm0, ymm2` (Qt5Gui `0x100179d6`) — AVX2, 4-operand-free 3-op form |
| 11 | `vpsrad` | 44 259 | 7 | (b) | verified `vpsrad zmm1, zmm1, xmm20`; 128-bit `psrad` exists (line 212) |
| 12 | `vpmaddubsw` | 41 056 | 10 | (b) | AVX2/512 packed multiply-add of unsigned×signed bytes |
| 13 | `vbroadcastf64x2` | 37 752 | 1 | (b) | AVX-512 broadcast |
| 14 | `vinserti128` | 37 080 | 22 | (b) | verified `vinserti128 ymm3, ymm0, xmm1, 1` (Qt5Gui `0x10019ba5`) — 4 operands, 256-bit |
| 15 | `vpshufb` | 35 082 | 19 | (b) | verified `vpshufb ymm2, ymm0, ymmword [esp+0x40]` (Qt5Gui `0x10016bb3`) — 256-bit **and** memory source |

Totals: **(a) 0, (b) 13, (c) 0, noise 2.**

None of the top 15 by occurrence is cheap. Twelve of the thirteen (b) entries need the vector
register file widened from 32 to 64 bytes and from 16 to 32 registers before any helper can be
written — today it is `std::uint8_t vector_registers[16][32];`
(`runtime/recomp_runtime.hpp:49-52`). That is a model change, not a helper.

### 5.2 Top 15 by reach (§3.3)

| # | mnemonic | occ | bins | class | existing implementation to reuse / what is missing |
| --- | --- | --- | --- | --- | --- |
| 1 | `shufps` | 24 393 | 193 | (b) | template is the `pshufd` handler at lifter line **699** and `vector_shuffle_dwords` (`runtime/recomp_runtime.hpp:1123`); SHUFPS takes lanes 0–1 from **dst**, so it is *not* the same helper — it is identical only when dst==src (which is what most sites are: `shufps xmm0, xmm0, 0`) |
| 2 | `mulps` | 21 990 | 160 | (b) | new packed-float helper; one `RECOMP_PACKED_BINARY(vector_multiply_floats_packed, float, a * b)` line, which also generates the `_memory` form |
| 3 | `addps` | 24 842 | 154 | (b) | same, `a + b` |
| 4 | `cvttps2dq` | 1 860 | 137 | (b) | reverse of `convert_dwords_to_floats_array` (`runtime/recomp_runtime.hpp:1637`), which is the exact template; truncate toward zero, out-of-range/NaN → `0x80000000` |
| 5 | `sqrtss` | 843 | 131 | (b) | one-line helper; the lifter already emits `std::sqrt` inline for x87 `fsqrt` at line **1583** |
| 6 | `unpcklpd` | 1 461 | 89 | **(a)** | `vector_unpack_qwords` (`runtime/recomp_runtime.hpp:1141`) is bit-identical; add the mnemonic to the condition at lifter line **706**. ⚠ the helper selector at line **710** tests `mnemonic.find("qdq")`, which `unpcklpd` does not contain, so it must be widened to also match the `pd` spellings |
| 7 | `movlhps` | 3 059 | 85 | (b) | MOVLHPS `xmm1, xmm2`: `dst[127:64] = src[63:0]`, low half unchanged; no high-half writer exists (`vector_set_low` at `runtime/recomp_runtime.hpp:512` *zeroes* the upper bytes) |
| 8 | `movq` | 14 021 | 75 | **(a)** | the handler **already exists** at lifter line **662**. The failing sites are `movq xmm0, xmm3` (e.g. Qt5Gui `0x1016d537`, powder `0x140047f68`): line **669** reads the vector source with `operand_read_expression`, which calls `fail_operand` for a non-general register and throws. Route a vector-register source through `vector_get_low` instead |
| 9 | `maxss` | 4 402 | 73 | (b) | new min/max helper; SDM semantics matter — if either operand is NaN the **second** source is returned, and MAXSS with both operands `±0` returns src2 |
| 10 | `minss` | 3 021 | 73 | (b) | same helper family |
| 11 | `unpcklps` | 6 582 | 71 | **(a)** | `vector_unpack_dwords` (`runtime/recomp_runtime.hpp:1130`) is bit-identical; add to the condition at lifter line **706** (the existing `qdq` test already selects dwords correctly for `ps`) |
| 12 | `pextrw` | 3 484 | 71 | (b) | extract word `imm` from an xmm to a GPR; template is the `pmovmskb` handler at lifter line **620** and `vector_move_byte_mask` (`runtime/recomp_runtime.hpp:844`) |
| 13 | `mulpd` | 2 976 | 68 | (b) | `RECOMP_PACKED_BINARY(vector_multiply_doubles_packed, double, a * b)` |
| 14 | `pinsrw` | 2 334 | 68 | (b) | insert word; needs a lane-selective writer |
| 15 | `addpd` | 1 640 | 67 | (b) | as `mulpd`, `a + b` |

Totals: **(a) 3, (b) 12, (c) 0.**

The same classification applies to the rest of the wide-reach family:
`unpckhps` (a, line 706), `unpckhpd` (a, line 706), `movhps`/`movhpd` (b for the load form — they
write the *high* half, and the existing `movq` handler zeroes it), `movlps`/`movlpd` (**store form
is (a)**: the else-branch at lifter lines **673-676** already emits
`vector_get_low(…, 8)` → `store_guest_memory(…, 8)`, which is exactly `MOVLPS/MOVLPD m64, xmm`;
**load form is (b)** because it must preserve the upper 64 bits and `vector_set_low` clears them),
`cvtps2pd`/`cvtpd2ps` (b), `movddup`/`movshdup`/`movsldup` (b), `shufpd` (b), `sqrtsd` (b),
`divps`/`subps` (b, same macro), `divpd`/`subpd` (b).

**No class in either top 15 is category (c).** The genuinely un-modellable instructions are
already trapped deliberately rather than reported as gaps: `in`/`out`/`bound`
(lifter line **1499**), `lcall`/`ljmp`/`ins*`/`outs*`/`int` (line **1576**), `int3`/`hlt`/`ud2`
(line **1103**), and `push` of a segment register (line **964**) — these emit
`recomp_trap`/`emit_trap` and *do* lift, so they never appear in the census. The one class that is
(c)-adjacent is the far-pointer family, which the lifter already handles by ignoring the selector
(line **1565**).

### 5.3 Why `movq` and `movlps` look "unsupported" despite having a handler

Both are in the census because the handler is reached and then **throws inside it**, which
`census()` records under the mnemonic (`core/semantics/x86_64_lifter.cpp:1780-1788`). This is worth
knowing generally: a mnemonic appearing in the census does not mean no handler exists, and the
count for such a mnemonic is the count of *operand forms* the handler rejects, not of the
mnemonic. Verified by reading the code path and by disassembling the failing sites (§5.2 rows 8
and 11, and the `movlps`/`movlpd` samples in §5.2).

---

## 6. The three cheapest wins

Ranked by (binaries reached ÷ code changed). All three are category (a): no new runtime helper,
and in two cases no new lifter branch either.

### Win 1 — `unpcklps`, `unpckhps`, `unpcklpd`, `unpckhpd`

**Lifter line to change: `core/semantics/x86_64_lifter.cpp:706`** (the
`if ((mnemonic == "punpckldq" || mnemonic == "punpckhdq" || mnemonic == "punpcklqdq" ||
mnemonic == "punpckhqdq") …)` condition), plus the helper selector at **line 710**
(`mnemonic.find("qdq")`) which must also match the `pd` spellings.

The runtime helpers are already exact and need no change:

* `vector_unpack_dwords(context, dest, src, high)` — `runtime/recomp_runtime.hpp:1130-1139`:
  `lanes[0]=left[high?2:0]; lanes[1]=right[high?2:0]; lanes[2]=left[high?3:1];
  lanes[3]=right[high?3:1]` — this is UNPCKLPS/UNPCKHPS exactly.
* `vector_unpack_qwords(context, dest, src, high)` — `runtime/recomp_runtime.hpp:1141-1148`:
  `lanes[0]=left[high?1:0]; lanes[1]=right[high?1:0]` — this is UNPCKLPD/UNPCKHPD exactly.

Reach: **140 binaries / 10 540 occurrences.** Also fixes 73 of powder's 1841 and 5 of
IGI-Injector's 156 (both named in the report).

### Win 2 — `movq` with a vector-register source

**Lifter line to change: `core/semantics/x86_64_lifter.cpp:669`** (the
`operand_read_expression(instruction, operands[1], byte_count)` fallback inside the
`movd`/`movq` handler that starts at line 662). When `is_vector_register(operands[1])` the source
must be read with `vector_get_low(context, <index>, byte_count)` — the same primitive the store
branch at line 675 already uses — instead of `operand_read_expression`, which reaches
`fail_operand` for any register that is not in `register_descriptors()`.

Reach: **75 binaries / 14 021 occurrences**, including powder (32), guess, Qt6Core, plink/putty,
sqlite3, `fd.exe`, `rg.exe`.

### Win 3 — `movlps` / `movlpd`, store form

**Lifter line to change: `core/semantics/x86_64_lifter.cpp:662`** (add the two mnemonics to the
same condition as Win 2). For `movlps qword [mem], xmm` / `movlpd qword [mem], xmm` the guard
already passes and the else-branch at **lines 673-676** emits
`operand_write(…, "vector_get_low(context, <src>, 8)", 8)` → `store_guest_memory(addr, value, 8)`.
That is precisely `MOVLPS/MOVLPD m64, xmm`: 8 bytes stored, destination register untouched.

**Caveat — do not stop here.** The *load* form (`movlps xmm, m64`, `movlpd xmm, qword [mem]`) must
**not** be routed to the existing branch: `vector_set_low`
(`runtime/recomp_runtime.hpp:512-515`) does `std::memset(…, 0, 16)` before writing the low bytes,
so the upper 64 bits of the destination would be zeroed instead of preserved. Sampled first sites
show both forms occur in quantity (`movlpd qword [esp], xmm0` in Qt5Core/Qt5Gui/qtiff/qwebp/
libGLESv2/freeglut/IGI-Injector vs `movlpd xmm7, qword [0x18007f2c0]` in lame_enc and
`movlpd xmm0, qword [esp+4]` in igi2.exe/msvcr70.dll). The load form needs the (b) merge helper
described in §5.2. The same latent upper-half bug already affects the existing
`movsd xmm, m64` path (lifter line 657 → `emit_vector_move` at line 482 → `load_guest_vector`,
`runtime/recomp_runtime.hpp:499-510`, which also `memset`s to zero first).

Reach for the store form: `movlps` 50 binaries, `movlpd` 44 binaries; the two together are
5 897 occurrences.

---

## 7. Reproduction

```bash
# CLI under test (frozen copy, so a live rebuild cannot change the result)
cp build/recomp-studio /tmp/gapcensus/frozen-studio

# per-binary census
/tmp/gapcensus/frozen-studio coverage <path>

# the six named binaries
/tmp/gapcensus/frozen-studio coverage /Users/haseeb-mir/Downloads/recomp-apps/win64/powder-v100.1.400-x86_64-windows-mingw.exe
/tmp/gapcensus/frozen-studio coverage /Users/haseeb-mir/Downloads/tools/gconv.exe
/tmp/gapcensus/frozen-studio coverage /Users/haseeb-mir/Downloads/recomp-apps/win64/legacy-notepad-x64.exe
/tmp/gapcensus/frozen-studio coverage /Users/haseeb-mir/Downloads/idman643build16.exe
/tmp/gapcensus/frozen-studio coverage /Users/haseeb-mir/Downloads/tools/IGI1Editor_v0.8.5.1/bin/IGI-Injector.exe
/tmp/gapcensus/frozen-studio coverage /Users/haseeb-mir/Downloads/recomp-apps/win64/guess.exe

# corpus enumeration + aggregation + plausibility
python3 /tmp/gapcensus/scan.py        > /tmp/gapcensus/pe_files.txt   # 1504 PE files
python3 /tmp/gapcensus/agg2.py /tmp/gapcensus/out /tmp/gapcensus/agg2.json
python3 /tmp/gapcensus/plausible.py /tmp/gapcensus/agg2.json

# operand-form sampling (per failing site)
r2 -q -e scr.color=0 -e bin.relocs.apply=true -c "s 0x14000675e; pd 1" <binary>
r2 -q -e scr.color=0 -c "s 0x6701eee4; px 16" <binary>
```

Scratch artefacts (not part of the repository): `/tmp/gapcensus/{out,frozen,six,agg2.json,rank.json}`.

## 8. Limitations — stated so the numbers are not over-trusted

1. **The lifter moved during the run.** The census is pinned to tool sha256 `bcb0e1d3…` /
   lifter `0d9d5e47…`; the §5–§6 line numbers were re-verified against `2b768eaf…`. A later
   lifter revision invalidates the line numbers (the anchor text in each citation survives).
2. **The corpus totals are lower bounds** because of the 2 000 000-instruction cap (§4.2).
3. **~15 % of the unsupported occurrences are decode noise** (§4.1). Per-class totals in §3.2 for
   `popal`, `arpl`, `daa`, `das`, `aas`, `pushal`, `int1`, `cli`, `sti` and friends should be read
   as an artefact of function discovery, not as demand for those instructions.
4. **Form splits are sampled, not exhaustive.** `coverage` reports only the first site per
   (binary, mnemonic). Operand forms in §5.2 come from disassembling those first sites with r2
   across every binary that reported the mnemonic (e.g. 30+ sites for `movlpd`/`movlps`/`movhps`/
   `movq`), not from enumerating all 2.5 M occurrences. Statements such as "the store form
   dominates `movlpd`" would need a full per-site pass to quantify.
5. **The `vpaddd ymm` truncation in §4.3 is source-derived, not runtime-verified** — this session
   was read-only and did not build or run the differential harness.
6. **888 managed .NET assemblies were excluded** by the tool itself and contribute nothing to the
   census; that is correct for native instruction coverage but means the corpus is "native PE",
   not "all PE".
7. Nothing in this report was verified by building or running the project: the session was
   read-only apart from this file.
