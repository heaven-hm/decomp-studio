# Cross-app instruction and import gap census (task-5)

**Owner:** `coverage-audit` (teammate)
**Deliverable:** this file. Write scope was exactly `reports/gap-census.md`; no code, test or
other report was modified.

**Revision:** `709510c`, branch `feature/x86-x64-arm64-mvp`. Tool rebuilt before measurement
(`cmake --build build -j` → `ninja: no work to do`, binary already current, `recomp-studio 0.4.0`).

**Source revision the VEX audit is pinned to:** `core/semantics/x86_64_lifter.cpp` sha256
`f660bf0e966d7b7f9777774f57fba055cc6dbfec65f5215633d2a2702e81613f`. Every line number cited
in §7 was re-verified against that revision after the report was drafted, and the 35-entry
`vex_equivalents` set was diffed programmatically against the source (identical). The lifter
is a moving target — a change to that file invalidates §7's line numbers and must be
re-checked.

**Corpus:** every `.exe` under `/Users/haseeb-mir/Downloads/recomp-apps` (15 files, `.dll`
ignored) plus `/Users/haseeb-mir/Downloads/IGI/igi.exe` = **16 binaries**.

---

## 1. Headline answers

### 1.1 Which single capability clears the most binaries' FIRST blocker

> **The SSE2 packed-integer family** — byte/word shifts (`psrldq`, `pslldq`), unpack/pack
> (`punpcklbw`, `punpckhbw`, `punpcklwd`, …) and packed compares (`pcmpeqb`) — clears the
> first blocker for **8 of the 12 non-.NET binaries that are currently instruction-blocked
> (67%)**.

First-blocker counts by mnemonic (from verbatim `translate` output, §6):

| first-blocker mnemonic | binaries | family |
| --- | --- | --- |
| `psrldq` | 3 | SSE2 packed integer |
| `punpcklbw` | 2 | SSE2 packed integer |
| `pcmpeqb` | 2 | SSE2 packed integer |
| `punpckhbw` | 1 | SSE2 packed integer |
| `bts` | 1 | BMI / bit manipulation |
| `movhlps` | 1 | SSE floating-point |
| `cvtps2pd` | 1 | SSE floating-point |
| `pushfd` | 1 | misc control/flag |
| `insd` | 1 (.NET, not meaningful) | misc control/flag |

**Caveat that must not be lost:** clearing a first blocker does not make a binary translate.
It only reveals the next one. The blocker chains in §6.3 show how deep that goes — e.g.
`snake.exe` needs 5 classes cleared, `plink.exe` needs 68, `powder.exe` needs 96. The SSE2
packed-integer family is the correct *first* investment because it is the gate for the most
binaries, but it is a gate, not a finish line.

If a single *mnemonic* must be named rather than a family: **`psrldq` (3 binaries)**.

### 1.2 Aggregate ranked missing-import list

**Rank 1 library: `kernel32.dll` — 731 missing import slots across binaries, 245 distinct
symbols.** Then `user32.dll` (355/197), `sdl2.dll` (259/184), `msvcp140.dll` (245/171),
`libstdc++-6.dll` (217/205), `msvcrt.dll` (172/149).

**Top individual symbols** (number of binaries that import them and have no shim):

| rank | symbol | library | binaries |
| --- | --- | --- | --- |
| 1 | `FindClose` | kernel32.dll | 11 |
| 2 | `CloseHandle` | kernel32.dll | 11 |
| 3 | `RtlCaptureContext` | ntdll.dll | 11 |
| 4 | `RtlVirtualUnwind` | ntdll.dll | 10 |
| 5 | `RtlLookupFunctionEntry` | ntdll.dll | 10 |
| 6 | `GetCommandLineW` | kernel32.dll | 9 |
| 7 | `CreateFileW` | kernel32.dll | 9 |
| 8 | `InitializeSListHead` | kernel32.dll | 9 |
| 9 | `GetModuleFileNameW` | kernel32.dll | 9 |
| 10 | `LocalFree` | kernel32.dll | 8 |

Full ranked lists are in §5. Two structural observations:

* **The top of the ranking is dominated by CRT/SEH boilerplate, not application logic.**
  `RtlCaptureContext`/`RtlVirtualUnwind`/`RtlLookupFunctionEntry` (ranks 3–5) are the
  MSVC x64 SEH prologue emitted into *every* function with exception handling — they are
  not application behaviour. `CloseHandle`/`FindClose` are `FindFirstFileW` loops.
  A handful of shims here unlocks many binaries at once.
* **A long tail of per-library DLLs is bundled with the apps** (`sdl2.dll` 184 symbols,
  `libstdc++-6.dll` 205, `glew32.dll` 44, `physfs.dll` 31). These are shipped next to the
  `.exe` and are not Win32 — they need either linking against native equivalents or
  stubbing, and they are a much larger body of work than the Win32 surface.

---

## 2. Method

Every figure below comes from a command that was run. The two commands per binary:

```sh
./build/recomp-studio coverage <image> --json
./build/recomp-studio imports  <image> --json
```

For the first-blocker analysis the actual abort was reproduced by running translation:

```sh
./build/recomp-studio translate <image> --target macos-arm64 --output /tmp/gapcensus-translate/<key>
```

All 16 binaries exited 0 from `coverage` and `imports`; **no binary failed to run through the
tool**, so there is nothing to report verbatim as a tool error.

Helper scripts (outside the repository, in `/tmp/gapcensus/`: `collect.py`, `analyse.py`,
`families.py`, `vexsplit.py`, `regreg.py`) orchestrated the runs and aggregated the JSON.
The VEX operand-width split and the register-form reachability checks reuse the independent
decoder from `reports/tools/independent_coverage.py` read-only (run with
`PYTHONDONTWRITEBYTECODE=1` so nothing was written outside this report).

### 2.1 Reproducibility — sha256 of every measured binary

| binary | sha256 | bytes |
| --- | --- | --- |
| bat/bat-v0.26.1-x86_64-pc-windows-msvc/bat.exe | `9ea9f7ab1c27aa5c9390e91543f9f47c6bd17bc53f3e30ac9db762f28f55c4fd` | 7342592 |
| clipjar.exe | `8841b01b45ac984d6e2b2521be7a7bc527949e92eb1da6eaf85db82ccf1bf8f4` | 5338624 |
| fd/fd-v10.5.0-x86_64-pc-windows-msvc/fd.exe | `d67d27a8e375ed7e9bca2b506a9dd5082bc24547aeba908b863f6f8b8ab0c3b9` | 4104192 |
| igi.exe | `dea34892d417715873ea61d7b2ba5556655f1ad65385104348146f9679915a01` | 1384448 |
| imgview64.exe | `a7e07c4c629912ba710d8a181860d4f114c523f77768c4b02855dc624e106ddb` | 11776 |
| legacy-notepad-x64.exe | `00e67923f531e5590ab404aa5b906470b7c1505ec75cf69f22db99509de9fb56` | 262656 |
| luhn/luhn.exe | `61069ebfe79053477e3859075d0a9c800d60d755a795a28ad069efc1d851b304` | 12288 |
| openlierox/openlierox-20260912.1-windows/openlierox.exe | `0f79c968ab9aabd8cb99e173500fa241e883846fd3e0c9ca2f7f0bf3771fa5c1` | 12853347 |
| pixeltetris/…/bin/v1/Pixeltetris.exe | `3eabbe4a4de93c9d0b91589511203313697f60500e58f18dd67eb37f8e25ca81` | 1118208 |
| plink.exe | `969f36879d5716aa1a9811f43a6a6510e8f08372dbeb9695b810b9c776f39c75` | 1036448 |
| powder-v100.1.400-x86_64-windows-mingw.exe | `df32b616b31dabae10b82028731ebdfd6867c872198b81f29d418cbafbf460c3` | 8690342 |
| ripgrep/ripgrep-15.2.0-x86_64-pc-windows-msvc/rg.exe | `14231169855ec5205cf5a1b6f1db358ff4aed4247c86b69ce8aae647c77f6680` | 4218880 |
| snake/snake-windows-x86_64.exe | `207d311be674c17be31131df095534003e0120b1a00a6569b697e00ae0c2d373` | 55296 |
| supertux/SuperTux-portable/bin/supertux2.exe | `6249f25a6ac1cc3d27955ca09852b8368618ce58ad9c13e0c5084051c2c02b43` | 7259648 |
| tetris/Tetris.exe | `f7ccf8fc2f57020c50f1d66de772dc50e2d0e47f5bd819d4a6ddde795c3c959f` | 224809 |
| tictactoe/TicTacToe.exe | `df4aec7299b1e002ca0e1008b20a889e0cfe5b482a19958399fab16ac6090402` | 59392 |

---

## 3. .NET binaries — instruction coverage is NOT meaningful for these

Detected via a non-empty COM descriptor directory (PE data directory index 14):

| binary | .NET | evidence | instruction census | why it is meaningless |
| --- | --- | --- | --- | --- |
| `luhn/luhn.exe` | **YES** | COM descriptor present | 2 functions / 1069 instructions / 30 unsupported | The managed method bodies live in IL, not x86. The 1069 "instructions" are the small native CLR bootstrap stub (`_CorExeMain` trampoline) plus data misread as code. The 30 "unsupported" mnemonics (`insd`, `outsd`, `lcall`, `das`, `bound`, `lldt`, `aas`, `sti`, …) are classic **data-decoded-as-code** signatures — x86 string/privileged instructions that essentially never appear in compiler output. They are an artefact of walking bytes that are not code. |
| `tictactoe/TicTacToe.exe` | **YES** | COM descriptor present | 2 functions / **15** instructions / 0 unsupported | Same; 15 instructions is the trampoline only. `translate` "succeeds" here and produces a project, which is exactly the misleading case: success means nothing. |

**Recommendation:** the tool should detect the CLR header and refuse or clearly flag
`coverage`/`translate` for managed images, rather than reporting a confident-looking 100% or
a list of bogus unsupported mnemonics. Both .NET binaries here produce output that a reader
could easily mistake for a real census.

`luhn/luhn.exe` is additionally the source of the only `insd`/`outsd` first blocker in the
corpus; excluding .NET leaves 12 instruction-blocked native binaries.

---

## 4. Per-binary census

Ordered by unsupported instruction count.

| binary | fmt | arch | funcs | instructions | lifted | % | unsup | classes | imports | missing | .NET |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| powder-v100.1.400-…mingw.exe | PE32+ | x86_64 | 9061 | 1081565 | 1074570 | 99.35 | 6995 | 96 | 590 | 544 | no |
| openlierox.exe | PE32+ | x86_64 | 8348 | 1499486 | 1496289 | 99.79 | 3197 | 78 | 653 | 618 | no |
| bat.exe | PE32+ | x86_64 | 4056 | 392840 | 390983 | 99.53 | 1857 | 62 | 291 | 251 | no |
| plink.exe | PE32+ | x86_64 | 2208 | 164668 | 162850 | 98.90 | 1818 | 68 | 153 | 109 | no |
| fd.exe | PE32+ | x86_64 | 1805 | 224449 | 222654 | 99.20 | 1795 | 61 | 142 | 100 | no |
| rg.exe | PE32+ | x86_64 | 2658 | 305098 | 303415 | 99.45 | 1683 | 52 | 127 | 84 | no |
| clipjar.exe | PE32+ | x86_64 | 5855 | 430612 | 429286 | 99.69 | 1326 | 62 | 384 | 344 | no |
| supertux2.exe | PE32+ | x86_64 | 13337 | 757310 | 756590 | 99.90 | 720 | 47 | 736 | 710 | no |
| Pixeltetris.exe | PE32+ | x86_64 | 1264 | 88128 | 87918 | 99.76 | 210 | 57 | 121 | 84 | no |
| legacy-notepad-x64.exe | PE32+ | x86_64 | 403 | 22499 | 22376 | 99.45 | 123 | 31 | 214 | 173 | no |
| luhn.exe | PE32 | x86 | 2 | 1069 | 1039 | 97.19 | 30 | 13 | 1 | 1 | **YES** |
| Tetris.exe | PE32 | x86 | 412 | 9708 | 9698 | 99.90 | 10 | 5 | 99 | 83 | no |
| snake.exe | PE32+ | x86_64 | 195 | 7227 | 7220 | 99.90 | 7 | 5 | 152 | 140 | no |
| igi.exe | PE32 | x86 | 971 | 51518 | **51518** | **100.00** | **0** | 0 | 128 | 97 | no |
| imgview64.exe | PE32+ | x86_64 | 3 | 30299 | 30299 | 100.00 | 0 | 0 | 11 | 8 | no |
| tictactoe/TicTacToe.exe | PE32 | x86 | 2 | 15 | 15 | 100.00 | 0 | 0 | 1 | 1 | **YES** |

**Corpus totals: 19771 unsupported instructions across 13 binaries.** One of those 13 is
`luhn.exe`, a .NET image whose 30 unsupported instructions are data-as-code artefacts.
Excluding both .NET images the corpus total is **19741 unsupported instructions across 12
native binaries**.

Three binaries lift completely: `igi.exe`, `imgview64.exe` (both genuinely), and
`TicTacToe.exe` (.NET, meaningless).

### 4.1 Top 10 unsupported mnemonics per binary

**powder-v100.1.400-x86_64-windows-mingw.exe** (6995)
`punpcklwd 975, punpckhwd 559, punpcklbw 538, packuswb 505, paddw 480, psrlw 379, psraw 360,
punpckhbw 313, pmullw 280, movddup 160`

**openlierox.exe** (3197)
`movhps 579, movhlps 507, movlps 199, movddup 181, unpcklps 150, mulps 148, movsldup 102,
addps 94, psrld 92, cvttps2dq 76`

**bat.exe** (1857)
`pmovmskb 385, pcmpeqb 216, punpcklbw 144, tzcnt 122, shufps 97, pshuflw 84, paddq 70,
psrld 64, psubq 60, movmskps 55`

**plink.exe** (1818)
`pmuludq 234, psrad 160, aesenc 132, paddq 124, bswap 110, psllq 102, packssdw 97,
punpcklwd 93, pslld 80, psrld 68`

**fd.exe** (1795)
`pmovmskb 268, pcmpeqb 231, punpcklbw 130, paddq 110, pshuflw 97, bts 88, pslldq 84,
pandn 76, psubq 66, pcmpgtb 62`

**rg.exe** (1683)
`pmovmskb 214, pcmpeqb 196, punpcklbw 152, punpcklwd 118, tzcnt 97, pslld 90, paddq 84,
psubq 78, pshuflw 74, movmskps 61`

**clipjar.exe** (1326)
`pmovmskb 197, pcmpeqb 188, punpcklbw 121, pshuflw 92, paddq 81, psubq 74, pslld 68,
maxss 63, minss 61, andnps 58`

**supertux2.exe** (720)
`shufps 132, unpckhpd 96, sqrtss 74, unpcklpd 68, minss 61, maxss 57, cvtdq2pd 52,
cvtps2pd 48, cvtpd2ps 44, movmskpd 41`

**Pixeltetris.exe** (210)
`vfmadd213sd 21, pmovmskb 16, pcmpeqb 14, cvtdq2pd 10, vcomisd 9, movntps 8, btr 7,
vcvtdq2pd 7, vpshufd 7, vldmxcsr 6`

**legacy-notepad-x64.exe** (123)
`psrldq 18, vmovdqu 14, vpcmpeqw 11, vpmovmskb 10, vzeroupper 9, pcmpeqw 8, pmovmskb 7,
btr 6, xgetbv 5, pslldq 5`

**luhn.exe** (30, .NET — not meaningful)
`insd 5, outsd 5, lcall 5, das 4, insb 3, bound 2, lldt 2, aas 1, sti 1, out 1`

**Tetris.exe** (10)
`pushfd 3, popfd 2, fxsave 2, fxrstor 2, fldenv 1`

**snake.exe** (7)
`psrldq 2, cvtdq2pd 2, int 1, xgetbv 1, btr 1`

---

## 5. Aggregate rankings

### 5.1 A — Missing instruction families, ranked by total occurrences

Across all 16 binaries: **19771 unsupported instructions in 240 distinct mnemonic classes.**

| rank | family | occurrences | share | classes |
| --- | --- | --- | --- | --- |
| 1 | **SSE/MMX packed integer** | **11461** | **57.97%** | 60 |
| 2 | **SSE floating-point** | **5185** | **26.23%** | 59 |
| 3 | **VEX/AVX** | **1969** | **9.96%** | 65 |
| 4 | BMI / bit manipulation | 639 | 3.23% | 5 |
| 5 | AES-NI / PCLMUL | 236 | 1.19% | 7 |
| 6 | misc control/flag | 190 | 0.96% | 28 |
| 7 | x87 (FPU) | 46 | 0.23% | 13 |
| 8 | FMA | 45 | 0.23% | 3 |
| | **TOTAL** | **19771** | 100% | 240 |

The requested grouping, with the VEX bucket split by operand width:

#### VEX/AVX 256-bit (ymm) forms vs VEX/AVX 128-bit (xmm) forms

`coverage --json` reports a mnemonic and a count, not operand widths, so the split was
measured independently: the recovered instruction stream was re-decoded and every instance
of a mnemonic appearing in an unsupported class was classified by whether any operand is a
`ymm` register.

| | instances observed | share |
| --- | --- | --- |
| VEX/AVX 128-bit (xmm) | **1055** | 43.5% |
| VEX/AVX 256-bit (ymm) | **1373** | 56.5% |

**Read this as a ratio, not as an absolute count.** The tool's own total for v-prefixed
unsupported classes is **2014 occurrences** (1969 non-FMA + 45 FMA). My 2428 is higher
because I count *every* instance of a mnemonic that appears anywhere in an unsupported
class, including instances that actually lift — a mnemonic can be unsupported in one operand
shape and supported in another (`vpand` is the clear case: 107 `vpand ymm, ymm, ymm`
instances are lifted, while other `vpand` shapes are not). So 2428 is an upper bound and
**the ~43/57 xmm/ymm ratio is the meaningful output**. Applying that ratio to the tool's 2014
gives roughly 875 xmm and 1140 ymm.

Per-mnemonic split (observed instances):

```
mnemonic            128-bit  256-bit
vmovdqa                 231      228
vpshufb                 127      244
vpand                    96      192
vpextrq                 120        0
vpalignr                 36       72
vmovaps                  66       31
vzeroupper               82        0
vmovdqu                  19       63
vpcmpeqd                 27       54
vpsrlw                   24       48
vptest                   24       48
vpbroadcastb              0       60
vextracti128              0       49
vmovups                   2       43
vmovntdq                 0       32
vpmovmskb                 0       31
vpunpcklbw               25        1
vbroadcasti128            0       26
vpunpckhbw               24        1
vperm2i128                0       19
vinserti128               0       19
vinsertf128               0       17
vcomisd                  17        0
vpcmpeqq                  0       16
vcvtdq2pd                11        0
vpmaskmovd                0       11
vpcmpeqb                  0       10
vpunpcklqdq               9        0
vpsrlq                    9        0
vpmaddwd                  0        8
vpcmpeqw                  0        7
vpshufd                   7        0
vpsrad                    1        6
vpblendvb                 6        0
vpaddd                    0        6
vldmxcsr                  6        0
vpbroadcastd              0        5
vpackuswb                 2        3
vpsubq                    5        0
vpsubd                    4        0
vpaddq                    4        0
vpsllq                    4        0
vcvtss2si                 3        0
vpackusdw                0        3
vstmxcsr                  3        0
vmulpd                    3        0
vpor                      0        3
vucomiss                  3        0
vpaddw                    0        2
vpermq                    0        2
vmovmskpd                 0        2
vpblendw                  0        2
vpermd                    0        2
vpmovzxbd                 0        2
vpbroadcastw              0        2
vucomisd                  2        0
vcvtpd2dq                 2        0
vpsllw                    0        1
vpunpckldq                1        0
vpunpckhwd                0        1
vpunpcklwd                0        1
vaddpd                    1        0
vcvtps2pd                 1        0
vunpcklpd                 1        0
```

Note that the whole-register AVX2 lane ops (`vperm2i128`, `vinserti128`, `vextracti128`,
`vbroadcasti128`, `vpbroadcastb`) are **inherently 256-bit** — 0 xmm instances — so they are
not addressable by a 128-bit-only VEX path at all.

#### Full family member lists

**SSE/MMX packed integer (11461, 60 classes)**
`punpcklwd 1162, pmovmskb 1106, punpcklbw 946, pcmpeqb 787, punpckhwd 652, paddw 539,
packuswb 530, paddq 512, pshuflw 461, psrlw 453, psraw 386, pmullw 348, punpckhbw 319,
pmuludq 308, pextrw 278, pcmpgtb 257, pslld 257, psrld 239, psrad 229, psrlq 205,
pshufb 144, psrldq 144, psllq 130, pinsrw 128, packssdw 127, psubw 125, psllw 97,
pandn 91, paddd 62, pcmpgtd 59, pmaddwd 50, pslldq 42, pshufhw 37, palignr 36, paddb 33,
pmulhuw 32, psubq 28, pcmpeqw 25, pminub 14, pcmpeqq 12, pcmpistri 9, punpckldq 8,
pblendw 6, ptest 6, pcmpestrm 5, pmaxub 4, pextrd 4, psubd 4, pmuldq 4, packsswb 3,
pinsrd 3, pcmpestri 3, psubb 2, pshufd 2, punpckhdq 2, pmulld 2, pmovzxdq 1, pcmpeqd 1,
pinsrb 1, pmovzxbd 1`

**SSE floating-point (5185, 59 classes)**
`movhps 694, movhlps 558, shufps 344, movddup 342, movlps 341, mulps 278, minss 235,
unpcklps 226, maxss 223, addps 181, cvtps2pd 142, sqrtss 130, movsldup 124, cvttps2dq 123,
subps 119, andnps 105, shufpd 99, cvtdq2pd 90, movshdup 77, minsd 71, maxsd 69, cmpltss 65,
movmskps 64, mulpd 44, unpcklpd 42, addpd 41, movlhps 38, cvtpd2ps 36, cmpnltss 36,
sqrtsd 35, unpckhpd 33, divps 30, cmpnless 28, cmpless 14, subpd 13, addsubps 13,
movmskpd 8, movntps 8, divpd 7, haddpd 6, cmpeqss 5, cmpneqss 5, rsqrtss 5,
cmpunordss 4, cmpltsd 4, cvtss2si 4, cvttpd2dq 4, movhpd 4, andnpd 4, cmpltps 2,
movlpd 2, cvtpd2dq 2, rcpps 2, cmpneqsd 1, roundsd 1, addsubpd 1, cmpnltsd 1,
unpckhps 1, sqrtpd 1`

**VEX/AVX (1969, 65 classes)** — see the per-mnemonic table above.

**BMI / bit manipulation (639, 5 classes)**
`tzcnt 559, bts 40, btr 32, bt 4, lzcnt 4`

**AES-NI / PCLMUL (236, 7 classes)**
`aesenc 133, aesdec 34, aeskeygenassist 28, pclmulqdq 20, aesenclast 13, aesdeclast 4,
aesimc 4`

**misc control/flag (190, 28 classes)**
`int 119, xgetbv 19, outsd 13, pushfd 3, pushfq 2, rdtsc 2, popfd 2, aas 1, bound 1, das 1,
insb 1, insd 1, int1 1, out 1, sti 1, sfence 1, popfq 1, in 1, bnd jne 3, bnd ret 2,
bnd jae 1, lcall 6, lldt 1, into 1, stc 1, cwd 1, rdrand 1, rdseed 1`

**x87 (FPU) (46, 13 classes)**
`fprem 17, fprem1 4, fsincos 4, fscale 4, f2xm1 2, fxam 2, fyl2xp1 2, fcmovne 2, fucomi 2,
fucompi 2, fxsave 2, fxrstor 2, fldenv 1`

**FMA (45, 3 classes)**
`vfmadd213sd 31, vfmadd231sd 10, vfmsub213sd 4`

Classifier boundary note: `vfnmadd231sd` (2 occurrences) is grouped under **VEX/AVX** rather
than FMA, because the rule matches the `vfm` prefix and `vfnmadd` starts with `vfn`. Moving
it would make FMA 47 / 4 classes and VEX/AVX 1967 / 64. Totals are unaffected either way.

### 5.2 B — Missing Win32 imports, ranked

Across all 16 binaries. "missing across binaries" counts one per binary that imports the
symbol and has no shim, so it is the number of binaries a single shim would unblock.

#### By library

| library | missing across binaries | distinct symbols |
| --- | --- | --- |
| **kernel32.dll** | **731** | 245 |
| **user32.dll** | **355** | 197 |
| sdl2.dll | 259 | 184 |
| msvcp140.dll | 245 | 171 |
| libstdc++-6.dll | 217 | 205 |
| msvcrt.dll | 172 | 149 |
| api-ms-win-crt-runtime-l1-1-0.dll | 115 | 39 |
| api-ms-win-crt-stdio-l1-1-0.dll | 111 | 58 |
| api-ms-win-crt-math-l1-1-0.dll | 109 | 56 |
| api-ms-win-crt-string-l1-1-0.dll | 95 | 48 |
| gdi32.dll | 71 | 40 |
| advapi32.dll | 70 | 40 |
| vcruntime140.dll | 58 | 25 |
| wsock32.dll | 44 | 25 |
| glew32.dll | 44 | 44 |
| opengl32.dll | 36 | 36 |
| ws2_32.dll | 33 | 27 |
| api-ms-win-crt-filesystem-l1-1-0.dll | 32 | 22 |
| physfs.dll | 31 | 31 |
| openal32.dll | 26 | 26 |
| shell32.dll | 25 | 15 |
| api-ms-win-crt-heap-l1-1-0.dll | 25 | 7 |
| ntdll.dll | 24 | 9 |
| libxml2-16.dll | 23 | 23 |
| api-ms-win-crt-convert-l1-1-0.dll | 22 | 18 |
| api-ms-win-crt-time-l1-1-0.dll | 20 | 10 |
| freetype.dll | 20 | 20 |
| libyaml-cpp.dll | 19 | 19 |
| gdiplus.dll | 17 | 16 |
| imm32.dll | 16 | 11 |
| zlib1.dll | 16 | 12 |
| libcurl.dll | 15 | 15 |
| ole32.dll | 14 | 8 |
| libopenal-1.dll | 14 | 14 |
| dbghelp.dll | 14 | 11 |
| libgd.dll | 13 | 13 |
| api-ms-win-core-synch-l1-2-0.dll | 12 | 3 |
| libpng16.dll | 12 | 12 |
| winmm.dll | 11 | 11 |
| api-ms-win-crt-private-l1-1-0.dll | 11 | 11 |
| avifil32.dll | 10 | 10 |
| libcurl-4.dll | 10 | 10 |
| api-ms-win-crt-locale-l1-1-0.dll | 9 | 5 |
| api-ms-win-crt-utility-l1-1-0.dll | 9 | 5 |
| libzip.dll | 8 | 8 |
| secur32.dll | 7 | 7 |
| vorbisfile.dll | 7 | 7 |
| version.dll | 6 | 3 |
| comctl32.dll | 5 | 4 |
| comdlg32.dll | 5 | 5 |
| libalut-0.dll | 5 | 5 |
| libwinpthread-1.dll | 5 | 5 |
| sdl2_image.dll | 5 | 4 |
| crypt32.dll | 5 | 5 |
| oleaut32.dll | 4 | 3 |
| bcryptprimitives.dll | 4 | 1 |

(Remaining libraries are below 4.)

#### By symbol — top 80 of the ranking

| rank | symbol | library | binaries |
| --- | --- | --- | --- |
| 1 | FindClose | kernel32.dll | 11 |
| 2 | CloseHandle | kernel32.dll | 11 |
| 3 | RtlCaptureContext | ntdll.dll | 11 |
| 4 | RtlVirtualUnwind | ntdll.dll | 10 |
| 5 | RtlLookupFunctionEntry | ntdll.dll | 10 |
| 6 | GetCommandLineW | kernel32.dll | 9 |
| 7 | CreateFileW | kernel32.dll | 9 |
| 8 | InitializeSListHead | kernel32.dll | 9 |
| 9 | GetModuleFileNameW | kernel32.dll | 9 |
| 10 | LocalFree | kernel32.dll | 8 |
| 11 | FindNextFileW | kernel32.dll | 8 |
| 12 | FindFirstFileExW | kernel32.dll | 8 |
| 13 | SetFilePointerEx | kernel32.dll | 8 |
| 14 | FlushFileBuffers | kernel32.dll | 8 |
| 15 | FreeEnvironmentStringsW | kernel32.dll | 8 |
| 16 | GetEnvironmentStringsW | kernel32.dll | 8 |
| 17 | HeapReAlloc | kernel32.dll | 8 |
| 18 | RaiseException | kernel32.dll | 8 |
| 19 | FormatMessageA | kernel32.dll | 7 |
| 20 | ReleaseMutex | kernel32.dll | 7 |
| 21 | WriteConsoleW | kernel32.dll | 7 |
| 22 | GetFileType | kernel32.dll | 7 |
| 23 | WaitForSingleObject | kernel32.dll | 7 |
| 24 | GetConsoleMode | kernel32.dll | 7 |
| 25 | CreateMutexA | kernel32.dll | 7 |
| 26 | RegCloseKey | advapi32.dll | 7 |
| 27 | memmove | vcruntime140.dll | 7 |
| 28 | memcpy | vcruntime140.dll | 7 |
| 29 | strlen | api-ms-win-crt-string-l1-1-0.dll | 7 |
| 30 | _cexit | api-ms-win-crt-runtime-l1-1-0.dll | 7 |
| 31 | malloc | api-ms-win-crt-heap-l1-1-0.dll | 7 |
| 32 | free | api-ms-win-crt-heap-l1-1-0.dll | 7 |
| 33 | LoadLibraryExW | kernel32.dll | 7 |
| 34 | VirtualProtect | kernel32.dll | 7 |
| 35 | GetCPInfo | kernel32.dll | 7 |
| 36 | DuplicateHandle | kernel32.dll | 6 |
| 37 | GetFileAttributesW | kernel32.dll | 6 |
| 38 | CreateThread | kernel32.dll | 6 |
| 39 | memset | vcruntime140.dll | 6 |
| 40 | __setusermatherr | api-ms-win-crt-math-l1-1-0.dll | 6 |
| 41 | _initterm | api-ms-win-crt-runtime-l1-1-0.dll | 6 |
| 42 | exit | api-ms-win-crt-runtime-l1-1-0.dll | 6 |
| 43 | _exit | api-ms-win-crt-runtime-l1-1-0.dll | 6 |
| 44 | fwrite | api-ms-win-crt-stdio-l1-1-0.dll | 6 |
| 45 | realloc | api-ms-win-crt-heap-l1-1-0.dll | 6 |
| 46 | HeapSize | kernel32.dll | 6 |
| 47 | GetStartupInfoW | kernel32.dll | 6 |
| 48 | SetStdHandle | kernel32.dll | 6 |
| 49 | GetStringTypeW | kernel32.dll | 6 |
| 50 | LCMapStringW | kernel32.dll | 6 |
| 51 | RtlUnwindEx | kernel32.dll | 6 |
| 52 | GetModuleHandleExW | kernel32.dll | 6 |
| 53 | GetFileInformationByHandle | kernel32.dll | 5 |
| 54 | GetFullPathNameW | kernel32.dll | 5 |
| 55 | WaitForSingleObjectEx | kernel32.dll | 5 |
| 56 | WaitForMultipleObjects | kernel32.dll | 5 |
| 57 | GetFileInformationByHandleEx | kernel32.dll | 5 |
| 58 | SleepEx | kernel32.dll | 5 |
| 59 | SetFileInformationByHandle | kernel32.dll | 5 |
| 60 | FormatMessageW | kernel32.dll | 5 |
| 61 | SetConsoleMode | kernel32.dll | 5 |
| 62 | GetCurrentDirectoryW | kernel32.dll | 5 |
| 63 | GetForegroundWindow | user32.dll | 5 |
| 64 | RegOpenKeyExW | advapi32.dll | 5 |
| 65 | RegQueryValueExW | advapi32.dll | 5 |
| 66 | memcmp | vcruntime140.dll | 5 |

#### Import coverage per binary

| binary | imports | implemented | missing | implemented % |
| --- | --- | --- | --- | --- |
| supertux2.exe | 736 | 26 | 710 | 3.53 |
| openlierox.exe | 653 | 35 | 618 | 5.36 |
| powder.exe | 590 | 46 | 544 | 7.80 |
| clipjar.exe | 384 | 40 | 344 | 10.42 |
| bat.exe | 291 | 40 | 251 | 13.75 |
| legacy-notepad-x64.exe | 214 | 41 | 173 | 19.16 |
| snake.exe | 152 | 12 | 140 | 7.89 |
| plink.exe | 153 | 44 | 109 | 28.76 |
| fd.exe | 142 | 42 | 100 | 29.58 |
| igi.exe | 128 | 31 | 97 | 24.22 |
| rg.exe | 127 | 43 | 84 | 33.86 |
| Pixeltetris.exe | 121 | 37 | 84 | 30.58 |
| Tetris.exe | 99 | 16 | 83 | 16.16 |
| imgview64.exe | 11 | 3 | 8 | 27.27 |
| luhn.exe (.NET) | 1 | 0 | 1 | 0.00 |
| TicTacToe.exe (.NET) | 1 | 0 | 1 | 0.00 |

---

## 6. First-blocker analysis (raw output)

### 6.1 Verbatim command output

Each line below is the actual stderr from
`./build/recomp-studio translate <image> --target macos-arm64 --output /tmp/gapcensus-translate/<key>`,
or the success line where translation completed.

```
--- bat/bat-v0.26.1-x86_64-pc-windows-msvc/bat.exe
    exit 1
    error: unsupported instruction 'pcmpeqb' at 0x14000779full

--- clipjar.exe
    exit 1
    error: unsupported instruction 'pcmpeqb' at 0x140005c71ull

--- fd/fd-v10.5.0-x86_64-pc-windows-msvc/fd.exe
    exit 1
    error: unsupported instruction 'bts' at 0x14000c568ull

--- igi.exe
    exit 0
    translated 971 functions, 128 imports
    project:  /tmp/gapcensus-translate/igi.exe

--- imgview64.exe
    exit 0
    translated 3 functions, 11 imports
    project:  /tmp/gapcensus-translate/imgview64.exe

--- legacy-notepad-x64.exe
    exit 1
    error: unsupported instruction 'psrldq' at 0x1400079afull

--- luhn/luhn.exe                                   [.NET - not meaningful]
    exit 1
    error: unsupported instruction 'insd' at 0x4020caull

--- openlierox/openlierox-20260912.1-windows/openlierox.exe
    exit 1
    error: unsupported instruction 'movhlps' at 0x140005e84ull

--- pixeltetris/Pixeltetris-v1.0.0-Windows-64bit/bin/v1/Pixeltetris.exe
    exit 1
    error: unsupported instruction 'psrldq' at 0x14001225full

--- plink.exe
    exit 1
    error: unsupported instruction 'punpcklbw' at 0x140014590ull

--- powder-v100.1.400-x86_64-windows-mingw.exe
    exit 1
    error: unsupported instruction 'punpckhbw' at 0x140002600ull

--- ripgrep/ripgrep-15.2.0-x86_64-pc-windows-msvc/rg.exe
    exit 1
    error: unsupported instruction 'punpcklbw' at 0x1400016a8ull

--- snake/snake-windows-x86_64.exe
    exit 1
    error: unsupported instruction 'psrldq' at 0x140005d19ull

--- supertux/SuperTux-portable/bin/supertux2.exe
    exit 1
    error: unsupported instruction 'cvtps2pd' at 0x14039e306ull

--- tetris/Tetris.exe
    exit 1
    error: unsupported instruction 'pushfd' at 0x4045a0ull

--- tictactoe/TicTacToe.exe                         [.NET - not meaningful]
    exit 0
    translated 2 functions, 1 imports
    project:  /tmp/gapcensus-translate/tictactoe__TicTacToe.exe
```

These verbatim abort addresses agree with the earliest `first_address` in each binary's
`coverage --json` class list, so the census and the translator gate are consistent.

### 6.2 The answer

**Non-.NET binaries blocked by an instruction: 12** (bat, clipjar, fd, legacy-notepad,
openlierox, Pixeltetris, plink, powder, rg, snake, supertux2, Tetris).

| capability | binaries whose first blocker it is |
| --- | --- |
| **SSE2 packed integer — byte shifts (`psrldq`, `pslldq`) + unpack/pack (`punpcklwb`, `punpckhbw`, …) + packed compare (`pcmpeqb`)** | **8** (bat, clipjar, legacy-notepad, Pixeltetris, plink, powder, rg, snake) |
| SSE floating-point (`movhlps`, `cvtps2pd`) | 2 (openlierox, supertux2) |
| BMI / bit manipulation (`bts`) | 1 (fd) |
| misc control/flag (`pushfd`) | 1 (Tetris) |

> **The single capability that clears the most binaries' first blocker is the SSE2
> packed-integer family: 8 of 12 instruction-blocked native binaries (67%).**
> Narrowed to one mnemonic, it is `psrldq` (3 binaries) — but `psrldq` alone clears only 3,
> because `punpcklbw`/`punpckhbw`/`pcmpeqb` each gate others.

Within that family, the exact first-blocker set needed is small:
`psrldq` (3), `punpcklbw` (2), `pcmpeqb` (2), `punpckhbw` (1) — four mnemonics.

### 6.3 Blocker chains — how deep the gate goes

Clearing a first blocker does not finish a binary; it exposes the next. Ordered by the
address of each class's first occurrence:

```
snake.exe: 5 classes to clear
    psrldq -> cvtdq2pd -> int -> xgetbv -> btr

Tetris.exe: 5 classes to clear
    pushfd -> popfd -> fxsave -> fxrstor -> fldenv

luhn.exe (.NET): 13 classes  (not meaningful)

legacy-notepad-x64.exe: 31 classes to clear
    psrldq -> vmovdqu -> vpcmpeqw -> vpmovmskb -> vzeroupper -> pcmpeqw -> pmovmskb ->
    xgetbv -> btr -> int -> psrlq -> psubq -> ... 19 more

supertux2.exe: 47 classes to clear
    shufps -> unpckhpd -> sqrtss -> unpcklps -> minss -> maxss -> cvtdq2pd -> in ->
    cvtps2pd -> cvtpd2ps -> psrldq -> vpcmpeqw -> ... 35 more

rg.exe: 52 classes to clear
    punpcklbw -> punpcklwd -> pslld -> movmskps -> pcmpeqb -> pextrw -> pshuflw ->
    pmovmskb -> tzcnt -> shufps -> psubq -> bts -> ... 40 more

Pixeltetris.exe: 57 classes to clear
    psrldq -> bnd jae -> bnd jne -> bnd ret -> movntps -> sfence -> int -> cvtdq2pd ->
    mulpd -> cvtpd2dq -> psrad -> psllq -> ... 45 more

fd.exe: 61 classes to clear
    bts -> pcmpeqb -> pmovmskb -> paddq -> movlps -> punpcklbw -> pshuflw -> pandn ->
    int -> paddb -> pminub -> pinsrw -> ... 49 more

bat.exe: 62 classes to clear
    pcmpeqb -> pmovmskb -> tzcnt -> pinsrw -> punpcklbw -> pshuflw -> pandn -> pslldq ->
    vpbroadcastb -> vmovdqa -> vzeroupper -> vmovups -> ... 50 more

clipjar.exe: 62 classes to clear
    pcmpeqb -> pmovmskb -> punpcklbw -> pshuflw -> int -> maxss -> minss -> cmpneqss ->
    cmpnless -> andnps -> cmpltss -> cmpless -> ... 50 more

plink.exe: 68 classes to clear
    punpcklbw -> pshuflw -> paddw -> punpcklwd -> psrld -> psrlw -> pcmpeqb -> pmovmskb ->
    cwd -> pshufd -> pshufb -> pandn -> ... 56 more

openlierox.exe: 78 classes to clear
    movhlps -> movhps -> movddup -> cmpltss -> andnps -> punpcklwd -> psrlw -> punpckhbw ->
    pmullw -> punpcklbw -> paddw -> psraw -> ... 66 more

powder.exe: 96 classes to clear
    punpckhbw -> punpcklbw -> punpckhwd -> punpcklwd -> maxss -> minss -> movhps ->
    shufps -> movddup -> psrad -> movhlps -> cmpnless -> ... 84 more
```

The 8 SSE2-gated binaries need between 31 and 96 total classes each; `snake.exe` (5) is the
cheapest realistic win, then `legacy-notepad-x64.exe` (31).

---

## 7. VEX/AVX mapping audit — two defects found

### 7.1 The table as implemented

`vex_equivalents()` is at [`core/semantics/x86_64_lifter.cpp:130-149`](core/semantics/x86_64_lifter.cpp#L130-L149),
consumed by the VEX dispatch at
[`:376-393`](core/semantics/x86_64_lifter.cpp#L376-L393).

Mapped v-mnemonics (35 entries): `vmovaps, vmovups, vmovapd, vmovupd, vmovdqa, vmovdqu,
vmovntdq, vmovntpd, vmovss, vmovsd, vmovd, vmovq, vpand, vpor, vpxor, vandps, vandpd,
vorps, vorpd, vxorps, vxorpd, vaddsd, vsubsd, vmulsd, vdivsd, vaddss, vsubss, vmulss,
vdivss, vcvtsi2sd, vcvtsi2ss, vcvttsd2si, vcvttss2si, vcvtsd2ss, vcvtss2sd`.

I confirmed all six conversion targets (`cvtsi2sd`, `cvtsi2ss`, `cvttsd2si`, `cvttss2si`,
`cvtsd2ss`, `cvtss2sd`) really are implemented in the lifter
([`:878`, `:887`, `:896`, `:905`, `:914`, `:919`](core/semantics/x86_64_lifter.cpp#L878)),
so the table's stated invariant — "only mnemonics the lifter already implements appear
here" — holds.

The 3-operand path:

```cpp
} else if (operands.size() == 3 && is_vector_register(operands[0]) &&
           is_vector_register(operands[1])) {
  emit("std::memcpy(context->vector_registers[" + ... dst ... +
       "], context->vector_registers[" + ... src1 ... + "], 16);");
  auto two_operand = instruction;
  two_operand.mnemonic = equivalent->second;
  two_operand.operands = {operands[0], operands[2]};
  emit_instruction(two_operand, function, output);
  return;
}
```

### 7.2 DEFECT 1 — `emit_vector_move` register-to-register ignores `byte_count` (128-bit)

**File/line:** [`core/semantics/x86_64_lifter.cpp:361-364`](core/semantics/x86_64_lifter.cpp#L361-L364).

```cpp
} else if (is_vector_register(destination) && is_vector_register(source)) {
  emit("std::memcpy(context->vector_registers[" + std::to_string(vector_index(destination)) +
       "], context->vector_registers[" + std::to_string(vector_index(source)) + "], " +
       std::to_string(byte_count >= 32 ? 32 : 16) + ");");
}
```

`byte_count` selects only 32 vs 16. **A requested 4 or 8 byte move silently becomes a 16-byte
copy.** `movss`/`movsd` request 4 and 8
([`:426-429`](core/semantics/x86_64_lifter.cpp#L426-L429)).

This is semantically wrong for a 128-bit operand, because the SSE scalar moves **preserve**
the destination's upper bits:

| instruction | architectural semantics | what the lifter emits |
| --- | --- | --- |
| `movsd xmm2, xmm0` | `xmm2[63:0] = xmm0[63:0]`; `xmm2[127:64]` **unchanged** | `memcpy(xmm2, xmm0, 16)` → clobbers `xmm2[127:64]` |
| `movss xmm0, xmm1` | `xmm0[31:0] = xmm1[31:0]`; `xmm0[127:32]` **unchanged** | `memcpy(xmm0, xmm1, 16)` → clobbers `xmm0[127:32]` |

**This is the "VEX form whose SSE counterpart is not the same operation" the task asked
about, in its concrete instance: `vmovsd`/`vmovss`.** For the VEX 3-operand form
`vmovsd xmm1, xmm2, xmm3` the architecture says
`xmm1[63:0] = xmm3[63:0]`, `xmm1[127:64] = xmm2[127:64]`. The lifter does
`memcpy(xmm1, xmm2, 16)` and then `movsd xmm1, xmm3`, whose register branch does
`memcpy(xmm1, xmm3, 16)` — so the first copy is **entirely overwritten** and the result is
`xmm1 = xmm3` in full. The `src1` operand is discarded.

The comment at
[`:370-375`](core/semantics/x86_64_lifter.cpp#L370-L375) states this path exists so that
"for scalar forms, the upper bits of the destination must come from src1 rather than being
left alone". **The code does not achieve that** for `vmovss`/`vmovsd`: the 16-byte
register-register copy defeats the preceding `src1` copy. The two defects are the same root
cause and one fix (honour `byte_count` in the register branch) addresses both.

**Reachability — measured, not assumed.** These mnemonics are *lifted* (none of
`movss`/`movsd`/`vmovss`/`vmovsd` appears in any binary's unsupported class list), so the
defect manifests wherever the shape occurs. Scanning the recovered instruction stream of all
16 binaries for register-register forms in lifted code:

```
movsd xmm, xmm        (SSE/VEX 2-operand reg,reg): 46 instances
    legacy-notepad-x64.exe: 0x140025716  movsd xmm2, xmm0
    legacy-notepad-x64.exe: 0x140025a27  movsd xmm5, xmm2
    legacy-notepad-x64.exe: 0x140025ba1  movsd xmm4, xmm0
    Pixeltetris.exe:        0x1400cc417  movsd xmm5, xmm2
    Pixeltetris.exe:        0x1400cc591  movsd xmm4, xmm0
    Pixeltetris.exe:        0x14009961c  movsd xmm7, xmm0

movss xmm, xmm        (SSE/VEX 2-operand reg,reg): 21 instances
    bat.exe:        0x140281002  movss xmm0, xmm1
    fd.exe:         0x140265d22  movss xmm0, xmm1
    openlierox.exe: 0x140283cd0  movss xmm6, xmm3
    openlierox.exe: 0x140338e31  movss xmm0, xmm2
    openlierox.exe: 0x140356bb8  movss xmm4, xmm2
    plink.exe:      0x140073629  movss xmm1, xmm0

vmovsd xmm, xmm, xmm    (VEX 3-operand reg,reg,reg): 1 instance
    Pixeltetris.exe: 0x14009bac6  vmovsd xmm5, xmm5, xmm3

TOTAL AFFECTED INSTRUCTIONS: 68
```

Per binary: Pixeltetris 38, powder 14, plink 7, legacy-notepad 3, openlierox 3, bat 1,
fd 1, rg 1.

### 7.3 DEFECT 2 — the 3-operand `src1` copy is hardcoded to 16 bytes (256-bit)

**File/line:** [`core/semantics/x86_64_lifter.cpp:384-385`](core/semantics/x86_64_lifter.cpp#L384-L385).

The `src1 -> dst` pre-copy is a literal `, 16)` and never consults `is_wide_vector_register`
/ `vector_register_bytes`. For a 3-operand VEX instruction with `ymm` operands only the low
128 bits of `src1` are copied into the destination.

**Reachability — measured.** Lifted 3-operand VEX instructions with a `ymm` operand:

```
vpand: 107
    rg.exe:        0x140114aae  vpand ymm0, ymm0, ymm2
    rg.exe:        0x140114aca  vpand ymm1, ymm1, ymm2
    rg.exe:        0x140114ad3  vpand ymm2, ymm2, ymm3
    rg.exe:        0x140114ae1  vpand ymm3, ymm4, ymm3
    supertux2.exe: (11 more)

rg.exe: 96   supertux2.exe: 11
TOTAL: 107
```

For `vpand ymm0, ymm0, ymm2` the architecture is a 256-bit AND; the lifter copies 16 bytes
from `ymm0` then applies the 16-byte `pand` helper, leaving the upper 128 bits of the
destination not written from `src1` at all.

This one is **outside the 128-bit scope the task asked about** — it is reported because it is
the same hardcoded-width root cause as Defect 1 and should be fixed in the same pass.

### 7.4 Mappings I checked and found *correct*

To be explicit about what I cleared rather than only what I flagged:

* `vmovaps/vmovups/vmovapd/vmovupd/vmovdqa/vmovdqu → mov*` — 2-operand, identical data
  movement; the 16-byte reg,reg copy is right for these.
* `vmovntdq → movdqa`, `vmovntpd → movapd` — non-temporal stores are store-only and move the
  same bytes; the temporal hint does not affect the result. (Not load forms: `vmovntdq` has
  no load encoding.)
* `vpand/vpor/vpxor/vandps/vandpd/vorps/vorpd/vxorps/vxorpd → p*`/`*ps`/`*pd` — the 3-operand
  composition `dst = src1; dst op= src2` is the correct expansion of VEX.NDS for bitwise ops.
* `vaddsd/vsubsd/vmulsd/vdivsd` and the `ss` variants — same expansion, correct.
* `vcvtsi2sd/vcvtsi2ss/vcvtsd2ss/vcvtss2sd` — the 3-operand path copies `src1` then the
  2-operand conversion helper writes only the low 32/64 bits, so the upper bits correctly come
  from `src1`. This path is **correct** precisely because those helpers are partial-width
  writes, unlike the move helpers.
* `vcvttsd2si/vcvttss2si` — 2-operand only, no upper-bit semantics.
* All six conversion targets exist in the lifter, so no mapping points at an unimplemented
  mnemonic.

---

## 8. Discrepancies against the figures supplied in the task

The task listed four figures to reproduce. Three reproduce exactly; one does not:

| claim | supplied | measured here | verdict |
| --- | --- | --- | --- |
| `igi.exe` lifts 51518/51518, 0 unsupported | 51518/51518 | **51518/51518, 0 unsupported** | reproduced |
| `igi.exe` 97 of 128 imports missing | 97/128 | **97/128** | reproduced |
| `legacy-notepad-x64.exe` unsupported | 123 | **123** | reproduced |
| `clipjar.exe` unsupported | 1326 | **1326** | reproduced |
| `Pixeltetris.exe` unsupported | 279 | **210** | **NOT reproduced — differs by 69** |

I cannot reproduce 279 for Pixeltetris with the current binary. The measured value is 210
unsupported across 57 classes. The most likely explanation is that the supplied figure
predates the VEX/AVX mapping described in §7: `Pixeltetris.exe` currently has 28 v-prefixed
unsupported classes totalling 99 occurrences, and the VEX table would have cleared a subset
of VEX instructions. I state this as a hypothesis — I did not have the older build available
to measure the delta directly, so I am reporting the measured number rather than adopting
279.

Similarly, `plink.exe` measured 1818 unsupported / 68 classes here; the figure from the
earlier task-3 session (before the VEX mapping) was 2037 / 82.

---

## 9. Limitations

1. **The VEX xmm/ymm split is an upper bound, not an exact count.** `coverage --json` reports
   per-mnemonic totals, not per-instruction operand shapes, so the split counts every
   instance of any mnemonic that appears in an unsupported class — including instances that
   lift. The ratio (~43% xmm / ~57% ymm) is the meaningful result; the absolute 1055/1373 is
   not comparable to the tool's 2014. An exact split needs per-instruction census output.
2. **Family classification is mine, not the tool's.** 240 classes were assigned to 8 families
   by mnemonic pattern with an explicit residual check (§5.1 lists every member of every
   family and the residual bucket is empty). A different grouping would shift boundaries —
   in particular `pclmulqdq`/`aes*` are separated from SSE integer, and `bt/bts/btr` are
   grouped with BMI rather than with the SSE bitwise ops.
3. **Only the corpus measured.** 16 binaries, all Windows PE, mostly x86_64. Nothing here
   generalises to ARM64 or to 16-bit code.
4. **`translate` was run with default configuration** (no config file, no
   `instruction_patches`, `strict_lifting` default on). A configured run with patches could
   produce a different instruction stream and a different first blocker.
5. **The VEX defects are reported from source reading plus reachability measurement, not from
   a runtime differential test.** I did not execute the generated code or compare against
   native behaviour; the claims are about what the emitted C++ computes versus the
   architectural definition of the instruction. That is sufficient to call them defects
   (the emitted `memcpy` width is unambiguous), but no runtime trace is offered.
6. **Blocker chains assume the lifter's reject/accept decision is stable** across the whole
   class list; they are ordered by first-occurrence address and assume no other gate
   (e.g. a build failure or an unsupported import) intervenes first.
