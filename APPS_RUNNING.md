# Application corpus: work in progress

This is an evidence ledger for the `recomp-apps` corpus on macOS ARM64. A
successful build or instruction-coverage result alone does not establish that
an application runs. “Verified” below means the native run and differential
verification both succeeded. Counts are observations from the indicated run,
not a claim about every copy of a binary in the corpus.

| Application | Input | Build | Native run | Differential verification | Evidence |
| --- | --- | --- | --- | --- | --- |
| blackbox | `win32/blackbox.exe` | Passed | Exit 3 | Failed | Baseline `c14ef07`; at `4e9d7dc` it reaches missing `InitCommonControls` |
| blackbox | `win64/blackbox.exe` | Not reached | Not reached | Not reached | At `7c86a19`, translation advances from `movlhps` to `mulps`; 21 unsupported occurrences remain. |
| BusyBox | `win32/busybox-w32.exe` | Interrupted | Not established | Not established | At `84499a6`, all 200,955 recovered instructions lift, including the previously unsupported `aas`; 224 of 311 imports are missing. Its repair-enabled build was interrupted after more than seven minutes as available disk space fell; no run result was obtained. |
| cube | `win32/cube.exe` | Passed | Exit 3, no stdout | Failed | SHA-256 `7844757c04eea2fcee04a7029e0ed6e4893d471c44c0bef81d00d009f15e9814`. At the current revision, all 30,337 instructions lift and the native build completes; the first runtime call is missing `comctl32.dll!InitCommonControls` at `0x4181e7`. There are 126 missing imports. Evidence: `build/cube-run-2/autorecomp.log`. |
| fifteensolver | `win32/fifteensolver.exe` | Passed | Exit 1, no stdout | Failed; reference completed, candidate did not | `autorecomp` with `--autorepair --buildrun`, baseline at `c14ef07` |
| plink | `win64/plink.exe` | Not reached | Not reached | Not reached | Before `374664f`, translation stopped on memory-source `pshufd`; after `3c90f4d`, it stops on `aeskeygenassist` |
| game2048 | `windows/x64/games/game2048.exe` | Passed | EOF: exit 0 and 347 bytes; `q`: exit 3 | EOF comparison and repair passed once; interactive path not verified | At `cf3fb74`, EOF output matched and repair passed, but three registered exit handlers did not run. `q` input still reaches an unresolved indirect jump at `0x140002daf`. The game is not counted as fixed. |
| arith-calc | `windows/x64/apps/arith-calc.exe` | Passed | Exit 0; 172 bytes | Passed | Corpus audit; SHA-256 `bb67ed0c581a1a00cfce9fd324c4003a970d4869829bb472e5f91b4ee476be3c` |
| arith-calc | `windows/x86/apps/arith-calc.exe` | Passed | Exit 0; 172 bytes | Passed | Corpus audit; SHA-256 `9b59ee613acc7b5a1512f8a5fcc5f65317f0fa79452d01728e1715b63f23d7a6` |

**Applications established as fixed by this work: 0.** The audit and fixes are
still in progress. The two arith-calc executables above were observed to verify; no
before-and-after evidence establishes that these fixes made them work. The other
corpus locations have not yet been fully run and cannot be counted as passing.

| Corpus slice | Commands completed | Exit 0 | Exit nonzero | Notes |
| --- | ---: | ---: | ---: | --- |
| `win32/*.exe` | 74 | 1 | 73 | Historical shared-output loop. `fillingsolver.exe` reported verification with zero output bytes; this does not demonstrate interactive use. Builds changed during the run. The then-unrecognized `--autorepair` was silently ignored, so repair did not run. |
| `win64/*.exe` | 52 | 0 | 52 | Historical per-app output sweep; revisions changed during the run and `--autorepair` was silently ignored. |
| `win64/*.exe` rerun | 52 | 0 | 52 | Per-app output sweep after `5fe2627`; all returned nonzero before `ac4a69c`. `--autorepair` was silently ignored. |
| `win32/*.exe` with repair | 8 | 0 | 8 | The requested shared-output loop was interrupted during the ninth executable to avoid exhausting disk space. Repair ran; the retained log is `build/requested-win32.log`. |
| `win64/*.exe` with repair | 2 | 0 | 2 | The per-app sweep was interrupted during the third executable for the same reason. The build changed during the sweep; the retained log is `build/win64-repair.log`. |

The feature branch's architecture-neutral IR updates were merged at `53f773e`
and its subsequent verification and discovery updates at `c9b4d81`. The
`--autorepair` spelling is accepted and enables repair starting at `0be6c42`;
the exact requested win32 loop was started again but remains incomplete. Observations made before these
changes need to be rerun on the integrated revision. Temporary logs from the
earlier sweeps were removed by the host; the counts above are the recorded
observations, not a retained per-app log archive.

## Open-issue priority

| Issue | Priority for running apps | Reason |
| --- | --- | --- |
| [#4 Wine-derived compatibility](https://github.com/heaven-hm/recomp-studio/issues/4) | Highest | The GUI corpus reaches missing `comctl32`, `user32`, and `gdi32` APIs; reusable compatibility code addresses that broad blocker. |
| [#5 Remill or similar semantics](https://github.com/heaven-hm/recomp-studio/issues/5) | High | Missing instruction and discovery coverage blocks many x64 programs; integration must retain the current verification gate. |
| [#6 OSS integration policy](https://github.com/heaven-hm/recomp-studio/issues/6) | Supporting | Document source provenance and licensing. The issue's proposed no-copy policy conflicts with the requested source reuse and does not govern this audit. |
| [#3 semantic names](https://github.com/heaven-hm/recomp-studio/issues/3) | Later | Improves readability but does not itself make an executable run. |

Wine's LGPL-2.1-or-later [`commctrl.c`](https://github.com/wine-mirror/wine/blob/f343ca6085bfac807c33e9c1a8a43105071f1416/dlls/comctl32/commctrl.c)
was inspected for the `InitCommonControls` failure in `blackbox.exe`. Its empty
function depends on Wine registering the control classes during DLL
initialization; copying the empty function alone would omit that behavior.
The runtime does not yet provide that initialization and control implementation,
so this source has not been integrated or counted as a fix. A usable Wine port
needs those dependencies and the applicable LGPL distribution requirements.

Ghidra 12.2 headless imported `game2048.exe` and ran its supplied
`FixSwitchStatementsWithDecompiler.java` and `FindUnrecoveredSwitchesScript.java`
scripts. The latter reported one possible bad switch without identifying its
address in headless output. This does not establish that the `q` jump was
recovered or fixed. The host's Homebrew JDK could not load `libhvf.dylib`;
the successful run used a checksum-verified Temurin JDK in a temporary directory.
Radare2 6.2.0's `aaa; agfj @ 0x140002d50` identifies a 55-entry switch at
`0x140002daf` and six distinct code references, including the `q` destination
`0x140002e10`. This is an independent recovery lead, not a fix: the current
recompiler does not yet consume those references.

As a diagnostic only, LIEF 1.0.0 added six synthetic exports for those Radare2
targets to a temporary copy of the game. The original SHA-256 is
`6882192760f4b47c2d79b3739ad9a4cf40bef59c00e383c47160156ca84d81eb`;
the modified copy is `af647ebdda026917180b05677e0757ede4030c64289b8037a3f16a394181445c`.
Before `ac4a69c`, the modified copy's `w` command incorrectly returned to input
without rendering another board. After that commit, `w`, `a`, `s`, `d`, `q`
produced five boards and exited 0. This is a native-run observation on a
modified input, not differential proof or a fix for the original executable.

For scanf support, Wine's LGPL implementation in
[`dlls/msvcrt/scanf.c`](https://github.com/wine-mirror/wine/blob/f343ca6085bfac807c33e9c1a8a43105071f1416/dlls/msvcrt/scanf.c)
and the MIT-licensed [`hisahi/scanf`](https://github.com/hisahi/scanf/tree/9acf085770db2a7319cdb2d7498e855d5edba9ab)
were downloaded for evaluation. `hisahi/scanf` is copied unmodified at
`12953ff` and a guest ABI adapter was added at `5fe2627`. The adapter supports
only `%c` and ` %c` on standard input with the tested non-secure options; other
formats and streams fail explicitly. Wine's implementation is not integrated
and requires its CRT dependencies and LGPL distribution terms. Input replay
between candidate and reference and general scanf support remain open.

A recursive signature inventory found 489 valid PE files, 10 Mach-O/fat files and
8 ELF files among 13,810 files. The PE files have 303 distinct SHA-256 hashes;
152 hashes are associated with images without the PE DLL flag. These are input
counts, including copies and images not necessarily runnable as applications,
not successful recompilations. Executable paths outside `win32` and `win64`
remain to be audited. The project
currently accepts Windows PE input, so the non-PE inputs need separate support
and must not be counted as running on the basis of their presence.

| Fix | Evidence | Commit |
| --- | --- | --- |
| Correct Universal CRT import compatibility counts | `fifteensolver.exe` was reported as 10/58 shimmed even though its runtime reported 50/58; after the fix `imports` reports 50/58. The generated API-set fixture checks both a supported and an unsupported symbol with `ctest -R '^import_compatibility$'`. | `f9ad1c8` |
| Provide the CRT command-line pointer and place runtime data within the PE32 address space | `blackbox.exe` previously stopped at `__p__acmdln`; after the change it reached `IsDBCSLeadByte`. `runtime_command_line` checks both pointer widths and the independent environment block. The application still fails. | `0689e1a` |
| Implement the DBCS lead-byte probe for the runtime's UTF-8 ANSI code page | The runtime test checks ASCII and high-byte inputs on both guest widths. `blackbox.exe` then advances to the unimplemented `comctl32.dll!InitCommonControls`; it still fails and is not counted as an app fixed. | `4e9d7dc` |
| Lift memory-source `pshufd` | A PE fixture failed at this instruction before the fix; afterward `pshufd_mem_ok=1`, native run exited 0, and 1,548 output bytes matched the reference. `plink.exe` advances to `shufps` but remains unsupported. | `374664f` |
| Lift register and memory forms of `shufps` | The PE fixture failed before the fix; afterward both `shufps_reg_ok=1` and `shufps_mem_ok=1`, and 1,582 output bytes matched the reference. `plink.exe` advances to `punpcklwd` and remains unsupported. | `0ffb4de` |
| Lift memory-source packed unpack forms | A PE fixture first failed on `punpcklbw`; after the fix all eight byte/word/dword/qword low/high checks equal 1. Both PE32 and PE32+ runs produced 1,718 bytes matching their references. `plink.exe` advances to `aeskeygenassist` and remains unsupported. | `3c90f4d` |
| Lift packed floating-point unpack forms | A PE fixture failed before the fix; afterward register and memory low/high single/double checks equal 1 on both guest widths, and 1,862 bytes matched the reference. `game2048` progressed to `_time64`. | `ad0a845` |
| Implement CRT `_time64` | `runtime_time` checks null and non-null pointers, 64-bit stores and guest returns on both widths. `game2048` progressed to a divide error. | `bc6e538` |
| Restore the x64 stack after import tail calls | The `tail_import` PE fixture reports `tail_stack_ok=1` and matches 39 reference bytes; `game2048` no longer hits the divide error and reaches missing `puts`. | `0a82d05` |
| Implement CRT `puts` and `putchar` | `runtime_time` checks output and returns on both guest widths. `game2048` now displays a 347-byte initial board and reaches the unimplemented `__stdio_common_vfscanf`; it is not yet verified. | `e4a533f` |
| Port `GetLocalTime` from MIT-licensed igi-recomp | `runtime_time` checks the eight SYSTEMTIME fields on both guest widths. The source revision and MIT license are recorded in `THIRD_PARTY_NOTICES.md`; no app is yet claimed as fixed by this port. | `c9be7d5` |
| Bridge single-character UCRT scanf to the copied MIT scanner | The upstream scanner passes 104 upstream tests; `runtime_time` tests guest input, pushback, and EOF on both pointer widths. `game2048` matches 347 reference bytes on EOF but fails the `q` input due to an unresolved jump. | `12953ff`, `5fe2627` |
| Enter functions at their real entry when backward blocks sort earlier | An x64 PE fixture produced `entry_zero=7` before the port, instead of the reference's `42`; after it both branches match 32 reference bytes. The temporary LIEF/Radare2 experiment above exercises the resulting game input paths. | `ac4a69c` |
| Report the real repair failure | An unimplemented-import fixture previously reported a fabricated divergence at `0x0`; `autorecomp_pipeline` now checks that the missing `user32.dll!MessageBoxA` is reported and the absent divergence is not invented. | `cf3fb74` |
| Port Remill `MOVLHPS`/`MOVHLPS` | PE32 and PE32+ fixtures check normal and self moves and match 54 reference bytes. `win64/blackbox.exe` advances from `movlhps` to `mulps`, reducing unsupported occurrences from 22 to 21; it is not yet running. | `7c86a19` |
| Port Remill `AAS` | A PE32 fixture adapted from Remill's cases failed on `aas` before the port; after it, `remill_aas=1` and all 14 output bytes matched the reference. The 32-bit BusyBox coverage census reaches zero unsupported instructions, but 224 imports remain missing. | `84499a6` |

The observed input SHA-256 values are `7773fa08db2ab5a620a4ef4391a5f0fbd1af73474589128c6d0ef46f1c0b2d6e`
for `win32/blackbox.exe` and `47b443772e36be8a8cf8c45fe80951a466264f370fa28a4851ea57b5c1f17d95`
for `win32/fifteensolver.exe`. For an independent blackbox reproduction, run
`build/recomp-studio autorecomp /path/to/blackbox.exe --output /tmp/blackbox-audit --autorepair --buildrun`
and inspect `/tmp/blackbox-audit/autorecomp.log` for the actual runtime error.

The requested loop sends every generated project to the same `$TMPDIR/`
directory. Each iteration replaces the preceding project's files and
`autorecomp.log`, so individual evidence should also be captured using a
separate output directory per input. A nonzero exit from a console program may
depend on its arguments or input; it must be investigated rather than counted
as a working application.
