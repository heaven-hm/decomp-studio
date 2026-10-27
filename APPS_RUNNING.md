# Application corpus: work in progress

This is an evidence ledger for the `recomp-apps` corpus on macOS ARM64. A
successful build or instruction-coverage result alone does not establish that
an application runs. “Verified” below means the native run and differential
verification both succeeded. Counts are observations from the indicated run,
not a claim about every copy of a binary in the corpus.

| Application | Input | Build | Native run | Differential verification | Evidence |
| --- | --- | --- | --- | --- | --- |
| blackbox | `win32/blackbox.exe` | Passed | Exit 3 | Failed | Baseline `c14ef07`; at `4e9d7dc` it reaches missing `InitCommonControls` |
| fifteensolver | `win32/fifteensolver.exe` | Passed | Exit 1, no stdout | Failed; reference completed, candidate did not | `autorecomp` with `--autorepair --buildrun`, baseline at `c14ef07` |
| plink | `win64/plink.exe` | Not reached | Not reached | Not reached | Before `374664f`, translation stopped on memory-source `pshufd`; after `3c90f4d`, it stops on `aeskeygenassist` |
| game2048 | `windows/x64/games/game2048.exe` | Passed | Exit 3 after 347 bytes | Failed | After `e4a533f`, displays a board and reaches missing `__stdio_common_vfscanf`; previously stopped at `unpcklpd`, `_time64`, a divide error, then `puts` |
| arith-calc | `windows/x64/apps/arith-calc.exe` | Passed | Exit 0; 172 bytes | Passed | Corpus audit; SHA-256 `bb67ed0c581a1a00cfce9fd324c4003a970d4869829bb472e5f91b4ee476be3c` |
| arith-calc | `windows/x86/apps/arith-calc.exe` | Passed | Exit 0; 172 bytes | Passed | Corpus audit; SHA-256 `9b59ee613acc7b5a1512f8a5fcc5f65317f0fa79452d01728e1715b63f23d7a6` |

**Applications newly verified by this work: 0.** The audit and fixes are still
in progress. The two arith-calc executables above were observed to verify; no
before-and-after evidence establishes that these fixes made them work. The other
corpus locations have not yet been fully run and cannot be counted as passing.

| Corpus slice | Commands completed | Exit 0 | Exit nonzero | Notes |
| --- | ---: | ---: | ---: | --- |
| `win64/*.exe` | 52 | 0 | 52 | Sweep used per-app output directories; builds changed during the run, so this is a mixed-revision observation, not a single-version benchmark. |

The feature branch's architecture-neutral IR updates were merged at `53f773e`;
observations made before that merge need to be rerun on the integrated revision.

A recursive signature inventory found 489 valid PE files, 10 Mach-O/fat files and
8 ELF files among 13,810 files. The PE files have 303 distinct SHA-256 hashes;
152 hashes are associated with images without the PE DLL flag. These are input
counts, including copies and images not necessarily runnable as applications,
not successful recompilations. A run of executable paths outside `win32` and
`win64` is in progress. The project
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
