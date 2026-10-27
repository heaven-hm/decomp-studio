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
| plink | `win64/plink.exe` | Not reached | Not reached | Not reached | Before `374664f`, translation stopped on memory-source `pshufd`; after `0ffb4de`, it stops on `punpcklwd` |

**Applications newly verified by this work: 0.** The audit and fixes are still
in progress. The other corpus locations have not yet been fully run and cannot
be counted as passing.

| Corpus slice | Commands completed | Exit 0 | Exit nonzero | Notes |
| --- | ---: | ---: | ---: | --- |
| `win64/*.exe` | 52 | 0 | 52 | Sweep used per-app output directories; builds changed during the run, so this is a mixed-revision observation, not a single-version benchmark. |

A recursive signature inventory found 489 MZ files, 10 Mach-O/fat files and
8 ELF files among 13,810 files. These are file counts, including copies and
libraries, not unique applications or successful recompilations. The project
currently accepts Windows PE input, so the non-PE inputs need separate support
and must not be counted as running on the basis of their presence.

| Fix | Evidence | Commit |
| --- | --- | --- |
| Correct Universal CRT import compatibility counts | `fifteensolver.exe` was reported as 10/58 shimmed even though its runtime reported 50/58; after the fix `imports` reports 50/58. The generated API-set fixture checks both a supported and an unsupported symbol with `ctest -R '^import_compatibility$'`. | `f9ad1c8` |
| Provide the CRT command-line pointer and place runtime data within the PE32 address space | `blackbox.exe` previously stopped at `__p__acmdln`; after the change it reached `IsDBCSLeadByte`. `runtime_command_line` checks both pointer widths and the independent environment block. The application still fails. | `0689e1a` |
| Implement the DBCS lead-byte probe for the runtime's UTF-8 ANSI code page | The runtime test checks ASCII and high-byte inputs on both guest widths. `blackbox.exe` then advances to the unimplemented `comctl32.dll!InitCommonControls`; it still fails and is not counted as an app fixed. | `4e9d7dc` |
| Lift memory-source `pshufd` | A PE fixture failed at this instruction before the fix; afterward `pshufd_mem_ok=1`, native run exited 0, and 1,548 output bytes matched the reference. `plink.exe` advances to `shufps` but remains unsupported. | `374664f` |
| Lift register and memory forms of `shufps` | The PE fixture failed before the fix; afterward both `shufps_reg_ok=1` and `shufps_mem_ok=1`, and 1,582 output bytes matched the reference. `plink.exe` advances to `punpcklwd` and remains unsupported. | `0ffb4de` |

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
