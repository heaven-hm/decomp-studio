# Application corpus: work in progress

This is an evidence ledger for the `recomp-apps` corpus on macOS ARM64. A
successful build or instruction-coverage result alone does not establish that
an application runs. “Verified” below means the native run and differential
verification both succeeded. Counts are observations from the indicated run,
not a claim about every copy of a binary in the corpus.

| Application | Input | Build | Native run | Differential verification | Evidence |
| --- | --- | --- | --- | --- | --- |
| blackbox | `win32/blackbox.exe` | Passed | Exit 3 | Failed | Requested loop, feature-branch baseline at `c14ef07` |
| fifteensolver | `win32/fifteensolver.exe` | Passed | Exit 1, no stdout | Failed; reference completed, candidate did not | `autorecomp` with `--autorepair --buildrun`, baseline at `c14ef07` |

**Applications newly verified by this work: 0.** The audit and fixes are still
in progress. In particular, the win64 directory and other corpus locations have
not yet been fully run and cannot be counted as passing.

| Fix | Evidence | Commit |
| --- | --- | --- |
| Correct Universal CRT import compatibility counts | `fifteensolver.exe` was reported as 10/58 shimmed even though its runtime reported 50/58; after the fix `imports` reports 50/58. The generated API-set fixture checks both a supported and an unsupported symbol with `ctest -R '^import_compatibility$'`. | `f9ad1c8` |

The requested loop sends every generated project to the same `$TMPDIR/`
directory. Each iteration replaces the preceding project's files and
`autorecomp.log`, so individual evidence should also be captured using a
separate output directory per input. A nonzero exit from a console program may
depend on its arguments or input; it must be investigated rather than counted
as a working application.
