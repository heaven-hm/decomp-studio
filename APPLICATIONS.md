# Applications

Applications this studio has actually ported: translated from a Windows PE
binary, built as a native host executable, run, and **differentially verified**
against a Unicorn reference executing the original instructions.

A row appears here only when all of that happened. An application that
translates but does not run, or runs but does not verify, is not a port and is
not listed -- see the refused list at the end of this file for those, with the
reason each one gave.

**What VERIFIED does and does not mean.** The reference and the candidate call the SAME shim
table, so a shim that is wrong in the same way on both sides agrees with itself. Verification
therefore bounds the TRANSLATION -- that the machine code was lifted faithfully -- and not
the Windows API semantics. A program can be VERIFIED and still behave differently from a real
Windows machine.

**Output is LF-normalized.** The recorder collapses CRLF, so a recorded byte count is not the
raw byte count: `arith-calc` emits 172 raw bytes and is recorded as 161.

**Not every port is deterministic.** `hangman_x64` picks a random word, so its output length
varies between runs (observed 345, 347, 349, 353, 357) -- 347 is one sample, not a constant.
And 2 of 36 verification runs of the same byte-identical `hangman` binaries DIVERGED
(`state_match` false) with identical output, so rows 5 and 6 are reproducible MOST of the
time, not always. The other four apps diverged 0 times in 24 runs.

The screenshot is the ported program's own output, rendered as an image. For a
console application that is the whole observable result, so the image is the
evidence rather than a decoration.

Host: `macos (macos-arm64)`

## Ported -- do NOT rework these

Every row below has been translated, built, run AND differentially verified against the
Unicorn reference. Re-running one is a regression check, not work. The list is deduplicated
by (application, source architecture): the same name appears twice only when two different
binaries of that name were ported, and the architecture column is what distinguishes them.

| # | application | source arch | source OS | language | target host | output | screenshot |
|---|---|---|---|---|---|---|---|
| 1 | `arith-calc.exe` | x86 | windows | C | macos (macos-arm64) | 161 bytes | [view](screenshots/arith-calc-x86.png) |
| 2 | `tetris.exe` | x86 | windows | C | macos (macos-arm64) | 220 bytes | [view](screenshots/tetris-x86.png) |
| 3 | `base64_x64.exe` | x86_64 | windows | C | macos (macos-arm64) | 218 bytes | [view](screenshots/base64_x64-x86_64.png) |
| 4 | `base64_x86.exe` | x86 | windows | C | macos (macos-arm64) | 204 bytes | [view](screenshots/base64_x86-x86.png) |
| 5 | `hangman_x64.exe` | x86_64 | windows | C | macos (macos-arm64) | 347 bytes (VARIABLE, see below) | [view](screenshots/hangman_x64-x86_64.png) |
| 6 | `hangman_x86.exe` | x86 | windows | C | macos (macos-arm64) | 178 bytes | [view](screenshots/hangman_x86-x86.png) |

| 7 | `g64_game2048.exe` | x86_64 | windows | C | macos (macos-arm64) | 353 bytes | not yet captured |

| 8 | `fillingsolver.exe` | x86 | windows | C | macos (macos-arm64) | see note | not yet captured |
| 9 | `game2048.exe` | x86 | windows | C | macos (macos-arm64) | see note | not yet captured |
| 10 | `snake.exe` | x86 | windows | C | macos (macos-arm64) | see note | not yet captured |
| 11 | `tictactoe.exe` | x86 | windows | C | macos (macos-arm64) | see note | not yet captured |

**Count: 11 ported binaries, from 9 distinct programs** (arith-calc, tetris, base64, hangman,
g64_game2048, fillingsolver, game2048, snake, tictactoe).

Rows 8-11 come from the x86 corpus sweep, each with `AUTORECOMP COMPLETE` in its own log.
They are listed without byte counts because the sweep recorded the verdict rather than the
output size, and a number nobody measured is worse than no number.

**A NOTE ON THE FIRST PASS OF THAT SWEEP, which is why it is worth re-running rather than
trusting:** it found only FIVE passes. `fillingsolver`, `hangman_x86` and `snake` had been
killed by memory pressure (load average peaked at 73) and passed only on a clean sequential
re-run. Believing the first pass would have understated the corpus by three ports, and the
same pressure produced 13 spurious SIGKILL/SIGTERM results that all produced real verdicts
when re-run.

Row 7 is the first port from OUTSIDE the shipped corpus: it comes from the
`cricket07-browser` project's own Windows builds. It is listed with `AUTORECOMP COMPLETE`,
exit code 0, 353 bytes of output, 2 of 2 guest-state checkpoints matched, and its output
matching the reference byte for byte -- but with **no screenshot yet**, because the
screenshot is rendered from a run rather than asserted. A row with a known gap is worth more
than a row that quietly claims one it does not have.

Two more were measured as reaching `AUTORECOMP COMPLETE` in the corpus sweep and are
deliberately NOT listed here. The earlier version of this note attributed a `base64` to
`windows/x64/apps/`; **no base64 binary exists there**. The x86_64 base64 build is
`windows/cli-apps/4-base64-tool-c/build/base64_x64.exe`, which is already row 3. The
`arith-calc` half was correct and reproduces. Listing either again under a second corpus path
would inflate the count without adding a port.

## Refused -- correct refusals, not defects

**Coverage: this table lists 45 of the 157 executables in scope (6 ported + 45 refused = 51).
The remaining 106 are unmeasured, and unmeasured is not the same as refused.**

**These reasons are a SNAPSHOT and are now partly STALE.** A re-audit found that 15 of the 21
instruction-based refusals no longer reproduce: 11 of them (`palisade`, `slant`, `keen`,
`samegame`, `guess`, `unruly`, `magnets`, `cube`, `loopy`, `legacy-notepad-x64`, `singles`)
now lift with ZERO unsupported instructions and fail later on a missing import, and 4
(`clipjar`, `procexp64`, `putty`, `zoomit64`) fail on a different, smaller set. The refusal
may still be correct; the REASON is out of date, and a reader would take it as current.
Re-run before trusting any row.

These are NOT failures to fix. Each one is the studio declining an input it cannot
honestly port, with the reason it gave. **The reasons are DATED**: a re-audit found
that 15 of the 21 instruction-based refusals no longer reproduce, because the
instructions they name have since been implemented. See the note below the table.

| application | source arch | language | reason |
|---|---|---|---|
| `micro.exe` | arm64 | C | input is a Windows PE image for arm64; this build reads Windows PE32 (x86) and PE32+ (x86-64) input only |
| `TicTacToe.exe` | x86 | .NET / C# | managed .NET image; its code is IL bytecode, so there is nothing for a machine-code lifter to lift |
| `luhn.exe` | x86 | .NET / C# | managed .NET image; its code is IL bytecode, so there is nothing for a machine-code lifter to lift |
| `psftp.exe` | x86 | C | error: unsupported instruction 'str' at 0x45004aull |
| `putty.exe` | x86 | C | error: unsupported instruction 'sldt' at 0x48c3f0ull |
| `busybox.exe` | x86 | C | exited with code 3 |
| `pageant.exe` | x86 | C | error: unsupported instruction 'sha1rnds4' at 0x42ad2dull |
| `micro.exe` | x86 | C | error: unsupported instruction 'aesenc' at 0x4788fcull |
| `clipjar.exe` | x86_64 | C | error: unsupported instruction 'cmpeqss' at 0x14004884bull |
| `putty.exe` | x86_64 | C | error: unsupported instruction 'cvtps2pd' at 0x14000c893ull |
| `zoomit64.exe` | x86_64 | C | error: unsupported instruction 'cvtps2pd' at 0x14000879dull |
| `pageant.exe` | x86_64 | C | error: unsupported instruction 'sha1rnds4' at 0x14002d5f2ull |
| `psftp.exe` | x86_64 | C | error: unsupported instruction 'sha256rnds2' at 0x1400695e5ull |
| `imgview64.exe` | x86_64 | C | error: input appears to be packed (UPX section 'UPX0'); its machine code is not present in the file, so functions cannot |
| `blackbox.exe` | x86 | C | exited with code 3 |
| `pearl.exe` | x86 | C | exited with code 3 |
| `mapsolver.exe` | x86 | C | exited with code 1 |
| `untangle.exe` | x86 | C | exited with code 3 |
| `tents.exe` | x86 | C | exited with code 3 |
| `palisade.exe` | x86_64 | C | error: unsupported instruction 'pinsrw' at 0x140006fe6ull |
| `slant.exe` | x86_64 | C | error: unsupported instruction 'mulps' at 0x140008d91ull |
| `keen.exe` | x86_64 | C | error: unsupported instruction 'cvttps2dq' at 0x140004517ull |
| `samegame.exe` | x86_64 | C | error: unsupported instruction 'mulps' at 0x140005fa1ull |
| `guess.exe` | x86_64 | C | error: unsupported instruction 'addpd' at 0x140002c34ull |
| `unruly.exe` | x86_64 | C | error: unsupported instruction 'mulps' at 0x140007fe1ull |
| `singles.exe` | x86 | C | exited with code 3 |
| `guess.exe` | x86 | C | exited with code 3 |
| `mosaic.exe` | x86 | C | exited with code 3 |
| `unrulysolver.exe` | x86 | C | exited with code 3 |
| `galaxiessolver.exe` | x86 | C | exited with code 3 |
| `magnets.exe` | x86_64 | C | error: unsupported instruction 'mulps' at 0x140008b71ull |
| `cube.exe` | x86_64 | C | error: unsupported instruction 'mulps' at 0x140002ee6ull |
| `loopy.exe` | x86_64 | C | error: unsupported instruction 'maxss' at 0x140007a8dull |
| `legacy-notepad-x64.exe` | x86_64 | C | error: unsupported instruction 'roundsd' at 0x1400268e0ull |
| `singles.exe` | x86_64 | C | error: unsupported instruction 'mulps' at 0x1400079e1ull |
| `procexp64.exe` | x86_64 | C | error: unsupported instruction 'maxsd' at 0x14006400aull |
| `prime-gen_x86.exe` | x86 | C | did not finish within 120s |
| `passgen_x64.exe` | x86_64 | C++ | exited with code 3 |
| `guess_game_x64.exe` | x86_64 | C | did not finish within 120s |
| `guess_game_x86.exe` | x86 | C | did not finish within 120s |
| `tictactoe_x64.exe` | x86_64 | C++ | exited with code 3 |
| `tictactoe_x86.exe` | x86 | C++ | exited with code 3 |
| `mastermind_x64.exe` | x86_64 | C++ | exited with code 3 |
| `mastermind_x86.exe` | x86 | C++ | exited with code 3 |
