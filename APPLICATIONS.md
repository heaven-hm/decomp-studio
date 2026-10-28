# Applications

Applications this studio has actually ported: translated from a Windows PE
binary, built as a native host executable, run, and **differentially verified**
against a Unicorn reference executing the original instructions.

A row appears here only when all of that happened. An application that
translates but does not run, or runs but does not verify, is not a port and is
not listed -- see the refused list at the end of this file for those, with the
reason each one gave.

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
| 5 | `hangman_x64.exe` | x86_64 | windows | C | macos (macos-arm64) | 347 bytes | [view](screenshots/hangman_x64-x86_64.png) |
| 6 | `hangman_x86.exe` | x86 | windows | C | macos (macos-arm64) | 178 bytes | [view](screenshots/hangman_x86-x86.png) |

**Count: 6 ported binaries, from 4 distinct programs** (arith-calc, tetris, base64, hangman).

Two more were measured as reaching `AUTORECOMP COMPLETE` in the corpus sweep and are
deliberately NOT listed here: `arith-calc` and `base64` from `windows/x64/apps/`, which are
the same two programs as rows 1, 3 and 4 above built from the same sources. Listing them
again under their corpus path would inflate the count without adding a port.

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
| `tents.exe` | x86 | C | exited with code 3 |
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
