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

| application | source arch | source OS | language | target host | output | screenshot |
|---|---|---|---|---|---|---|
| `arith-calc.exe` | x86 | windows | C | macos (macos-arm64) | 161 bytes | [view](screenshots/arith-calc-x86.png) |
| `tetris.exe` | x86 | windows | C | macos (macos-arm64) | 220 bytes | [view](screenshots/tetris-x86.png) |
| `base64_x64.exe` | x86_64 | windows | C | macos (macos-arm64) | 218 bytes | [view](screenshots/base64_x64-x86_64.png) |
| `base64_x86.exe` | x86 | windows | C | macos (macos-arm64) | 204 bytes | [view](screenshots/base64_x86-x86.png) |
| `hangman_x64.exe` | x86_64 | windows | C | macos (macos-arm64) | 347 bytes | [view](screenshots/hangman_x64-x86_64.png) |
| `hangman_x86.exe` | x86 | windows | C | macos (macos-arm64) | 178 bytes | [view](screenshots/hangman_x86-x86.png) |

## Refused, with the reason each one gave

Recorded so the list above cannot be mistaken for the whole story. Every entry
here is an application that did **not** reach a verified native port.

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
| `zoomit64.exe` | x86_64 | C | error: unsupported instruction 'lfence' at 0x1400049efull |
| `pageant.exe` | x86_64 | C | error: unsupported instruction 'sha1rnds4' at 0x14002d5f2ull |
| `psftp.exe` | x86_64 | C | error: unsupported instruction 'sha256rnds2' at 0x1400695e5ull |
| `imgview64.exe` | x86_64 | C | error: input appears to be packed (UPX section 'UPX0'); its machine code is not present in the file, so functions cannot |
| `blackbox.exe` | x86 | C | exited with code 3 |
| `pearl.exe` | x86 | C | exited with code 3 |
| `mapsolver.exe` | x86 | C | exited with code 1 |
| `untangle.exe` | x86 | C | exited with code 3 |
| `tents.exe` | x86 | C | exited with code 3 |
| `palisade.exe` | x86_64 | C | error: unsupported instruction 'pinsrw' at 0x140006fe6ull |
| `slant.exe` | x86_64 | C | error: unsupported instruction 'sqrtss' at 0x140006ad3ull |
| `keen.exe` | x86_64 | C | error: unsupported instruction 'cvttps2dq' at 0x140004517ull |
| `samegame.exe` | x86_64 | C | error: unsupported instruction 'sqrtss' at 0x140004f16ull |
| `guess.exe` | x86_64 | C | error: unsupported instruction 'addpd' at 0x140002c34ull |
| `unruly.exe` | x86_64 | C | error: unsupported instruction 'sqrtss' at 0x140006d2cull |
| `singles.exe` | x86 | C | exited with code 3 |
| `tents.exe` | x86 | C | exited with code 3 |
| `guess.exe` | x86 | C | exited with code 3 |
| `mosaic.exe` | x86 | C | exited with code 3 |
| `unrulysolver.exe` | x86 | C | exited with code 3 |
| `galaxiessolver.exe` | x86 | C | exited with code 3 |
| `magnets.exe` | x86_64 | C | error: unsupported instruction 'sqrtss' at 0x140007263ull |
| `cube.exe` | x86_64 | C | error: unsupported instruction 'mulps' at 0x140002ee6ull |
| `loopy.exe` | x86_64 | C | error: unsupported instruction 'sqrtsd' at 0x1400041e5ull |
| `legacy-notepad-x64.exe` | x86_64 | C | error: unsupported instruction 'roundsd' at 0x1400268e0ull |
| `singles.exe` | x86_64 | C | error: unsupported instruction 'sqrtss' at 0x140005ae3ull |
| `procexp64.exe` | x86_64 | C | error: unsupported instruction 'lfence' at 0x140001e40ull |
| `prime-gen_x86.exe` | x86 | C | did not finish within 120s |
| `passgen_x64.exe` | x86_64 | C++ | exited with code 3 |
| `guess_game_x64.exe` | x86_64 | C | did not finish within 120s |
| `guess_game_x86.exe` | x86 | C | did not finish within 120s |
| `tictactoe_x64.exe` | x86_64 | C++ | exited with code 3 |
| `tictactoe_x86.exe` | x86 | C++ | exited with code 3 |
| `mastermind_x64.exe` | x86_64 | C++ | exited with code 3 |
| `mastermind_x86.exe` | x86 | C++ | exited with code 3 |
