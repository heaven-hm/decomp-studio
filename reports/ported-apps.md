# Verified Native Ports

This is the authoritative skip list for compatibility work. An entry is listed
only after `autorecomp --buildrun` completed with native exit code `0` and the
differential verifier reported success. Import coverage or a successful build
alone does **not** qualify.

Do not use these samples as new shim targets unless a regression is suspected.
The detailed corpus history remains in [apps-running-results.md](apps-running-results.md).

| App | Guest | Kind | Corpus path | Evidence |
| --- | --- | --- | --- | --- |
| Prime Generator | x86 | CLI | `windows/cli-apps/1-prime-generator-c/build/prime-gen_x86.exe` | `../apps-running-screenshots/prime_gen_x86.png` |
| Base64 Tool | x86 | CLI | `windows/cli-apps/4-base64-tool-c/build/base64_x86.exe` | `../apps-running-screenshots/base64_x86.png` |
| Base64 Tool | x64 | CLI | `windows/cli-apps/4-base64-tool-c/build/base64_x64.exe` | `../apps-running-screenshots/base64_x64.png` |
| Hangman | x86 | CLI game | `windows/cli-games/2-hangman-c/build/hangman_x86.exe` | `../apps-running-screenshots/hangman_x86_terminal.png` |
| Hangman | x64 | CLI game | `windows/cli-games/2-hangman-c/build/hangman_x64.exe` | `../apps-running-screenshots/hangman_x64_terminal.png` |
| Arithmetic Calculator | x86 | CLI | `windows/x86/apps/arith-calc.exe` | `../apps-running-screenshots/arith_calc_x86.png` |
| Arithmetic Calculator | x64 | CLI | `windows/x64/apps/arith-calc.exe` | `../apps-running-screenshots/arith_calc_x64.png` |
| Base64 Tool | x86 | CLI | `windows/x86/apps/base64.exe` | `../apps-running-screenshots/base64_x86.png` |
| Base64 Tool | x64 | CLI | `windows/x64/apps/base64.exe` | `../apps-running-screenshots/base64_x64.png` |
| Prime Generator | x86 | CLI | `windows/x86/apps/prime-gen.exe` | `../apps-running-screenshots/prime_gen_x86.png` |
| 2048 | x86 | CLI game | `windows/x86/games/game2048.exe` | `../apps-running-screenshots/game2048_x86.png` |
| 2048 | x64 | CLI game | `windows/x64/games/game2048.exe` | `../apps-running-screenshots/game2048_x64.png` |
| Filling Solver | x86 | puzzle solver | `windows/x86/games/fillingsolver.exe` | pipeline log only |
| Hangman | x86 | CLI game | `windows/x86/games/hangman_x86.exe` | `../apps-running-screenshots/hangman_x86_terminal.png` |
| Hangman | x64 | CLI game | `windows/x64/games/hangman_x64.exe` | `../apps-running-screenshots/hangman_x64_terminal.png` |
| Snake | x86 | CLI game | `windows/x86/games/snake.exe` | `../apps-running-screenshots/snake_x86.png` |
| Snake | x64 | CLI game | `windows/x64/games/snake.exe` | `../apps-running-screenshots/snake_x64.png` |
| Tetris | x86 | CLI game | `windows/x86/games/tetris.exe` | `../apps-running-screenshots/tetris_x86_terminal.png` |
| Tetris | x64 | CLI game | `windows/x64/games/tetris.exe` | `../apps-running-screenshots/tetris_x64.png` |
| Tic-Tac-Toe | x86 | CLI game | `windows/x86/games/tictactoe.exe` | `../apps-running-screenshots/tictactoe_x86_terminal.png` |
| Tic-Tac-Toe | x64 | CLI game | `windows/x64/games/tictactoe.exe` | `../apps-running-screenshots/tictactoe_x64.png` |

## Current candidates, not yet ports

| Group | Current state | Work selection rule |
| --- | --- | --- |
| x86 Win32 puzzle GUIs (including `win32/cube.exe`) | Import-complete after the shared GDI/user32 shims; native GUI behavior has not yet passed differential verification. | Test behavior and message/GDI state; do not claim a port from import coverage. |
| x64 puzzle GUIs (including `win64/cube.exe`) | Import-complete after MSVC exception/CRT coverage; native GUI behavior remains unverified. | Test one representative end-to-end, then fix shared behavior. |
| IGI retail/runtime variants | Need DirectDraw, DirectSound, DirectInput, WinMM/MCI, AVI and COM behavior. | Work by subsystem, beginning with the smallest reachable runtime blocker. |
| Mono/.NET applications | Rejected as managed IL, not native PE machine code. | Requires a CLR/IL frontend; do not add Win32 shims as a substitute. |
| Windows ARM64 PE | Unsupported guest decoder. | Requires an ARM64 instruction-lifting frontend. |
