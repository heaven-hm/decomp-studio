# Recompilation corpus run matrix

- Date: 2026-10-28
- Worktree/branch: `.worktrees/apps-audit` / `feature/apps-running-audit`
- Host tested: macOS arm64, Darwin 24.3.0
- Target generated: `macos-arm64`
- Binary corpus: `/Users/haseeb-mir/Downloads/recomp-apps`
- The corpus contains 302 Windows PE `.exe` files (171 x86, 130 x86-64, 1 ARM64). All are covered by this matrix: 166 canonical files under `windows/` were run directly, seven distinct external payloads were run directly, and the remaining 129 external paths are byte-identical aliases of a canonical input (SHA-256 compared), so inherit that input's recorded outcome.
- Windows run command: `build/recomp-studio autorecomp <EXE> --output "$TMPDIR/<name>" --buildrun --timeout 5`, with stdin file containing `3`.
- Windows folder inventory: 166 EXEs, all attempted. The first 151 logs are in `$TMPDIR/<basename>/batch-autorecomp.log` and `autorecomp.log` (duplicate basenames overwrite); the final 15 use distinct directories under `$TMPDIR/recomp-final-x86/`. The seven additional direct runs use distinct directories under `$TMPDIR/recomp-full-corpus/`.
- 21 runs reported full autorecomp completion, 137 failed, 7 ended before a pipeline summary, and 1 (`tetris-classic.exe`) was interrupted after it emitted 3.2 MB during verification. Six failed runs hit the guest timeout. “Complete” means the tool's build/run/differential pipeline returned success; it does not guarantee meaningful behavior for every input. `fillingsolver.exe` is a no-output smoke case and is not counted as a useful app result.
- The input is machine code, so a C/C++/Rust label describes how a sample was authored only when known; the PE itself does not reliably retain its source language. The pipeline translates supported native x86/x64 instructions to generated C++ and links a native macOS arm64 executable.

## Audit dashboard

This page separates the executive result from the complete evidence ledger. The
full 166-row matrix is preserved below so no attempted application disappears,
while this dashboard makes the current state readable at a glance.

| Measure | Result |
| --- | ---: |
| Canonical Windows PE inputs attempted | **166** |
| Complete native build/run/differential passes | **21** |
| Pass rate across attempted canonical inputs | **12.7%** |
| x86 passes | **12** |
| x86-64 passes | **9** |
| Windows ARM64 inputs | **1** (rejected: guest decoder absent) |
| Captured successful-run screenshots | **20** |
| External unique payloads attempted | **7** |

“Pass” means the generated macOS arm64 program built, ran to completion, and
matched the differential reference for the recorded input. It does not mean
that every possible interaction path or GUI surface is implemented.

### What is working

- Native PE32 (x86) and PE32+ (x86-64) console samples can reach a verified
  native macOS arm64 executable.
- The verified set includes arithmetic, Base64, Hangman, 2048, Snake, Tetris,
  Tic-Tac-Toe, and a prime generator. The screenshot gallery below links only
  to captures that exist in this repository.
- The reference/native differential checker is part of the pass criterion; a
  successful build without a matching reference is not counted as a pass.

### Why the remaining inputs fail

| Root cause | Typical evidence | Scope |
| --- | --- | --- |
| Missing Win32/CRT imports | `110–125` missing imports in the legacy puzzle GUI group | Runtime surface, not instruction lifting |
| Unsupported x86/x64 instructions | `pinsrw`, `bnd jae`, `cmpltss`, and scalar/vector conversions | Lifter coverage |
| Managed binaries | C#/.NET IL examples rejected before native lifting | CLR frontend/runtime integration absent |
| Guest lifecycle differences | unresolved `atexit` handlers, timeouts, or differential mismatch | Runtime semantics and test input |
| Unsupported guest format | Windows ARM64 PE, ELF, Mach-O, and JVM probes rejected | Frontend scope |

### Verified screenshot gallery

These are repository-local captures of completed native runs. The complete row
for each result, including its log path, is in the appendix.

| x86 | x86-64 |
| --- | --- |
| ![Prime generator](../apps-running-screenshots/prime_gen_x86.png) | ![Arithmetic calculator](../apps-running-screenshots/arith_calc_x64.png) |
| ![Base64 tool](../apps-running-screenshots/base64_x86.png) | ![Base64 tool](../apps-running-screenshots/base64_x64.png) |
| ![Hangman](../apps-running-screenshots/hangman_x86_terminal.png) | ![Hangman](../apps-running-screenshots/hangman_x64_terminal.png) |
| ![Snake](../apps-running-screenshots/snake_x86.png) | ![Snake](../apps-running-screenshots/snake_x64.png) |
| ![Tetris](../apps-running-screenshots/tetris_x86_terminal.png) | ![Tetris](../apps-running-screenshots/tetris_x64.png) |
| ![Tic-Tac-Toe](../apps-running-screenshots/tictactoe_x86_terminal.png) | ![Tic-Tac-Toe](../apps-running-screenshots/tictactoe_x64.png) |

The pass table contains one additional no-output smoke pass,
`fillingsolver.exe`; it intentionally has no screenshot because there was no
visible application output to capture.

### Navigation

- [WORKING (PASS) applications & games](#working-pass)
- [Format, architecture, and language/runtime matrix](#format-architecture-and-language-runtime-matrix)
- [Post-runtime retests](#post-runtime-update-retests)
- [Complete 166-input appendix](#complete-appendix-windows-pe-files-tested)
- [External unique payloads](#external-unique-windows-pe-payloads)
- [Validation and known limitations](#project-validation)

## WORKING (PASS)

The following 21 Windows applications and games achieved 100% instruction lifting, built into native macOS ARM64 binaries without external emulation, ran successfully to completion (exit code 0), and passed differential reference verification byte-for-byte.

| # | Application / Game | Guest Architecture | Category | Input Binary | Lift Coverage | Missing Imports | Pipeline & Verification Result | Evidence |
| ---: | --- | --- | --- | --- | ---: | ---: | --- | --- |
| 1 | Prime Generator | x86 (PE32) | CLI App | `windows/cli-apps/1-prime-generator-c/build/prime-gen_x86.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/prime_gen_x86.png) |
| 2 | Base64 Tool | x86-64 (PE32+) | CLI App | `windows/cli-apps/4-base64-tool-c/build/base64_x64.exe` | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/base64_x64.png) |
| 3 | Base64 Tool | x86 (PE32) | CLI App | `windows/cli-apps/4-base64-tool-c/build/base64_x86.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/base64_x86.png) |
| 4 | Hangman | x86-64 (PE32+) | CLI Game | `windows/cli-games/2-hangman-c/build/hangman_x64.exe` | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/hangman_x64_terminal.png) |
| 5 | Hangman | x86 (PE32) | CLI Game | `windows/cli-games/2-hangman-c/build/hangman_x86.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/hangman_x86_terminal.png) |
| 6 | Arithmetic Calculator | x86-64 (PE32+) | Console App | `windows/x64/apps/arith-calc.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/arith_calc_x64.png) |
| 7 | Base64 Tool | x86-64 (PE32+) | Console App | `windows/x64/apps/base64.exe` | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/base64_x64.png) |
| 8 | 2048 Game | x86-64 (PE32+) | Console Game | `windows/x64/games/game2048.exe` | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/game2048_x64.png) |
| 9 | Hangman | x86-64 (PE32+) | Console Game | `windows/x64/games/hangman_x64.exe` | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/hangman_x64_terminal.png) |
| 10 | Snake | x86-64 (PE32+) | Console Game | `windows/x64/games/snake.exe` | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/snake_x64.png) |
| 11 | Tetris | x86-64 (PE32+) | Console Game | `windows/x64/games/tetris.exe` | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/tetris_x64.png) |
| 12 | Tic-Tac-Toe | x86-64 (PE32+) | Console Game | `windows/x64/games/tictactoe.exe` | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/tictactoe_x64.png) |
| 13 | Arithmetic Calculator | x86 (PE32) | Console App | `windows/x86/apps/arith-calc.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/arith_calc_x86.png) |
| 14 | Base64 Tool | x86 (PE32) | Console App | `windows/x86/apps/base64.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/base64_x86.png) |
| 15 | Prime Generator | x86 (PE32) | Console App | `windows/x86/apps/prime-gen.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/prime_gen_x86.png) |
| 16 | Filling Solver | x86 (PE32) | Puzzle Solver | `windows/x86/games/fillingsolver.exe` | 100% | 3 | PASS (exit 0; differential yes) | log: `$TMPDIR/fillingsolver/batch-autorecomp.log` |
| 17 | 2048 Game | x86 (PE32) | Console Game | `windows/x86/games/game2048.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/game2048_x86.png) |
| 18 | Hangman | x86 (PE32) | Console Game | `windows/x86/games/hangman_x86.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/hangman_x86_terminal.png) |
| 19 | Snake | x86 (PE32) | Console Game | `windows/x86/games/snake.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/snake_x86.png) |
| 20 | Tetris | x86 (PE32) | Console Game | `windows/x86/games/tetris.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/tetris_x86_terminal.png) |
| 21 | Tic-Tac-Toe | x86 (PE32) | Console Game | `windows/x86/games/tictactoe.exe` | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/tictactoe_x86_terminal.png) |

## Format, architecture, and language/runtime matrix

| Input / runtime | Tested result on this host | What it means |
| --- | --- | --- |
| Windows PE x86 | 100% lift and native build/run/differential success for several console C/C++ samples; many GUI/CRT-heavy samples fail on missing imports. | The x86 path works for a subset, not every application. |
| Windows PE x86-64 | 100% lift and successful native build/run/differential checks for several console C/C++ samples; larger apps fail on missing imports or unsupported instructions. | The x64 path works for a subset, not every application. |
| Windows PE ARM64 | Rejected during inspection (`windows/arm64/apps/micro.exe`). | ARM64 guest decoding is not implemented in this build. |
| macOS Mach-O x86-64 | Recognized, rejected: only Windows PE32/PE32+ lifting is implemented. | No Mach-O source frontend. |
| macOS Mach-O arm64 | Present in the corpus; used as the native host architecture. | These are host binaries, not recompiled Windows guests. |
| Linux ELF x86, x86-64, ARM32, ARM64 | ELF format recognized; x86-64 `micro` probe rejected because only Windows PE lifting is implemented. | No ELF source frontend. |
| C / C++ | Native Windows console executables tested. Several passed; the C++ password generator failed on 45 missing imports. | Source language is not interpreted; runtime imports and guest ISA determine support. |
| Rust | Two Rust source projects have macOS arm64 native builds; unit converter and blackjack both ran successfully with scripted input. The external Rust/MSVC distributions `bat.exe`, `fd.exe`, and `rg.exe` were also attempted as Windows x64 guests; all stop first at `pinsrw`, with 63–175 imports still unshimmed. | Native Rust builds work on the host; the Windows Rust payloads confirm that the current native PE frontend still needs additional x64/SSE lifting and Win32/CRT coverage. Evidence: `$TMPDIR/recomp-runtime-matrix/rust-host.log` and `$TMPDIR/recomp-full-corpus/`. |
| C# / .NET | Three managed .NET PE examples were detected and rejected before lifting: `TicTacToe.exe`, `luhn.exe`, and `tictactoe-net.exe`. | They contain IL bytecode; an IL/CLR frontend is not implemented. The installed .NET host runtime is not integrated into autorecomp. |
| Java / JVM | No `.java`, `.jar`, or `.class` input was present in the supplied corpus. I compiled and ran a minimal Java 23 host-runtime probe successfully. `inspect` recognized its `.class` file and rejected it because a JVM bytecode frontend is not implemented. | Host Java runtime works; Java bytecode recompilation is unsupported. |
| .NET host runtime | A minimal .NET 10 console app ran and printed `Hello, World!`. | This confirms the host runtime installation only; it does not make the managed Windows PE examples autorecomp-compatible. |
| Mono | Attempted to run the corpus `luhn.exe`; Mono reported that the required .NET runtime is not installed. | Direct compatibility execution via Mono did not succeed for this artifact. |

## Post-runtime-update retests

After importing the latest console CRT and legacy MSVCRT shims from `feature/x86-x64-arm64-mvp`, the project rebuilt successfully. A post-update retest of the x64 C++ `passgen_x64.exe` lifted all 823,048 instructions and built a macOS arm64 guest, with 105/144 imports shimmed. It still failed at runtime on an indirect jump to unmapped guest address `0x14002c610`; 39 imports remain unsupported, including `rand_s`, CRT exception/unwind and thread functions, and several wide-character/stdio calls. This is a build success but not a runnable-app pass. Log: `$TMPDIR/recomp-post-runtime/passgen_x64.log`.

On the corrected build, x86 `hangman_x86.exe`, x86 `tetris.exe`, x86 `tictactoe.exe`, and x64 `base64_x64.exe` completed native macOS arm64 build/run and differential verification with byte-for-byte matching output. Their real Terminal screenshots are linked in the main results table; the final x86 sweep logs are in `$TMPDIR/recomp-final-x86/`. The x86 CTest runtime check also passed.

The focused edits also correct Win64 XMM0 versus x86 x87 double math ABI handling, the six-argument UCRT `__stdio_common_vsprintf` layout (including its 64-bit options word on x86), its documented `0x3f` option mask, CRT cdecl stack cleanup, `__stdio_common_vsscanf`, and `GlobalAlloc` fixed/zero-init flags plus freeing fixed blocks. The generated-code baseline was refreshed from reproducible current fixtures, and the full CTest run now passes 23/23. Screenshots above are real Terminal captures of completed native runs.

Runtime and non-PE inspection output is saved at `$TMPDIR/recomp-runtime-matrix/runtime-matrix.log`; Rust native run output is at `$TMPDIR/recomp-runtime-matrix/rust-host.log`.

The host only permits a macOS arm64 execution result here. Windows-host execution and macOS x86-64-host execution were not available in this run.

## Complete appendix: Windows PE files tested

“Pass” below means `AUTORECOMP COMPLETE`, native exit 0, and differential verification reported yes. Every other result is a failure/incomplete pipeline outcome, even when instruction coverage is 100%.

| # | Source OS | Guest architecture | Language / runtime | Input EXE | Host target | Lift coverage | Missing imports | Pipeline result | Screenshot / evidence |
| ---: | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |
| 1/166 | Windows PE | ARM64 | Native PE; source language unknown | `windows/arm64/apps/micro.exe` | macOS arm64 | 100% | 0 | FAILED | log: `$TMPDIR/micro/batch-autorecomp.log` |
| 2/166 | Windows PE | x86 | C (native PE) | `windows/cli-apps/1-prime-generator-c/build/prime-gen_x86.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/prime_gen_x86.png); log: `$TMPDIR/prime-gen_x86/batch-autorecomp.log` |
| 3/166 | Windows PE | x86-64 | C++ (native PE) | `windows/cli-apps/2-password-generator-cpp/build/passgen_x64.exe` | macOS arm64 | 100% | 39 post-update (was 45) | FAILED (post-update retest: builds, then unmapped indirect jump) | log: `$TMPDIR/recomp-post-runtime/passgen_x64.log`; baseline: `$TMPDIR/passgen_x64/batch-autorecomp.log` |
| 4/166 | Windows PE | x86-64 | C (native PE) | `windows/cli-apps/4-base64-tool-c/build/base64_x64.exe` | macOS arm64 | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/base64_x64.png); log: `$TMPDIR/base64_x64/batch-autorecomp.log` |
| 5/166 | Windows PE | x86 | C (native PE) | `windows/cli-apps/4-base64-tool-c/build/base64_x86.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/base64_x86.png); log: `$TMPDIR/base64_x86/batch-autorecomp.log` |
| 6/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/cli-games/1-guess-game-c/build/guess_game_x64.exe` | macOS arm64 | 100% | 1 | TIMEOUT (guest exit 124) | log: `$TMPDIR/guess_game_x64/batch-autorecomp.log` |
| 7/166 | Windows PE | x86 | Native PE; source language unknown | `windows/cli-games/1-guess-game-c/build/guess_game_x86.exe` | macOS arm64 | 100% | 0 | TIMEOUT (guest exit 124) | log: `$TMPDIR/guess_game_x86/batch-autorecomp.log` |
| 8/166 | Windows PE | x86-64 | C (native PE) | `windows/cli-games/2-hangman-c/build/hangman_x64.exe` | macOS arm64 | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/hangman_x64_terminal.png); log: `$TMPDIR/hangman_x64/batch-autorecomp.log` |
| 9/166 | Windows PE | x86 | C (native PE) | `windows/cli-games/2-hangman-c/build/hangman_x86.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/hangman_x86_terminal.png); log: `$TMPDIR/hangman_x86/batch-autorecomp.log` |
| 10/166 | Windows PE | x86-64 | C++ (native PE) | `windows/cli-games/3-tictactoe-cpp/build/tictactoe_x64.exe` | macOS arm64 | 100% | 44 | FAILED | log: `$TMPDIR/tictactoe_x64/batch-autorecomp.log` |
| 11/166 | Windows PE | x86 | C++ (native PE) | `windows/cli-games/3-tictactoe-cpp/build/tictactoe_x86.exe` | macOS arm64 | n/a | n/a | CRASHED (CLI exit 3; no summary) | log: `$TMPDIR/tictactoe_x86/batch-autorecomp.log` |
| 12/166 | Windows PE | x86-64 | C++ (native PE) | `windows/cli-games/4-mastermind-cpp/build/mastermind_x64.exe` | macOS arm64 | 100% | 44 | FAILED | log: `$TMPDIR/mastermind_x64/batch-autorecomp.log` |
| 13/166 | Windows PE | x86 | C++ (native PE) | `windows/cli-games/4-mastermind-cpp/build/mastermind_x86.exe` | macOS arm64 | n/a | n/a | CRASHED (CLI exit 3; no summary) | log: `$TMPDIR/mastermind_x86/batch-autorecomp.log` |
| 14/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/arith-calc.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/arith_calc_x64.png); log: `$TMPDIR/recomp-screenshot-rebuilds/arith_calc_x64.log` |
| 15/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/base64.exe` | macOS arm64 | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/base64_x64.png); log: `$TMPDIR/base64_x64/batch-autorecomp.log` |
| 16/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/busybox.exe` | macOS arm64 | 100% | 191 | FAILED | log: `$TMPDIR/busybox/batch-autorecomp.log` |
| 17/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/clipjar.exe` | macOS arm64 | n/a | 296 | FAILED | log: `$TMPDIR/clipjar/batch-autorecomp.log` |
| 18/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/imgview64.exe` | macOS arm64 | 100% | 7 | FAILED | log: `$TMPDIR/imgview64/batch-autorecomp.log` |
| 19/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/micro.exe` | macOS arm64 | n/a | 28 | FAILED | log: `$TMPDIR/micro/batch-autorecomp.log` |
| 20/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/notepad.exe` | macOS arm64 | n/a | 156 | FAILED | log: `$TMPDIR/notepad/batch-autorecomp.log` |
| 21/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/pageant.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/pageant/batch-autorecomp.log` |
| 22/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/passgen.exe` | macOS arm64 | 100% | 45 | FAILED | log: `$TMPDIR/passgen/batch-autorecomp.log` |
| 23/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/plink.exe` | macOS arm64 | n/a | 81 | FAILED | log: `$TMPDIR/plink/batch-autorecomp.log` |
| 24/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/procexp64.exe` | macOS arm64 | n/a | 619 | FAILED | log: `$TMPDIR/procexp64/batch-autorecomp.log` |
| 25/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/psftp.exe` | macOS arm64 | n/a | 81 | FAILED | log: `$TMPDIR/psftp/batch-autorecomp.log` |
| 26/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/putty.exe` | macOS arm64 | n/a | 272 | FAILED | log: `$TMPDIR/putty/batch-autorecomp.log` |
| 27/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/sqlite3.exe` | macOS arm64 | n/a | 78 | FAILED | log: `$TMPDIR/sqlite3/batch-autorecomp.log` |
| 28/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/apps/zoomit64.exe` | macOS arm64 | n/a | 424 | FAILED | log: `$TMPDIR/zoomit64/batch-autorecomp.log` |
| 29/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/blackbox.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/blackbox/batch-autorecomp.log` |
| 30/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/bridges.exe` | macOS arm64 | n/a | 133 | FAILED | log: `$TMPDIR/bridges/batch-autorecomp.log` |
| 31/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/cube.exe` | macOS arm64 | n/a | 135 | FAILED | log: `$TMPDIR/cube/batch-autorecomp.log` |
| 32/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/dominosa.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/dominosa/batch-autorecomp.log` |
| 33/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/fifteen.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/fifteen/batch-autorecomp.log` |
| 34/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/filling.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/filling/batch-autorecomp.log` |
| 35/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/flip.exe` | macOS arm64 | n/a | 131 | FAILED | log: `$TMPDIR/flip/batch-autorecomp.log` |
| 36/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/flood.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/flood/batch-autorecomp.log` |
| 37/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/galaxies.exe` | macOS arm64 | n/a | 134 | FAILED | log: `$TMPDIR/galaxies/batch-autorecomp.log` |
| 38/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/game2048.exe` | macOS arm64 | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/game2048_x64.png); log: `$TMPDIR/recomp-screenshot-rebuilds/game2048_x64.log` |
| 39/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/guess.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/guess/batch-autorecomp.log` |
| 40/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/guess_game_x64.exe` | macOS arm64 | 100% | 1 | TIMEOUT (guest exit 124) | log: `$TMPDIR/guess_game_x64/batch-autorecomp.log` |
| 41/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/hangman_x64.exe` | macOS arm64 | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/hangman_x64_terminal.png); log: `$TMPDIR/hangman_x64/batch-autorecomp.log` |
| 42/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/inertia.exe` | macOS arm64 | n/a | 135 | FAILED | log: `$TMPDIR/inertia/batch-autorecomp.log` |
| 43/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/keen.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/keen/batch-autorecomp.log` |
| 44/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/lightup.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/lightup/batch-autorecomp.log` |
| 45/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/loopy.exe` | macOS arm64 | n/a | 135 | FAILED | log: `$TMPDIR/loopy/batch-autorecomp.log` |
| 46/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/magnets.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/magnets/batch-autorecomp.log` |
| 47/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/map.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/map/batch-autorecomp.log` |
| 48/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/mastermind_x64.exe` | macOS arm64 | 100% | 44 | FAILED | log: `$TMPDIR/mastermind_x64/batch-autorecomp.log` |
| 49/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/mines.exe` | macOS arm64 | n/a | 138 | FAILED | log: `$TMPDIR/mines/batch-autorecomp.log` |
| 50/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/mosaic.exe` | macOS arm64 | n/a | 131 | FAILED | log: `$TMPDIR/mosaic/batch-autorecomp.log` |
| 51/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/netgame.exe` | macOS arm64 | n/a | 135 | FAILED | log: `$TMPDIR/netgame/batch-autorecomp.log` |
| 52/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/netslide.exe` | macOS arm64 | n/a | 131 | FAILED | log: `$TMPDIR/netslide/batch-autorecomp.log` |
| 53/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/palisade.exe` | macOS arm64 | n/a | 135 | FAILED | log: `$TMPDIR/palisade/batch-autorecomp.log` |
| 54/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/pattern.exe` | macOS arm64 | n/a | 134 | FAILED | log: `$TMPDIR/pattern/batch-autorecomp.log` |
| 55/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/pearl.exe` | macOS arm64 | n/a | 135 | FAILED | log: `$TMPDIR/pearl/batch-autorecomp.log` |
| 56/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/pegs.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/pegs/batch-autorecomp.log` |
| 57/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/powder-toy.exe` | macOS arm64 | n/a | 417 | FAILED | log: `$TMPDIR/powder-toy/batch-autorecomp.log` |
| 58/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/range.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/range/batch-autorecomp.log` |
| 59/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/rect.exe` | macOS arm64 | n/a | 133 | FAILED | log: `$TMPDIR/rect/batch-autorecomp.log` |
| 60/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/samegame.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/samegame/batch-autorecomp.log` |
| 61/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/signpost.exe` | macOS arm64 | n/a | 136 | FAILED | log: `$TMPDIR/signpost/batch-autorecomp.log` |
| 62/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/singles.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/singles/batch-autorecomp.log` |
| 63/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/sixteen.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/sixteen/batch-autorecomp.log` |
| 64/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/slant.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/slant/batch-autorecomp.log` |
| 65/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/snake-game.exe` | macOS arm64 | n/a | n/a | CRASHED (CLI exit 3; no summary) | log: `$TMPDIR/snake-game/batch-autorecomp.log` |
| 66/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/snake.exe` | macOS arm64 | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/snake_x64.png); log: `$TMPDIR/recomp-screenshot-rebuilds/snake_x64.log` |
| 67/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/solo.exe` | macOS arm64 | n/a | 133 | FAILED | log: `$TMPDIR/solo/batch-autorecomp.log` |
| 68/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/tents.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/tents/batch-autorecomp.log` |
| 69/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/tetris.exe` | macOS arm64 | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/tetris_x64.png); log: `$TMPDIR/tetris/batch-autorecomp.log` |
| 70/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/tictactoe.exe` | macOS arm64 | 100% | 1 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/tictactoe_x64.png); log: `$TMPDIR/tictactoe/batch-autorecomp.log` |
| 71/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/tictactoe_x64.exe` | macOS arm64 | 100% | 44 | FAILED | log: `$TMPDIR/tictactoe_x64/batch-autorecomp.log` |
| 72/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/towers.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/towers/batch-autorecomp.log` |
| 73/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/tracks.exe` | macOS arm64 | n/a | 134 | FAILED | log: `$TMPDIR/tracks/batch-autorecomp.log` |
| 74/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/twiddle.exe` | macOS arm64 | n/a | 136 | FAILED | log: `$TMPDIR/twiddle/batch-autorecomp.log` |
| 75/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/undead.exe` | macOS arm64 | n/a | 133 | FAILED | log: `$TMPDIR/undead/batch-autorecomp.log` |
| 76/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/unequal.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/unequal/batch-autorecomp.log` |
| 77/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/unruly.exe` | macOS arm64 | n/a | 132 | FAILED | log: `$TMPDIR/unruly/batch-autorecomp.log` |
| 78/166 | Windows PE | x86-64 | Native PE; source language unknown | `windows/x64/games/untangle.exe` | macOS arm64 | n/a | 134 | FAILED | log: `$TMPDIR/untangle/batch-autorecomp.log` |
| 79/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/apps/arith-calc.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/arith_calc_x86.png); log: `$TMPDIR/arith-calc/batch-autorecomp.log` |
| 80/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/apps/base64.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/base64_x86.png); log: `$TMPDIR/base64/batch-autorecomp.log` |
| 81/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/apps/busybox.exe` | macOS arm64 | 100% | 188 | FAILED | log: `$TMPDIR/busybox/batch-autorecomp.log` |
| 82/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/apps/micro.exe` | macOS arm64 | n/a | 25 | FAILED | log: `$TMPDIR/micro/batch-autorecomp.log` |
| 83/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/apps/pageant.exe` | macOS arm64 | n/a | 128 | FAILED | log: `$TMPDIR/pageant/batch-autorecomp.log` |
| 84/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/apps/prime-gen.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/prime_gen_x86.png); log: `$TMPDIR/prime-gen/batch-autorecomp.log` |
| 85/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/apps/psftp.exe` | macOS arm64 | n/a | 77 | FAILED | log: `$TMPDIR/psftp/batch-autorecomp.log` |
| 86/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/apps/putty.exe` | macOS arm64 | n/a | 268 | FAILED | log: `$TMPDIR/putty/batch-autorecomp.log` |
| 87/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/blackbox.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/blackbox/batch-autorecomp.log` |
| 88/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/bridges.exe` | macOS arm64 | 100% | 111 | FAILED | log: `$TMPDIR/bridges/batch-autorecomp.log` |
| 89/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/cube.exe` | macOS arm64 | 100% | 113 | FAILED | log: `$TMPDIR/cube/batch-autorecomp.log` |
| 90/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/dominosa.exe` | macOS arm64 | 100% | 111 | FAILED | log: `$TMPDIR/dominosa/batch-autorecomp.log` |
| 91/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/dominosasolver.exe` | macOS arm64 | 100% | 5 | FAILED | log: `$TMPDIR/dominosasolver/batch-autorecomp.log` |
| 92/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/fifteen.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/fifteen/batch-autorecomp.log` |
| 93/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/fifteensolver.exe` | macOS arm64 | 100% | 4 | FAILED | log: `$TMPDIR/fifteensolver/batch-autorecomp.log` |
| 94/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/filling.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/filling/batch-autorecomp.log` |
| 95/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/fillingsolver.exe` | macOS arm64 | 100% | 3 | PASS (exit 0; differential yes) | log: `$TMPDIR/fillingsolver/batch-autorecomp.log` |
| 96/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/flip.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/flip/batch-autorecomp.log` |
| 97/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/flood.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/flood/batch-autorecomp.log` |
| 98/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/fuzzpuzz.exe` | macOS arm64 | 100% | 22 | FAILED | log: `$TMPDIR/fuzzpuzz/batch-autorecomp.log` |
| 99/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/galaxies.exe` | macOS arm64 | 100% | 111 | FAILED | log: `$TMPDIR/galaxies/batch-autorecomp.log` |
| 100/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/galaxieseditor.exe` | macOS arm64 | 100% | 111 | FAILED | log: `$TMPDIR/galaxieseditor/batch-autorecomp.log` |
| 101/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/galaxiespicture.exe` | macOS arm64 | 100% | 8 | FAILED | log: `$TMPDIR/galaxiespicture/batch-autorecomp.log` |
| 102/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/galaxiessolver.exe` | macOS arm64 | 100% | 5 | FAILED | log: `$TMPDIR/galaxiessolver/batch-autorecomp.log` |
| 103/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/game2048.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/game2048_x86.png); log: `$TMPDIR/game2048/batch-autorecomp.log` |
| 104/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/grapheditor.exe` | macOS arm64 | 100% | 113 | FAILED | log: `$TMPDIR/grapheditor/batch-autorecomp.log` |
| 105/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/guess.exe` | macOS arm64 | 100% | 111 | FAILED | log: `$TMPDIR/guess/batch-autorecomp.log` |
| 106/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/guess_game_x86.exe` | macOS arm64 | 100% | 0 | TIMEOUT (guest exit 124) | log: `$TMPDIR/guess_game_x86/batch-autorecomp.log` |
| 107/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/hangman_x86.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/hangman_x86_terminal.png); log: `$TMPDIR/hangman_x86/batch-autorecomp.log` |
| 108/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/inertia.exe` | macOS arm64 | 100% | 113 | FAILED | log: `$TMPDIR/inertia/batch-autorecomp.log` |
| 109/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/keen.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/keen/batch-autorecomp.log` |
| 110/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/keensolver.exe` | macOS arm64 | 100% | 4 | FAILED | log: `$TMPDIR/keensolver/batch-autorecomp.log` |
| 111/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/lightup.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/lightup/batch-autorecomp.log` |
| 112/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/lightupsolver.exe` | macOS arm64 | 100% | 4 | FAILED | log: `$TMPDIR/lightupsolver/batch-autorecomp.log` |
| 113/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/loopy.exe` | macOS arm64 | 100% | 115 | FAILED | log: `$TMPDIR/loopy/batch-autorecomp.log` |
| 114/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/loopysolver.exe` | macOS arm64 | 100% | 12 | FAILED | log: `$TMPDIR/loopysolver/batch-autorecomp.log` |
| 115/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/magnets.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/magnets/batch-autorecomp.log` |
| 116/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/magnetssolver.exe` | macOS arm64 | 100% | 4 | FAILED | log: `$TMPDIR/magnetssolver/batch-autorecomp.log` |
| 117/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/map.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/map/batch-autorecomp.log` |
| 118/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/mapsolver.exe` | macOS arm64 | 100% | 4 | FAILED | log: `$TMPDIR/mapsolver/batch-autorecomp.log` |
| 119/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/mastermind_x86.exe` | macOS arm64 | n/a | n/a | CRASHED (CLI exit 3; no summary) | log: `$TMPDIR/mastermind_x86/batch-autorecomp.log` |
| 120/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/mineobfusc.exe` | macOS arm64 | 100% | 13 | FAILED | log: `$TMPDIR/mineobfusc/batch-autorecomp.log` |
| 121/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/mines.exe` | macOS arm64 | 100% | 116 | FAILED | log: `$TMPDIR/mines/batch-autorecomp.log` |
| 122/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/mosaic.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/mosaic/batch-autorecomp.log` |
| 123/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/netgame.exe` | macOS arm64 | 100% | 113 | FAILED | log: `$TMPDIR/netgame/batch-autorecomp.log` |
| 124/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/netslide.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/netslide/batch-autorecomp.log` |
| 125/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/nullgame.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/nullgame/batch-autorecomp.log` |
| 126/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/palisade.exe` | macOS arm64 | 100% | 113 | FAILED | log: `$TMPDIR/palisade/batch-autorecomp.log` |
| 127/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/pattern.exe` | macOS arm64 | 100% | 112 | FAILED | log: `$TMPDIR/pattern/batch-autorecomp.log` |
| 128/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/patternpicture.exe` | macOS arm64 | 100% | 8 | FAILED | log: `$TMPDIR/patternpicture/batch-autorecomp.log` |
| 129/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/patternsolver.exe` | macOS arm64 | 100% | 6 | FAILED | log: `$TMPDIR/patternsolver/batch-autorecomp.log` |
| 130/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/pearl.exe` | macOS arm64 | 100% | 114 | FAILED | log: `$TMPDIR/pearl/batch-autorecomp.log` |
| 131/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/pearlbench.exe` | macOS arm64 | 100% | 9 | TIMEOUT (guest exit 124) | log: `$TMPDIR/pearlbench/batch-autorecomp.log` |
| 132/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/pearlsolver.exe` | macOS arm64 | 100% | 9 | FAILED | log: `$TMPDIR/pearlsolver/batch-autorecomp.log` |
| 133/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/pegs.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/pegs/batch-autorecomp.log` |
| 134/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/progress-quest.exe` | macOS arm64 | n/a | 369 | FAILED | log: `$TMPDIR/progress-quest/batch-autorecomp.log` |
| 135/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/puzzles.exe` | macOS arm64 | 100% | 125 | FAILED | log: `$TMPDIR/puzzles/batch-autorecomp.log` |
| 136/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/range.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/range/batch-autorecomp.log` |
| 137/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/rect.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/rect/batch-autorecomp.log` |
| 138/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/samegame.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/samegame/batch-autorecomp.log` |
| 139/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/signpost.exe` | macOS arm64 | 100% | 114 | FAILED | log: `$TMPDIR/signpost/batch-autorecomp.log` |
| 140/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/signpostsolver.exe` | macOS arm64 | 100% | 9 | FAILED | log: `$TMPDIR/signpostsolver/batch-autorecomp.log` |
| 141/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/singles.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/singles/batch-autorecomp.log` |
| 142/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/singlessolver.exe` | macOS arm64 | 100% | 4 | FAILED | log: `$TMPDIR/singlessolver/batch-autorecomp.log` |
| 143/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/sixteen.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/sixteen/batch-autorecomp.log` |
| 144/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/slant.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/slant/batch-autorecomp.log` |
| 145/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/slantsolver.exe` | macOS arm64 | 100% | 4 | FAILED | log: `$TMPDIR/slantsolver/batch-autorecomp.log` |
| 146/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/snake.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/snake_x86.png); log: `$TMPDIR/snake/batch-autorecomp.log` |
| 147/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/solo.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/solo/batch-autorecomp.log` |
| 148/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/solosolver.exe` | macOS arm64 | 100% | 4 | FAILED | log: `$TMPDIR/solosolver/batch-autorecomp.log` |
| 149/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/tents.exe` | macOS arm64 | 100% | 110 | FAILED | log: `$TMPDIR/tents/batch-autorecomp.log` |
| 150/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/tentssolver.exe` | macOS arm64 | 100% | 4 | FAILED | log: `$TMPDIR/tentssolver/batch-autorecomp.log` |
| 151/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/tetris-classic.exe` | macOS arm64 | 100% | 0 | INCOMPLETE (guest timed out; differential run interrupted) | log: `$TMPDIR/tetris-classic/batch-autorecomp.log` |
| 152/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/tetris.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/tetris_x86_terminal.png); log: `$TMPDIR/recomp-final-x86/tetris/batch-autorecomp.log` |
| 153/166 | Windows PE | x86 | C# / .NET IL | `windows/x86/games/tictactoe-net.exe` | macOS arm64 | n/a | 1 | FAILED (managed IL frontend absent) | log: `$TMPDIR/recomp-final-x86/tictactoe-net/batch-autorecomp.log` |
| 154/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/tictactoe.exe` | macOS arm64 | 100% | 0 | PASS (exit 0; differential yes) | [real Terminal screenshot](../apps-running-screenshots/tictactoe_x86_terminal.png); log: `$TMPDIR/recomp-final-x86/tictactoe/batch-autorecomp.log` |
| 155/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/tictactoe_x86.exe` | macOS arm64 | 100% | 33 | CRASHED (guest abort during verification; CLI exit 3) | log: `$TMPDIR/recomp-final-x86/tictactoe_x86/batch-autorecomp.log` |
| 156/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/towers.exe` | macOS arm64 | 100% | 97 | FAILED (guest exit 3) | log: `$TMPDIR/recomp-final-x86/towers/batch-autorecomp.log` |
| 157/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/towerssolver.exe` | macOS arm64 | 100% | 0 post-update | FAILED (exit 1; atexit handlers remain unresolved) | log: `$TMPDIR/recomp-post-vsscanf/towerssolver/autorecomp.log` |
| 158/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/tracks.exe` | macOS arm64 | 100% | 97 | FAILED (guest exit 3) | log: `$TMPDIR/recomp-final-x86/tracks/batch-autorecomp.log` |
| 159/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/trackssolver.exe` | macOS arm64 | 100% | 0 post-update | FAILED (exit 1; atexit handlers remain unresolved) | log: `$TMPDIR/recomp-post-vsscanf/trackssolver/autorecomp.log` |
| 160/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/twiddle.exe` | macOS arm64 | 100% | 98 | FAILED (guest exit 3) | log: `$TMPDIR/recomp-final-x86/twiddle/batch-autorecomp.log` |
| 161/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/undead.exe` | macOS arm64 | 100% | 98 | FAILED (guest exit 3) | log: `$TMPDIR/recomp-final-x86/undead/batch-autorecomp.log` |
| 162/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/unequal.exe` | macOS arm64 | 100% | 97 | FAILED (guest exit 3) | log: `$TMPDIR/recomp-final-x86/unequal/batch-autorecomp.log` |
| 163/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/unequalsolver.exe` | macOS arm64 | 100% | 0 post-update | TIMEOUT (guest exit 124) | log: `$TMPDIR/recomp-post-vsscanf/unequalsolver/autorecomp.log` |
| 164/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/unruly.exe` | macOS arm64 | 100% | 97 | FAILED (guest exit 3) | log: `$TMPDIR/recomp-final-x86/unruly/batch-autorecomp.log` |
| 165/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/unrulysolver.exe` | macOS arm64 | 100% | 0 post-update | FAILED (native exit 0; differential verification failed) | log: `$TMPDIR/recomp-post-vsscanf/unrulysolver/autorecomp.log` |
| 166/166 | Windows PE | x86 | Native PE; source language unknown | `windows/x86/games/untangle.exe` | macOS arm64 | 100% | 98 | FAILED (guest exit 3) | log: `$TMPDIR/recomp-final-x86/untangle/batch-autorecomp.log` |

## External unique Windows PE payloads

The external `win32/` and `win64/` directories contain 129 byte-identical aliases of rows in the canonical `windows/` table; SHA-256 identity makes a second pipeline run non-informative. The following seven external payloads have no canonical duplicate and were each run directly with the same command and host target. None completed, so there is no running-app screenshot to attach.

| Input EXE | Guest architecture / runtime | Lift coverage | Missing imports | Direct pipeline result | Evidence |
| --- | --- | ---: | ---: | --- | --- |
| `luhn/luhn.exe` | x86, managed Mono/.NET IL | 99.8232% | 1 | FAILED: IL frontend absent | `$TMPDIR/recomp-full-corpus/luhn/autorecomp.log` |
| `pixeltetris/Pixeltetris-v1.0.0-Windows-64bit/bin/v1/Pixeltetris.exe` | x86-64, native SDL | 99.8830% | 68 | FAILED: first unsupported instruction `bnd jae` | `$TMPDIR/recomp-full-corpus/pixeltetris/autorecomp.log` |
| `fd/fd-v10.5.0-x86_64-pc-windows-msvc/fd.exe` | x86-64, native Rust/MSVC | 99.8925% | 75 | FAILED: first unsupported instruction `pinsrw` | `$TMPDIR/recomp-full-corpus/fd/autorecomp.log` |
| `bat/bat-v0.26.1-x86_64-pc-windows-msvc/bat.exe` | x86-64, native Rust/MSVC | 99.9704% | 175 | FAILED: first unsupported instruction `pinsrw` | `$TMPDIR/recomp-full-corpus/bat/autorecomp.log` |
| `ripgrep/ripgrep-15.2.0-x86_64-pc-windows-msvc/rg.exe` | x86-64, native Rust/MSVC | 99.8938% | 63 | FAILED: first unsupported instruction `pinsrw` | `$TMPDIR/recomp-full-corpus/ripgrep/autorecomp.log` |
| `openlierox/openlierox-20260912.1-windows/openlierox.exe` | x86-64, native GUI | 99.9933% | 497 | FAILED: first unsupported instruction `cmpltss` | `$TMPDIR/recomp-full-corpus/openlierox/autorecomp.log` |
| `supertux/SuperTux-portable/bin/supertux2.exe` | x86-64, native GUI | 99.9659% | 636 | FAILED: first unsupported instruction `cvtps2pd` | `$TMPDIR/recomp-full-corpus/supertux/autorecomp.log` |

## Project validation

- `cmake --build build -j2`: passed after the UCRT bridge change.
- `env LC_ALL=C LANG=C ctest --test-dir build --output-on-failure`: 23/23 tests passed in 265.51 seconds on the final pushed branch.
- An initial CTest run under the machine's invalid `C.UTF-8` locale failed fixture builds; rerunning under `C` passed those locale-sensitive tests.

## Issues exposed by this run

- Windows ARM64 PE guest support is absent.
- GUI app startup is blocked by broad Win32 gaps; the legacy puzzle GUI group commonly has 110-125 missing imports. A 100% lift does not imply the process can start.
- Several CRT-heavy console programs remain outside the implemented runtime surface; the C++ password generator still reports 39 missing imports, including `rand_s`, exception/unwind, threading, and wide-character/stdio functions.
- Some generated native builds take minutes. The provided one-token input is not suitable for every game and can produce large output or timeouts; `guess_game` and `tetris-classic` are examples of tests that did not establish useful gameplay.
- CLR and JVM bytecode need managed-code frontends and runtime integration. Installing a host runtime alone does not translate or bundle those apps.
- Linux ELF and macOS Mach-O inputs are recognized for diagnosis but are not source formats handled by the current Windows PE lifter.
- The external x64 applications establish three recurring instruction-lifting gaps: `pinsrw` (the first blocker in the three Rust/MSVC tools), `bnd jae`, and scalar/vector SSE conversion/comparison instructions. Even after those are lifted, the SDL and large-GUI distributions require broad API/runtime work: PixelTetris is missing 68 imports, OpenLieroX 497, and SuperTux 636.

## Screenshots

Rows with completed, meaningful console runs link to actual macOS Terminal captures of the generated native executable. The same image is reused only where the input EXEs were byte-identical (prime generator, Base64, and Hangman architecture aliases). The `fillingsolver.exe` smoke run produced no visible output, and failed apps have no successful-running screenshot.

The existing `fillingsolver.png`, `hangman_x64.png`, and `hangman_x86.png` files are status-card illustrations rather than application screenshots; this report does not use them as proof.
