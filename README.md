<p align="center">
  <img src="assets/recomp-studio-logo.png" alt="Recomp Studio: executable blocks transform into a native-output arrow" width="260">
</p>

# Recomp Studio

Recomp Studio is an experimental, open-source static recompilation CLI for
legally obtained Windows executables. It analyzes genuine PE32 (x86) and
PE32+ (x64) machine code, lifts a tested instruction subset, emits portable
C++20, and can build a native macOS arm64 host program.

The project is intentionally fail-closed: unsupported formats, instructions,
imports, and runtime behavior report errors rather than fabricated success.

## Verified snapshot

The latest corpus run attempted **166 canonical Windows PE files** on macOS
arm64. **21 completed the full build/run/differential pipeline**, including
console samples such as Base64, Hangman, 2048, Snake, Tetris, and Tic-Tac-Toe.
Every successful result is backed by a repository-local screenshot or an
explicit no-output note.

| | Result |
| --- | ---: |
| Canonical inputs attempted | **166** |
| Complete verified passes | **21** |
| x86 passes | **12** |
| x86-64 passes | **9** |
| Screenshot-backed passes | **20** |

This is a measured subset, not a claim of universal Windows compatibility.
GUI-heavy programs, broad Win32 imports, managed .NET/JVM binaries, Windows
ARM64 guests, and many instructions remain outside the current frontend or
runtime scope. See the [full application audit](reports/apps-running-results.md)
for the complete 166-row ledger, logs, limitations, and evidence links.

### Evidence gallery

| x86 | x86-64 |
| --- | --- |
| ![Base64 x86](apps-running-screenshots/base64_x86.png) | ![Base64 x64](apps-running-screenshots/base64_x64.png) |
| ![Hangman x86](apps-running-screenshots/hangman_x86_terminal.png) | ![Hangman x64](apps-running-screenshots/hangman_x64_terminal.png) |
| ![Snake x86](apps-running-screenshots/snake_x86.png) | ![Snake x64](apps-running-screenshots/snake_x64.png) |
| ![Tetris x86](apps-running-screenshots/tetris_x86_terminal.png) | ![Tetris x64](apps-running-screenshots/tetris_x64.png) |
| ![Tic-Tac-Toe x86](apps-running-screenshots/tictactoe_x86_terminal.png) | ![Tic-Tac-Toe x64](apps-running-screenshots/tictactoe_x64.png) |

All images above are checked-in captures of generated native programs. A
successful lift or build without a completed differential run is not shown as
a success.

## Capability status

| Capability | Status |
| --- | --- |
| PE32/x86 and PE32+/x64 structural inspection | Supported |
| Entry-reachable instruction analysis and canonical IR | Supported subset |
| macOS ARM64 generated-host build and execution | Supported subset |
| Differential reference-vs-native verification | Supported subset |
| Windows imports, memory, calls, branches, graphics, x87/SSE | Not implemented |
| Linux, WebAssembly, .NET, and full-game portability | Not implemented |

The working subset includes immediate register `mov`, `add`, `sub`, `nop`, and
`ret`. Other decoded instructions are not automatically safe to lower yet.

## Architecture

```mermaid
flowchart LR
    A[Windows PE32 / PE32+ binary] --> B[PE parser]
    B --> C[Entry analysis and CFG]
    C --> D[Canonical semantic IR]
    D --> E[C++20 host generator]
    E --> F[CMake + Ninja]
    F --> G[Native macOS ARM64 executable]
    A --> H[Reference interpreter]
    G --> I[Differential verifier]
    H --> I
    I --> J[PASS / FAIL evidence]
```

The parser and analyzer retain guest RVAs rather than treating guest addresses
as host pointers. The verifier independently evaluates the supported original
instruction stream before comparing it with the generated native executable.

## Quick start

Requirements: macOS on Apple Silicon, CMake 3.26+, Ninja, a C++20 compiler,
and Python 3. The test fixtures are generated locally and do not contain game
assets.

```sh
git clone https://github.com/heaven-hm/recomp-studio.git
cd recomp-studio
./scripts/test.sh
```

## CLI workflow

```sh
# Build the CLI
./scripts/build.sh

# Inspect, analyze, and lift a user-supplied PE executable
build/recomp-studio inspect game.exe --json
build/recomp-studio analyze game.exe --json
build/recomp-studio lift game.exe --json

# Generate, build, run, and verify a supported macOS ARM64 project
build/recomp-studio translate game.exe --target macos-arm64 --output out/game
build/recomp-studio build out/game
build/recomp-studio run out/game
build/recomp-studio verify out/game --json

# See demonstrator and public-profile status
build/recomp-studio examples list
```

JSON output is clean for automation; normal output includes compact progress
logs (`loading`, `working`, `idle`, and `complete`).

## Legal and security

Use only executables and assets you are authorized to analyze. Recomp Studio
does not include commercial game files and makes no claim of compatibility with
any game or application beyond the documented, verified subset. Do not run
untrusted generated projects. See [SECURITY.md](SECURITY.md) for reporting
security issues and [LICENSE](LICENSE) for licensing terms.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md), run
`./scripts/test.sh` before submitting changes, and keep unsupported behavior
explicit. Release history is maintained in [CHANGELOG.md](CHANGELOG.md).
