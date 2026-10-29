# RevEng-Studio

<p align="center">
  <img src="assets/reveng-studio-logo.svg" alt="RevEng-Studio — legacy game reverse engineering" width="760">
</p>

<p align="center">
  <strong>Decompile. Recompile. Bring legacy games to modern operating systems.</strong>
</p>

RevEng-Studio is a **game-only reverse-engineering and recompilation toolkit** for understanding, rebuilding, and preserving old games. The goal is to take legacy game executables and their supporting code, analyze how they work, reconstruct or translate their behavior, and produce native builds for modern platforms.

It is designed as a **generic, extensible solution for games**, not a one-game port and not a general-purpose application decompiler. Shared pipelines handle common binary-analysis and recompilation work; game-specific adapters can provide engine, graphics, audio, input, filesystem, and operating-system compatibility where required.

## What it aims to do

- **Analyze legacy game binaries** — inspect executable formats, identify functions, and collect evidence from reverse-engineering tools.
- **Decompile and translate code** — recover higher-level information where possible and use lower-level translation when reliable source reconstruction is not available.
- **Recompile for other platforms** — build native game code for supported host architectures and operating systems, with compatibility layers for legacy APIs.
- **Reuse generic game infrastructure** — support multiple games and engines through modular format, analysis, and runtime adapters instead of hard-coding the entire pipeline to one title.
- **Verify behavior** — compare observable execution against the original game and document what works, what fails, and what remains unverified.

The long-term goal is to help legacy PC games run on **Windows, Linux, macOS, and other platforms as support is implemented**. Cross-platform support is a design goal, not a promise that every game or operating system works today.

## Design inspiration

RevEng-Studio combines ideas from existing reverse-engineering and recompilation projects:

| Project | What it contributes to the ecosystem | RevEng-Studio's intended use |
| --- | --- | --- |
| [PCRecomp](https://github.com/sp00nznet/pcrecomp) | Static recompilation tools and runtime infrastructure for PC software. | Reuse compatible recompilation/runtime techniques as part of a game-focused pipeline. Integration is experimental. |
| [rev.ng](https://rev.ng/) | Binary analysis and decompilation across architectures. | Use analysis artifacts and provider adapters to inform reconstruction and recompilation. The adapter is experimental. |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Disassembly, decompilation, and reverse-engineering framework. | Optional analysis provider for examining game binaries. |
| [N64Recomp](https://github.com/N64Recomp/N64Recomp) | Static recompilation focused on Nintendo 64 games. | A reference point for game recompilation workflows; RevEng-Studio targets a broader set of legacy game formats and hosts over time. |

These projects have different scopes and maturity levels. RevEng-Studio is not a replacement for them; it aims to connect reusable analysis, translation, runtime, and verification components into a more general workflow for legacy games.

## Current status

The project is experimental. The current pipeline can inspect PE files, recover candidate functions, lift a subset of x86 instructions, emit low-level C++, compile it, and compare selected behavior using Unicorn. `translate --source-mode hybrid` classifies every function as `high-level verified`, `low-level fallback`, or `unresolved` and delivers the classification with the source (`recomp-source-map.json`, `recomp-source-manifest.json`, and a build manifest that hashes the exact compiled tree). The current recognizers cover whole-body constant-return, stack-argument-return, and register-argument-return leaves; every function outside a proven pattern remains explicit machine-level fallback code. `--source-quality human-readable` is a fail-closed gate that refuses to emit a tree unless the measured census supports the claim. Ghidra analysis and rev.ng artifacts have external-tool adapters. PCRecomp runtime integration is experimental, and the Windows-native target rows of the matrix are explicitly unsupported.

**Playable-game support is not yet verified.** A 15-game test produced zero verified playable games. A reliable original-Windows oracle, a complete game runtime, and verified gameplay scenarios remain open work. A successful build or instruction-coverage result does not prove that a game works correctly.

An experimental PCRecomp host has rendered the Ikachan title screen using the user's original game files and a scripted Enter key. This is not a verified playable port or proof that the standard recompilation pipeline works end to end.

## How the pipeline fits together

1. **Inspect:** identify the executable format, architecture, and candidate functions.
2. **Analyze:** gather disassembly and decompilation evidence through supported tools and adapters.
3. **Translate and recompile:** generate low-level translated code where higher-level reconstruction is not yet reliable, then compile for a supported host.
4. **Add game compatibility:** connect the runtime and platform services a particular game needs, such as graphics, audio, input, files, and timing.
5. **Verify:** compare observable behavior against a suitable original-game reference and record evidence and limitations.

Game-specific compatibility may still be required. “Generic” means the architecture is intended to be reusable across games; it does not mean every game can be ported automatically without per-game work.

## Build and try

The CLI is currently named `recomp-studio`; the repository and product name are **RevEng-Studio**.

Install a C++20 toolchain, CMake, Ninja, and the dependencies listed in `CMakeLists.txt`, then run:

```sh
./scripts/build.sh
build/recomp-studio doctor
build/recomp-studio autorecomp /path/to/game.exe --output /tmp/recomp-game --buildrun --timeout 5
```

Use legally obtained game executables and assets. Generated output is experimental and may not run correctly.

## Project documentation

- [Architecture](docs/ARCHITECTURE.md) and [implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Semantic bridge](docs/SEMANTIC_BRIDGE.md), [ABI and types](docs/ABI_AND_TYPES.md), and [verification](docs/VERIFICATION.md)
- [Upstream components](docs/UPSTREAM_COMPONENTS.md) and [third-party notices](THIRD_PARTY_NOTICES.md)
- [Game test results](reports/real-games-2026-10-29.md) and [historical application results](reports/apps-running-results.md)

Game binaries and assets are not distributed with this project. See [LICENSE](LICENSE) and the third-party notices for licensing and attribution.
