# Recomp-Agent

**Recover, recompile, and verify software for the future.**

Recomp-Agent (formerly Recomp Studio) is a general-purpose hybrid decompilation
and static recompilation project, with an initial focus on preserving 2D and 3D
games. It combines machine-level translation with external analysis providers
and aims to produce source and native executables whose behavior can be tested
against the original.

## Direction and current status

Our target is Windows, macOS, and Linux software across x86, x86-64, ARM32,
and ARM64, both as input architectures and native targets. These are **project
goals, not a support guarantee**. Initial work concentrates on Windows x86 and
x86-64 PE executables and macOS ARM64 output. Other formats, architectures,
runtimes, graphics, audio, and input require further implementation and testing.

The existing pipeline can inspect PE files, recover candidate functions, lift a
subset of x86 instructions, emit low-level C++, compile it, and compare selected
behavior using Unicorn. Ghidra analysis and rev.ng artifacts have external-tool
adapters. The PCRecomp runtime has experimental integration tests. These pieces
are not yet a complete high-level reconstruction pipeline, and generated source
is not necessarily human-readable recovered game logic.

A [15-game test](reports/real-games-2026-10-29.md) produced **zero verified
playable games**. An independent Windows oracle, a complete GUI/game runtime,
and verified gameplay scenarios remain open work. Instruction coverage and a
successful build do not establish behavioral equivalence.

<p align="center"><img src="apps-running-screenshots/ikachan-pcrecomp-title.png" alt="Ikachan title screen in an experimental native PCRecomp host" width="640"></p>

*Experimental PCRecomp host rendering Ikachan's title screen using the user's
original game files and a scripted Enter key. This is not the standard
`autorecomp` pipeline, a verified gameplay scenario, or a released port.*

## Build and try

Install a C++20 toolchain, CMake, Ninja, and the dependencies listed in `CMakeLists.txt`, then:

```sh
./scripts/build.sh
build/recomp-studio doctor
build/recomp-studio autorecomp /path/to/game.exe --output /tmp/recomp-game --buildrun --timeout 5
```

Use a legally obtained executable and assets. Generated output is experimental;
a built executable is not necessarily functional. Run `build/recomp-studio --help`
for commands and `ctest --test-dir build --output-on-failure` for tests.

## How it fits together

1. **Inspect and analyze:** parse the binary and recover candidate functions;
   use Ghidra and other providers for additional evidence.
2. **Reconstruct and recompile:** retain low-level translated code where
   high-level reconstruction is not verified, and compile the delivered source.
3. **Provide compatibility:** reuse appropriately licensed runtime components
   for OS and game APIs, reporting missing behavior explicitly.
4. **Verify:** compare execution and observable behavior, recording the oracle,
   coverage, limitations, and evidence for each scenario.

Verification currently shares some runtime shims between the candidate and its
Unicorn reference, so agreement can miss errors common to both. Independent
execution of the original on Windows remains a priority.

## Project documentation

- [Architecture](docs/ARCHITECTURE.md) and [implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Semantic bridge](docs/SEMANTIC_BRIDGE.md), [ABI and types](docs/ABI_AND_TYPES.md), and [verification](docs/VERIFICATION.md)
- [Upstream components](docs/UPSTREAM_COMPONENTS.md) and [third-party notices](THIRD_PARTY_NOTICES.md)
- [Game test results](reports/real-games-2026-10-29.md) and [historical application results](reports/apps-running-results.md)

Game binaries and assets are not distributed with this project. See [LICENSE](LICENSE)
and the third-party notices for source licensing and attribution.
