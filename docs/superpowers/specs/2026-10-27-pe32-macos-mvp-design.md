# Recomp Studio PE32-to-macOS MVP Design

## Scope

Recomp Studio is a C++20 command-line static recompiler. This first vertical
slice accepts genuine PE32 (IA-32) and PE32+ (x86-64) files, reports their
structure, discovers entry-rooted control flow, lifts a deliberately small but
real subset of both architectures to a typed canonical IR, emits portable C++
host code, builds and runs that host program on macOS ARM64, and records
verification evidence. It is generic: the pipeline does not recognize fixture
source or hashes as a special case.

The executable demonstration uses two independently-built machine-code PE32
fixtures with different control-flow shapes. The catalogue also exposes
TicTacToe and Plink as public game/software profiles, but reports their actual
format/backend compatibility rather than pretending they can run before their
required .NET or PE32+ support exists.

## Architecture

`apps/cli` owns argument parsing and JSON diagnostics. `core/binary` parses
DOS/PE/COFF/optional headers, sections and imports without trusting host
addresses. `core/discovery` decodes intentionally supported x86 and x64 byte
subsets and constructs a CFG from the entry point. `core/ir` serializes
explicit-width operations with source-address provenance. `core/lifters/x86`
and `core/lifters/x64` map decoded instructions to that IR. `core/codegen`
emits a standalone C++ host project; the generated program links `runtime`
guest CPU/memory/interpreter support.

The first code generator is deterministic C++ rather than direct LLVM API
construction: CMake uses Apple Clang's ARM64 backend to produce the required
native macOS executable while keeping the lowering boundary ready for an LLVM
IR backend. Platform capability is reported centrally: macOS ARM64 is
supported; Linux and WebAssembly are accurately marked unavailable or
experimental until built and executed.

## Supported execution semantics

The MVP supports register-immediate/register-register `mov`, `add`, `sub`,
`xor`, `cmp`, `test`, `jmp`, `jz`, `jnz`, `call`, `ret`, `push`, `pop`, and
`nop`; x64 support includes REX register forms and 64-bit call/stack width.
Unknown instructions produce explicit diagnostics. The runtime models 32/64-bit
guest registers, bounded guest memory, a guest stack, EFLAGS (CF/ZF/SF/OF/PF),
and direct guest-address dispatch. It never converts guest addresses into host
pointers. Unsupported imports/indirect targets fail closed.

Fixtures issue only no-import code paths. The Win32 compatibility registry
still reports each imported symbol as IMPLEMENTED, PARTIALLY_IMPLEMENTED,
UNSUPPORTED, or NOT_REACHED; no API is falsely stubbed as successful.

## CLI and project evidence

`inspect`, `analyze`, `functions`, `cfg`, `lift`, `translate`, `build`, `run`,
`verify`, `report`, `doctor`, `tools list`, `tools doctor`, `tools install`,
and `examples list` share structured JSON diagnostics. Commands which are not
yet feasible expose an explicit unsupported result and non-zero exit code.

Translation produces a project manifest, IR, generated C++, build log,
coverage report and run result. Verification independently runs the decoded
instruction stream with the bundled reference interpreter and compares final
registers, flags, and memory against the generated host executable for fixed
and seeded test states. Evidence is stored as JSON; no VERIFIED label follows
from compilation alone.

## Testing seams

The public test seams are: CLI JSON output, PE32 parser output, decoded/lifted
IR, generated-project host executable, and verifier evidence. Tests create
PE32 and PE32+ files from raw machine-code bytes during the test run, then pass the
actual binary through the CLI; no source-language fixture substitution occurs.

## Constraints and limits

No commercial files/assets are downloaded. The project uses original code and
documents research-only upstream references in `THIRD_PARTY_NOTICES.md` and
`tools.lock.json`. Packed files, .NET, unimplemented imports/opcodes,
and unavailable targets are rejected with precise reasons. Graphics, x87/SSE,
TLS callbacks, relocations beyond fixture needs, Ghidra, Unicorn, SQLite,
real-app porting, Linux execution, and WASM execution remain explicitly
unimplemented workstreams rather than implied capability.

## Terminal experience

Human-readable CLI commands render a restrained ASCII panel and lifecycle
events (`loading`, `working`, `idle`, `complete`, `error`) for each executed
stage. This renderer is deterministic (no terminal control codes or timing
dependence) so captured logs remain useful. JSON mode emits only one JSON
document on stdout, with no animation/log contamination.
