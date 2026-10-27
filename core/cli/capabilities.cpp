#include "core/cli/capabilities.hpp"

namespace recomp::cli {

const char* support_name(Support support) {
  return support == Support::Implemented ? "implemented" : "planned";
}

const std::vector<Capability>& capabilities() {
  // Ordered as the options appear in --help, so the two read the same way.
  static const std::vector<Capability> all = {
      // --- source ---------------------------------------------------------
      {"source-os:auto", "--source-os", "auto", "detect the source operating system from the image", Support::Implemented, ""},
      {"source-os:windows", "--source-os", "windows", "a Windows PE image", Support::Implemented, ""},
      {"source-os:linux", "--source-os", "linux", "a Linux ELF image", Support::Planned,
       "the ELF frontend is not implemented; detection recognises ELF and refuses it"},
      {"source-os:macos", "--source-os", "macos", "a macOS Mach-O image", Support::Planned,
       "the Mach-O frontend is not implemented; detection recognises Mach-O and refuses it"},
      {"source-arch:auto", "--source-arch", "auto", "detect the source architecture from the image", Support::Implemented, ""},
      {"source-arch:x86", "--source-arch", "x86", "32-bit x86 (PE32)", Support::Implemented, ""},
      {"source-arch:x64", "--source-arch", "x64", "64-bit x86-64 (PE32+)", Support::Implemented, ""},
      {"source-arch:arm64", "--source-arch", "arm64", "AArch64 machine code", Support::Planned, "no AArch64 lifter"},
      {"source-arch:arm32", "--source-arch", "arm32", "32-bit ARM machine code", Support::Planned, "no ARM lifter"},
      {"source-arch:riscv64", "--source-arch", "riscv64", "RISC-V 64-bit machine code", Support::Planned, "no RISC-V lifter"},
      {"source-lang:auto", "--source-lang", "auto", "detect the source language from the image", Support::Implemented, ""},
      {"source-lang:native", "--source-lang", "native", "native machine code", Support::Implemented, ""},
      {"source-lang:c", "--source-lang", "c", "C source recovery", Support::Planned, "no C decompiler frontend"},
      {"source-lang:cpp", "--source-lang", "cpp", "C++ source recovery", Support::Planned, "no C++ decompiler frontend"},
      {"source-lang:rust", "--source-lang", "rust", "Rust source recovery", Support::Planned, "no Rust decompiler frontend"},
      {"source-lang:go", "--source-lang", "go", "Go source recovery", Support::Planned, "no Go decompiler frontend"},
      {"source-lang:csharp", "--source-lang", "csharp", "managed .NET IL", Support::Planned,
       "detection recognises the CLR runtime header; no IL frontend is registered"},
      {"source-lang:java", "--source-lang", "java", "JVM bytecode", Support::Planned,
       "detection recognises class files; no JVM frontend is registered"},
      {"source-lang:python", "--source-lang", "python", "CPython bytecode", Support::Planned,
       "detection recognises .pyc files; no Python frontend is registered"},

      // --- target ---------------------------------------------------------
      {"target-os:auto", "--target-os", "auto", "build for the host operating system", Support::Implemented, ""},
      {"target-os:macos", "--target-os", "macos", "native macOS output", Support::Implemented, ""},
      {"target-os:windows", "--target-os", "windows", "native Windows output", Support::Planned,
       "the generated runtime is POSIX; a Windows host runtime is not implemented"},
      {"target-os:linux", "--target-os", "linux", "native Linux output", Support::Planned,
       "the target triple is declared but the generated project does not build for it"},
      {"target-arch:auto", "--target-arch", "auto", "build for the host architecture", Support::Implemented, ""},
      {"target-arch:arm64", "--target-arch", "arm64", "Apple Silicon (arm64-apple-macos)", Support::Implemented, ""},
      {"target-arch:x64", "--target-arch", "x64", "Intel macOS (x86_64-apple-macos)", Support::Implemented, ""},
      {"target-arch:x86", "--target-arch", "x86", "32-bit x86 target", Support::Planned, "no 32-bit x86 code generator"},
      {"target-arch:arm32", "--target-arch", "arm32", "32-bit ARM target", Support::Planned, "no 32-bit ARM code generator"},
      {"target-arch:riscv64", "--target-arch", "riscv64", "RISC-V 64-bit target", Support::Planned, "no RISC-V code generator"},
      {"output-lang:auto", "--output-lang", "auto", "the primary editable source output (C++20)", Support::Implemented, ""},
      {"output-lang:cpp", "--output-lang", "cpp", "C++20, the primary editable source output", Support::Implemented, ""},
      {"output-lang:c", "--output-lang", "c", "C source output", Support::Planned, "only the C++ backend exists"},
      {"output-lang:rust", "--output-lang", "rust", "Rust source output", Support::Planned, "only the C++ backend exists"},
      {"output-lang:llvm-ir", "--output-lang", "llvm-ir", "LLVM IR output", Support::Planned,
       "the IR backend is not implemented; Remill is not integrated"},
      {"output-lang:csharp", "--output-lang", "csharp", "C# source output", Support::Planned, "only the C++ backend exists"},
      {"output-lang:java", "--output-lang", "java", "Java source output", Support::Planned, "only the C++ backend exists"},
      {"output-lang:python", "--output-lang", "python", "Python source output", Support::Planned, "only the C++ backend exists"},

      // --- recompilation --------------------------------------------------
      {"mode:recompile", "--mode", "recompile", "lift and rebuild the program as native code", Support::Implemented, ""},
      {"mode:compat", "--mode", "compat", "run under a compatibility layer", Support::Planned,
       "no compatibility layer; this project does static recompilation and does not claim otherwise"},
      {"mode:source-only", "--mode", "source-only", "emit source without building it", Support::Planned,
       "not wired to the pipeline"},
      {"fidelity:semantic", "--fidelity", "semantic", "preserve observable semantics", Support::Implemented, ""},
      {"fidelity:instruction", "--fidelity", "instruction", "one-to-one instruction mapping", Support::Planned,
       "no separate instruction-fidelity mode"},
      {"runtime:auto", "--runtime", "auto", "the runtime this build provides", Support::Implemented, ""},
      {"runtime:native", "--runtime", "native", "the built-in Win32 and C runtime shims", Support::Implemented, ""},
      {"runtime:compat", "--runtime", "compat", "a third-party compatibility runtime", Support::Planned,
       "no external runtime is integrated; Wine and QEMU are GPL-2.0 and are not linked"},
      {"emit:source", "--emit", "source", "generate the source project", Support::Implemented, ""},
      {"emit:binary", "--emit", "binary", "build the native executable", Support::Implemented, ""},
      {"emit:both", "--emit", "both", "generate and build", Support::Implemented, ""},
      {"emit:ir", "--emit", "ir", "emit the intermediate representation", Support::Planned,
       "the architecture-neutral IR exists internally but has no serialised form"},
      {"optimize:0", "--optimize", "0", "no optimisation", Support::Implemented, ""},
      {"optimize:1", "--optimize", "1", "basic optimisation", Support::Planned, "no optimisation pipeline"},
      {"optimize:2", "--optimize", "2", "standard optimisation", Support::Planned, "no optimisation pipeline"},
      {"optimize:3", "--optimize", "3", "aggressive optimisation", Support::Planned, "no optimisation pipeline"},
      {"output:", "--output", "", "output directory or file", Support::Implemented, ""},

      // --- verification ---------------------------------------------------
      {"verify:strict", "--verify", "strict", "require output and guest-state agreement", Support::Implemented, ""},
      {"verify:output", "--verify", "output", "require output agreement only", Support::Planned,
       "not wired; today the verdict requires guest-state agreement as well"},
      {"verify:none", "--verify", "none", "do not verify", Support::Planned, "not wired to the pipeline"},
      {"reference:auto", "--reference", "auto", "the reference engine this build provides", Support::Implemented, ""},
      {"reference:unicorn", "--reference", "unicorn", "Unicorn as the reference engine", Support::Implemented, ""},
      {"reference:qemu", "--reference", "qemu", "QEMU as the reference engine", Support::Planned,
       "not integrated; QEMU is GPL-2.0 and is not linked into this core"},
      {"reference:native", "--reference", "native", "the original binary as its own reference", Support::Planned,
       "not implemented"},
      {"checkpoints:auto", "--checkpoints", "auto", "registers and flags, with memory reported", Support::Implemented, ""},
      {"checkpoints:output", "--checkpoints", "output", "compare program output only", Support::Planned, "not wired"},
      {"checkpoints:registers", "--checkpoints", "registers", "compare registers and flags", Support::Implemented, ""},
      {"checkpoints:memory", "--checkpoints", "memory", "compare memory as a gate", Support::Planned,
       "memory is digested and reported but does not yet gate the verdict; the first comparison "
       "found an unexplained divergence"},
      {"checkpoints:full", "--checkpoints", "full", "compare registers, flags and memory", Support::Planned,
       "memory does not yet gate the verdict"},
      {"trace:", "--trace", "", "save execution traces", Support::Implemented, ""},
      {"seed:", "--seed", "", "deterministic verification seed", Support::Planned,
       "the reference is deterministic but there is no seed control"},
      {"timeout:", "--timeout", "", "execution timeout in seconds", Support::Planned,
       "an instruction budget exists; a wall-clock timeout does not"},

      // --- source generation ----------------------------------------------
      {"source-style:faithful", "--source-style", "faithful", "machine-faithful source", Support::Implemented, ""},
      {"source-style:readable", "--source-style", "readable", "restructured, readable source", Support::Planned,
       "no control-flow restructuring or type recovery"},
      {"recover-types:", "--recover-types", "", "recover types", Support::Planned, "no type recovery"},
      {"recover-symbols:", "--recover-symbols", "", "recover symbols", Support::Planned, "no symbol recovery"},
      {"preserve-metadata:", "--preserve-metadata", "", "preserve original metadata", Support::Planned,
       "no metadata reconstruction"},

      // --- execution ------------------------------------------------------
      {"buildrun:", "--buildrun", "", "build and execute the generated project", Support::Implemented, ""},
      {"repair:", "--repair", "", "enable the automated repair loop", Support::Implemented, ""},
      {"dry-run:", "--dry-run", "", "validate and preview without executing", Support::Implemented, ""},
      {"explain:", "--explain", "", "explain the selected pipeline and capabilities", Support::Implemented, ""},
      {"report-format:text", "--report-format", "text", "human-readable reports", Support::Implemented, ""},
      {"report-format:json", "--report-format", "json", "machine-readable reports", Support::Implemented, ""},
  };
  return all;
}

const Capability* find_capability(const std::string& option, const std::string& value) {
  for (const auto& capability : capabilities())
    if (capability.option == option && capability.value == value) return &capability;
  return nullptr;
}

const Capability* resolve_auto(const std::string& option) {
  return find_capability(option, "auto");
}

}  // namespace recomp::cli
