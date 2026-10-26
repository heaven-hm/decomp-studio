#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace recomp::common {

struct InstructionPatch {
  std::uint64_t address{};
  std::vector<std::uint8_t> replacement_bytes;
};

struct Configuration {
  std::string name = "recomp-project";
  std::string input_format = "auto";
  std::string architecture = "auto";
  std::string target = "native";
  bool strict_lifting = true;
  std::optional<std::uint64_t> stack_top;
  std::optional<std::uint64_t> heap_base;
  std::optional<std::uint32_t> entry_point_rva;
  std::vector<std::filesystem::path> extra_source_files;
  std::vector<std::string> compile_flags;
  std::string compiler = "clang++";
  std::filesystem::path runtime_directory;

  // Advanced, config-driven recompilation controls (N64Recomp/igi-recomp parity).
  std::vector<InstructionPatch> instruction_patches;
  std::vector<std::uint64_t> stubbed_functions;
  std::map<std::uint64_t, std::string> native_overrides;  // guest address -> host symbol

  static Configuration load(const std::filesystem::path& path);
};

std::string target_triple_for(const std::string& target);

}  // namespace recomp::common
