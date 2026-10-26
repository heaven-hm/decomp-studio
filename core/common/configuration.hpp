#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace recomp::common {

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

  static Configuration load(const std::filesystem::path& path);
};

std::string target_triple_for(const std::string& target);

}  // namespace recomp::common
