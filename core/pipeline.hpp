#pragma once

#include "core/common/configuration.hpp"
#include "core/semantics/high_level_reconstruction.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace recomp::pipeline {

struct TranslateReport {
  std::filesystem::path output_directory;
  std::filesystem::path guest_source;
  std::size_t function_count{};
  std::size_t import_count{};
  std::map<std::string, int> unsupported_mnemonics;
  std::string architecture;
  std::string format;
  std::string sha256;
  std::uint64_t image_base{};
  std::uint64_t stack_top{};
  std::uint64_t heap_base{};
  std::uint32_t entry_point_rva{};
  std::size_t high_level_function_count{};
  std::size_t low_level_fallback_count{};
  std::size_t unresolved_function_count{};
  std::size_t policy_override_count{};
  double high_level_percent{};
  std::string source_mode;
  std::string source_quality;
  std::vector<semantics::FunctionSourceRecord> source_records;
  std::vector<std::filesystem::path> source_files;
  std::filesystem::path input_path;
};

struct BuildReport {
  std::filesystem::path executable;
  std::string command;
};

struct RunReport {
  int exit_code{};
  std::string standard_output;
  std::string standard_error;
};

TranslateReport translate(const std::filesystem::path& input, const std::filesystem::path& output_directory,
                          const common::Configuration& configuration);
BuildReport build(const std::filesystem::path& output_directory, const common::Configuration& configuration,
                  bool enforce_source_manifest = true);
RunReport run(const std::filesystem::path& output_directory);
void write_manifest(const TranslateReport& report, const std::filesystem::path& output_directory);
void write_project_configuration(const common::Configuration& configuration, const std::filesystem::path& output_directory);
common::Configuration load_project_configuration(const std::filesystem::path& output_directory);

}  // namespace recomp::pipeline
