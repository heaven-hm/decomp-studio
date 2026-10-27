#pragma once

#include "core/common/configuration.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace recomp::harness {

struct RepairOptions {
  std::size_t iteration_budget{4};
  std::string agent_command;              // external coding agent (optional)
  std::filesystem::path tool_build_directory;  // rebuilt between iterations
  std::size_t trace_limit{4000000};
};

struct IterationRecord {
  std::size_t iteration{};
  std::size_t function_count{};
  std::size_t import_count{};
  std::vector<std::string> unsupported_mnemonics;
  bool built{};
  bool verified{};
  bool diverged{};
  std::uint64_t divergence_reference_address{};
  std::uint64_t divergence_candidate_address{};
  std::string divergence_instruction;
  std::string diagnosis;
};

struct RepairReport {
  bool verified{};
  std::filesystem::path output_directory;
  std::vector<IterationRecord> iterations;
  std::filesystem::path report_path;
};

RepairReport run_repair(const std::filesystem::path& input, const std::filesystem::path& output_directory,
                        const common::Configuration& configuration, const RepairOptions& options);

}  // namespace recomp::harness
