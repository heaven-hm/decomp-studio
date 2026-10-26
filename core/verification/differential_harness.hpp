#pragma once

#include "core/binary/pe.hpp"
#include "core/common/configuration.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace recomp::verification {

struct ReferenceRun {
  bool completed{};               // emulation reached a terminal state
  std::string failure_reason;     // set when completed == false
  std::string output;
  std::vector<std::uint64_t> trace;
  std::uint64_t instruction_count{};
};

struct DifferentialResult {
  bool reference_completed{};     // reference executed and captured output
  bool candidate_completed{};     // candidate exited with status 0
  bool outputs_match{};
  int candidate_exit_code{};
  std::string reference_output;
  std::string candidate_output;
  std::string candidate_error;
  std::string diagnosis;
  std::uint64_t executed_instructions{};
  std::vector<std::string> unsupported_mnemonics;

  // Verification only passes when the reference completed, the candidate exited
  // cleanly, and the outputs are identical. A missing backend is never a pass.
  bool verified() const {
    return reference_completed && candidate_completed && outputs_match;
  }
};

struct TraceComparison {
  bool available{};
  bool diverged{};
  std::size_t first_divergence_index{};
  std::uint64_t reference_address{};
  std::uint64_t candidate_address{};
  std::size_t reference_steps{};
  std::size_t candidate_steps{};
};

ReferenceRun run_reference(const binary::PortableExecutable& executable,
                           const binary::LoadedImage& loaded_image,
                           std::uint64_t stack_top, std::uint64_t heap_base,
                           std::size_t trace_limit);

DifferentialResult compare_project(const std::filesystem::path& project_directory,
                                   const common::Configuration& configuration);

TraceComparison compare_execution_traces(const std::filesystem::path& project_directory,
                                         const common::Configuration& configuration,
                                         std::size_t trace_limit);

}  // namespace recomp::verification
