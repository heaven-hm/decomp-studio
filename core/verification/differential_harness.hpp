#pragma once

#include "core/binary/pe.hpp"
#include "core/common/configuration.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace recomp::verification {

struct ReferenceRun {
  std::string output;
  std::vector<std::uint64_t> trace;
  std::uint64_t instruction_count{};
};

struct DifferentialResult {
  bool completed{};
  std::string reference_output;
  std::string candidate_output;
  std::string diagnosis;
  std::uint64_t executed_instructions{};
  bool outputs_match{};
};

struct TraceComparison {
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
