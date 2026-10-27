#pragma once

#include "core/binary/pe.hpp"
#include "core/common/configuration.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "recomp_runtime.hpp"

namespace recomp::verification {

struct ReferenceRun {
  bool completed{};               // emulation reached a terminal state
  std::string failure_reason;     // set when completed == false
  std::string output;
  std::vector<std::uint64_t> trace;
  std::uint64_t instruction_count{};
  // Set when the reference had to compensate for an emulator limitation.
  std::string note;
  // Guest state recorded at the same checkpoints the candidate records, so the
  // two can be compared directly.
  std::vector<GuestCheckpoint> checkpoints;
};

struct DifferentialResult {
  bool reference_completed{};     // reference executed and captured output
  bool candidate_completed{};     // candidate exited with status 0
  bool outputs_match{};
  // Guest-state comparison: how many checkpoints were compared, whether they
  // agreed, and -- when they did not -- where the machine stopped matching, which
  // is something an output comparison cannot say.
  std::size_t checkpoints_compared{};
  bool state_match{};
  std::string state_diagnosis;
  int candidate_exit_code{};
  std::string reference_output;
  std::string candidate_output;
  std::string candidate_error;
  std::string diagnosis;
  std::uint64_t executed_instructions{};
  std::vector<std::string> unsupported_mnemonics;

  // Verification only passes when the reference completed, the candidate exited
  // cleanly, and the outputs are identical. A missing backend is never a pass.
  // A program is verified when the reference and the candidate agree on the
  // program's output *and* on the machine state at every checkpoint they both
  // reached. Output alone cannot see a wrong register, a wrong flag or a wrong
  // store that never reaches the output, so agreeing on output is not sufficient
  // -- and reporting a pass while the state disagrees would be exactly the
  // "verified because it ran" claim this project forbids.
  //
  // Checkpoints are only required when some were actually compared: a run with
  // capture disabled is not evidence of disagreement.
  bool verified() const {
    if (!reference_completed || !candidate_completed || !outputs_match) return false;
    if (checkpoints_compared == 0) return true;
    return state_match;
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
