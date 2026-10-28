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
  std::vector<std::vector<std::uint8_t>> memory_windows;
};

struct DifferentialResult {
  bool reference_completed{};     // reference executed and captured output
  bool candidate_completed{};     // candidate exited with status 0
  bool outputs_match{};
  // Guest-state comparison: how many checkpoints were compared, whether they
  // agreed, and -- when they did not -- where the machine stopped matching, which
  // is something an output comparison cannot say.
  std::size_t checkpoints_compared{};
  std::size_t checkpoints_matched{};
  std::size_t checkpoints_total{};
  bool state_match{};
  std::string state_diagnosis;
  // Guest memory is digested at every checkpoint and compared, and the result is
  // reported here rather than folded into the verdict. The first comparison found
  // a divergence in the stack window at checkpoint 1 that registers, flags and
  // output all agree on, and it is not yet explained -- so it is reported, not
  // gated. A gate that fails for a reason nobody has diagnosed either gets
  // weakened or gets ignored, and both are worse than an honest diagnostic.
  bool memory_match{true};
  std::string memory_diagnosis;
  // A difference classified as the documented x87 precision limit -- one unit in
  // the last place of a double -- rather than as an unexplained divergence. A gate
  // that cannot tell those apart either fails on every program that uses x87 or has
  // to be loosened until it catches nothing, and both are worse than naming the
  // class.
  std::size_t x87_precision_differences{};
  // Control registers -- MXCSR and the x87 control and status words -- compared at
  // every checkpoint and reported, not gated. Two of the last three divergences
  // found were control registers that a guest read and that disagreed between the
  // two sides, so they are worth comparing directly; the one found this way is not
  // yet explained, so it is a diagnostic rather than a verdict.
  bool control_registers_match{true};
  std::string control_diagnosis;
  int candidate_exit_code{};
  std::string reference_output;
  std::string candidate_output;
  std::string candidate_error;
  std::string diagnosis;
  std::uint64_t executed_instructions{};
  std::vector<std::string> unsupported_mnemonics;

  std::size_t checkpoint_match_percent() const {
    return checkpoints_total == 0 ? 0 : checkpoints_matched * 100 / checkpoints_total;
  }

  // Verification only passes when the reference completed, the candidate exited
  // cleanly, and the outputs are identical. A missing backend is never a pass.
  // A program is verified when the reference and the candidate agree on the
  // program's output *and* on the machine state at every checkpoint they both
  // reached. Output alone cannot see a wrong register, a wrong flag or a wrong
  // store that never reaches the output, so agreeing on output is not sufficient
  // -- and reporting a pass while the state disagrees would be exactly the
  // "verified because it ran" claim this project forbids.
  //
  // A comparison of zero checkpoints is not a pass. The harness enables capture
  // itself before running either side, so zero does not mean "capture was turned
  // off" -- it means the capture failed, and reporting a pass from it would be a
  // verdict issued without the measurement it claims to rest on. Any program that
  // executes at least one guest instruction records checkpoint 0, so requiring one
  // cannot reject a genuinely verified run.
  bool verified() const {
    if (!reference_completed || !candidate_completed || !outputs_match) return false;
    if (checkpoints_compared == 0) return false;
    // Memory and the control registers gate the verdict as well as the registers and
    // flags. They did not until every fixture but one agreed, and the one that does
    // not is `vex`, whose divergence is a known defect in the emulator used as the
    // reference rather than in the translation. Gating on a comparison that fails for
    // a reason nobody has diagnosed teaches people to ignore it; gating on one that
    // fails only for a documented defect is worth having.
    return state_match && memory_match && control_registers_match;
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
