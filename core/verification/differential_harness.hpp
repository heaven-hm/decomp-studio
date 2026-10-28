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
  // Set when the reference stopped at the shared instruction ceiling rather than
  // because the program terminated.
  bool truncated{};
  // Set when the reference had to compensate for an emulator limitation.
  std::string note;
  // Guest state recorded at the same checkpoints the candidate records, so the
  // two can be compared directly.
  std::vector<GuestCheckpoint> checkpoints;
  std::vector<std::vector<std::uint8_t>> memory_windows;
};

// What a verification run actually established. Issue #11 asks for an explicit verdict
// rather than a boolean, and the reason is in the list: "the two sides agreed" and "the
// reference could not model this program" and "the run was cut off at a budget" are
// three different findings that a single `false` reports identically, and the reader
// cannot tell which one they are looking at.
enum class Verdict {
  // The reference and the candidate reached an equivalent terminal condition and agreed
  // on output, machine state, memory and control registers at every checkpoint.
  VERIFIED,
  // Both sides ran and disagreed. This is a finding about the translation.
  DIVERGED,
  // The reference could not model something (an import it does not implement, an
  // instruction the emulator cannot execute). This says NOTHING about the translation:
  // there was no usable oracle.
  REFERENCE_UNSUPPORTED,
  // The candidate could not run -- a missing import, an unsupported instruction at
  // runtime, a crash. Again not a statement about correctness.
  CANDIDATE_UNSUPPORTED,
  // The run stopped before either side reached a terminal condition, so what was
  // compared is a prefix. Never a pass.
  INCOMPLETE,
  // The candidate was never executed, so nothing about it was established at all.
  NOT_RUN,
};

const char* verdict_name(Verdict verdict);

struct DifferentialResult {
  bool reference_completed{};     // reference executed and captured output
  bool candidate_completed{};
  // False when the candidate was never executed. Without this, a run that stopped
  // because the REFERENCE did not complete reported `candidate_bytes: 0` and
  // `outputs_match: false`, which reads as "the candidate ran and produced nothing" --
  // a claim about a program that was never started.
  bool candidate_ran{};     // candidate exited with status 0
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
  // Defaults to FALSE, and is set true only where a comparison actually ran. It
  // defaulted to true, so a run that compared nothing printed "guest-memory digest
  // agrees: yes" beside "checkpoints compared: 0" -- an agreement the run had not
  // established. A default that asserts agreement is the wrong way round for a gate.
  bool memory_match{};
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
  // False until a comparison runs, for the same reason as memory_match above.
  bool control_registers_match{};
  std::string control_diagnosis;
  int candidate_exit_code{};
  std::string reference_output;
  std::string candidate_output;
  std::string candidate_error;
  std::string diagnosis;
  std::uint64_t executed_instructions{};
  // Set when a side stopped because it reached the shared instruction ceiling rather
  // than because the program terminated.
  bool truncated{};
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
  // The ONE place a verdict is decided. `verify`, `autorecomp` and the repair harness
  // all read this, so they cannot disagree about what a run established -- which they
  // could when each computed its own answer from the booleans.
  Verdict verdict() const {
    // Not run is checked first: it is the strongest statement available, and every
    // other field is a default that would otherwise be read as a measurement.
    if (!candidate_ran) return Verdict::NOT_RUN;
    // A reference that could not model the program leaves no oracle. This is reported
    // as such rather than as a divergence, because calling it a divergence would blame
    // the translation for a gap in the reference.
    if (!reference_completed) return Verdict::REFERENCE_UNSUPPORTED;
    if (!candidate_completed) return Verdict::CANDIDATE_UNSUPPORTED;
    // Both sides stopped at a shared budget. What they did up to that point can be
    // compared and may agree, but a prefix is not a whole program.
    if (truncated) return Verdict::INCOMPLETE;
    if (checkpoints_compared == 0) return Verdict::INCOMPLETE;
    if (!outputs_match || !state_match || !memory_match || !control_registers_match)
      return Verdict::DIVERGED;
    return Verdict::VERIFIED;
  }

  bool verified() const { return verdict() == Verdict::VERIFIED; }

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
