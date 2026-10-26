#include "core/harness/repair_harness.hpp"

#include "core/binary/pe.hpp"
#include "core/pipeline.hpp"
#include "core/verification/differential_harness.hpp"

#include <capstone/capstone.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace recomp::harness {
namespace {

std::string format_hex(std::uint64_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << value;
  return stream.str();
}

std::string decode_instruction(const binary::PortableExecutable& executable, std::uint64_t address) {
  const auto rva = static_cast<std::uint32_t>(address - executable.image_base);
  const auto bytes = executable.read_rva(rva, 16);
  csh handle = 0;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return {};
  cs_insn* instruction = nullptr;
  std::string text;
  if (cs_disasm(handle, bytes.data(), bytes.size(), address, 1, &instruction) == 1) {
    text = std::string(instruction->mnemonic) + " " + instruction->op_str;
    cs_free(instruction, 1);
  }
  cs_close(&handle);
  return text;
}

void write_iteration_report(const std::filesystem::path& directory, const IterationRecord& record) {
  std::filesystem::create_directories(directory);
  std::ofstream output(directory / ("iteration-" + std::to_string(record.iteration) + ".json"));
  output << "{\n";
  output << "  \"iteration\": " << record.iteration << ",\n";
  output << "  \"function_count\": " << record.function_count << ",\n";
  output << "  \"import_count\": " << record.import_count << ",\n";
  output << "  \"built\": " << (record.built ? "true" : "false") << ",\n";
  output << "  \"verified\": " << (record.verified ? "true" : "false") << ",\n";
  output << "  \"diverged\": " << (record.diverged ? "true" : "false") << ",\n";
  output << "  \"divergence\": {\"reference\": \"" << format_hex(record.divergence_reference_address)
         << "\", \"candidate\": \"" << format_hex(record.divergence_candidate_address)
         << "\", \"instruction\": \"" << record.divergence_instruction << "\"},\n";
  output << "  \"unsupported_mnemonics\": [";
  for (std::size_t index = 0; index < record.unsupported_mnemonics.size(); ++index) {
    if (index != 0) output << ", ";
    output << "\"" << record.unsupported_mnemonics[index] << "\"";
  }
  output << "],\n";
  output << "  \"diagnosis\": \"" << record.diagnosis << "\"\n";
  output << "}\n";
}

}  // namespace

RepairReport run_repair(const std::filesystem::path& input, const std::filesystem::path& output_directory,
                        const common::Configuration& configuration, const RepairOptions& options) {
  RepairReport report;
  report.output_directory = output_directory;
  report.report_path = output_directory / "reports" / "harness";

  for (std::size_t iteration = 1; iteration <= options.iteration_budget; ++iteration) {
    IterationRecord record;
    record.iteration = iteration;

    auto iteration_configuration = configuration;
    iteration_configuration.strict_lifting = false;
    const auto translation = pipeline::translate(input, output_directory, iteration_configuration);
    record.function_count = translation.function_count;
    record.import_count = translation.import_count;
    for (const auto& [mnemonic, count] : translation.unsupported_mnemonics) {
      (void)count;
      record.unsupported_mnemonics.push_back(mnemonic);
    }
    pipeline::write_manifest(translation, output_directory);

    try {
      pipeline::build(output_directory, configuration);
      record.built = true;
    } catch (const std::exception& error) {
      record.diagnosis = std::string("build failed: ") + error.what();
      report.iterations.push_back(record);
      write_iteration_report(report.report_path, record);
      break;
    }

    const auto verification = verification::compare_project(output_directory, configuration);
    record.verified = verification.verified();
    if (verification.verified()) {
      record.diagnosis = "candidate output is byte-identical to the reference execution";
      report.iterations.push_back(record);
      write_iteration_report(report.report_path, record);
      report.verified = true;
      break;
    }

    const auto traces = verification::compare_execution_traces(output_directory, configuration, options.trace_limit);
    record.diverged = traces.diverged;
    record.divergence_reference_address = traces.reference_address;
    record.divergence_candidate_address = traces.candidate_address;
    const auto executable = binary::PortableExecutable::parse(input);
    record.divergence_instruction = decode_instruction(executable, traces.reference_address);

    std::ostringstream diagnosis;
    diagnosis << "first control-flow divergence at step " << traces.first_divergence_index
              << ": reference executed " << format_hex(traces.reference_address) << " ("
              << record.divergence_instruction << ") while the candidate executed "
              << format_hex(traces.candidate_address);
    if (!record.unsupported_mnemonics.empty()) {
      diagnosis << "; unsupported mnemonics: ";
      for (std::size_t index = 0; index < record.unsupported_mnemonics.size(); ++index) {
        if (index != 0) diagnosis << ", ";
        diagnosis << record.unsupported_mnemonics[index];
      }
    }
    record.diagnosis = diagnosis.str();
    report.iterations.push_back(record);
    write_iteration_report(report.report_path, record);

    if (options.agent_command.empty()) break;

    std::ostringstream command;
    command << options.agent_command << " '" << (report.report_path / ("iteration-" + std::to_string(iteration) + ".json")).string() << "'";
    std::system(command.str().c_str());
    if (!options.tool_build_directory.empty()) {
      std::string rebuild = "cmake --build '" + options.tool_build_directory.string() + "'";
      std::system(rebuild.c_str());
    }
  }
  return report;
}

}  // namespace recomp::harness
