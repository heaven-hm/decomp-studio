#include "core/binary/pe.hpp"
#include "core/common/configuration.hpp"
#include "core/common/diagnostic.hpp"
#include "core/common/sha256.hpp"
#include "core/discovery/function_discovery.hpp"
#include "core/pipeline.hpp"
#include "core/semantics/x86_64_lifter.hpp"
#ifdef RECOMP_HAS_UNICORN
#include "core/harness/repair_harness.hpp"
#include "core/verification/differential_harness.hpp"
#endif

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace {

constexpr const char* kVersion = "0.3.1";

#ifndef RECOMP_DEFAULT_RUNTIME_DIR
#define RECOMP_DEFAULT_RUNTIME_DIR "runtime"
#endif

std::string format_hex(std::uint64_t value, int width = 8) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::setw(width) << std::setfill('0') << value;
  return stream.str();
}

void print_help() {
  std::cout << "recomp-studio " << kVersion << "\n"
            << "Usage: recomp-studio <command> [options]\n\n"
            << "Commands:\n"
            << "  doctor                       Report host and toolchain capability\n"
            << "  inspect <image>              Inspect a PE32/PE32+ executable\n"
            << "  analyze <image>              Recover functions and instructions\n"
            << "  coverage <image>             Instruction coverage and unsupported classes\n"
            << "  functions <image>            List recovered function candidates\n"
            << "  cfg <image> --address <hex>  Export a function CFG as Graphviz DOT\n"
            << "  translate <image> --target <t> --output <dir>   Recompile to a host project\n"
            << "  build <project>              Build a generated host project\n"
            << "  run <project>                Run a generated host project\n"
            << "  verify <project>             Differentially verify a generated project\n"
            << "  repair <image> --output <dir>  Autonomous translate/build/verify/repair loop\n"
            << "  report <project>             Print the generated project manifest\n"
            << "  examples list                List bundled example profiles\n";
}

int fail(const std::string& message, bool json, int code = 1) {
  if (json) std::cout << recomp::common::to_json({"error", message, code}) << "\n";
  else std::cerr << "error: " << message << "\n";
  return code;
}

int command_doctor(bool json) {
  const auto runtime_directory = RECOMP_DEFAULT_RUNTIME_DIR;
  const bool runtime_present = std::filesystem::exists(std::filesystem::path(runtime_directory) / "recomp_runtime.hpp");
  if (json) {
    std::cout << "{\"status\":\"ok\",\"host\":\"macos\",\"target\":\"macos-arm64\",\"format\":\"pe\","
              << "\"architecture\":\"x86_64\",\"runtime_present\":" << (runtime_present ? "true" : "false") << "}\n";
  } else {
    std::cout << "host:    macos\n"
              << "target:  macos-arm64 (native)\n"
              << "input:   PE32+ x86_64\n"
              << "runtime: " << (runtime_present ? "present" : "missing") << " (" << runtime_directory << ")\n";
  }
  return 0;
}

int command_inspect(const std::filesystem::path& input, bool json) {
  const auto executable = recomp::binary::PortableExecutable::parse(input);
  const auto digest = recomp::common::sha256(executable.file_bytes);
  if (json) {
    std::cout << "{\"status\":\"ok\",\"format\":\"" << executable.format_name()
              << "\",\"architecture\":\"" << executable.architecture_name()
              << "\",\"entry_point\":" << recomp::common::quote_json(format_hex(executable.entry_point_rva))
              << ",\"image_base\":" << recomp::common::quote_json(format_hex(executable.image_base, 9))
              << ",\"sha256\":\"" << digest << "\",\"section_count\":" << executable.sections.size()
              << ",\"import_count\":" << executable.imports.size()
              << ",\"imports\":[";
    for (std::size_t index = 0; index < executable.imports.size(); ++index) {
      if (index != 0) std::cout << ",";
      std::cout << recomp::common::quote_json(executable.imports[index].library_name + "!" +
                                              executable.imports[index].symbol_name);
    }
    std::cout << "]}\n";
  } else {
    std::cout << "format:      " << executable.format_name() << " (" << executable.architecture_name() << ")\n"
              << "entry point: " << format_hex(executable.entry_point_rva) << "\n"
              << "image base:  " << format_hex(executable.image_base, 9) << "\n"
              << "sha256:      " << digest << "\n"
              << "sections:    " << executable.sections.size() << "\n"
              << "imports:     " << executable.imports.size() << "\n";
    for (const auto& imported : executable.imports)
      std::cout << "  " << imported.library_name << "!" << imported.symbol_name << "\n";
  }
  return 0;
}

int command_analyze(const std::filesystem::path& input, bool json) {
  const auto executable = recomp::binary::PortableExecutable::parse(input);
  recomp::discovery::FunctionDiscovery discovery(executable);
  discovery.discover();
  std::size_t instruction_count = 0;
  for (const auto& [address, function] : discovery.functions()) {
    (void)address;
    instruction_count += function.instructions.size();
  }
  if (json) {
    std::cout << "{\"status\":\"ok\",\"architecture\":\"" << executable.architecture_name()
              << "\",\"function_count\":" << discovery.functions().size()
              << ",\"instruction_count\":" << instruction_count << "}\n";
  } else {
    std::cout << "architecture: " << executable.architecture_name() << "\n"
              << "functions:    " << discovery.functions().size() << "\n"
              << "instructions: " << instruction_count << "\n";
  }
  return 0;
}

int command_coverage(const std::filesystem::path& input, bool json) {
  const auto executable = recomp::binary::PortableExecutable::parse(input);
  recomp::discovery::FunctionDiscovery discovery(executable);
  discovery.discover();
  recomp::semantics::X86_64Lifter lifter(discovery);
  const auto census = lifter.census();

  std::ostringstream percent;
  percent << std::fixed << std::setprecision(2) << census.coverage_percent();

  if (json) {
    std::cout << "{\"status\":\"ok\",\"architecture\":\"" << executable.architecture_name()
              << "\",\"format\":\"" << executable.format_name()
              << "\",\"function_count\":" << discovery.functions().size()
              << ",\"total_instructions\":" << census.total_instructions
              << ",\"lifted_instructions\":" << census.lifted_instructions
              << ",\"unsupported_instructions\":" << census.unsupported_instructions
              << ",\"coverage_percent\":" << percent.str()
              << ",\"unsupported_class_count\":" << census.unsupported.size()
              << ",\"unsupported\":[";
    for (std::size_t index = 0; index < census.unsupported.size(); ++index) {
      const auto& entry = census.unsupported[index];
      if (index != 0) std::cout << ",";
      std::cout << "{\"mnemonic\":" << recomp::common::quote_json(entry.mnemonic)
                << ",\"occurrences\":" << entry.occurrences
                << ",\"first_address\":" << recomp::common::quote_json(format_hex(entry.first_address, 10))
                << ",\"first_function\":" << recomp::common::quote_json(format_hex(entry.first_function_entry, 10))
                << ",\"reason\":" << recomp::common::quote_json(entry.reason) << "}";
    }
    std::cout << "]}\n";
    return 0;
  }

  std::cout << "architecture:   " << executable.architecture_name() << "\n"
            << "functions:      " << discovery.functions().size() << "\n"
            << "instructions:   " << census.total_instructions << "\n"
            << "lifted:         " << census.lifted_instructions << " (" << percent.str() << "%)\n"
            << "unsupported:    " << census.unsupported_instructions << "\n";
  if (census.unsupported.empty()) {
    std::cout << "coverage:       complete — every recovered instruction lifts\n";
    return 0;
  }
  std::cout << "classes:        " << census.unsupported.size()
            << " distinct unsupported instruction classes\n"
            << "\n"
            << "occurrences  mnemonic                    first site\n";
  for (const auto& entry : census.unsupported) {
    std::ostringstream line;
    line << std::setw(11) << std::left << entry.occurrences << "  " << std::setw(26) << std::left << entry.mnemonic
         << "  " << format_hex(entry.first_address, 10) << " in " << format_hex(entry.first_function_entry, 10);
    std::cout << line.str() << "\n";
  }
  return 0;
}

int command_functions(const std::filesystem::path& input, bool json) {
  const auto executable = recomp::binary::PortableExecutable::parse(input);
  recomp::discovery::FunctionDiscovery discovery(executable);
  discovery.discover();
  if (json) {
    std::cout << "{\"status\":\"ok\",\"functions\":[";
    bool first = true;
    for (const auto& [address, function] : discovery.functions()) {
      if (!first) std::cout << ",";
      first = false;
      std::cout << "{\"address\":" << recomp::common::quote_json(format_hex(address))
                << ",\"instruction_count\":" << function.instructions.size()
                << ",\"block_count\":" << function.block_starts.size() << "}";
    }
    std::cout << "]}\n";
  } else {
    for (const auto& [address, function] : discovery.functions())
      std::cout << format_hex(address) << "  instructions=" << function.instructions.size()
                << " blocks=" << function.block_starts.size() << "\n";
  }
  return 0;
}

int command_cfg(const std::filesystem::path& input, std::uint64_t address, bool json) {
  const auto executable = recomp::binary::PortableExecutable::parse(input);
  recomp::discovery::FunctionDiscovery discovery(executable);
  discovery.discover();
  const auto iterator = discovery.functions().find(address);
  if (iterator == discovery.functions().end()) return fail("function not found at " + format_hex(address), json);
  const auto& function = iterator->second;
  std::ostringstream dot;
  dot << "digraph cfg {\n";
  for (const auto& [instruction_address, instruction] : function.instructions) {
    dot << "  n" << std::hex << instruction_address << " [label=\"" << format_hex(instruction_address)
        << "\\n" << instruction.text << "\"];\n";
    const auto next = instruction_address + instruction.size;
    dot << "  n" << std::hex << instruction_address << " -> n" << next << ";\n";
  }
  dot << "}\n";
  if (json) {
    std::cout << "{\"status\":\"ok\",\"dot\":" << recomp::common::quote_json(dot.str()) << "}\n";
  } else {
    std::cout << dot.str();
  }
  return 0;
}

recomp::common::Configuration make_configuration(const std::filesystem::path& config_path,
                                                 const std::string& target,
                                                 const std::filesystem::path& output_directory) {
  recomp::common::Configuration configuration;
  if (!config_path.empty()) configuration = recomp::common::Configuration::load(config_path);
  if (!target.empty()) configuration.target = target;
  if (configuration.runtime_directory.empty()) configuration.runtime_directory = RECOMP_DEFAULT_RUNTIME_DIR;
  (void)output_directory;
  return configuration;
}

int command_translate(const std::filesystem::path& input, const std::filesystem::path& output,
                      const std::filesystem::path& config_path, const std::string& target, bool json) {
  const auto configuration = make_configuration(config_path, target, output);
  const auto report = recomp::pipeline::translate(input, output, configuration);
  recomp::pipeline::write_manifest(report, output);
  if (json) {
    std::cout << "{\"status\":\"ok\",\"target\":\"" << configuration.target << "\",\"output\":"
              << recomp::common::quote_json(output.string()) << ",\"function_count\":" << report.function_count
              << ",\"import_count\":" << report.import_count << ",\"unsupported_mnemonics\":"
              << report.unsupported_mnemonics.size() << "}\n";
  } else {
    std::cout << "translated " << report.function_count << " functions, " << report.import_count << " imports\n"
              << "project:  " << output.string() << "\n"
              << "source:   sha256=" << report.sha256.substr(0, 16) << "...\n";
    if (!report.unsupported_mnemonics.empty()) {
      std::cout << "unsupported mnemonics:\n";
      for (const auto& [mnemonic, count] : report.unsupported_mnemonics)
        std::cout << "  " << mnemonic << " x" << count << "\n";
    }
  }
  return 0;
}

int command_build(const std::filesystem::path& project, const std::filesystem::path& config_path, bool json) {
  auto configuration = config_path.empty() ? recomp::pipeline::load_project_configuration(project)
                                           : make_configuration(config_path, "", project);
  if (configuration.compiler.empty()) configuration.compiler = "clang++";
  if (configuration.target.empty()) configuration.target = "native";
  const auto report = recomp::pipeline::build(project, configuration);
  if (json) {
    std::cout << "{\"status\":\"ok\",\"executable\":" << recomp::common::quote_json(report.executable.string())
              << "}\n";
  } else {
    std::cout << "built " << report.executable.string() << "\n";
  }
  return 0;
}

int command_run(const std::filesystem::path& project, bool json) {
  const auto report = recomp::pipeline::run(project);
  std::cout << report.standard_output;
  if (!report.standard_error.empty()) std::cerr << report.standard_error;
  if (json) std::cout << "{\"status\":\"ok\",\"exit_code\":" << report.exit_code << "}\n";
  return report.exit_code == 0 ? 0 : report.exit_code;
}

int command_report(const std::filesystem::path& project, bool json) {
  const auto manifest_path = project / "recomp-manifest.json";
  if (!std::filesystem::exists(manifest_path)) return fail("manifest not found; run translate first", json);
  std::ifstream input(manifest_path);
  std::string manifest{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  std::cout << manifest;
  return 0;
}

#ifdef RECOMP_HAS_UNICORN
int command_verify(const std::filesystem::path& project, const std::filesystem::path& config_path, bool json) {
  auto configuration = make_configuration(config_path, "", project);
  const auto result = recomp::verification::compare_project(project, configuration);
  const bool verified = result.verified();
  if (json) {
    std::cout << "{\"status\":\"" << (verified ? "pass" : "fail")
              << "\",\"reference_completed\":" << (result.reference_completed ? "true" : "false")
              << ",\"candidate_completed\":" << (result.candidate_completed ? "true" : "false")
              << ",\"outputs_match\":" << (result.outputs_match ? "true" : "false")
              << ",\"candidate_exit_code\":" << result.candidate_exit_code
              << ",\"executed_instructions\":" << result.executed_instructions
              << ",\"reference_bytes\":" << result.reference_output.size()
              << ",\"candidate_bytes\":" << result.candidate_output.size()
              << ",\"unsupported_mnemonics\":[";
    for (std::size_t index = 0; index < result.unsupported_mnemonics.size(); ++index) {
      if (index != 0) std::cout << ",";
      std::cout << recomp::common::quote_json(result.unsupported_mnemonics[index]);
    }
    std::cout << "]}\n";
  } else {
    std::cout << "executed instructions (reference): " << result.executed_instructions << "\n"
              << "reference completed: " << (result.reference_completed ? "yes" : "no") << "\n"
              << "candidate completed: " << (result.candidate_completed ? "yes" : "no") << "\n"
              << "reference output: " << result.reference_output.size() << " bytes\n"
              << "candidate output: " << result.candidate_output.size() << " bytes\n"
              << (verified ? "VERIFY: PASS (identical output)\n" : "VERIFY: FAIL\n");
    if (!result.diagnosis.empty()) std::cout << result.diagnosis << "\n";
  }
  return verified ? 0 : 1;
}
#endif

#ifdef RECOMP_HAS_UNICORN
int command_repair(const std::filesystem::path& input, const std::filesystem::path& output,
                   const std::filesystem::path& config_path, std::size_t budget, const std::string& agent, bool json) {
  const auto configuration = make_configuration(config_path, "native", output);
  recomp::harness::RepairOptions options;
  options.iteration_budget = budget;
  options.agent_command = agent;
  if (!agent.empty()) options.tool_build_directory = "build";
  const auto report = recomp::harness::run_repair(input, output, configuration, options);
  if (json) {
    std::cout << "{\"status\":\"" << (report.verified ? "verified" : "unresolved")
              << "\",\"iterations\":" << report.iterations.size() << "}\n";
  } else {
    std::cout << "repair harness: " << report.iterations.size() << " iteration(s)\n";
    for (const auto& record : report.iterations) {
      std::cout << "  [" << record.iteration << "] functions=" << record.function_count
                << " imports=" << record.import_count << " built=" << (record.built ? "yes" : "no")
                << " verified=" << (record.verified ? "yes" : "no") << "\n";
      if (!record.diagnosis.empty()) std::cout << "      " << record.diagnosis << "\n";
    }
    std::cout << (report.verified ? "RESULT: VERIFIED\n" : "RESULT: UNRESOLVED\n");
    std::cout << "report: " << report.report_path.string() << "\n";
  }
  return report.verified ? 0 : 1;
}
#endif

int command_examples(bool json) {
  if (json) {
    std::cout << "{\"status\":\"ok\",\"profiles\":["
                 "{\"name\":\"arith\",\"kind\":\"console fixture\",\"status\":\"supported\"},"
                 "{\"name\":\"tictactoe\",\"kind\":\"game\",\"status\":\"supported\"},"
                 "{\"name\":\"snake\",\"kind\":\"game\",\"status\":\"supported\"}]}\n";
  } else {
    std::cout << "arith      console arithmetic fixture (x86_64 PE32+)\n"
                 "tictactoe  minimax AI tic-tac-toe game (x86_64 PE32+)\n"
                 "snake      deterministic snake simulation game (x86_64 PE32+)\n";
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 1) {
    print_help();
    return 0;
  }
  const std::string command{argv[1]};
  const bool json = argc >= 3 && std::string{argv[argc - 1]} == "--json";

  try {
    if (command == "--help" || command == "help") { print_help(); return 0; }
    if (command == "--version") {
      if (json) std::cout << "{\"status\":\"ok\",\"version\":\"" << kVersion << "\"}\n";
      else std::cout << kVersion << "\n";
      return 0;
    }
    if (command == "doctor") return command_doctor(json);
    if (command == "examples" && argc >= 3 && std::string{argv[2]} == "list") return command_examples(json);
    if (command == "inspect") {
      if (argc < 3) return fail("inspect requires an image path", json);
      return command_inspect(argv[2], json);
    }
    if (command == "analyze") {
      if (argc < 3) return fail("analyze requires an image path", json);
      return command_analyze(argv[2], json);
    }
    if (command == "coverage") {
      if (argc < 3) return fail("coverage requires an image path", json);
      return command_coverage(argv[2], json);
    }
    if (command == "functions") {
      if (argc < 3) return fail("functions requires an image path", json);
      return command_functions(argv[2], json);
    }
    if (command == "cfg") {
      std::filesystem::path image;
      std::uint64_t address = 0;
      for (int index = 2; index < argc; ++index) {
        const std::string option{argv[index]};
        if (option == "--json") continue;
        if (option == "--address" && index + 1 < argc) { address = std::stoull(argv[++index], nullptr, 0); continue; }
        if (image.empty()) image = argv[index];
      }
      if (image.empty() || address == 0) return fail("cfg requires <image> --address <hex>", json);
      return command_cfg(image, address, json);
    }
    if (command == "translate") {
      std::filesystem::path image, output, config;
      std::string target = "native";
      for (int index = 2; index < argc; ++index) {
        const std::string option{argv[index]};
        if (option == "--json") continue;
        if (option == "--target" && index + 1 < argc) { target = argv[++index]; continue; }
        if (option == "--output" && index + 1 < argc) { output = argv[++index]; continue; }
        if (option == "--config" && index + 1 < argc) { config = argv[++index]; continue; }
        if (image.empty()) image = argv[index];
      }
      if (image.empty() || output.empty()) return fail("translate requires <image> --output <dir>", json);
      return command_translate(image, output, config, target, json);
    }
    if (command == "build") {
      std::filesystem::path project, config;
      for (int index = 2; index < argc; ++index) {
        const std::string option{argv[index]};
        if (option == "--json") continue;
        if (option == "--config" && index + 1 < argc) { config = argv[++index]; continue; }
        if (project.empty()) project = argv[index];
      }
      if (project.empty()) return fail("build requires a project directory", json);
      return command_build(project, config, json);
    }
    if (command == "run") {
      if (argc < 3) return fail("run requires a project directory", json);
      return command_run(argv[2], json);
    }
    if (command == "verify") {
      std::filesystem::path project, config;
      for (int index = 2; index < argc; ++index) {
        const std::string option{argv[index]};
        if (option == "--json") continue;
        if (option == "--config" && index + 1 < argc) { config = argv[++index]; continue; }
        if (project.empty()) project = argv[index];
      }
      if (project.empty()) return fail("verify requires a project directory", json);
      return command_verify(project, config, json);
    }
    if (command == "repair") {
      std::filesystem::path image, output, config;
      std::size_t budget = 4;
      std::string agent;
      for (int index = 2; index < argc; ++index) {
        const std::string option{argv[index]};
        if (option == "--json") continue;
        if (option == "--output" && index + 1 < argc) { output = argv[++index]; continue; }
        if (option == "--config" && index + 1 < argc) { config = argv[++index]; continue; }
        if (option == "--budget" && index + 1 < argc) { budget = std::stoul(argv[++index]); continue; }
        if (option == "--agent" && index + 1 < argc) { agent = argv[++index]; continue; }
        if (image.empty()) image = argv[index];
      }
      if (image.empty() || output.empty()) return fail("repair requires <image> --output <dir>", json);
      return command_repair(image, output, config, budget, agent, json);
    }
    if (command == "report") {
      if (argc < 3) return fail("report requires a project directory", json);
      return command_report(argv[2], json);
    }
    return fail("unknown command: " + command, json, 2);
  } catch (const recomp::binary::ParseError& error) {
    return fail(error.what(), json);
  } catch (const std::exception& error) {
    return fail(error.what(), json);
  }
}
