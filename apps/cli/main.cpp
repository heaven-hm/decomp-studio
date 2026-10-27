#include "core/binary/pe.hpp"
#include "core/common/configuration.hpp"
#include "core/common/diagnostic.hpp"
#include "core/common/sha256.hpp"
#include "core/discovery/function_discovery.hpp"
#include "core/pipeline.hpp"
#include "core/semantics/x86_64_lifter.hpp"
#include "win32_abi.hpp"
#ifdef RECOMP_HAS_UNICORN
#include "core/harness/repair_harness.hpp"
#include "core/verification/differential_harness.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <thread>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/utsname.h>
#include <unistd.h>

namespace {

constexpr const char* kVersion = "0.4.0";

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
            << "  imports <image>              Import compatibility and missing shims\n"
            << "  autorecomp <image> [--output <dir>] [--target <t>] [--buildrun] [--repair]\n"
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
    // A managed image looks like an ordinary PE until the CLR directory is read,
    // and saying so here is what stops a reader concluding it is recompilable.
    if (executable.is_managed())
      std::cout << "managed:     yes — " << executable.managed_reason
                << "; the code is IL bytecode, so it cannot be recompiled\n";
    if (executable.is_packed())
      std::cout << "packed:      yes — " << executable.packing_reason << "\n";
    for (const auto& imported : executable.imports)
      std::cout << "  " << imported.library_name << "!" << imported.symbol_name << "\n";
  }
  return 0;
}

int command_analyze(const std::filesystem::path& input, bool json) {
  const auto executable = recomp::binary::PortableExecutable::parse(input);
  // A function count for a managed image counts the CLR launcher stub, not the
  // program, so it is refused for the same reason coverage is.
  if (executable.is_managed())
    throw std::runtime_error("input is a " + executable.managed_reason +
                             "; the native code is only a CLR launcher, so a function count would "
                             "describe that stub rather than the program. Managed images are not supported.");
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
  // A coverage figure for a packed image is worse than no figure: the "code" is
  // whatever the packer left behind, so a high percentage is meaningless.
  if (executable.is_packed())
    throw std::runtime_error("input appears to be packed (" + executable.packing_reason +
                             "); instruction coverage would describe padding, not the program. "
                             "Unpack it first.");
  if (executable.is_managed())
    throw std::runtime_error("input is a " + executable.managed_reason +
                             "; the native code is only a CLR launcher, so any coverage figure would "
                             "describe that stub rather than the program. Managed images are not supported.");
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

bool is_shimmed_import(const std::string& library, const std::string& symbol) {
  for (const auto& shim : recomp::kWin32ImportAbiTable) {
    if (library == shim.library_name && symbol == shim.symbol_name) return true;
  }
  return false;
}

// Dependency and compatibility report. Instruction coverage says whether the
// code can be lifted; this says whether the program's operating-system surface
// exists. A binary can be at 100% instruction coverage and still stop on its
// first call into an unimplemented DLL, which is the case for every real
// application in the mission set.
int command_imports(const std::filesystem::path& input, bool json) {
  const auto executable = recomp::binary::PortableExecutable::parse(input);

  struct LibraryTally {
    std::size_t imports{};
    std::size_t implemented{};
  };
  std::map<std::string, LibraryTally> by_library;
  std::vector<std::pair<std::string, std::string>> missing;
  std::size_t implemented = 0;
  for (const auto& imported : executable.imports) {
    const bool shimmed = is_shimmed_import(imported.library_name, imported.symbol_name);
    auto& tally = by_library[imported.library_name];
    ++tally.imports;
    if (shimmed) {
      ++tally.implemented;
      ++implemented;
    } else {
      missing.emplace_back(imported.library_name, imported.symbol_name);
    }
  }
  const auto total = executable.imports.size();

  std::ostringstream percent;
  percent << std::fixed << std::setprecision(2)
          << (total == 0 ? 100.0 : 100.0 * static_cast<double>(implemented) / static_cast<double>(total));

  std::vector<std::pair<std::string, LibraryTally>> libraries(by_library.begin(), by_library.end());
  std::sort(libraries.begin(), libraries.end(),
            [](const auto& left, const auto& right) {
              const auto left_missing = left.second.imports - left.second.implemented;
              const auto right_missing = right.second.imports - right.second.implemented;
              if (left_missing != right_missing) return left_missing > right_missing;
              return left.first < right.first;
            });

  if (json) {
    std::cout << "{\"status\":\"ok\",\"architecture\":\"" << executable.architecture_name()
              << "\",\"library_count\":" << libraries.size()
              << ",\"import_count\":" << total
              << ",\"implemented_count\":" << implemented
              << ",\"missing_count\":" << missing.size()
              << ",\"implemented_percent\":" << percent.str()
              << ",\"libraries\":[";
    for (std::size_t index = 0; index < libraries.size(); ++index) {
      if (index != 0) std::cout << ",";
      std::cout << "{\"name\":" << recomp::common::quote_json(libraries[index].first)
                << ",\"imports\":" << libraries[index].second.imports
                << ",\"implemented\":" << libraries[index].second.implemented
                << ",\"missing\":" << (libraries[index].second.imports - libraries[index].second.implemented) << "}";
    }
    std::cout << "],\"missing\":[";
    for (std::size_t index = 0; index < missing.size(); ++index) {
      if (index != 0) std::cout << ",";
      std::cout << "{\"library\":" << recomp::common::quote_json(missing[index].first)
                << ",\"symbol\":" << recomp::common::quote_json(missing[index].second) << "}";
    }
    std::cout << "]}\n";
    return 0;
  }

  std::cout << "architecture:   " << executable.architecture_name() << "\n"
            << "libraries:      " << libraries.size() << "\n"
            << "imports:        " << total << "\n"
            << "implemented:    " << implemented << " (" << percent.str() << "%)\n"
            << "missing:        " << missing.size() << "\n";
  if (missing.empty()) {
    std::cout << "compatibility:  complete — every import has a shim\n";
    return 0;
  }
  std::cout << "\n"
            << "library                          imports  implemented  missing\n";
  for (const auto& [name, tally] : libraries) {
    std::ostringstream line;
    line << std::setw(32) << std::left << name << std::setw(9) << std::right << tally.imports
         << std::setw(13) << tally.implemented << std::setw(9) << (tally.imports - tally.implemented);
    std::cout << line.str() << "\n";
  }
  std::cout << "\nmissing imports:\n";
  for (const auto& [library, symbol] : missing) std::cout << "  " << library << "!" << symbol << "\n";
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

// ---------------------------------------------------------------------------
// autorecomp: the whole pipeline, in order, with progress, logs and repair.
// ---------------------------------------------------------------------------

constexpr const char* kReset = "\x1b[0m";
constexpr const char* kBold = "\x1b[1m";
constexpr const char* kDim = "\x1b[2m";
constexpr const char* kGreen = "\x1b[32m";
constexpr const char* kRed = "\x1b[31m";
constexpr const char* kCyan = "\x1b[36m";
constexpr const char* kYellow = "\x1b[33m";

bool stdout_is_a_terminal() { return ::isatty(STDOUT_FILENO) != 0; }

bool colour_is_enabled(bool animate) { return animate && std::getenv("NO_COLOR") == nullptr; }

// A step display that animates while a step runs and writes every step, its
// duration and its outcome to a log file. The animation is disabled whenever
// stdout is not a terminal, when --json is in use, or when NO_COLOR is set, so
// piped output stays machine-readable.
class StepDisplay {
 public:
  StepDisplay(std::size_t total, bool animate, bool colour, std::ostream& log)
      : total_(total), animate_(animate), colour_(colour), log_(log) {}

  ~StepDisplay() { stop_spinner(); }

  void begin(const std::string& label) {
    ++index_;
    label_ = label;
    started_ = std::chrono::steady_clock::now();
    log_ << "[" << index_ << "/" << total_ << "] " << label << "\n";
    log_.flush();
    if (animate_) {
      running_ = true;
      spinner_ = std::thread([this] { spin(); });
    } else if (verbose_) {
      std::cout << "[" << index_ << "/" << total_ << "] " << label << " ..." << std::endl;
    }
  }

  void finish(bool ok, const std::string& detail) {
    emit(ok ? kGreen : kRed, ok ? "✔" : "✘", ok ? "ok" : "FAILED", detail);
  }

  // A warning is not a pass. The step found something that will stop the port
  // later — missing shims, say — but the pipeline can keep going and report
  // more, so it is neither an ok nor a reason to abandon the remaining steps.
  void warn(const std::string& detail) { emit(kYellow, "⚠", "WARN", detail); }

  // Detail that belongs in the log without disturbing the animation.
  void note(const std::string& message) {
    log_ << "      " << message << "\n";
    log_.flush();
  }

  void set_verbose(bool verbose) { verbose_ = verbose; }

  std::size_t completed() const { return index_; }

 private:
  void emit(const char* accent, const char* glyph, const char* label, const std::string& detail) {
    const auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
    const bool animated = animate_;
    stop_spinner();
    if (verbose_) {
      if (animated) std::cout << "\r\x1b[2K";
      std::ostringstream line;
      line << (colour_ ? accent : "") << glyph << (colour_ ? kReset : "") << " " << (colour_ ? kDim : "") << "["
           << index_ << "/" << total_ << "]" << (colour_ ? kReset : "") << " " << (colour_ ? kBold : "") << label_
           << (colour_ ? kReset : "");
      if (!detail.empty()) line << " — " << detail;
      line << (colour_ ? kDim : "") << " (" << std::fixed << std::setprecision(2) << seconds << "s)"
           << (colour_ ? kReset : "");
      std::cout << line.str() << "\n";
      std::cout.flush();
    }
    log_ << "    " << label << ": " << detail << " (" << std::fixed << std::setprecision(3) << seconds << "s)\n";
    log_.flush();
  }

  void spin() {
    static const char* frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
    std::size_t frame = 0;
    while (running_) {
      const auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
      std::ostringstream line;
      line << "\r\x1b[2K" << (colour_ ? kCyan : "") << frames[frame++ % 10] << (colour_ ? kReset : "") << " "
           << (colour_ ? kDim : "") << "[" << index_ << "/" << total_ << "]" << (colour_ ? kReset : "") << " "
           << (colour_ ? kBold : "") << label_ << (colour_ ? kReset : "") << " " << (colour_ ? kYellow : "")
           << std::fixed << std::setprecision(1) << seconds << "s" << (colour_ ? kReset : "");
      std::cout << line.str() << std::flush;
      std::this_thread::sleep_for(std::chrono::milliseconds(80));
    }
  }

  void stop_spinner() {
    running_ = false;
    if (spinner_.joinable()) spinner_.join();
  }

  std::size_t total_{};
  std::size_t index_{};
  bool animate_{};
  bool colour_{};
  bool verbose_{true};
  std::ostream& log_;
  std::string label_;
  std::atomic<bool> running_{false};
  std::thread spinner_;
  std::chrono::steady_clock::time_point started_{};
};

struct HostTarget {
  std::string operating_system;
  std::string architecture;
  std::string target;
};

// Detect the host the studio is running on and map it to a target name. This is
// runtime detection through uname rather than a compile-time guess, so the
// reported target is what the machine actually is.
HostTarget detect_host_target() {
  struct utsname information {};
  if (::uname(&information) != 0) throw std::runtime_error("cannot determine the host operating system");
  const std::string system_name = information.sysname;
  const std::string machine = information.machine;
  std::string architecture = machine;
  if (machine == "arm64" || machine == "aarch64") architecture = "arm64";
  else if (machine == "x86_64" || machine == "amd64") architecture = "x86_64";

  std::string target;
  if (system_name == "Darwin") target = architecture == "arm64" ? "macos-arm64" : "macos-x86_64";
  else if (system_name == "Linux") target = architecture == "arm64" ? "linux-arm64" : "linux-x86_64";
  if (target.empty())
    throw std::runtime_error("no native target for host " + system_name + "/" + machine +
                             "; pass --target explicitly");
  return {system_name, architecture, target};
}

int command_autorecomp(const std::filesystem::path& input, const std::filesystem::path& output,
                       const std::string& requested_target, bool repair, bool build_and_run, bool json,
                       std::size_t repair_budget) {
  const bool animate = stdout_is_a_terminal() && !json;
  const bool colour = colour_is_enabled(animate);
  std::filesystem::create_directories(output);
  const auto log_path = output / "autorecomp.log";
  std::ofstream log_file(log_path, std::ios::trunc);
  if (!log_file) throw std::runtime_error("cannot open the log file " + log_path.string());

  std::size_t total = 7;  // detect inspect analyze coverage imports translate build
  if (build_and_run) total += 2;
  if (repair) total += 1;

  log_file << "recomp-studio autorecomp\n"
           << "  input   : " << std::filesystem::absolute(input).string() << "\n"
           << "  output  : " << std::filesystem::absolute(output).string() << "\n"
           << "  target  : " << (requested_target.empty() ? "detect" : requested_target) << "\n"
           << "  mode    : " << (build_and_run ? "build and run" : "build only") << "\n"
           << "  repair  : " << (repair ? "on" : "off") << "\n\n";

  StepDisplay display(total, animate, colour, log_file);
  display.set_verbose(!json);
  if (!json && animate) {
    std::cout << (colour ? kBold : "") << "recomp-studio autorecomp" << (colour ? kReset : "") << "  "
              << (colour ? kDim : "") << std::filesystem::path(input).filename().string() << " -> "
              << (requested_target.empty() ? "native host" : requested_target) << (colour ? kReset : "")
              << "\n\n";
  }

  std::string failure;
  auto fail_step = [&](const std::string& detail) {
    if (failure.empty()) failure = detail;
  };

  // 1. detect ---------------------------------------------------------------
  std::string target = requested_target;
  display.begin("detect host and target");
  try {
    const auto host = detect_host_target();
    if (target.empty()) target = host.target;
    display.note("host " + host.operating_system + "/" + host.architecture + " -> target " + target);
    display.finish(true, host.operating_system + "/" + host.architecture + ", target " + target);
  } catch (const std::exception& error) {
    display.finish(false, error.what());
    fail_step(error.what());
  }

  // Everything below needs the target, so stop here if detection failed.
  recomp::binary::PortableExecutable executable;
  if (failure.empty()) {
    display.begin("inspect executable");
    try {
      executable = recomp::binary::PortableExecutable::parse(input);
      const auto digest = recomp::common::sha256(executable.file_bytes);
      display.note("format " + executable.format_name() + ", architecture " + executable.architecture_name() +
                   ", entry " + format_hex(executable.entry_point_rva) + ", image base " +
                   format_hex(executable.image_base, 9));
      display.note("sha256 " + digest);
      display.finish(true, executable.format_name() + " " + executable.architecture_name() + ", " +
                               std::to_string(executable.imports.size()) + " imports");
    } catch (const std::exception& error) {
      display.finish(false, error.what());
      fail_step(error.what());
    }
  }

  std::size_t function_count = 0;
  std::size_t instruction_count = 0;
  if (failure.empty()) {
    display.begin("recover functions");
    try {
      recomp::discovery::FunctionDiscovery discovery(executable);
      discovery.discover();
      function_count = discovery.functions().size();
      for (const auto& [address, function] : discovery.functions()) {
        (void)address;
        instruction_count += function.instructions.size();
      }
      display.note(std::to_string(function_count) + " functions, " + std::to_string(instruction_count) +
                   " instructions");
      display.finish(true, std::to_string(function_count) + " functions, " +
                               std::to_string(instruction_count) + " instructions");
    } catch (const std::exception& error) {
      display.finish(false, error.what());
      fail_step(error.what());
    }
  }

  std::size_t unsupported = 0;
  std::size_t unsupported_classes = 0;
  if (failure.empty()) {
    display.begin("classify instruction coverage");
    try {
      recomp::discovery::FunctionDiscovery discovery(executable);
      discovery.discover();
      recomp::semantics::X86_64Lifter lifter(discovery);
      const auto census = lifter.census();
      unsupported = census.unsupported_instructions;
      unsupported_classes = census.unsupported.size();
      std::ostringstream detail;
      detail << census.lifted_instructions << "/" << census.total_instructions << " lifted, " << unsupported
             << " unsupported";
      for (std::size_t index = 0; index < census.unsupported.size() && index < 5; ++index)
        display.note("unsupported " + census.unsupported[index].mnemonic + " x" +
                     std::to_string(census.unsupported[index].occurrences));
      display.finish(true, detail.str());
    } catch (const std::exception& error) {
      display.finish(false, error.what());
      fail_step(error.what());
    }
  }

  bool translated = false;
  std::size_t missing_imports = 0;
  if (failure.empty()) {
    display.begin("check import compatibility");
    try {
      std::size_t implemented = 0;
      for (const auto& imported : executable.imports)
        if (is_shimmed_import(imported.library_name, imported.symbol_name)) ++implemented;
      missing_imports = executable.imports.size() - implemented;
      display.note(std::to_string(implemented) + " of " + std::to_string(executable.imports.size()) +
                   " imports have shims");
      const auto summary = std::to_string(implemented) + "/" + std::to_string(executable.imports.size()) +
                           " imports shimmed, " + std::to_string(missing_imports) + " missing";
      if (missing_imports == 0) {
        display.finish(true, summary);
      } else {
        display.warn(summary);
        display.note("the recompiled program will stop at the first call into an unshimmed import");
        display.note("run `recomp-studio imports " + input.string() + "` for the full list");
      }
    } catch (const std::exception& error) {
      display.finish(false, error.what());
      fail_step(error.what());
    }
  }

  if (failure.empty()) {
    display.begin("translate to host source");
    try {
      const auto configuration = make_configuration({}, target, output);
      const auto report = recomp::pipeline::translate(input, output, configuration);
      recomp::pipeline::write_manifest(report, output);
      translated = true;
      display.note("project written to " + std::filesystem::absolute(output).string());
      display.finish(true, std::to_string(report.function_count) + " functions, " +
                               std::to_string(report.import_count) + " imports");
    } catch (const std::exception& error) {
      display.finish(false, error.what());
      fail_step(error.what());
    }
  }

  std::filesystem::path built_executable;
  if (failure.empty()) {
    display.begin("build native executable");
    try {
      auto configuration = recomp::pipeline::load_project_configuration(output);
      if (configuration.compiler.empty()) configuration.compiler = "clang++";
      if (configuration.target.empty()) configuration.target = target;
      const auto report = recomp::pipeline::build(output, configuration);
      built_executable = report.executable;
      display.note("command: " + report.command);
      display.finish(true, report.executable.filename().string());
    } catch (const std::exception& error) {
      display.finish(false, error.what());
      fail_step(error.what());
    }
  }

  int run_exit_code = 0;
  bool verified = false;
  if (failure.empty() && build_and_run) {
    display.begin("run native executable");
    try {
      const auto report = recomp::pipeline::run(output);
      run_exit_code = report.exit_code;
      log_file << "---- program output ----\n" << report.standard_output;
      if (!report.standard_error.empty()) log_file << "---- program stderr ----\n" << report.standard_error;
      log_file << "---- end program output ----\n";
      log_file.flush();
      if (!report.standard_output.empty()) display.note("program produced " +
                                                        std::to_string(report.standard_output.size()) + " bytes");
      display.finish(report.exit_code == 0,
                     "exit code " + std::to_string(report.exit_code) + ", " +
                         std::to_string(report.standard_output.size()) + " bytes of output");
      if (report.exit_code != 0) {
        display.note("the program ran but exited non-zero, so the port is not verified");
        fail_step("the translated program exited with code " + std::to_string(report.exit_code));
      }
    } catch (const std::exception& error) {
      display.finish(false, error.what());
      display.note("the translated program could not be executed; see the log for the pipeline's own output");
      fail_step(error.what());
    }
  }

  if (build_and_run && translated) {
    display.begin("verify against the reference");
#ifdef RECOMP_HAS_UNICORN
    try {
      auto configuration = recomp::pipeline::load_project_configuration(output);
      if (configuration.target.empty()) configuration.target = target;
      const auto result = recomp::verification::compare_project(output, configuration);
      verified = result.verified();
      display.note("reference executed " + std::to_string(result.executed_instructions) + " instructions");
      if (!result.diagnosis.empty()) display.note(result.diagnosis);
      display.finish(verified, verified
                                  ? "outputs match byte for byte"
                                  : "reference_completed=" +
                                        std::string(result.reference_completed ? "yes" : "no") +
                                        " candidate_completed=" +
                                        std::string(result.candidate_completed ? "yes" : "no") +
                                        " outputs_match=" + std::string(result.outputs_match ? "yes" : "no"));
      if (!verified) {
        fail_step("differential verification did not pass");
        display.note("run `recomp-studio verify " + output.string() + "` for the full report");
      }
    } catch (const std::exception& error) {
      display.finish(false, error.what());
      fail_step(error.what());
    }
#else
    display.finish(false, "the verification backend was not compiled in");
    display.note("rebuild with Unicorn available (brew install unicorn) to enable differential verification");
#endif
  }

  bool repaired = false;
  if (repair && translated) {
    display.begin("repair loop");
#ifdef RECOMP_HAS_UNICORN
    try {
      const auto configuration = make_configuration({}, target, output);
      recomp::harness::RepairOptions options;
      options.iteration_budget = repair_budget;
      const auto report = recomp::harness::run_repair(input, output, configuration, options);
      repaired = report.verified;
      for (const auto& record : report.iterations)
        display.note("iteration " + std::to_string(record.iteration) + ": built=" +
                     (record.built ? "yes" : "no") + " verified=" + (record.verified ? "yes" : "no") +
                     (record.diagnosis.empty() ? "" : " — " + record.diagnosis));
      display.note("report: " + report.report_path.string());
      display.finish(repaired, std::to_string(report.iterations.size()) + " iteration(s), " +
                                  (repaired ? "verified" : "unresolved"));
      if (!repaired) fail_step("the repair loop did not reach a verified translation");
    } catch (const std::exception& error) {
      display.finish(false, error.what());
      display.note("the repair harness needs a buildable project; see the log");
    }
#else
    display.finish(false, "the repair harness was not compiled in");
#endif
  }

  // Success means the requested pipeline finished *and*, when the program was
  // run, that it was verified. A program that builds and then fails to run is
  // not a port, and reporting COMPLETE for it would be exactly the kind of
  // claim this project refuses to make.
  const bool ok = failure.empty() && (!build_and_run || verified);
  if (json) {
    std::cout << "{\"status\":\"" << (ok ? "ok" : "error") << "\",\"target\":"
              << recomp::common::quote_json(target) << ",\"output\":"
              << recomp::common::quote_json(std::filesystem::absolute(output).string())
              << ",\"build_and_run\":" << (build_and_run ? "true" : "false")
              << ",\"repair\":" << (repair ? "true" : "false")
              << ",\"function_count\":" << function_count
              << ",\"instruction_count\":" << instruction_count
              << ",\"unsupported_instructions\":" << unsupported
              << ",\"unsupported_class_count\":" << unsupported_classes
              << ",\"missing_imports\":" << missing_imports
              << ",\"built\":" << (built_executable.empty() ? "false" : "true")
              << ",\"run_exit_code\":" << run_exit_code
              << ",\"verified\":" << (verified ? "true" : "false")
              << ",\"repaired\":" << (repaired ? "true" : "false")
              << ",\"log\":" << recomp::common::quote_json(log_path.string());
    if (!ok) std::cout << ",\"error\":" << recomp::common::quote_json(failure);
    std::cout << "}\n";
  } else {
    std::cout << "\n" << (colour ? kBold : "")
              << (ok ? (colour ? kGreen : "") : (colour ? kRed : ""))
              << (ok ? "AUTORECOMP COMPLETE" : "AUTORECOMP FAILED") << (colour ? kReset : "") << "\n"
              << "  target      " << target << "\n"
              << "  project     " << std::filesystem::absolute(output).string() << "\n"
              << "  functions   " << function_count << "  instructions " << instruction_count << "\n"
              << "  coverage    " << (instruction_count == 0 ? 100.0
                                                             : 100.0 * static_cast<double>(instruction_count - unsupported) /
                                                                   static_cast<double>(instruction_count))
              << "%  (" << unsupported << " unsupported in " << unsupported_classes << " classes)\n"
              << "  imports     " << missing_imports << " without shims\n";
    if (!built_executable.empty()) std::cout << "  executable  " << built_executable.string() << "\n";
    if (build_and_run) std::cout << "  run         exit code " << run_exit_code << "\n";
    if (build_and_run) std::cout << "  verified    " << (verified ? "yes" : "no") << "\n";
    if (repair) std::cout << "  repaired    " << (repaired ? "yes" : "no") << "\n";
    std::cout << "  log         " << log_path.string() << "\n";
    if (!ok) std::cout << "\n" << (colour ? kRed : "") << "error: " << failure << (colour ? kReset : "") << "\n";
  }
  log_file << "\nresult: " << (ok ? "ok" : "failed") << (failure.empty() ? "" : " — " + failure) << "\n";
  return ok ? 0 : 1;
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
    if (command == "imports") {
      if (argc < 3) return fail("imports requires an image path", json);
      return command_imports(argv[2], json);
    }
    if (command == "autorecomp") {
      std::filesystem::path image, output;
      std::string target;
      bool repair = false, build_and_run = false;
      std::size_t budget = 4;
      for (int index = 2; index < argc; ++index) {
        const std::string option{argv[index]};
        if (option == "--json") continue;
        if (option == "--repair") { repair = true; continue; }
        if (option == "--buildrun") { build_and_run = true; continue; }
        if (option == "--target" && index + 1 < argc) { target = argv[++index]; continue; }
        if (option == "--output" && index + 1 < argc) { output = argv[++index]; continue; }
        if (option == "--budget" && index + 1 < argc) { budget = std::stoul(argv[++index]); continue; }
        if (image.empty()) image = argv[index];
      }
      if (image.empty()) return fail("autorecomp requires an image path", json);
      if (output.empty()) output = std::filesystem::path("out") / image.stem();
      return command_autorecomp(image, output, target, repair, build_and_run, json, budget);
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
