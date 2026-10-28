#include "core/pipeline.hpp"

#include "core/detection/detection.hpp"

#include "core/binary/pe.hpp"
#include "core/codegen/project_generator.hpp"
#include "core/common/sha256.hpp"
#include "core/discovery/function_discovery.hpp"
#include "core/semantics/x86_64_lifter.hpp"

#include <array>
#include <cstdio>
#include <sys/types.h>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace recomp::pipeline {
namespace {

void apply_instruction_patches(binary::PortableExecutable& executable,
                               const std::vector<common::InstructionPatch>& patches) {
  for (const auto& patch : patches) {
    const auto rva = static_cast<std::uint32_t>(patch.address - executable.image_base);
    const auto offset = executable.file_offset_for_rva(rva);
    if (!offset) continue;
    for (std::size_t index = 0; index < patch.replacement_bytes.size(); ++index) {
      if (*offset + index < executable.file_bytes.size())
        executable.file_bytes[*offset + index] = patch.replacement_bytes[index];
    }
  }
}

std::string read_whole_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string quote_json(const std::string& value) {
  std::string output = "\"";
  for (const char character : value) {
    if (character == '\\' || character == '"') output.push_back('\\');
    if (character == '\n') { output += "\\n"; continue; }
    output.push_back(character);
  }
  return output + "\"";
}

int spawn_and_wait(const std::vector<std::string>& arguments) {
  std::vector<char*> raw_arguments;
  raw_arguments.reserve(arguments.size() + 1);
  for (const auto& argument : arguments) raw_arguments.push_back(const_cast<char*>(argument.c_str()));
  raw_arguments.push_back(nullptr);
  pid_t child = 0;
  const auto status = posix_spawnp(&child, raw_arguments[0], nullptr, nullptr, raw_arguments.data(), environ);
  if (status != 0) throw std::runtime_error("failed to launch " + arguments.front());
  int wait_status = 0;
  if (waitpid(child, &wait_status, 0) < 0) throw std::runtime_error("failed to wait for build process");
  return WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : 1;
}

std::string join_command(const std::vector<std::string>& arguments) {
  std::string joined;
  for (const auto& argument : arguments) {
    if (!joined.empty()) joined.push_back(' ');
    joined += argument.find(' ') != std::string::npos ? "'" + argument + "'" : argument;
  }
  return joined;
}

std::string escape_shell(const std::filesystem::path& value) {
  std::string output{"'"};
  for (const char character : value.string()) output += character == '\'' ? "'\\''" : std::string(1, character);
  return output + "'";
}

RunReport capture_process(const std::string& command, const std::filesystem::path& error_path) {
  RunReport report;
  // The generated guest and the timeout supervisor must start even when Codex,
  // CI, or a parent terminal exports a locale that is not installed on this
  // host (for example C.UTF-8 on macOS).  A C locale is available on every
  // supported POSIX host and keeps the guest's default CRT locale deterministic.
  std::string invocation = "env LC_ALL=C LANG=C sh -c " +
                           escape_shell(command + " 2> " + escape_shell(error_path));
  // The runtime loads RECOMP_STDIN_FILE into the guest-side input capture during
  // initialization. Do not also append a shell redirection here: a stale path would
  // make `/bin/sh` exit before the generated guest starts, hiding the actual guest
  // diagnostic (and turning a missing input file into a misleading exit code 1).
  if (const char* timeout_env = std::getenv("RECOMP_RUN_TIMEOUT")) {
    int seconds = std::atoi(timeout_env);
    if (seconds > 0) {
      // Keep the supervisor alive while its child runs. `exec` here would replace
      // Perl before the alarm fires, so the handler could not kill a guest that hangs
      // waiting for input; it would instead leave that child orphaned.
      invocation = "env LC_ALL=C LANG=C perl -e 'my $t=shift; my $pid=fork(); die \"fork failed\" unless defined $pid; "
                   "if (!$pid) { setpgrp; exec @ARGV; exit 127; } my $expired=0; "
                   "$SIG{ALRM}=sub { $expired=1; kill 9, -$pid; }; alarm $t; waitpid($pid,0); "
                   "my $status=$?; alarm 0; exit($expired ? 124 : (($status & 127) ? "
                   "128 + ($status & 127) : ($status >> 8)));' " +
                   std::to_string(seconds) + " sh -c " + escape_shell(invocation);
    }
  }
  FILE* stream = ::popen(invocation.c_str(), "r");
  if (stream == nullptr) throw std::runtime_error("cannot launch generated executable");
  std::array<char, 4096> buffer{};
  while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), stream) != nullptr)
    report.standard_output += buffer.data();
  const auto status = ::pclose(stream);
  if (WIFEXITED(status)) report.exit_code = WEXITSTATUS(status);
  else if (WIFSIGNALED(status)) report.exit_code = 128 + WTERMSIG(status);
  else report.exit_code = 1;
  if (std::filesystem::exists(error_path)) report.standard_error = read_whole_file(error_path);
  return report;
}

// Reads one string field out of a generated project's manifest. The manifest is
// written by this same file with a known shape, so a full JSON parser would be
// machinery for a format the project controls. A missing field returns an empty
// string rather than inventing a default, because the question being asked is
// "what did the input image call itself", and a guess is not an answer.
std::string manifest_string_field(const std::filesystem::path& project, const std::string& field) {
  const auto text = read_whole_file(project / "recomp-manifest.json");
  const auto key = "\"" + field + "\": \"";
  const auto start = text.find(key);
  if (start == std::string::npos) return {};
  const auto from = start + key.size();
  const auto end = text.find('"', from);
  if (end == std::string::npos) return {};
  return text.substr(from, end - from);
}

}  // namespace

TranslateReport translate(const std::filesystem::path& input, const std::filesystem::path& output_directory,
                          const common::Configuration& configuration) {
  // Detect before parsing, so an input this build cannot lift is named for what it
  // is and for the capability it would need, rather than reported as a parse
  // failure by the PE reader -- which is the one component guaranteed not to know.
  const auto detection = detection::detect_file(input.string());
  if (!detection.is_supported()) throw std::runtime_error(detection.unsupported_reason());
  auto executable = binary::PortableExecutable::parse(input);
  // Fail closed rather than recover functions from bytes that are not the
  // program. UPX leaves whole sections as zero padding, which decodes happily
  // as `add [eax], al` and yields a confident, wrong translation.
  if (executable.is_packed())
    throw std::runtime_error("input appears to be packed (" + executable.packing_reason +
                             "); its machine code is not present in the file, so functions cannot be "
                             "recovered. Unpack it first.");
  // A managed image is the same kind of failure in a different disguise: the
  // native code is a small stub that starts the CLR, so recovering functions
  // from it yields a confident report about a program that was never read.
  if (executable.is_managed())
    throw std::runtime_error("input is a " + executable.managed_reason +
                             "; its code is IL bytecode, not machine code, so there is nothing to "
                             "recompile. Managed images are not supported.");
  if (configuration.input_format != "auto" && configuration.input_format != "pe")
    throw std::runtime_error("unsupported input format: " + configuration.input_format);
  if (configuration.architecture != "auto" && configuration.architecture != executable.architecture_name())
    throw std::runtime_error("configured architecture does not match the input image");

  apply_instruction_patches(executable, configuration.instruction_patches);
  auto loaded_image = binary::load_image(executable, executable.image_base);
  discovery::FunctionDiscovery discovery(executable);
  discovery.discover();
  semantics::X86_64Lifter lifter(discovery);
  lifter.configure_overrides(configuration.stubbed_functions, configuration.native_overrides);
  codegen::ProjectGenerator generator(executable, discovery, lifter, loaded_image, configuration);
  const auto project = generator.generate(output_directory);

  TranslateReport report;
  report.output_directory = output_directory;
  report.guest_source = project.guest_source;
  report.function_count = project.function_count;
  report.import_count = project.import_count;
  report.unsupported_mnemonics = lifter.unsupported_mnemonics();
  report.architecture = executable.architecture_name();
  report.format = executable.format_name();
  report.sha256 = common::sha256(executable.file_bytes);
  report.image_base = executable.image_base;
  report.stack_top = project.stack_top;
  report.heap_base = project.heap_base;
  report.entry_point_rva = configuration.entry_point_rva.value_or(executable.entry_point_rva);
  report.input_path = std::filesystem::absolute(input);
  write_project_configuration(configuration, output_directory);
  return report;
}

BuildReport build(const std::filesystem::path& output_directory, const common::Configuration& configuration) {
  const auto guest_source = output_directory / "guest.cpp";
  const auto runtime_source = output_directory / "recomp_runtime.cpp";
  if (!std::filesystem::exists(guest_source) || !std::filesystem::exists(runtime_source))
    throw std::runtime_error("project is missing generated sources; run translate first");

  const auto built_executable = output_directory / "recomp-guest";
  // Clang's -O2 pass over the single generated translation unit can spend
  // minutes and exhaust memory on large recovered images. Those images are
  // already expensive to optimize as one unit; use a bounded compile strategy
  // while keeping the default optimization for normal-sized projects.
  constexpr std::uintmax_t kLargeGuestSourceBytes = 32 * 1024 * 1024;
  const auto optimization = std::filesystem::file_size(guest_source) >= kLargeGuestSourceBytes
                                ? "-O0"
                                : "-O2";
  std::vector<std::string> arguments{configuration.compiler, "-std=c++20", optimization, "-w", "-I",
                                     output_directory.string(), "-o", built_executable.string(),
                                     guest_source.string(), runtime_source.string()};
  const auto triple = common::target_triple_for(configuration.target);
  if (!triple.empty()) {
    arguments.push_back("-target");
    arguments.push_back(triple);
  }
  for (const auto& flag : configuration.compile_flags) arguments.push_back(flag);
  for (const auto& extra : configuration.extra_source_files) arguments.push_back(extra.string());

  const auto exit_code = spawn_and_wait(arguments);
  if (exit_code != 0) throw std::runtime_error("generated build failed:\n$ " + join_command(arguments));
  return {built_executable, join_command(arguments)};
}

RunReport run(const std::filesystem::path& output_directory) {
  const auto executable = output_directory / "recomp-guest";
  if (!std::filesystem::exists(executable)) throw std::runtime_error("no built executable; run build first");
  const auto error_path = std::filesystem::absolute(output_directory / "recomp-stderr.log");
  // Run from the project directory. A program that opens "savegame.dat" means the
  // one beside itself, and the app-directory policy takes the working directory as
  // its root -- so where the process starts decides which files it can reach, and
  // running a generated project from wherever the studio happened to be invoked
  // sent those reads somewhere nobody intended.
  //
  // RECOMP_APP_NAME is the input image's own filename: GetModuleFileNameA has to
  // answer with a path that ends in a name, because a program that strips the last
  // component to find its directory gets one level too high if it does not.
  const auto input_path = manifest_string_field(output_directory, "input_path");
  std::string app_name = "recomp-guest";
  if (!input_path.empty()) {
    const auto leaf = std::filesystem::path(input_path).filename().string();
    if (!leaf.empty()) app_name = leaf;
  }
  // Named explicitly rather than left to the working directory, so `run` and the
  // differential harness choose the same root for the same project.
  ::setenv("RECOMP_APP_DIR", std::filesystem::absolute(output_directory).string().c_str(), 1);
  const auto command = "cd " + escape_shell(std::filesystem::absolute(output_directory)) +
                       " && RECOMP_APP_NAME=" + escape_shell(app_name) + " " + escape_shell(executable);
  return capture_process(command, error_path);
}

void write_project_configuration(const common::Configuration& configuration,
                                 const std::filesystem::path& output_directory) {
  std::ofstream output(output_directory / "recomp-config.toml");
  output << "# Generated by recomp-studio; consumed by the build command.\n";
  output << "compiler = \"" << configuration.compiler << "\"\n";
  output << "target = \"" << configuration.target << "\"\n";
  output << "compile_flags = [";
  for (std::size_t index = 0; index < configuration.compile_flags.size(); ++index) {
    if (index != 0) output << ", ";
    output << "\"" << configuration.compile_flags[index] << "\"";
  }
  output << "]\n";
  output << "extra_sources = [";
  for (std::size_t index = 0; index < configuration.extra_source_files.size(); ++index) {
    if (index != 0) output << ", ";
    output << "\"" << configuration.extra_source_files[index].string() << "\"";
  }
  output << "]\n";
}

common::Configuration load_project_configuration(const std::filesystem::path& output_directory) {
  const auto path = output_directory / "recomp-config.toml";
  if (std::filesystem::exists(path)) {
    auto configuration = common::Configuration::load(path);
    // Was a self-assignment -- `x = x` -- so the default was never applied and a project
    // without a runtime directory in its config kept the empty one.
    if (configuration.runtime_directory.empty()) configuration.runtime_directory = RECOMP_DEFAULT_RUNTIME_DIR;
    return configuration;
  }
  return {};
}

void write_manifest(const TranslateReport& report, const std::filesystem::path& output_directory) {
  std::ofstream output(output_directory / "recomp-manifest.json");
  output << "{\n";
  output << "  \"status\": \"generated\",\n";
  output << "  \"architecture\": " << quote_json(report.architecture) << ",\n";
  output << "  \"format\": " << quote_json(report.format) << ",\n";
  output << "  \"source_sha256\": " << quote_json(report.sha256) << ",\n";
  output << "  \"image_base\": \"0x" << std::hex << report.image_base << std::dec << "\",\n";
  output << "  \"stack_top\": \"0x" << std::hex << report.stack_top << std::dec << "\",\n";
  output << "  \"heap_base\": \"0x" << std::hex << report.heap_base << std::dec << "\",\n";
  output << "  \"input_path\": " << quote_json(report.input_path.string()) << ",\n";
  output << "  \"entry_point_rva\": \"0x" << std::hex << report.entry_point_rva << std::dec << "\",\n";
  output << "  \"function_count\": " << report.function_count << ",\n";
  output << "  \"import_count\": " << report.import_count << ",\n";
  output << "  \"unsupported_mnemonics\": [";
  {
    bool first_mnemonic = true;
    for (const auto& [mnemonic, count] : report.unsupported_mnemonics) {
      (void)count;
      if (!first_mnemonic) output << ", ";
      first_mnemonic = false;
      output << quote_json(mnemonic);
    }
  }
  output << "],\n";
  output << "  \"unsupported\": {";
  bool first = true;
  for (const auto& [mnemonic, count] : report.unsupported_mnemonics) {
    if (!first) output << ",";
    first = false;
    output << "\n    " << quote_json(mnemonic) << ": " << count;
  }
  output << (first ? "" : "\n  ") << "}\n}\n";
}

}  // namespace recomp::pipeline
