#include "core/cli/options.hpp"

#include <algorithm>
#include <sstream>

namespace recomp::cli {
namespace {

// Every option the CLI declares. The defaults here are the ones the help text
// prints and the ones parse() fills in, so a documented default cannot be a
// default the parser does not apply.
const std::vector<OptionSpec>& specs() {
  static const std::vector<OptionSpec> all = {
      // --- Common Options -------------------------------------------------
      {"--source-os", "<os>", "Source operating system", ValueKind::Enum,
       {"auto", "windows", "linux", "macos"}, "auto", "Common Options", true},
      {"--source-arch", "<arch>", "Source CPU architecture", ValueKind::Enum,
       {"auto", "x86", "x64", "arm64", "arm32", "riscv64"}, "auto", "Common Options", true},
      {"--source-lang", "<lang>", "Source language", ValueKind::Enum,
       {"auto", "native", "c", "cpp", "rust", "go", "csharp", "java", "python"}, "auto", "Common Options", true},
      {"--target-os", "<os>", "Target operating system", ValueKind::Enum,
       {"auto", "windows", "linux", "macos"}, "auto", "Common Options", true},
      {"--target-arch", "<arch>", "Target CPU architecture", ValueKind::Enum,
       {"auto", "x86", "x64", "arm64", "arm32", "riscv64"}, "auto", "Common Options", true},
      {"--output-lang", "<lang>", "Source language to generate", ValueKind::Enum,
       {"auto", "cpp", "c", "rust", "llvm-ir", "csharp", "java", "python"}, "cpp", "Common Options", true},

      // --- Recompilation Options ------------------------------------------
      {"--mode", "<mode>", "Recompilation mode", ValueKind::Enum,
       {"recompile", "compat", "source-only"}, "recompile", "Recompilation Options", true},
      {"--fidelity", "<level>", "Fidelity level", ValueKind::Enum,
       {"semantic", "instruction"}, "semantic", "Recompilation Options", true},
      {"--runtime", "<type>", "Runtime to use", ValueKind::Enum,
       {"auto", "native", "compat"}, "auto", "Recompilation Options", true},
      {"--emit", "<type>", "What to emit", ValueKind::Enum,
       {"source", "binary", "both", "ir"}, "both", "Recompilation Options", true},
      {"--optimize", "<level>", "Optimisation level", ValueKind::Enum,
       {"0", "1", "2", "3"}, "0", "Recompilation Options", true},
      {"--output", "<path>", "Output directory or file", ValueKind::Path, {}, "", "Recompilation Options", false},

      // --- Verification Options -------------------------------------------
      {"--verify", "<level>", "Verification level", ValueKind::Enum,
       {"strict", "output", "none"}, "strict", "Verification Options", true},
      {"--reference", "<engine>", "Reference engine", ValueKind::Enum,
       {"auto", "unicorn", "qemu", "native"}, "auto", "Verification Options", true},
      {"--checkpoints", "<type>", "Checkpoint comparison", ValueKind::Enum,
       {"auto", "output", "registers", "memory", "full"}, "auto", "Verification Options", true},
      {"--trace", "", "Save execution traces", ValueKind::Flag, {}, "", "Verification Options", false},
      {"--seed", "<number>", "Deterministic verification seed", ValueKind::Integer, {}, "", "Verification Options", true},
      {"--timeout", "<seconds>", "Execution timeout", ValueKind::Integer, {}, "", "Verification Options", false},

      // --- Source Generation ----------------------------------------------
      {"--source-mode", "<mode>", "Source reconstruction mode", ValueKind::Enum,
       {"low-level", "hybrid"}, "low-level", "Source Generation", true},
      {"--source-quality", "<level>", "Minimum acceptable source quality", ValueKind::Enum,
       {"any", "human-readable"}, "any", "Source Generation", true},
      {"--source-style", "<style>", "Source style", ValueKind::Enum,
       {"faithful", "readable"}, "faithful", "Source Generation", true},
      {"--recover-types", "", "Enable type recovery", ValueKind::Flag, {}, "", "Source Generation", true},
      {"--recover-symbols", "", "Enable symbol recovery", ValueKind::Flag, {}, "", "Source Generation", true},
      {"--preserve-metadata", "", "Preserve available original metadata", ValueKind::Flag, {}, "", "Source Generation", true},

      // --- Execution Options ----------------------------------------------
      {"--buildrun", "", "Build and execute the generated project", ValueKind::Flag, {}, "", "Execution Options", false},
      {"--repair", "", "Enable automated repair", ValueKind::Flag, {}, "", "Execution Options", false},
      {"--autorepair", "", "Alias for --repair", ValueKind::Flag, {}, "", "Execution Options", false},
      {"--dry-run", "", "Validate and preview without execution", ValueKind::Flag, {}, "", "Execution Options", false},
      // The source manifest proves the delivered source IS the built source. This flag turns
      // that check off, for a caller that is DELIBERATELY modifying generated sources -- the
      // heap-corruption mutation test patches the project's runtime and rebuilds. It is named
      // rather than silent so the weakening is visible in the command and in the warning the
      // build prints, and it is not the default.
      {"--allow-modified-sources", "", "Build even if sources do not match the manifest", ValueKind::Flag, {}, "", "Execution Options", false},
      {"--explain", "", "Explain the selected pipeline and capabilities", ValueKind::Flag, {}, "", "Execution Options", false},
      {"--report-format", "<format>", "Report format", ValueKind::Enum,
       {"text", "json"}, "text", "Execution Options", true},
      {"--help", "", "Show this help", ValueKind::Flag, {}, "", "Execution Options", false},

      // --- options that existed before the table did ----------------------
      // Declared here so the central parser accepts them rather than rejecting
      // commands that have worked for several releases. They are not capability
      // checked: they select no backend and no architecture.
      {"--json", "", "Machine-readable output", ValueKind::Flag, {}, "", "Execution Options", false},
      {"--target", "<triple>", "Target triple (macos-arm64, macos-x86_64)", ValueKind::Text, {}, "", "Execution Options", false},
      {"--config", "<path>", "Project configuration file", ValueKind::Path, {}, "", "Execution Options", false},
      {"--address", "<hex>", "Function address, for cfg", ValueKind::Text, {}, "", "Execution Options", false},
      {"--budget", "<n>", "Instruction budget, for autorecomp", ValueKind::Integer, {}, "", "Execution Options", false},
      {"--agent", "<command>", "External repair agent command", ValueKind::Text, {}, "", "Execution Options", false},
  };
  return all;
}

}  // namespace

const std::vector<OptionSpec>& option_specs() { return specs(); }

const OptionSpec* find_option_spec(const std::string& name) {
  for (const auto& spec : specs())
    if (spec.name == name) return &spec;
  return nullptr;
}

std::string ParsedOptions::get(const std::string& name) const {
  const auto found = values.find(name);
  if (found != values.end()) return found->second;
  const auto* spec = find_option_spec(name);
  return spec == nullptr ? std::string{} : spec->default_value;
}

int ParsedOptions::integer(const std::string& name) const {
  const auto text = get(name);
  if (text.empty()) return 0;
  try {
    return std::stoi(text);
  } catch (const std::exception&) {
    throw UsageError(name + " expects a number, got '" + text + "'");
  }
}

ParsedOptions parse(const std::vector<std::string>& arguments) {
  ParsedOptions options;
  // Every declared option starts at its declared default, so a caller reading an
  // option that was not given gets the documented value rather than an empty
  // string it has to interpret.
  for (const auto& spec : specs()) options.values[spec.name] = spec.default_value;

  std::size_t index = 0;
  if (!arguments.empty() && !arguments.front().empty() && arguments.front()[0] != '-') {
    options.command = arguments.front();
    index = 1;
  }

  for (; index < arguments.size(); ++index) {
    const auto& argument = arguments[index];
    if (argument == "--") {
      for (++index; index < arguments.size(); ++index) options.positional.push_back(arguments[index]);
      break;
    }
    if (argument.size() < 2 || argument[0] != '-') {
      options.positional.push_back(argument);
      continue;
    }

    std::string name = argument;
    std::string inline_value;
    const auto equals = argument.find('=');
    if (equals != std::string::npos) {
      name = argument.substr(0, equals);
      inline_value = argument.substr(equals + 1);
    }

    const auto* spec = find_option_spec(name);
    if (spec == nullptr)
      throw UsageError("unknown option '" + name + "'; run 'recomp-studio --help' for the options this build declares");

    if (spec->kind == ValueKind::Flag) {
      if (!inline_value.empty())
        throw UsageError(name + " is a flag and takes no value");
      options.values[name] = "true";
      continue;
    }

    std::string value = inline_value;
    if (value.empty()) {
      if (index + 1 >= arguments.size())
        throw UsageError(name + " expects a value " + spec->placeholder);
      value = arguments[++index];
    }

    if (spec->kind == ValueKind::Enum &&
        std::find(spec->allowed.begin(), spec->allowed.end(), value) == spec->allowed.end()) {
      std::string allowed;
      for (const auto& candidate : spec->allowed) allowed += (allowed.empty() ? "" : "|") + candidate;
      throw UsageError(name + " does not accept '" + value + "'; it accepts " + allowed);
    }
    if (spec->kind == ValueKind::Integer) {
      try {
        std::stoll(value);
      } catch (const std::exception&) {
        throw UsageError(name + " expects a number, got '" + value + "'");
      }
    }
    options.values[name] = value;
  }
  return options;
}

void validate_capabilities(const ParsedOptions& options) {
  for (const auto& spec : specs()) {
    if (!spec.capability_checked) continue;
    const auto found = options.values.find(spec.name);
    if (found == options.values.end()) continue;
    const auto& value = found->second;
    // A flag that was not given is its empty default and asks for nothing.
    if (spec.kind == ValueKind::Flag && value != "true") continue;
    if (spec.kind != ValueKind::Flag && value.empty()) continue;

    const auto* capability = find_capability(spec.name, value);
    if (capability == nullptr) {
      // Declared in the option table but absent from the capability table is a bug
      // in this build, not in the command line, and it must not read as "fine".
      throw UnsupportedError(spec.name + "=" + value +
                             " has no declared capability; this is a build defect, not a supported request");
    }
    if (capability->support == Support::Planned) {
      throw UnsupportedError(spec.name + " " + value + " is not supported by this build" +
                             (capability->note.empty() ? "" : ": " + capability->note));
    }
  }
}

std::string render_help() {
  std::ostringstream text;
  text << "recomp-studio 0.5.0\n"
       << "Usage: recomp-studio <command> [options]\n\n"
       << "Commands:\n"
       << "  doctor                       Report host and toolchain capability\n"
       << "  inspect <image>              Inspect executable and detect binary format\n"
       << "  analyze <image>              Recover functions and instructions\n"
       << "  coverage <image>             Instruction coverage and unsupported classes\n"
       << "  imports <image>              Import compatibility and missing shims\n"
       << "  autorecomp <image>           Automatic recompilation pipeline\n"
       << "  functions <image>            List recovered function candidates\n"
       << "  cfg <image> --address <hex>  Export a function CFG as Graphviz DOT\n"
       << "  translate <image>            Generate source and host project\n"
       << "  build <project>              Build generated host project\n"
       << "  run <project>                Run generated host project\n"
       << "  verify <project>             Differentially verify generated project\n"
       << "  repair <image>               Autonomous repair loop\n"
       << "  report <project>             Print project manifest\n"
       << "  examples list                List bundled example profiles\n"
       << "  capabilities                 List supported and planned capabilities\n"
       << "  detect <image>               Detect OS, CPU, binary format and runtime\n"
       << "  backends list                List registered source and target backends\n\n";

  // Grouped from the table, in table order, so the headings and their contents
  // cannot disagree with what the parser accepts.
  std::vector<std::string> groups;
  for (const auto& spec : specs())
    if (std::find(groups.begin(), groups.end(), spec.group) == groups.end()) groups.push_back(spec.group);

  for (const auto& group : groups) {
    text << group << ":\n";
    for (const auto& spec : specs()) {
      if (spec.group != group) continue;
      std::string left = "  " + spec.name;
      if (!spec.placeholder.empty()) left += " " + spec.placeholder;
      while (left.size() < 30) left += ' ';
      text << left << spec.summary << "\n";
    }
    text << "\n";
  }

  text << "Defaults:\n";
  for (const auto& spec : specs()) {
    if (spec.default_value.empty()) continue;
    std::string left = "  " + spec.name.substr(2);
    while (left.size() < 18) left += ' ';
    text << left << spec.default_value << "\n";
  }

  text << "\nNote:\n"
       << "  Planned options are CLI declarations only.\n"
       << "  Unsupported combinations return UNSUPPORTED.\n"
       << "  No silent fallback or fabricated verification.\n"
       << "  Run 'recomp-studio capabilities' for what is implemented and what is planned.\n";
  return text.str();
}

std::string render_command_usage(const std::string& command) {
  std::ostringstream text;
  text << "Usage: recomp-studio " << command;
  if (command == "inspect" || command == "analyze" || command == "coverage" || command == "imports" ||
      command == "functions" || command == "cfg" || command == "detect" || command == "autorecomp" ||
      command == "translate" || command == "repair")
    text << " <image>";
  else if (command == "build" || command == "run" || command == "verify" || command == "report")
    text << " <project>";
  text << " [options]\n";
  return text.str();
}

}  // namespace recomp::cli
