#pragma once

// Centralised option parsing, validation and help.
//
// The option table is the single source of truth. `--help` is generated from it,
// the parser validates against it, and the capability table is consulted for each
// value, so help text, parsing and the `capabilities` command cannot drift apart.
//
// Three rules, all of them about not lying to the user:
//   * an option that is not declared is an error, never ignored;
//   * a value outside an option's declared set is an error, never defaulted;
//   * a value that is declared but not implemented is an explicit UNSUPPORTED
//     error naming the option, the value, and what is missing.

#include "core/cli/capabilities.hpp"

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace recomp::cli {

enum class ValueKind {
  Flag,     // present or absent; takes no value
  Enum,     // one of a declared set
  Integer,  // a number, optionally with a declared range
  Text,     // free text
  Path,     // a filesystem path
};

struct OptionSpec {
  std::string name;           // "--target-os"
  std::string placeholder;    // "<os>", empty for a flag
  std::string summary;
  ValueKind kind{ValueKind::Flag};
  std::vector<std::string> allowed;  // for Enum
  std::string default_value;         // "" for a flag
  std::string group;                 // the heading it appears under in --help
  bool capability_checked{true};     // whether values are looked up in the table
};

// A malformed command line: an unknown option, a missing value, a value outside
// the declared set. The user can fix these.
class UsageError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// A well-formed request for something this build does not implement. Distinct from
// UsageError because the command line is correct and the answer is still no.
class UnsupportedError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

const std::vector<OptionSpec>& option_specs();
const OptionSpec* find_option_spec(const std::string& name);

struct ParsedOptions {
  std::string command;
  std::vector<std::string> positional;
  std::map<std::string, std::string> values;  // option name -> value; "true" for a flag

  bool has(const std::string& name) const { return values.count(name) != 0; }
  bool flag(const std::string& name) const { return has(name) && values.at(name) == "true"; }
  std::string get(const std::string& name) const;
  int integer(const std::string& name) const;
};

// Parses a command line. Every declared option is present in the result, holding
// its declared default when it was not given, so a caller never has to guess.
ParsedOptions parse(const std::vector<std::string>& arguments);

// Checks every provided value against the capability table and throws
// UnsupportedError for anything planned. Separate from parse() so a caller can
// inspect a request before deciding whether to run it.
void validate_capabilities(const ParsedOptions& options);

// The help text, generated from the option table.
std::string render_help();

// The options the given command accepts, for a per-command usage line.
std::string render_command_usage(const std::string& command);

}  // namespace recomp::cli
