#pragma once

// What this build can actually do, declared in one place.
//
// Every option value the CLI accepts is either implemented or planned, and the
// distinction is data rather than documentation, so the parser, the help text and
// the `capabilities` command all read the same table. A planned value is refused
// with UNSUPPORTED; it is never accepted and quietly ignored, and it is never
// reported as supported.
//
// The rule this exists to enforce: a user asking for something this build cannot
// do must be told, in the words of the thing they asked for.

#include <string>
#include <vector>

namespace recomp::cli {

enum class Support {
  Implemented,
  Planned,
};

const char* support_name(Support support);

// One capability: an option value, or a named feature with no option of its own.
struct Capability {
  std::string id;           // "target-os:macos", stable and greppable
  std::string option;       // "--target-os" or "" for a feature
  std::string value;        // "macos" or ""
  std::string summary;      // what it does, in one line
  Support support{Support::Planned};
  std::string note;         // what is missing, when planned
};

// Every declared capability, in a stable order.
const std::vector<Capability>& capabilities();

// Looks up one capability by option and value. Returns nullptr when the pair is
// not declared at all, which the parser treats as an error rather than a default.
const Capability* find_capability(const std::string& option, const std::string& value);

// The capability that covers an option's "auto" value, which resolves to a
// concrete one. Returns nullptr when the option has no auto value.
const Capability* resolve_auto(const std::string& option);

}  // namespace recomp::cli
