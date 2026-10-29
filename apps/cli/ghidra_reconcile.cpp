// Reconcile a provider's function list against this project's OWN discovery.
//
// WHY THIS EXISTS. The Ghidra import marks `binary_export_association: "unverified"`, and
// that is honest: nothing in an ExportFunctions file proves which binary produced it. A
// record whose association is unverified cannot be used to change what the translator does,
// because a wrong association would attribute one program's functions to another.
//
// Comparing it with an INDEPENDENT source checks address agreement, but cannot establish
// binary identity: unrelated binaries can share the same function addresses. This project's
// own discovery is that independent source: it is
// derived from the binary by a different method (Capstone decoding, entry-point and
// relocation seeding) and shares no code with Ghidra.
//
// WHAT IT DOES NOT DO. It does not merge. Per the reconciliation rules, incompatible
// hypotheses are PRESERVED and reported separately rather than averaged into one answer:
// a function only the provider found and a function only this project found are different
// findings, and collapsing them would hide whichever is right. Agreement is reported as
// agreement; disagreement is reported as disagreement with both sides named.
#include "core/binary/pe.hpp"
#include "core/discovery/function_discovery.hpp"
#include "third_party/nlohmann/json.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string read_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("cannot read provider record");
  return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

// One provider function, as the record states it. The address and the convention come from
// the SAME JSON object, which is why this returns a map rather than two independent scans:
// two scans over the same text can pair an address with a neighbouring entry's convention
// and never say so.
struct ProviderFunction {
  std::uint64_t address{};
  std::string convention;
};

std::map<std::uint64_t, ProviderFunction> provider_functions(const std::string& record) {
  const auto json = nlohmann::json::parse(record);
  if (!json.is_object() || !json.contains("functions") || !json["functions"].is_array())
    throw std::runtime_error("provider record must contain a functions array");
  std::map<std::uint64_t, ProviderFunction> functions;
  for (const auto& function : json["functions"]) {
    if (!function.is_object() || !function.contains("address") || !function["address"].is_string())
      throw std::runtime_error("function address must be a hexadecimal string");
    const auto text = function["address"].get<std::string>();
    if (text.empty() || text.size() > 16 || text.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
      throw std::runtime_error("invalid function address");
    ProviderFunction fact;
    fact.address = std::stoull(text, nullptr, 16);
    // The convention is OPTIONAL: a record may not carry one, and an absent field is
    // "unstated" rather than a disagreement.
    if (function.contains("calling_convention") && function["calling_convention"].is_string())
      fact.convention = function["calling_convention"].get<std::string>();
    if (!functions.emplace(fact.address, fact).second)
      throw std::runtime_error("duplicate function address");
  }
  return functions;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "usage: ghidra-reconcile <binary> <provider-record.json>\n";
    return 2;
  }
  try {
    const auto executable = recomp::binary::PortableExecutable::parse(argv[1]);
    recomp::discovery::FunctionDiscovery discovery(executable);
    discovery.discover();

    // This project's functions, as ABSOLUTE addresses so the two sides are comparable.
    // The provider reports absolute addresses; discovery keys on them too.
    //
    // The CALLING CONVENTION is derived from the function's own `ret` instruction, which is
    // the ABI signal the machine actually carries: `ret` returns with no stack adjustment
    // (cdecl), and `ret N` pops N bytes (stdcall). This is not a guess about the source --
    // it is what the epilogue does, and the lifter already emits it
    // (`return_from_guest_function(context, N)` in core/semantics/x86_64_lifter.cpp).
    struct LocalFunction {
      std::string convention;
      std::uint64_t stack_bytes{};
    };
    std::set<std::uint64_t> local;
    std::map<std::uint64_t, LocalFunction> local_conventions;
    for (const auto& [address, function] : discovery.functions()) {
      local.insert(address);
      LocalFunction fact{"unknown", 0};
      for (const auto& [instruction_address, instruction] : function.instructions) {
        (void)instruction_address;
        if (instruction.mnemonic != "ret") continue;
        if (!instruction.operands.empty() &&
            instruction.operands[0].kind == recomp::discovery::Operand::Kind::Immediate) {
          fact.stack_bytes = instruction.operands[0].immediate_value;
          fact.convention = "stdcall";
        } else {
          fact.convention = "cdecl";
        }
        break;  // the first `ret` is the epilogue that matters
      }
      local_conventions[address] = fact;
    }

    const auto provider_map = provider_functions(read_file(argv[2]));
    std::set<std::uint64_t> provider;
    for (const auto& [address, fact] : provider_map) {
      (void)fact;
      provider.insert(address);
    }

    std::vector<std::uint64_t> agreed;
    std::vector<std::uint64_t> provider_only;
    std::vector<std::uint64_t> local_only;
    std::set_intersection(local.begin(), local.end(), provider.begin(), provider.end(),
                          std::back_inserter(agreed));
    std::set_difference(provider.begin(), provider.end(), local.begin(), local.end(),
                        std::back_inserter(provider_only));
    std::set_difference(local.begin(), local.end(), provider.begin(), provider.end(),
                        std::back_inserter(local_only));

    const bool all_provider_addresses_agree = !provider.empty() && provider_only.empty();
    const char* agreement = all_provider_addresses_agree ? "complete"
                            : agreed.empty()             ? "none"
                                                         : "partial";

    std::cout << "{\"schema_version\":1"
              << ",\"provider\":\"Ghidra\""
              << ",\"reconciled_against\":\"recomp-studio function discovery\""
              << ",\"binary_export_association\":\"unverified\""
              << ",\"address_agreement\":" << '"' << agreement << '"'
              << ",\"provider_functions\":" << provider.size()
              << ",\"local_functions\":" << local.size()
              << ",\"agreed\":" << agreed.size()
              << ",\"provider_only\":" << provider_only.size()
              << ",\"local_only\":" << local_only.size()
              << ",\"functions\":[";
    bool first = true;
    const auto emit = [&](const std::vector<std::uint64_t>& addresses, const char* state) {
      for (const auto address : addresses) {
        if (!first) std::cout << ',';
        first = false;
        std::ostringstream hex;
        hex << std::hex << address;
        std::cout << "{\"address\":\"" << hex.str() << "\",\"state\":\"" << state
                  << "\",\"confidence\":\""
                  << (std::string(state) == "agreed" ? "matching-address-only" : "single-provider")
                  << "\",\"verification\":\""
                  << "unresolved" << "\"}";
      }
    };
    emit(agreed, "agreed");
    emit(provider_only, "provider-only");
    emit(local_only, "local-only");
    std::cout << "],\"conventions\":{";
    // Reported, never applied. The reconciliation rule is explicit: a calling convention is
    // not changed without an ABI test, so a disagreement here is EVIDENCE for a later test,
    // not a reason to rewrite anything.
    std::map<std::string, std::size_t> tally;
    for (const auto& [address, fact] : local_conventions) {
      (void)address;
      tally[fact.convention] += 1;
    }

    // COMPARE the two sides' conventions where both stated one, and REPORT the result.
    // Nothing is rewritten: the rule is that a convention is not changed without an ABI
    // test, so a disagreement is evidence for that test rather than a reason to act. A
    // provider that states no convention for a function is counted as `unstated`, NOT as
    // agreement -- silence is not corroboration.
    std::size_t conventions_agreed = 0;
    std::size_t conventions_disagreed = 0;
    std::size_t conventions_unstated = 0;
    std::vector<std::string> disagreements;
    for (const auto& [address, local_fact] : local_conventions) {
      const auto found = provider_map.find(address);
      if (found == provider_map.end() || found->second.convention.empty()) {
        ++conventions_unstated;
        continue;
      }
      // The provider may spell it `__stdcall` where this project says `stdcall`; compare on
      // the name with leading underscores removed so the two vocabularies can be compared
      // at all, and say so rather than silently normalising into agreement.
      const auto normalise = [](std::string name) {
        while (!name.empty() && name.front() == '_') name.erase(name.begin());
        for (auto& character : name) character = static_cast<char>(std::tolower(character));
        return name;
      };
      if (normalise(found->second.convention) == normalise(local_fact.convention)) {
        ++conventions_agreed;
      } else {
        ++conventions_disagreed;
        std::ostringstream pair;
        pair << std::hex << address << ":provider=" << found->second.convention
             << ",local=" << local_fact.convention;
        disagreements.push_back(pair.str());
      }
    }
    // CLOSE the conventions object first, THEN emit the comparison as its sibling. The
    // first ordering emitted the comparison before the tally had filled the object, which
    // produced valid-looking output that no JSON parser would accept: the tally keys landed
    // after the closing brace. Order is the whole difference between a record and garbage.
    bool first_convention = true;
    for (const auto& [name, count] : tally) {
      if (!first_convention) std::cout << ',';
      first_convention = false;
      std::cout << '"' << name << "\":" << count;
    }
    std::cout << "},\"convention_comparison\":{\"agreed\":" << conventions_agreed
              << ",\"disagreed\":" << conventions_disagreed
              << ",\"provider_unstated\":" << conventions_unstated << ",\"conflicts\":[";
    for (std::size_t index = 0; index < disagreements.size(); ++index) {
      if (index != 0) std::cout << ',';
      std::cout << '"' << disagreements[index] << '"';
    }
    std::cout << "]}}\n";  // close convention_comparison, then the record
    // ANY unresolved disagreement is a finding, not a success. The first rule here was
    // `agreed.empty() && !provider.empty()`, which exited zero whenever the two sides
    // agreed on ANYTHING -- so a record that agreed on 36 functions and invented a 37th
    // was reported as fine. Partial agreement is still disagreement about the rest, and
    // the exit status is what a caller acts on, so it must reflect that.
    return all_provider_addresses_agree ? 0 : 1;
  } catch (const std::exception& error) {
    std::cerr << "reconcile failed: " << error.what() << '\n';
    return 2;
  }
}
