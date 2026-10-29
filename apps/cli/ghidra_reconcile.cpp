// Reconcile a provider's function list against this project's OWN discovery.
//
// WHY THIS EXISTS. The Ghidra import marks `binary_export_association: "unverified"`, and
// that is honest: nothing in an ExportFunctions file proves which binary produced it. A
// record whose association is unverified cannot be used to change what the translator does,
// because a wrong association would attribute one program's functions to another.
//
// Reconciling it against an INDEPENDENT source resolves that -- not by trusting either side,
// but by comparing them. This project's own discovery is that independent source: it is
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
  return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

// The provider's record is JSON written by this project's own importer, so the addresses are
// pulled out by scanning for the field rather than by a general parser. A missing field
// yields nothing rather than a guess: an address nobody stated is not an address of zero.
std::set<std::uint64_t> provider_addresses(const std::string& record) {
  std::set<std::uint64_t> addresses;
  // WHITESPACE BETWEEN THE KEY AND THE VALUE IS ALLOWED BY JSON, so the scan must allow
  // it. The first version required `"address":"` exactly, which meant a record produced by
  // any other writer -- including this project's own test, which uses json.dumps -- parsed
  // as having NO functions at all, and full agreement was reported as a contradiction. A
  // parser that only accepts one writer's spacing is not reading JSON, it is reading that
  // writer's output.
  const std::string key = "\"address\"";
  std::size_t position = 0;
  while ((position = record.find(key, position)) != std::string::npos) {
    position += key.size();
    position = record.find_first_not_of(" \t\r\n", position);
    if (position == std::string::npos || record[position] != ':') continue;
    position = record.find_first_not_of(" \t\r\n", position + 1);
    if (position == std::string::npos || record[position] != '"') continue;
    ++position;
    const auto end = record.find('"', position);
    if (end == std::string::npos) break;
    const auto text = record.substr(position, end - position);
    try {
      addresses.insert(std::stoull(text, nullptr, 16));
    } catch (const std::exception&) {
      // A malformed address is reported by its absence from the count, not by inventing one.
    }
    position = end;
  }
  return addresses;
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

    const auto provider = provider_addresses(read_file(argv[2]));

    std::vector<std::uint64_t> agreed;
    std::vector<std::uint64_t> provider_only;
    std::vector<std::uint64_t> local_only;
    std::set_intersection(local.begin(), local.end(), provider.begin(), provider.end(),
                          std::back_inserter(agreed));
    std::set_difference(provider.begin(), provider.end(), local.begin(), local.end(),
                        std::back_inserter(provider_only));
    std::set_difference(local.begin(), local.end(), provider.begin(), provider.end(),
                        std::back_inserter(local_only));

    // The association is VERIFIED when the independent source confirms the provider's
    // functions at the same addresses. It is not verified by the provider saying so.
    const bool association_verified = !provider.empty() && provider_only.empty();
    const char* association = association_verified ? "verified"
                              : agreed.empty()      ? "contradicted"
                                                    : "partially-verified";

    std::cout << "{\"schema_version\":1"
              << ",\"provider\":\"Ghidra\""
              << ",\"reconciled_against\":\"recomp-studio function discovery\""
              << ",\"binary_export_association\":" << '"' << association << '"'
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
                  << (std::string(state) == "agreed" ? "confirmed-by-two-providers" : "single-provider")
                  << "\",\"verification\":\""
                  << (std::string(state) == "agreed" ? "corroborated" : "unresolved") << "\"}";
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
    bool first_convention = true;
    for (const auto& [name, count] : tally) {
      if (!first_convention) std::cout << ',';
      first_convention = false;
      std::cout << '"' << name << "\":" << count;
    }
    std::cout << "}}\n";
    // ANY unresolved disagreement is a finding, not a success. The first rule here was
    // `agreed.empty() && !provider.empty()`, which exited zero whenever the two sides
    // agreed on ANYTHING -- so a record that agreed on 36 functions and invented a 37th
    // was reported as fine. Partial agreement is still disagreement about the rest, and
    // the exit status is what a caller acts on, so it must reflect that.
    return association_verified ? 0 : 1;
  } catch (const std::exception& error) {
    std::cerr << "reconcile failed: " << error.what() << '\n';
    return 2;
  }
}
