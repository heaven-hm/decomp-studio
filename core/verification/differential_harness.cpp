#include "core/verification/differential_harness.hpp"

#include "core/pipeline.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <unicorn/unicorn.h>
#include <vector>

namespace recomp::verification {
namespace {

constexpr std::uint64_t kThreadEnvironmentBlockAddress = 0x0000000164000000ull;
constexpr std::uint64_t kProcessEnvironmentBlockAddress = 0x0000000164001000ull;
constexpr std::uint64_t kImportThunkBase = 0x0000000100000000ull;
constexpr std::uint64_t kStackSize = 0x00100000ull;
constexpr std::uint64_t kHeapSize = 0x01000000ull;
constexpr std::uint64_t kPageSize = 0x1000ull;
constexpr std::uint64_t kInstructionBudget = 200000000ull;

struct ReferenceState {
  uc_engine* engine{};
  std::string output;
  std::vector<std::string> symbol_names;
  std::vector<std::uint64_t>* trace{};
  std::size_t trace_limit{};
  std::uint64_t instruction_count{};
  bool finished{};
};

std::map<std::string, std::string> read_manifest(const std::filesystem::path& project_directory) {
  std::ifstream input(project_directory / "recomp-manifest.json");
  if (!input) throw std::runtime_error("manifest not found; run translate first");
  std::map<std::string, std::string> values;
  std::string line;
  while (std::getline(input, line)) {
    const auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    const auto strip = [](std::string text) {
      const auto first = text.find_first_not_of("\" \t\r\n");
      const auto last = text.find_last_not_of("\" \t\r\n,");
      if (first == std::string::npos) return std::string{};
      return text.substr(first, last - first + 1);
    };
    values[strip(line.substr(0, colon))] = strip(line.substr(colon + 1));
  }
  return values;
}

std::uint64_t parse_hex(const std::map<std::string, std::string>& values, const std::string& key,
                        std::uint64_t fallback) {
  const auto iterator = values.find(key);
  if (iterator == values.end() || iterator->second.empty()) return fallback;
  return std::stoull(iterator->second, nullptr, 0);
}

void map_region(uc_engine* engine, std::uint64_t address, std::uint64_t size) {
  auto start = address & ~(kPageSize - 1);
  auto end = (address + size + kPageSize - 1) & ~(kPageSize - 1);
  if (end <= start) end = start + kPageSize;
  if (uc_mem_map(engine, start, end - start, UC_PROT_ALL) != UC_ERR_OK)
    throw std::runtime_error("unicorn: failed to map region");
}

std::uint64_t read_register(uc_engine* engine, int register_id) {
  std::uint64_t value = 0;
  uc_reg_read(engine, register_id, &value);
  return value;
}

void write_register(uc_engine* engine, int register_id, std::uint64_t value) {
  uc_reg_write(engine, register_id, &value);
}

void emulate_shim(ReferenceState& state, std::uint64_t stub_address) {
  const auto index = static_cast<std::size_t>((stub_address - kImportThunkBase) / 0x10);
  const auto& symbol = index < state.symbol_names.size() ? state.symbol_names[index] : std::string{};
  auto* engine = state.engine;
  const auto argument0 = read_register(engine, UC_X86_REG_RCX);
  const auto argument1 = read_register(engine, UC_X86_REG_RDX);
  const auto argument2 = read_register(engine, UC_X86_REG_R8);
  const auto argument3 = read_register(engine, UC_X86_REG_R9);

  if (symbol == "GetStdHandle") {
    const auto which = static_cast<std::int32_t>(argument0);
    write_register(engine, UC_X86_REG_RAX, which == -10 ? 10 : which == -12 ? 12 : 11);
  } else if (symbol == "WriteFile") {
    std::vector<char> buffer(static_cast<std::size_t>(argument2));
    if (argument2 != 0) uc_mem_read(engine, argument1, buffer.data(), buffer.size());
    state.output.append(buffer.data(), buffer.size());
    if (argument3 != 0) {
      const std::uint32_t written = static_cast<std::uint32_t>(argument2);
      uc_mem_write(engine, argument3, &written, 4);
    }
    write_register(engine, UC_X86_REG_RAX, 1);
  } else if (symbol == "ReadFile") {
    if (argument3 != 0) {
      const std::uint32_t read_count = 0;
      uc_mem_write(engine, argument3, &read_count, 4);
    }
    write_register(engine, UC_X86_REG_RAX, 1);
  } else if (symbol == "ExitProcess") {
    state.finished = true;
    uc_emu_stop(engine);
    return;
  } else {
    write_register(engine, UC_X86_REG_RAX, 0);
  }

  const auto stack_pointer = read_register(engine, UC_X86_REG_RSP);
  std::uint64_t return_address = 0;
  uc_mem_read(engine, stack_pointer, &return_address, 8);
  write_register(engine, UC_X86_REG_RSP, stack_pointer + 8);
  write_register(engine, UC_X86_REG_RIP, return_address);
}

void code_hook(uc_engine* engine, std::uint64_t address, std::uint32_t size, void* user_data) {
  (void)size;
  auto& state = *static_cast<ReferenceState*>(user_data);
  ++state.instruction_count;
  if (state.trace != nullptr && state.trace->size() < state.trace_limit) state.trace->push_back(address);
  if (address >= kImportThunkBase && address < kImportThunkBase + 0x10000) {
    emulate_shim(state, address);
    return;
  }
  if (state.instruction_count > kInstructionBudget) {
    state.finished = true;
    uc_emu_stop(engine);
  }
}

}  // namespace

ReferenceRun run_reference(const binary::PortableExecutable& executable,
                           const binary::LoadedImage& loaded_image, std::uint64_t stack_top,
                           std::uint64_t heap_base, std::size_t trace_limit) {
  uc_engine* engine = nullptr;
  if (uc_open(UC_ARCH_X86, UC_MODE_64, &engine) != UC_ERR_OK)
    throw std::runtime_error("unicorn: failed to open x86-64 engine");
  map_region(engine, executable.image_base, loaded_image.image_bytes.size());
  uc_mem_write(engine, executable.image_base, loaded_image.image_bytes.data(), loaded_image.image_bytes.size());
  map_region(engine, stack_top - kStackSize, kStackSize);
  map_region(engine, heap_base, kHeapSize);
  map_region(engine, kImportThunkBase, 0x10000);
  map_region(engine, kThreadEnvironmentBlockAddress, 0x2000);

  ReferenceState state;
  state.engine = engine;
  state.trace_limit = trace_limit != 0 ? trace_limit : 1;
  std::vector<std::uint64_t> trace;
  if (trace_limit != 0) state.trace = &trace;
  for (std::size_t index = 0; index < executable.imports.size(); ++index) {
    std::uint64_t stub_address = kImportThunkBase + index * 0x10;
    const auto slot_address = executable.image_base + executable.imports[index].import_address_table_rva;
    uc_mem_write(engine, slot_address, &stub_address, executable.is_64_bit ? 8 : 4);
    state.symbol_names.push_back(executable.imports[index].symbol_name);
  }

  const std::uint64_t stack_pointer = stack_top - 8;
  const std::uint64_t sentinel = 0;
  uc_mem_write(engine, stack_pointer, &sentinel, 8);
  write_register(engine, UC_X86_REG_RSP, stack_pointer);
  write_register(engine, UC_X86_REG_RIP, executable.image_base + executable.entry_point_rva);
  write_register(engine, UC_X86_REG_GS_BASE, kThreadEnvironmentBlockAddress);
  write_register(engine, UC_X86_REG_FS_BASE, kThreadEnvironmentBlockAddress);
  const std::uint64_t teb_fields[] = {stack_top, stack_top - kStackSize, kProcessEnvironmentBlockAddress,
                                      kProcessEnvironmentBlockAddress};
  const std::uint64_t teb_offsets[] = {0x08, 0x10, 0x30, 0x60};
  for (int index = 0; index < 4; ++index) {
    const auto offset = kThreadEnvironmentBlockAddress + teb_offsets[index];
    uc_mem_write(engine, offset, &teb_fields[index], 8);
  }
  const std::uint64_t image_base_field = executable.image_base;
  uc_mem_write(engine, kProcessEnvironmentBlockAddress + 0x10, &image_base_field, 8);

  uc_hook hook = 0;
  uc_hook_add(engine, &hook, UC_HOOK_CODE, reinterpret_cast<void*>(code_hook), &state, 1, 0);
  const auto error = uc_emu_start(engine, executable.image_base + executable.entry_point_rva, 0, 0, 0);
  if (error != UC_ERR_OK && !state.finished)
    throw std::runtime_error(std::string("unicorn: ") + uc_strerror(error));

  ReferenceRun run;
  run.output = state.output;
  run.instruction_count = state.instruction_count;
  run.trace = std::move(trace);
  uc_close(engine);
  return run;
}

DifferentialResult compare_project(const std::filesystem::path& project_directory,
                                   const common::Configuration& configuration) {
  (void)configuration;
  DifferentialResult result;
  const auto manifest = read_manifest(project_directory);
  const auto input_iterator = manifest.find("input_path");
  if (input_iterator == manifest.end()) throw std::runtime_error("manifest is missing input_path");
  const std::filesystem::path input_path = input_iterator->second;

  const auto executable = binary::PortableExecutable::parse(input_path);
  const auto loaded_image = binary::load_image(executable, executable.image_base);
  const auto stack_top = parse_hex(manifest, "stack_top", 0x0000000168000000ull);
  const auto heap_base = parse_hex(manifest, "heap_base", 0x0000000160000000ull);

  try {
    const auto reference = run_reference(executable, loaded_image, stack_top, heap_base, 0);
    result.executed_instructions = reference.instruction_count;
    result.reference_output = reference.output;
  } catch (const std::exception& error) {
    result.completed = false;
    result.diagnosis = std::string("reference execution did not complete: ") + error.what();
    return result;
  }

  const auto candidate = pipeline::run(project_directory);
  result.candidate_output = candidate.standard_output;
  result.completed = true;
  result.outputs_match = result.reference_output == result.candidate_output;

  if (!result.outputs_match) {
    std::size_t offset = 0;
    while (offset < result.reference_output.size() && offset < result.candidate_output.size() &&
           result.reference_output[offset] == result.candidate_output[offset])
      ++offset;
    const auto snippet = [](const std::string& text, std::size_t from) {
      if (from >= text.size()) return std::string{};
      return text.substr(from, std::min<std::size_t>(48, text.size() - from));
    };
    std::ostringstream diagnosis;
    diagnosis << "outputs diverge at byte " << offset << " (reference=" << result.reference_output.size()
              << ", candidate=" << result.candidate_output.size() << ")";
    diagnosis << "\n  reference: " << snippet(result.reference_output, offset);
    diagnosis << "\n  candidate: " << snippet(result.candidate_output, offset);
    result.diagnosis = diagnosis.str();
  }
  return result;
}

TraceComparison compare_execution_traces(const std::filesystem::path& project_directory,
                                         const common::Configuration& configuration,
                                         std::size_t trace_limit) {
  (void)configuration;
  TraceComparison comparison;
  const auto manifest = read_manifest(project_directory);
  const auto input_iterator = manifest.find("input_path");
  if (input_iterator == manifest.end()) throw std::runtime_error("manifest is missing input_path");
  const auto executable = binary::PortableExecutable::parse(input_iterator->second);
  const auto loaded_image = binary::load_image(executable, executable.image_base);
  ReferenceRun reference;
  try {
    reference = run_reference(executable, loaded_image, parse_hex(manifest, "stack_top", 0x0000000168000000ull),
                              parse_hex(manifest, "heap_base", 0x0000000160000000ull), trace_limit);
  } catch (const std::exception&) {
    return comparison;
  }

  const auto trace_path = project_directory / "candidate.trace";
  const auto executable_path = project_directory / "recomp-guest";
  std::string command = "RECOMP_TRACE='" + trace_path.string() + "' '" + executable_path.string() + "' > /dev/null 2>&1";
  std::system(command.c_str());

  std::vector<std::uint64_t> candidate_trace;
  std::ifstream trace_input(trace_path, std::ios::binary);
  if (trace_input) {
    std::uint64_t address = 0;
    while (candidate_trace.size() < trace_limit &&
           trace_input.read(reinterpret_cast<char*>(&address), sizeof(address)))
      candidate_trace.push_back(address);
  }

  comparison.reference_steps = reference.trace.size();
  comparison.candidate_steps = candidate_trace.size();
  const auto shared = std::min(reference.trace.size(), candidate_trace.size());
  for (std::size_t index = 0; index < shared; ++index) {
    if (reference.trace[index] != candidate_trace[index]) {
      comparison.diverged = true;
      comparison.first_divergence_index = index;
      comparison.reference_address = reference.trace[index];
      comparison.candidate_address = candidate_trace[index];
      return comparison;
    }
  }
  if (reference.trace.size() != candidate_trace.size()) {
    comparison.diverged = true;
    comparison.first_divergence_index = shared;
    comparison.reference_address = shared < reference.trace.size() ? reference.trace[shared] : 0;
    comparison.candidate_address = shared < candidate_trace.size() ? candidate_trace[shared] : 0;
  }
  return comparison;
}

}  // namespace recomp::verification
