#include "core/verification/differential_harness.hpp"

#include "core/pipeline.hpp"

#include "recomp_runtime.hpp"
#include "win32_abi.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <unicorn/unicorn.h>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace recomp::verification {
namespace {

std::string hex_text(std::uint64_t value) {
  std::ostringstream text;
  text << std::hex << value;
  return text.str();
}


constexpr std::uint64_t kThreadEnvironmentBlockAddress64 = 0x0000000164000000ull;
constexpr std::uint64_t kProcessEnvironmentBlockAddress64 = 0x0000000164001000ull;
constexpr std::uint64_t kThreadEnvironmentBlockAddress32 = 0x000000007ffd0000ull;
constexpr std::uint64_t kProcessEnvironmentBlockAddress32 = 0x000000007ffd1000ull;
constexpr std::uint64_t kImportThunkBase64 = 0x0000000100000000ull;
constexpr std::uint64_t kImportThunkBase32 = 0x0000000060000000ull;
constexpr std::uint64_t kStackSize = 0x00100000ull;
constexpr std::uint64_t kInstructionBudget = 200000000ull;

struct ReferenceState {
  uc_engine* engine{};
  std::string output;
  std::vector<std::string> symbol_names;
  std::vector<std::string> library_names;
  std::vector<std::uint64_t>* trace{};
  std::size_t trace_limit{};
  int pointer_width{8};
  std::uint64_t thunk_base{};
  std::uint64_t instruction_count{};
  bool finished{};
  std::string note;
  // Set when the reference meets something it cannot model. The reference must
  // never invent a result for an import it does not implement: doing so lets a
  // comparison "pass" against a program that never really ran.
  std::string failure_reason;
  // Guest state at recorded checkpoints, for comparison against the candidate's.
  std::uint64_t guest_instruction_count{};
  std::vector<GuestCheckpoint> checkpoints;
};

// The state the exit handler acts on. Only one reference runs at a time.
ReferenceState* reference_state = nullptr;

// Guest-state checkpoints are recorded every this many executed guest
// instructions, on both sides, so the two streams line up index for index. It is
// a compile-time constant rather than a flag because the two sides must agree on
// it or the comparison is meaningless.
constexpr std::uint64_t kCheckpointInterval = 1000;

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

std::vector<std::string> read_unsupported_mnemonics(const std::filesystem::path& project_directory) {
  std::vector<std::string> mnemonics;
  std::ifstream input(project_directory / "recomp-manifest.json");
  if (!input) return mnemonics;
  std::string content{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  const auto key = content.find("\"unsupported_mnemonics\"");
  if (key == std::string::npos) return mnemonics;
  const auto open = content.find('[', key);
  const auto close = content.find(']', open == std::string::npos ? key : open);
  if (open == std::string::npos || close == std::string::npos) return mnemonics;
  const auto body = content.substr(open + 1, close - open - 1);
  std::size_t position = 0;
  while ((position = body.find('"', position)) != std::string::npos) {
    const auto end = body.find('"', position + 1);
    if (end == std::string::npos) break;
    mnemonics.push_back(body.substr(position + 1, end - position - 1));
    position = end + 1;
  }
  return mnemonics;
}

std::uint64_t parse_hex(const std::map<std::string, std::string>& values, const std::string& key,
                        std::uint64_t fallback) {
  const auto iterator = values.find(key);
  if (iterator == values.end() || iterator->second.empty()) return fallback;
  return std::stoull(iterator->second, nullptr, 0);
}


std::uint64_t read_register(uc_engine* engine, int register_id) {
  std::uint64_t value = 0;
  uc_reg_read(engine, register_id, &value);
  return value;
}

void write_register(uc_engine* engine, int register_id, std::uint64_t value) {
  uc_reg_write(engine, register_id, &value);
}

// Writes a register and confirms the value stuck. Unicorn 2.1.4 returns
// UC_ERR_OK for UC_X86_REG_FS_BASE and GS_BASE in 32-bit mode while silently
// ignoring the write — the readback is 0 — so an unchecked write would surface
// later as a baffling unmapped-read divergence instead of the real cause.
bool write_register_checked(uc_engine* engine, int register_id, std::uint64_t value) {
  uc_reg_write(engine, register_id, &value);
  std::uint64_t readback = 0;
  if (uc_reg_read(engine, register_id, &readback) != UC_ERR_OK) return false;
  return readback == value;
}

// The reference dispatches through the runtime's own shim table. There is one
// implementation of each Win32 call, so a comparison cannot pass because two
// separate implementations happen to agree, and an import the runtime does not
// implement is reported as unimplemented rather than being quietly modelled here
// with different behaviour.
void sync_engine_to_context(uc_engine* engine, GuestContext& context, bool is_64_bit) {
  static const int registers32[8] = {UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
                                     UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI};
  static const int registers64[16] = {UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
                                      UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                                      UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
                                      UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15};
  if (is_64_bit) {
    for (int index = 0; index < 16; ++index) context.registers[index] = read_register(engine, registers64[index]);
  } else {
    for (int index = 0; index < 8; ++index)
      context.registers[index] = read_register(engine, registers32[index]) & 0xffffffffull;
  }
  set_eflags(&context, read_register(engine, UC_X86_REG_EFLAGS));
  context.fs_base = read_register(engine, UC_X86_REG_FS_BASE);
  context.gs_base = read_register(engine, UC_X86_REG_GS_BASE);
}

void sync_context_to_engine(uc_engine* engine, const GuestContext& context, bool is_64_bit) {
  static const int registers32[8] = {UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
                                     UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI};
  static const int registers64[16] = {UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
                                      UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                                      UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
                                      UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15};
  if (is_64_bit) {
    for (int index = 0; index < 16; ++index) write_register(engine, registers64[index], context.registers[index]);
  } else {
    for (int index = 0; index < 8; ++index) write_register(engine, registers32[index], context.registers[index]);
  }
  write_register(engine, UC_X86_REG_EFLAGS, eflags_value(&context));
}

void emulate_shim(ReferenceState& state, std::uint64_t stub_address) {
  const auto index = static_cast<std::size_t>((stub_address - state.thunk_base) / 0x10);
  const auto& library = index < state.library_names.size() ? state.library_names[index] : std::string{};
  const auto& symbol = index < state.symbol_names.size() ? state.symbol_names[index] : std::string{};
  auto* engine = state.engine;
  const bool is_64_bit = state.pointer_width == 8;

  GuestContext context{};
  sync_engine_to_context(engine, context, is_64_bit);
  if (!invoke_shared_shim(&context, library.c_str(), symbol.c_str())) {
    state.failure_reason = "the runtime does not implement " + library + "!" + symbol;
    state.finished = true;
    uc_emu_stop(engine);
    return;
  }
  sync_context_to_engine(engine, context, is_64_bit);

  // The thunk region holds no instructions: the emulator was about to execute at
  // the thunk address, so the return to the caller has to be performed here, the
  // same way the shim's own `ret`/`ret n` would have done it. The runtime's shim
  // only sets the result and never touches the stack.
  const int stack_register = is_64_bit ? UC_X86_REG_RSP : UC_X86_REG_ESP;
  const auto stack_pointer = read_register(engine, stack_register);
  std::uint64_t return_address = 0;
  uc_mem_read(engine, stack_pointer, &return_address, static_cast<std::size_t>(state.pointer_width));
  std::uint64_t cleanup = state.pointer_width;
  if (!is_64_bit) cleanup = win32_import_stack_cleanup(library.c_str(), symbol.c_str());
  write_register(engine, stack_register, stack_pointer + cleanup);
  write_register(engine, is_64_bit ? UC_X86_REG_RIP : UC_X86_REG_EIP, return_address);
}

void code_hook(uc_engine* engine, std::uint64_t address, std::uint32_t size, void* user_data) {
  (void)size;
  auto& state = *static_cast<ReferenceState*>(user_data);
  // An import thunk is a host bridge, not a guest instruction, and the candidate
  // never executes one. Counting it here made the reported instruction count
  // describe a stream the candidate does not have -- it was inflated by exactly
  // the number of import calls, and the comment below already said thunks are
  // excluded from the trace. The count and the trace now agree.
  if (address >= state.thunk_base && address < state.thunk_base + 0x10000) {
    emulate_shim(state, address);
    return;
  }
  ++state.instruction_count;
  if (state.trace != nullptr && state.trace->size() < state.trace_limit) state.trace->push_back(address);

  // Guest-state checkpoints. The candidate records these from its own
  // trace_instruction with the same interval and the same counter, so the two
  // streams line up and the first disagreement names the instruction responsible.
  if (guest_checkpoint_interval != 0) {
    const auto index = state.guest_instruction_count++;
    if (index % guest_checkpoint_interval == 0) {
      GuestCheckpoint checkpoint;
      checkpoint.index = index;
      checkpoint.address = address;
      // The 64-bit and 32-bit register files are named separately in Unicorn.
      // Reading RAX/RSP/... for a 32-bit guest returns zero rather than failing,
      // which looked exactly like a genuine state divergence on the one PE32
      // fixture until the register ids were made mode-aware.
      static const int registers32[8] = {UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
                                         UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI};
      static const int registers64[8] = {UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
                                         UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI};
      const bool is_64_bit = state.pointer_width == 8;
      for (int register_index = 0; register_index < 8; ++register_index) {
        const auto value = read_register(engine, is_64_bit ? registers64[register_index]
                                                            : registers32[register_index]);
        // A 32-bit guest's registers are 32 bits wide; the candidate masks them
        // the same way, so the comparison is between like and like.
        checkpoint.registers[register_index] = is_64_bit ? value : (value & 0xffffffffull);
      }
      checkpoint.flags = read_register(engine, UC_X86_REG_EFLAGS);
      state.checkpoints.push_back(checkpoint);
    }
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
  // Segment base registers (FS/GS) are written intentionally to model the TEB.
  // Unicorn marks those accesses deprecated in 2.x and warns on stderr.
  static const bool ignore_register_warning = [] {
    return setenv("UC_IGNORE_REG_BREAK", "1", 1) == 0;
  }();
  (void)ignore_register_warning;

  const bool is_64_bit = executable.is_64_bit;
  const std::uint32_t default_mxcsr = 0x1f80u;
  const int pointer_width = is_64_bit ? 8 : 4;
  const std::uint64_t thunk_base = is_64_bit ? kImportThunkBase64 : kImportThunkBase32;

  ReferenceRun run;
  uc_engine* engine = nullptr;
  if (uc_open(UC_ARCH_X86, is_64_bit ? UC_MODE_64 : UC_MODE_32, &engine) != UC_ERR_OK) {
    run.failure_reason = "unicorn: failed to open the x86 engine";
    return run;
  }
  // The reference addresses the same bytes the runtime does. Mapping the
  // runtime's own guest region into the emulator means a shim written once is
  // executed by both sides and its effects are seen by both, so the two cannot
  // drift apart -- which is the whole point of comparing them.
  if (!map_guest_memory(kGuestAddressSpaceBytes)) {
    run.failure_reason = "could not allocate the guest address space for the reference";
    uc_close(engine);
    return run;
  }
  guest_pointer_width = pointer_width;
  if (uc_mem_map_ptr(engine, 0, kGuestAddressSpaceBytes, UC_PROT_ALL, guest_memory) != UC_ERR_OK) {
    run.failure_reason = "unicorn: could not map the shared guest address space";
    uc_close(engine);
    return run;
  }
  std::memcpy(guest_memory + executable.image_base, loaded_image.image_bytes.data(),
              loaded_image.image_bytes.size());
  // The same startup the candidate performs. Without it the reference would run
  // against an uninitialised heap and report a divergence that says nothing about
  // the translation.
  initialize_guest_state(heap_base, stack_top);
  const std::uint64_t teb_address =
      is_64_bit ? kThreadEnvironmentBlockAddress64 : kThreadEnvironmentBlockAddress32;
  const std::uint64_t peb_address =
      is_64_bit ? kProcessEnvironmentBlockAddress64 : kProcessEnvironmentBlockAddress32;


  ReferenceState state;
  state.engine = engine;
  // The runtime's shims write through this sink, so the reference captures what
  // the guest wrote rather than echoing it to the studio's own stdout.
  reference_state = &state;
  guest_output_capture = &state.output;
  // The guest calling ExitProcess must end the reference run, not the studio.
  guest_exit_handler = [](int code) {
    (void)code;
    if (reference_state != nullptr) {
      reference_state->finished = true;
      uc_emu_stop(reference_state->engine);
    }
  };
  state.trace_limit = trace_limit != 0 ? trace_limit : 1;
  state.thunk_base = thunk_base;
  state.pointer_width = pointer_width;
  std::vector<std::uint64_t> trace;
  if (trace_limit != 0) state.trace = &trace;
  for (std::size_t index = 0; index < executable.imports.size(); ++index) {
    std::uint64_t stub_address = thunk_base + index * 0x10;
    const auto slot_address = executable.image_base + executable.imports[index].import_address_table_rva;
    uc_mem_write(engine, slot_address, &stub_address, static_cast<std::size_t>(pointer_width));
    state.symbol_names.push_back(executable.imports[index].symbol_name);
    state.library_names.push_back(executable.imports[index].library_name);
  }

  const int stack_register = is_64_bit ? UC_X86_REG_RSP : UC_X86_REG_ESP;
  const int instruction_register = is_64_bit ? UC_X86_REG_RIP : UC_X86_REG_EIP;
  const std::uint64_t stack_pointer = stack_top - pointer_width;
  const std::uint64_t sentinel = 0;
  uc_mem_write(engine, stack_pointer, &sentinel, static_cast<std::size_t>(pointer_width));
  write_register(engine, stack_register, stack_pointer);
  write_register(engine, instruction_register, executable.image_base + executable.entry_point_rva);

  if (is_64_bit) {
    write_register(engine, UC_X86_REG_GS_BASE, teb_address);
    write_register(engine, UC_X86_REG_FS_BASE, teb_address);
    const std::uint64_t fields[] = {stack_top, stack_top - kStackSize, peb_address, peb_address};
    const std::uint64_t offsets[] = {0x08, 0x10, 0x30, 0x60};
    for (int index = 0; index < 4; ++index)
      uc_mem_write(engine, teb_address + offsets[index], &fields[index], 8);
    const std::uint64_t image_base_field = executable.image_base;
    uc_mem_write(engine, peb_address + 0x10, &image_base_field, 8);
  } else {
    // A 32-bit guest reaches the TEB through fs:. If the base cannot be set,
    // put the TEB at address 0 instead: `fs:[offset]` then resolves to
    // `0 + offset`, which is the layout the guest expects. The trade-off is that
    // a genuine null-page access no longer faults in the reference, so it is
    // reported in the run note rather than being left implicit.
    std::uint64_t effective_teb = teb_address;
    if (!write_register_checked(engine, UC_X86_REG_FS_BASE, teb_address)) {
      effective_teb = 0;
      // Page 0 is already covered by the shared guest mapping.
      state.note =
          "the reference cannot set FS_BASE in 32-bit mode (unicorn 2.1.4 ignores the write); "
          "the TEB was placed at address 0 so fs: accesses resolve";
    }
    // The self-pointer reports the canonical TEB address even when the block
    // itself was relocated to 0, so a guest that reads fs:[0x18] sees the same
    // value on both sides. The alternative - reporting 0 - would make every
    // 32-bit guest that touches the self-pointer diverge for no reason.
    const std::uint32_t teb_self = static_cast<std::uint32_t>(teb_address);
    const std::uint32_t peb = static_cast<std::uint32_t>(peb_address);
    const std::uint32_t stack_base = static_cast<std::uint32_t>(stack_top);
    const std::uint32_t stack_limit = static_cast<std::uint32_t>(stack_top - kStackSize);
    uc_mem_write(engine, effective_teb + 0x04, &stack_base, 4);
    uc_mem_write(engine, effective_teb + 0x08, &stack_limit, 4);
    uc_mem_write(engine, effective_teb + 0x18, &teb_self, 4);
    uc_mem_write(engine, effective_teb + 0x30, &peb, 4);
    const std::uint32_t image_base_field = static_cast<std::uint32_t>(executable.image_base);
    uc_mem_write(engine, peb_address + 0x08, &image_base_field, 4);
  }

  write_register(engine, UC_X86_REG_MXCSR, default_mxcsr);
  uc_hook hook = 0;
  uc_hook_add(engine, &hook, UC_HOOK_CODE, reinterpret_cast<void*>(code_hook), &state, 1, 0);
  const auto error = uc_emu_start(engine, executable.image_base + executable.entry_point_rva, 0, 0, 0);
  run.output = state.output;
  run.instruction_count = state.instruction_count;
  run.note = state.note;
  run.checkpoints = std::move(state.checkpoints);
  run.trace = std::move(trace);
  uc_close(engine);
  guest_output_capture = nullptr;
  guest_exit_handler = nullptr;
  reference_state = nullptr;
  if (!state.failure_reason.empty()) {
    run.completed = false;
    run.failure_reason = state.failure_reason;
    return run;
  }
  if (error != UC_ERR_OK && !state.finished) {
    run.completed = false;
    run.failure_reason = std::string("unicorn: ") + uc_strerror(error);
    return run;
  }
  if (!state.finished) {
    run.completed = false;
    run.failure_reason = "instruction budget exhausted before ExitProcess";
    return run;
  }
  run.completed = true;
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

  result.unsupported_mnemonics = read_unsupported_mnemonics(project_directory);

  guest_checkpoint_interval = kCheckpointInterval;
  const auto reference = run_reference(executable, loaded_image, stack_top, heap_base, 0);
  guest_checkpoint_interval = 0;
  result.executed_instructions = reference.instruction_count;
  result.reference_output = reference.output;
  result.reference_completed = reference.completed;
  if (!reference.note.empty()) result.diagnosis = reference.note;
  if (!reference.completed) {
    result.diagnosis = "reference execution did not complete: " + reference.failure_reason;
    return result;
  }

  // Ask for guest-state checkpoints on both sides. Output comparison alone cannot
  // see a wrong register, a wrong flag or a wrong store that never reaches the
  // program's output; this can, because it compares the machine itself.
  const auto checkpoint_path = project_directory / "reports" / "candidate-checkpoints.txt";
  std::filesystem::create_directories(project_directory / "reports");
  std::filesystem::remove(checkpoint_path);
  ::setenv("RECOMP_CHECKPOINT", checkpoint_path.string().c_str(), 1);
  ::setenv("RECOMP_CHECKPOINT_INTERVAL", std::to_string(kCheckpointInterval).c_str(), 1);

  const auto candidate = pipeline::run(project_directory);

  ::unsetenv("RECOMP_CHECKPOINT");
  ::unsetenv("RECOMP_CHECKPOINT_INTERVAL");
  result.candidate_output = candidate.standard_output;
  result.candidate_error = candidate.standard_error;
  result.candidate_exit_code = candidate.exit_code;
  result.candidate_completed = candidate.exit_code == 0;
  {
    std::filesystem::create_directories(project_directory / "reports");
    std::ofstream(project_directory / "reports" / "reference.txt") << result.reference_output;
    std::ofstream(project_directory / "reports" / "candidate.txt") << result.candidate_output;
  }
  result.outputs_match = result.reference_output == result.candidate_output;

  // Guest-state comparison. The two streams are recorded at the same interval, so
  // the first index at which they differ names the guest instruction after which
  // the candidate and the reference stopped agreeing.
  {
    std::vector<GuestCheckpoint> candidate_checkpoints;
    if (std::ifstream input_stream(checkpoint_path); input_stream) {
      std::string line;
      while (std::getline(input_stream, line)) {
        std::istringstream fields(line);
        GuestCheckpoint checkpoint;
        fields >> checkpoint.index >> checkpoint.address >> checkpoint.flags;
        for (auto& value : checkpoint.registers)
          if (!(fields >> value)) break;
        if (!fields.fail()) candidate_checkpoints.push_back(checkpoint);
      }
    }
    result.checkpoints_compared = std::min(reference.checkpoints.size(), candidate_checkpoints.size());
    if (!candidate_checkpoints.empty()) {
      const auto limit = result.checkpoints_compared;
      for (std::size_t index = 0; index < limit; ++index) {
        const auto& expected = reference.checkpoints[index];
        const auto& actual = candidate_checkpoints[index];
        if (expected.address != actual.address) {
          result.state_diagnosis = "checkpoint " + std::to_string(index) + ": the guest instruction stream differs at " +
                                   "0x" + hex_text(actual.address) + " (reference 0x" + hex_text(expected.address) + ")";
          break;
        }
        bool flags_differ = (expected.flags & 0x8d5u) != (actual.flags & 0x8d5u);
        std::size_t differing_register = 16;
        for (std::size_t register_index = 0; register_index < 8; ++register_index) {
          if (expected.registers[register_index] != actual.registers[register_index]) {
            differing_register = register_index;
            break;
          }
        }
        if (flags_differ || differing_register != 16) {
          result.state_diagnosis = "checkpoint " + std::to_string(index) + " after guest instruction index " +
                                   std::to_string(expected.index) + " (0x" + hex_text(expected.address) + "): ";
          if (differing_register != 16) {
            static const char* names[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
            result.state_diagnosis += std::string(names[differing_register]) + " is 0x" +
                                      hex_text(actual.registers[differing_register]) + ", reference 0x" +
                                      hex_text(expected.registers[differing_register]);
          } else {
            result.state_diagnosis += "flags are 0x" + hex_text(actual.flags) + ", reference 0x" +
                                      hex_text(expected.flags);
          }
          break;
        }
      }
      result.state_match = result.state_diagnosis.empty();
    }
  }
  if (!result.candidate_completed) {
    result.outputs_match = false;
    result.diagnosis = "candidate execution failed with exit code " + std::to_string(candidate.exit_code) +
                       (candidate.standard_error.empty() ? "" : ": " + candidate.standard_error);
    return result;
  }

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
  const auto reference = run_reference(executable, loaded_image,
                                       parse_hex(manifest, "stack_top", 0x0000000168000000ull),
                                       parse_hex(manifest, "heap_base", 0x0000000160000000ull), trace_limit);
  if (!reference.completed) return comparison;
  comparison.available = true;

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
