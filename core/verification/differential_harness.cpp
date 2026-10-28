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
  std::uint64_t current_instruction{};
  bool requested_exit{};
  std::uint64_t last_counted_address{~0ull};
  std::FILE* mxcsr_log{};
  std::uint32_t mxcsr_last{0xffffffffu};
  std::FILE* store_log{};
  std::vector<GuestCheckpoint> checkpoints;
  // The memory windows themselves, when a byte-level comparison is asked for. A
  // digest says only that memory differs; classifying the difference needs the bytes.
  std::vector<std::vector<std::uint8_t>> memory_windows;
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

// Every store the emulator performs, logged in the same format the candidate
// writes, so the two logs can be diffed directly. Comparing the logs attributes a
// memory divergence to the store that caused it rather than to the byte that
// ended up wrong.
// The emulator reports a 16-byte store as two 8-byte writes, so the reference's
// log has finer granularity than the candidate's for vector stores. Merging
// adjacent writes from the same instruction was tried and withdrawn: it produced
// widths of 3, 5, 6, 7 and 19, which no x86 instruction can store, because a
// single instruction that makes two genuinely separate stores is indistinguishable
// from one store the emulator split. Comparing the logs per *instruction* -- the
// ranges each instruction wrote -- is the normalisation that avoids the question,
// and is not yet implemented.
void memory_write_hook(uc_engine* engine, uc_mem_type type, std::uint64_t address, int size, std::int64_t value,
                       void* user_data) {
  (void)engine;
  (void)type;
  auto& state = *static_cast<ReferenceState*>(user_data);
  if (state.store_log == nullptr) return;
  std::fprintf(state.store_log, "%llx %llx %llx %d\n",
               static_cast<unsigned long long>(state.current_instruction),
               static_cast<unsigned long long>(address),
               static_cast<unsigned long long>(static_cast<std::uint64_t>(value)), size);
}

void code_hook(uc_engine* engine, std::uint64_t address, std::uint32_t size, void* user_data) {
  (void)size;
  auto& state = *static_cast<ReferenceState*>(user_data);
  state.current_instruction = address;
  // A `rep`-prefixed instruction is one guest instruction that the emulator runs
  // once per iteration, and the hook fires for each. The candidate lifts it as a
  // single call, so counting and tracing every iteration makes the two streams --
  // and the checkpoint indices -- drift apart from the first `rep` a program
  // executes. Collapsing consecutive repeats counts it once, which is what the
  // guest instruction stream actually contains. A loop that legitimately revisits
  // an address does not repeat it consecutively, so it is unaffected.
  if (address == state.last_counted_address) return;
  state.last_counted_address = address;
  // Every change to MXCSR, so the two sides can be compared instruction by
  // instruction rather than at checkpoints 1000 apart. The collapse above means a
  // `rep` is seen once, which matches how the candidate traces it.
  if (state.mxcsr_log != nullptr) {
    const auto mxcsr = static_cast<std::uint32_t>(read_register(engine, UC_X86_REG_MXCSR));
    if (mxcsr != state.mxcsr_last) {
      state.mxcsr_last = mxcsr;
      std::fprintf(state.mxcsr_log, "%llx %x\n", static_cast<unsigned long long>(address), mxcsr);
    }
  }
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
      checkpoint.mxcsr = static_cast<std::uint32_t>(read_register(engine, UC_X86_REG_MXCSR));
      checkpoint.x87_control_word = static_cast<std::uint32_t>(read_register(engine, UC_X86_REG_FPCW));
      checkpoint.x87_status_word = static_cast<std::uint32_t>(read_register(engine, UC_X86_REG_FPSW));
      // The reference addresses the same bytes the runtime does, so the digest is
      // computed over the same memory the candidate digests.
      GuestContext digest_context{};
      for (int register_index = 0; register_index < 16; ++register_index)
        digest_context.registers[register_index] = checkpoint.registers[register_index];
      checkpoint.memory_digest = guest_memory_digest(&digest_context);
      const auto checkpoint_number = index / guest_checkpoint_interval;
      if (std::getenv("RECOMP_MEMORY_WINDOWS") != nullptr &&
          checkpoint_number < kMemoryWindowSampleLimit) {
        const auto sp = digest_context.registers[4];
        std::vector<std::uint8_t> window;
        window.reserve(0x11000);
        window.insert(window.end(), guest_memory + sp, guest_memory + sp + 0x1000);
        if (recompiled_image_base != 0)
          window.insert(window.end(), guest_memory + recompiled_image_base,
                        guest_memory + recompiled_image_base + 0x10000);
        else
          window.resize(window.size() + 0x10000, 0);
        state.memory_windows.push_back(std::move(window));
      }
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
  initialize_guest_state(executable.image_base, heap_base, stack_top);
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
  state.requested_exit = false;
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
  // The x87 control word after FINIT. Unicorn leaves it at zero, which is not a
  // value hardware ever has -- all exceptions unmasked and the precision field
  // reserved -- so a guest reading it with FNSTCW saw a different value from the
  // candidate's and from a real machine's.
  write_register(engine, UC_X86_REG_FPCW, 0x037f);
  if (const char* mxcsr_log_path = std::getenv("RECOMP_REF_MXCSR_LOG"))
    state.mxcsr_log = std::fopen(mxcsr_log_path, "w");
  if (const char* store_log_path = std::getenv("RECOMP_REF_STORE_LOG"))
    state.store_log = std::fopen(store_log_path, "w");
  uc_hook write_hook = 0;
  if (state.store_log != nullptr)
    uc_hook_add(engine, &write_hook, UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(memory_write_hook), &state, 1, 0);
  uc_hook hook = 0;
  uc_hook_add(engine, &hook, UC_HOOK_CODE, reinterpret_cast<void*>(code_hook), &state, 1, 0);
  const auto error = uc_emu_start(engine, executable.image_base + executable.entry_point_rva, 0, 0, 0);
  run.output = state.output;
  run.instruction_count = state.instruction_count;
  run.note = state.note;
  // Handlers the guest registered with atexit are NOT run here. The candidate can run
  // them because they are compiled functions; the reference has no compiled code and
  // would have to continue emulation, which was tried and consumed the instruction
  // budget. Running them on one side only makes the two sides' output differ for every
  // program that registers one, which is worse than not running them on either -- so
  // neither runs them, and the runtime says so instead of reporting success.
  run.checkpoints = std::move(state.checkpoints);
  run.memory_windows = std::move(state.memory_windows);
  run.trace = std::move(trace);
  if (state.store_log != nullptr) std::fclose(state.store_log);
  if (state.mxcsr_log != nullptr) std::fclose(state.mxcsr_log);
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

// Whether two 8-byte slots hold doubles within one unit in the last place of each
// other. That is the documented x87 limit: this runtime holds the x87 stack as a
// double with a 53-bit mantissa and the reference uses 80-bit extended with 64, so a
// result needing more than 53 bits rounds differently in the last bit. It is a known
// class, not a divergence, and naming it keeps the gate strict for everything else.
bool within_one_ulp_of_a_double(const std::uint8_t* left, const std::uint8_t* right) {
  std::uint64_t a = 0;
  std::uint64_t b = 0;
  std::memcpy(&a, left, 8);
  std::memcpy(&b, right, 8);
  const auto difference = a > b ? a - b : b - a;
  return difference <= 1;
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
  // Byte-level memory windows are sampled sparsely because each one is 68 KiB.
  // The memory digest is still captured at every state checkpoint; the sampled
  // windows provide byte-level context without growing with every instruction.
  // A project may carry the bytes the guest should read as stdin. Handing the SAME file
  // to both sides is the whole point: the reference runs in this process and the
  // candidate in a subprocess, so without it the first consumes the real stdin and the
  // second sees EOF, and the two differ for a reason that is not the translation.
  // A ceiling on the CANDIDATE, because the harness had none: `capture_process` reads
  // until EOF, so a program that never exits hung `verify` forever with no diagnosis.
  //
  // The value is chosen from measurement, not taste. The largest fixture, `tictactoe`,
  // legitimately executes 108,107,930 guest instructions, so a ceiling of 20,000,000
  // truncated it and broke the end-to-end test. One billion is ten times the largest
  // real run observed here, which leaves room for a bigger program while still stopping
  // a program that never terminates.
  //
  // This is a safety net, not a matching budget: the reference is unbounded and stops
  // when the guest reaches ExitProcess. The proper place for a limit is the harness's
  // wall-clock handling, which would also catch a candidate stuck outside guest code;
  // this catches the case that was actually observed.
  if (std::getenv("RECOMP_INSTRUCTION_BUDGET") == nullptr)
    ::setenv("RECOMP_INSTRUCTION_BUDGET", "1000000000", 1);

  const auto stdin_path = project_directory / "recomp-stdin.txt";
  const auto captured_stdin_path = project_directory / ".recomp-stdin.capture";
  if (std::filesystem::exists(stdin_path)) {
    ::setenv("RECOMP_STDIN_FILE", stdin_path.string().c_str(), 1);
  } else if (std::filesystem::exists(captured_stdin_path)) {
    ::setenv("RECOMP_STDIN_FILE", captured_stdin_path.string().c_str(), 1);
  } else {
    const char* env_stdin = std::getenv("RECOMP_STDIN_FILE");
    if (!env_stdin || *env_stdin == '\0' || (!std::filesystem::exists(env_stdin) && std::string_view(env_stdin) != "/dev/null")) {
      ::unsetenv("RECOMP_STDIN_FILE");
    }
  }

  const auto memory_windows_path = project_directory / "reports" / "candidate-memory.bin";
  ::setenv("RECOMP_MEMORY_WINDOWS", memory_windows_path.string().c_str(), 1);
  std::filesystem::remove(memory_windows_path);
  // The app directory both sides will resolve guest paths against. Set here rather
  // than inherited, because the reference runs in this process and the candidate in
  // a child: without one shared answer to "which file did the guest open", a
  // file-backed program would compare two runs of two different files and the
  // difference would be attributed to the translator.
  const auto app_directory = std::filesystem::absolute(project_directory);
  ::setenv("RECOMP_APP_DIR", app_directory.string().c_str(), 1);
  const auto app_name = input_path.filename().string();
  if (!app_name.empty()) ::setenv("RECOMP_APP_NAME", app_name.c_str(), 1);
  std::string captured_stdin;
  if (const char* stdin_path = std::getenv("RECOMP_STDIN_FILE")) {
    std::ifstream input(stdin_path, std::ios::binary);
    if (input) captured_stdin.assign(std::istreambuf_iterator<char>(input), {});
  }
  // A trace is collected only when asked for, because it is one word per executed
  // instruction and the corpus runs to millions. Comparing the two instruction
  // streams is how a memory divergence is localised: if the streams agree up to
  // the differing address, the difference is in what one side stored; if they
  // diverge earlier, the divergence is upstream of the store.
  const char* trace_path = std::getenv("RECOMP_REF_TRACE");
  const std::size_t trace_limit = trace_path != nullptr ? 20000000 : 0;
  guest_input_capture = captured_stdin.empty() && std::getenv("RECOMP_STDIN_FILE") == nullptr
                            ? nullptr
                            : &captured_stdin;
  guest_input_position = 0;
  const auto reference = run_reference(executable, loaded_image, stack_top, heap_base, trace_limit);
  guest_input_capture = nullptr;
  guest_input_position = 0;
  guest_checkpoint_interval = 0;
  if (trace_path != nullptr) {
    if (std::FILE* file = std::fopen(trace_path, "wb")) {
      for (const auto address : reference.trace) std::fwrite(&address, sizeof(address), 1, file);
      std::fclose(file);
    }
  }
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

  // Byte-level memory comparison, when both sides produced windows. A difference is
  // classified rather than simply failed: a byte inside an aligned 8-byte slot whose
  // two values are within one unit in the last place of each other is the documented
  // x87 precision limit, and everything else is a divergence.
  struct MemoryWindowClassification {
    bool has_differences{};
    bool only_x87_precision{};
  };
  std::map<std::uint64_t, MemoryWindowClassification> memory_window_classifications;
  if (std::ifstream windows(memory_windows_path, std::ios::binary); windows) {
    constexpr std::size_t kWindowBytes = 0x11000;
    // The candidate writes a 24-byte header per sampled checkpoint -- the index, the stack
    // pointer and the image base -- so that a reader can locate the windows. Reading
    // the windows without skipping it compares two ranges 24 bytes apart, which
    // reports a divergence at the very first checkpoint.
    constexpr std::size_t kHeaderBytes = 24;
    std::vector<std::uint8_t> header(kHeaderBytes);
    std::vector<std::uint8_t> candidate_window(kWindowBytes);
    std::size_t checkpoint = 0;
    std::size_t unclassified = 0;
    std::string first_unclassified;
    while (windows.read(reinterpret_cast<char*>(header.data()), kHeaderBytes) &&
           windows.read(reinterpret_cast<char*>(candidate_window.data()), kWindowBytes) &&
           checkpoint < reference.memory_windows.size()) {
      const auto& expected = reference.memory_windows[checkpoint];
      std::uint64_t checkpoint_index = 0;
      std::memcpy(&checkpoint_index, header.data(), sizeof(checkpoint_index));
      MemoryWindowClassification classification;
      classification.only_x87_precision = true;
      if (expected.size() == kWindowBytes) {
        for (std::size_t offset = 0; offset < kWindowBytes; ++offset) {
          if (expected[offset] == candidate_window[offset]) continue;
          classification.has_differences = true;
          // Which aligned 8-byte slot holds it, and are the two doubles within one ULP?
          const auto slot = offset & ~static_cast<std::size_t>(7);
          const bool is_x87_class = slot + 8 <= kWindowBytes &&
                                    within_one_ulp_of_a_double(expected.data() + slot,
                                                               candidate_window.data() + slot);
          if (is_x87_class) {
            ++result.x87_precision_differences;
          } else {
            classification.only_x87_precision = false;
            ++unclassified;
            if (first_unclassified.empty()) {
              // The whole 8-byte slot, not the single byte: a byte on its own says
              // nothing about whether the difference is a float, a double, an
              // address or an integer, and that is the first thing a reader needs.
              std::uint64_t expected_slot = 0;
              std::uint64_t candidate_slot = 0;
              std::memcpy(&expected_slot, expected.data() + slot, 8);
              std::memcpy(&candidate_slot, candidate_window.data() + slot, 8);
              double expected_double = 0;
              double candidate_double = 0;
              std::memcpy(&expected_double, expected.data() + slot, 8);
              std::memcpy(&candidate_double, candidate_window.data() + slot, 8);
              std::ostringstream text;
              text << "checkpoint " << checkpoint_index << ", window offset 0x" << std::hex << offset
                   << " (8-byte slot at 0x" << slot << "): candidate 0x" << candidate_slot
                   << " reference 0x" << expected_slot << std::dec << " (as doubles "
                   << candidate_double << " against " << expected_double << ")";
              first_unclassified = text.str();
            }
          }
        }
      }
      memory_window_classifications[checkpoint_index] = classification;
      ++checkpoint;
    }
    if (unclassified != 0) {
      result.memory_match = false;
      result.memory_diagnosis = first_unclassified;
    } else if (result.x87_precision_differences != 0) {
      result.memory_diagnosis = std::to_string(result.x87_precision_differences) +
                                " byte(s) differ by at most one unit in the last place of a double; "
                                "this is the documented x87 precision limit";
    }
  }

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
        fields >> checkpoint.index >> checkpoint.address >> checkpoint.flags >> checkpoint.memory_digest >>
            checkpoint.mxcsr >> checkpoint.x87_control_word >> checkpoint.x87_status_word;
        for (auto& value : checkpoint.registers)
          if (!(fields >> value)) break;
        if (!fields.fail()) candidate_checkpoints.push_back(checkpoint);
      }
    }
    result.checkpoints_compared = std::min(reference.checkpoints.size(), candidate_checkpoints.size());
    result.checkpoints_total = std::max(reference.checkpoints.size(), candidate_checkpoints.size());
    if (!candidate_checkpoints.empty()) {
      const auto limit = result.checkpoints_compared;
      for (std::size_t index = 0; index < limit; ++index) {
        const auto& expected = reference.checkpoints[index];
        const auto& actual = candidate_checkpoints[index];
        bool checkpoint_matches = expected.address == actual.address;
        if (!checkpoint_matches && result.state_diagnosis.empty())
          result.state_diagnosis = "checkpoint " + std::to_string(index) + ": the guest instruction stream differs at " +
                                   "0x" + hex_text(actual.address) + " (reference 0x" + hex_text(expected.address) + ")";
        bool flags_differ = (expected.flags & 0x8d5u) != (actual.flags & 0x8d5u);
        std::size_t differing_register = 16;
        for (std::size_t register_index = 0; register_index < 8; ++register_index) {
          if (expected.registers[register_index] != actual.registers[register_index]) {
            differing_register = register_index;
            break;
          }
        }
        if (expected.memory_digest != actual.memory_digest) {
          checkpoint_matches = false;
          const auto window = memory_window_classifications.find(expected.index);
          const bool explained_by_x87 = window != memory_window_classifications.end() &&
                                        window->second.has_differences &&
                                        window->second.only_x87_precision;
          if (!explained_by_x87) {
            result.memory_match = false;
            if (result.memory_diagnosis.empty())
              result.memory_diagnosis = "checkpoint " + std::to_string(index) +
                                        " after guest instruction index " + std::to_string(expected.index) +
                                        " (0x" + hex_text(expected.address) + "): guest memory digest 0x" +
                                        hex_text(actual.memory_digest) + ", reference 0x" +
                                        hex_text(expected.memory_digest);
          }
        }
        const bool mxcsr_differs = expected.mxcsr != actual.mxcsr;
        const bool x87_control_differs = expected.x87_control_word != actual.x87_control_word;
        const bool x87_status_differs = expected.x87_status_word != actual.x87_status_word;
        if (flags_differ || differing_register != 16 || mxcsr_differs || x87_control_differs || x87_status_differs)
          checkpoint_matches = false;
        if (checkpoint_matches) ++result.checkpoints_matched;
        // A control register that disagrees is reported, not gated, for the same
        // reason the memory digest is: the divergence is not yet explained, and a
        // gate that fails for a reason nobody has diagnosed gets weakened or
        // ignored. It is recorded with its checkpoint so it cannot be lost.
        if (result.control_diagnosis.empty() &&
            (mxcsr_differs || x87_control_differs || x87_status_differs)) {
          result.control_registers_match = false;
          result.control_diagnosis = "checkpoint " + std::to_string(index) + " after guest instruction index " +
                                     std::to_string(expected.index) + " (0x" + hex_text(expected.address) + "): ";
          if (mxcsr_differs)
            result.control_diagnosis += "mxcsr is 0x" + hex_text(actual.mxcsr) + ", reference 0x" +
                                        hex_text(expected.mxcsr);
          else if (x87_control_differs)
            result.control_diagnosis += "the x87 control word is 0x" + hex_text(actual.x87_control_word) +
                                        ", reference 0x" + hex_text(expected.x87_control_word);
          else
            result.control_diagnosis += "the x87 status word is 0x" + hex_text(actual.x87_status_word) +
                                        ", reference 0x" + hex_text(expected.x87_status_word);
        }
        if (flags_differ || differing_register != 16) {
          if (result.state_diagnosis.empty()) {
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
          }
        }
      }
      if (reference.checkpoints.size() != candidate_checkpoints.size() && result.state_diagnosis.empty())
        result.state_diagnosis = "checkpoint stream lengths differ (reference " +
                                 std::to_string(reference.checkpoints.size()) + ", candidate " +
                                 std::to_string(candidate_checkpoints.size()) + ")";
      result.state_match = result.state_diagnosis.empty() &&
                           reference.checkpoints.size() == candidate_checkpoints.size();
    } else if (!reference.checkpoints.empty()) {
      result.state_diagnosis = "candidate recorded no guest-state checkpoints (reference " +
                               std::to_string(reference.checkpoints.size()) + ")";
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
