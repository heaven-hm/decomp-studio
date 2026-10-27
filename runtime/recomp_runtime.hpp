#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

// The import calling-convention table. import_argument consults it, so a shim
// reads its arguments correctly whether it was reached as cdecl, stdcall or a
// C++ member function.
#include "win32_abi.hpp"

namespace recomp {

enum ConditionCode {
  ConditionCodeOverflow,
  ConditionCodeNotOverflow,
  ConditionCodeBelow,
  ConditionCodeAboveOrEqual,
  ConditionCodeEqual,
  ConditionCodeNotEqual,
  ConditionCodeBelowOrEqual,
  ConditionCodeAbove,
  ConditionCodeSign,
  ConditionCodeNotSign,
  ConditionCodeParity,
  ConditionCodeNotParity,
  ConditionCodeLess,
  ConditionCodeGreaterOrEqual,
  ConditionCodeLessOrEqual,
  ConditionCodeGreater,
};

struct GuestContext {
  std::uint64_t registers[16];
  std::uint64_t instruction_pointer;
  std::uint32_t carry_flag;
  std::uint32_t zero_flag;
  std::uint32_t sign_flag;
  std::uint32_t overflow_flag;
  std::uint32_t auxiliary_flag;
  std::uint32_t parity_flag;
  std::uint32_t direction_flag;
  std::uint64_t fs_base;
  std::uint64_t gs_base;
  // 32 bytes each: the low 16 are xmm, all 32 are ymm. AVX widened the
  // architectural vector registers, so a 128-bit-only file cannot
  // represent a guest that uses ymm.
  std::uint8_t vector_registers[16][32];
  double x87_registers[8];
  std::uint32_t x87_top;
  std::uint32_t x87_control_word;
  std::uint32_t x87_status_word;
  std::uint32_t mxcsr;
};

// Allocates the guest address space without running anything, so the differential
// reference can map the same bytes the runtime uses.
// The size of the guest address space. Public because the differential reference
// maps exactly this region into the emulator.
inline constexpr std::uint64_t kGuestAddressSpaceBytes = 0x200000000ull;

bool map_guest_memory(std::uint64_t bytes);

// Runs one Win32 import through the runtime's own shim table, on behalf of the
// differential reference. Both sides therefore execute the same implementation
// of every call rather than two that can drift apart, and an import the runtime
// does not implement is reported as such instead of being modelled separately.
// Returns false when the import is not implemented.
bool invoke_shared_shim(GuestContext* context, const char* library_name, const char* symbol_name);

// Brings the guest address space to the state a program starts in, with the image
// already loaded. The candidate and the differential reference both call this, so
// they begin from the same state rather than from two lists that happen to agree.
void initialize_guest_state(std::uint64_t image_base, std::uint64_t heap_base, std::uint64_t stack_top);

// The stack pointer a guest starts with, and the address a sentinel return is
// written to. A guest entry point is entered as if called, so a return address is
// on the stack; placing a zero there means the entry point's `ret` terminates
// instead of running off the stack. Defined once because the candidate and the
// reference must agree on it: they did not, and the eight-byte difference shifted
// every memory checkpoint by eight bytes.
std::uint64_t initial_guest_stack_pointer(std::uint64_t stack_top, int pointer_width);

// When set, everything the guest writes to a standard stream is appended here
// instead of being sent to the host. The differential reference uses this to
// capture what the program wrote, so that a shim written once can serve both
// sides and the two outputs can still be compared.
extern std::string* guest_output_capture;

// Called instead of terminating the host when the guest asks to exit. A generated
// executable leaves this null, because exiting the process is exactly right there.
// The differential reference installs a handler: the guest calling ExitProcess
// must end the reference run, not the studio that is running it.
extern void (*guest_exit_handler)(int code);

// The guest has asked to exit: hand it to the handler when one is installed, and
// terminate the host otherwise.
void guest_request_exit(int code);

// Sends guest output to the capture buffer when one is installed, and to the host
// descriptor otherwise. Returns the number of bytes accepted, so a caller can
// report a short write rather than assuming the whole buffer went out.
std::ptrdiff_t write_guest_output(int descriptor, const char* data, std::size_t size);

extern std::uint8_t* guest_memory;
extern std::uint64_t guest_memory_size;
// The base address the guest image was loaded at; set by initialize_guest_state.
extern std::uint64_t recompiled_image_base;
extern bool guest_tracing_enabled;

// 4 for a PE32/x86 guest, 8 for a PE32+/x86-64 guest. Set once by
// run_recompiled_image before any translated code executes.
extern int guest_pointer_width;

inline std::uint64_t mask_guest_address(std::uint64_t address) {
  return guest_pointer_width >= 8 ? address : (address & 0xffffffffull);
}

// BSWAP. Written out rather than using a compiler builtin so the generated
// guest code depends only on the runtime, as every other lifted operation does.
inline std::uint32_t byte_swap_32(std::uint32_t value) {
  return ((value & 0x000000ffu) << 24) | ((value & 0x0000ff00u) << 8) |
         ((value & 0x00ff0000u) >> 8) | ((value & 0xff000000u) >> 24);
}

inline std::uint64_t byte_swap_64(std::uint64_t value) {
  return (static_cast<std::uint64_t>(byte_swap_32(static_cast<std::uint32_t>(value))) << 32) |
         static_cast<std::uint64_t>(byte_swap_32(static_cast<std::uint32_t>(value >> 32)));
}

void guest_trace_address(std::uint64_t address);

// Records the current instruction pointer; when tracing is enabled every
// executed guest address is appended to the trace stream for differential
// diagnosis against the reference execution.
// A guest-state checkpoint: what the machine looked like at a chosen point in the
// executed instruction stream. Comparing output alone cannot see a wrong register,
// a wrong flag or a wrong store that happens not to reach the program's output;
// comparing state can. Both the candidate and the reference record these against
// the same counter, so the first place they disagree names the instruction that
// caused it.
struct GuestCheckpoint {
  std::uint64_t index{};      // position in the executed instruction stream
  std::uint64_t address{};    // the guest instruction about to execute
  std::uint64_t registers[16]{};
  std::uint64_t flags{};
  // A digest of the guest's writable state: a window of the stack and a window of
  // the image's data. Comparing registers and flags alone cannot see a wrong
  // store that lands in memory the program reads later, or that it never reads at
  // all. Hashing the whole 8 GiB address space per checkpoint is not possible, and
  // hashing nothing is what comparing the output already does.
  std::uint64_t memory_digest{};
  // Control registers, compared directly rather than inferred from the memory a
  // guest eventually stores them to. Two of the last three divergences found were
  // control registers -- the x87 control word, and MXCSR's FTZ bit -- and both were
  // read by a guest and disagreed between the two sides. Comparing them here names
  // the checkpoint at which they part instead of leaving it to be localised from
  // memory afterwards.
  std::uint32_t mxcsr{};
  std::uint32_t x87_control_word{};
  std::uint32_t x87_status_word{};
};

// A bounded digest of the guest's writable state, computed the same way on both
// sides so the two can be compared. Bounded because a checkpoint happens every
// thousand instructions.
std::uint64_t guest_memory_digest(const GuestContext* context);

// Zero disables capture. The reference sets the same interval, so the two streams
// line up index for index.
extern std::uint64_t guest_checkpoint_interval;
extern std::vector<GuestCheckpoint> guest_checkpoints;
void capture_guest_checkpoint(GuestContext* context, std::uint64_t address);
// Writes the captured checkpoints when RECOMP_CHECKPOINT names a file.
void write_guest_checkpoints_if_requested();
// Opens the store log named by the environment, when one is asked for.
void open_guest_store_log(const char* path);

// Opens the memory-window export named by the environment, when one is asked for.
// A digest says only *that* memory differs; classifying the difference -- the x87
// precision class is one unit in the last place of a double, which is a known and
// documented limit -- needs the bytes. The windows are written per checkpoint,
// with the stack pointer and image base that locate them.
void open_guest_memory_windows(const char* path);
void open_guest_mxcsr_log(const char* path);

// The handlers the guest registered with atexit, oldest first. Exposed so the
// differential reference can run them: it has no compiled code, so it continues
// emulation at each handler rather than calling it.
const std::vector<std::uint64_t>& registered_atexit_handlers();

// Every change to MXCSR, in order, when a log is installed. Comparing two runs
// instruction by instruction is what localises a control-register divergence to the
// instruction that caused it, rather than to the checkpoint after it.
extern bool guest_mxcsr_logging;
extern std::uint64_t guest_mxcsr_previous_address;
void record_mxcsr_change(std::uint64_t address, std::uint32_t mxcsr);

inline void trace_instruction(GuestContext* context, std::uint64_t address) {
  context->instruction_pointer = address;
  if (guest_mxcsr_logging) record_mxcsr_change(address, context->mxcsr);
  guest_mxcsr_previous_address = address;
  if (guest_checkpoint_interval != 0) capture_guest_checkpoint(context, address);
  if (guest_tracing_enabled) guest_trace_address(address);
}

void report_guest_memory_fault(GuestContext* context, std::uint64_t address, int width, int is_write);
void recomp_trap(GuestContext* context, const char* reason);
void recomp_unsupported(GuestContext* context, const char* reason);
void report_divide_error(GuestContext* context);

// Guest memory watchpoint, enabled with RECOMP_WATCH=<hex address>. The first
// write covering that address reports the guest instruction pointer. Without it
// a corrupted value is very hard to trace, because the writer computed the
// address and so leaves no literal reference to it in the image.
extern std::uint64_t watched_guest_address;
void note_watched_write(const GuestContext* context, std::uint64_t address, int width);

inline std::uint64_t load_guest_memory(GuestContext* context, std::uint64_t address, int width) {
  if (address + static_cast<std::uint64_t>(width) > guest_memory_size) {
    report_guest_memory_fault(context, address, width, 0);
    return 0;
  }
  std::uint64_t value = 0;
  std::memcpy(&value, guest_memory + address, static_cast<std::size_t>(width));
  return value;
}

// Every store the guest performs, in order, when a log is installed. Comparing
// the two logs is how a memory divergence is attributed: identical instruction
// streams and identical checkpoints leave only "what was stored" as the
// difference, and a log says which store it was rather than which byte ended up
// wrong.
extern bool guest_store_logging;
// True while a shim is executing. The reference's store log cannot see shim writes
// -- the shim writes to guest_memory with a host memcpy, which the emulator never
// observes as a guest access -- so a store the candidate logs and the reference
// does not is not evidence of a difference unless the comparison knows which
// stores came from a shim. This marks them.
extern bool guest_in_shim;
void record_guest_store(std::uint64_t instruction_address, std::uint64_t address, std::uint64_t value, int width);
// A vector store writes a whole register; the log records it as one entry per
// register rather than as the bytes it happens to be made of, so that a 16-byte
// `movaps` is one line on both sides instead of two on one and one on the other.
void record_guest_vector_store(std::uint64_t instruction_address, std::uint64_t address, int width);

inline void store_guest_memory(GuestContext* context, std::uint64_t address, std::uint64_t value, int width) {
  note_watched_write(context, address, width);
  if (guest_store_logging) record_guest_store(context != nullptr ? context->instruction_pointer : 0, address, value, width);
  if (address + static_cast<std::uint64_t>(width) > guest_memory_size) {
    report_guest_memory_fault(context, address, width, 1);
    return;
  }
  std::memcpy(guest_memory + address, &value, static_cast<std::size_t>(width));
}

inline std::uint64_t value_mask(int width) {
  return width >= 8 ? ~0ull : ((1ull << (width * 8)) - 1);
}

inline std::int64_t sign_extend(std::uint64_t value, int width) {
  if (width >= 8) return static_cast<std::int64_t>(value);
  const std::uint64_t sign_bit = 1ull << (width * 8 - 1);
  value &= value_mask(width);
  return static_cast<std::int64_t>((value ^ sign_bit) - sign_bit);
}

inline void update_zero_sign_parity(GuestContext* context, std::uint64_t result, int width) {
  result &= value_mask(width);
  context->zero_flag = result == 0;
  context->sign_flag = static_cast<std::uint32_t>((result >> (width * 8 - 1)) & 1);
  context->parity_flag =
      static_cast<std::uint32_t>(__builtin_parity(static_cast<unsigned>(result & 0xff)) ^ 1);
}

inline std::uint64_t add_with_flags(GuestContext* context, std::uint64_t left, std::uint64_t right, int width) {
  const auto mask = value_mask(width);
  const auto result = (left + right) & mask;
  context->carry_flag = ((left & mask) + (right & mask)) > mask;
  context->overflow_flag = static_cast<std::uint32_t>(
      ((left ^ result) & (right ^ result) & (1ull << (width * 8 - 1))) != 0);
  context->auxiliary_flag = static_cast<std::uint32_t>(((left ^ right ^ result) >> 4) & 1);
  update_zero_sign_parity(context, result, width);
  return result;
}

inline std::uint64_t subtract_with_flags(GuestContext* context, std::uint64_t left, std::uint64_t right, int width) {
  const auto mask = value_mask(width);
  const auto result = (left - right) & mask;
  context->carry_flag = (left & mask) < (right & mask);
  context->overflow_flag = static_cast<std::uint32_t>(
      ((left ^ right) & (left ^ result) & (1ull << (width * 8 - 1))) != 0);
  context->auxiliary_flag = static_cast<std::uint32_t>(((left ^ right ^ result) >> 4) & 1);
  update_zero_sign_parity(context, result, width);
  return result;
}

inline std::uint64_t add_with_carry(GuestContext* context, std::uint64_t left, std::uint64_t right, int width) {
  return add_with_flags(context, left, right + context->carry_flag, width);
}

inline std::uint64_t subtract_with_borrow(GuestContext* context, std::uint64_t left, std::uint64_t right,
                                          int width) {
  return subtract_with_flags(context, left, right + context->carry_flag, width);
}

inline std::uint64_t bitwise_and(GuestContext* context, std::uint64_t left, std::uint64_t right, int width) {
  const auto result = left & right & value_mask(width);
  context->carry_flag = context->overflow_flag = context->auxiliary_flag = 0;
  update_zero_sign_parity(context, result, width);
  return result;
}

inline std::uint64_t bitwise_or(GuestContext* context, std::uint64_t left, std::uint64_t right, int width) {
  const auto result = (left | right) & value_mask(width);
  context->carry_flag = context->overflow_flag = context->auxiliary_flag = 0;
  update_zero_sign_parity(context, result, width);
  return result;
}

inline std::uint64_t bitwise_xor(GuestContext* context, std::uint64_t left, std::uint64_t right, int width) {
  const auto result = (left ^ right) & value_mask(width);
  context->carry_flag = context->overflow_flag = context->auxiliary_flag = 0;
  update_zero_sign_parity(context, result, width);
  return result;
}

inline void test_with_flags(GuestContext* context, std::uint64_t left, std::uint64_t right, int width) {
  const auto result = left & right & value_mask(width);
  context->carry_flag = context->overflow_flag = context->auxiliary_flag = 0;
  update_zero_sign_parity(context, result, width);
}

inline void compare_with_flags(GuestContext* context, std::uint64_t left, std::uint64_t right, int width) {
  (void)subtract_with_flags(context, left, right, width);
}

inline std::uint64_t increment_with_flags(GuestContext* context, std::uint64_t value, int width) {
  const auto saved_carry = context->carry_flag;
  const auto result = add_with_flags(context, value, 1, width);
  context->carry_flag = saved_carry;
  return result;
}

inline std::uint64_t decrement_with_flags(GuestContext* context, std::uint64_t value, int width) {
  const auto saved_carry = context->carry_flag;
  const auto result = subtract_with_flags(context, value, 1, width);
  context->carry_flag = saved_carry;
  return result;
}

inline std::uint64_t negate_with_flags(GuestContext* context, std::uint64_t value, int width) {
  const auto mask = value_mask(width);
  value &= mask;
  const auto result = (-value) & mask;
  context->carry_flag = value != 0;
  context->overflow_flag = value == (1ull << (width * 8 - 1));
  context->auxiliary_flag = static_cast<std::uint32_t>(((value ^ result) >> 4) & 1);
  update_zero_sign_parity(context, result, width);
  return result;
}

inline std::uint64_t bitwise_not(std::uint64_t value, int width) {
  return (~value) & value_mask(width);
}

inline std::uint64_t shift_left(GuestContext* context, std::uint64_t value, std::uint64_t count, int width) {
  const auto bits = static_cast<unsigned>(width * 8);
  const auto effective = static_cast<unsigned>(count % bits);
  const auto mask = value_mask(width);
  value &= mask;
  if (effective == 0) return value;
  const auto result = (value << effective) & mask;
  context->carry_flag = static_cast<std::uint32_t>((value >> (bits - effective)) & 1);
  context->overflow_flag = static_cast<std::uint32_t>(((result >> (bits - 1)) ^ context->carry_flag) & 1);
  context->auxiliary_flag = 0;
  update_zero_sign_parity(context, result, width);
  return result;
}

inline std::uint64_t shift_right_logical(GuestContext* context, std::uint64_t value, std::uint64_t count,
                                         int width) {
  const auto bits = static_cast<unsigned>(width * 8);
  const auto effective = static_cast<unsigned>(count % bits);
  const auto mask = value_mask(width);
  value &= mask;
  if (effective == 0) return value;
  const auto result = value >> effective;
  context->carry_flag = static_cast<std::uint32_t>((value >> (effective - 1)) & 1);
  context->overflow_flag = static_cast<std::uint32_t>((value >> (bits - 1)) & 1);
  context->auxiliary_flag = 0;
  update_zero_sign_parity(context, result, width);
  return result;
}

inline std::uint64_t shift_right_arithmetic(GuestContext* context, std::uint64_t value, std::uint64_t count,
                                            int width) {
  const auto bits = static_cast<unsigned>(width * 8);
  const auto effective = static_cast<unsigned>(count % bits);
  const auto extended = sign_extend(value, width);
  if (effective == 0) return static_cast<std::uint64_t>(extended) & value_mask(width);
  const auto result = extended >> effective;
  context->carry_flag = static_cast<std::uint32_t>((extended >> (effective - 1)) & 1);
  context->overflow_flag = 0;
  context->auxiliary_flag = 0;
  update_zero_sign_parity(context, static_cast<std::uint64_t>(result), width);
  return static_cast<std::uint64_t>(result);
}

// SHLD / SHRD: shift a value, pulling the vacated bits from a second operand.
inline std::uint64_t shift_right_double(GuestContext* context, std::uint64_t destination,
                                        std::uint64_t source, std::uint64_t count, int width) {
  const auto bits = static_cast<unsigned>(width * 8);
  const auto effective = static_cast<unsigned>(count % bits);
  const auto mask = value_mask(width);
  destination &= mask;
  source &= mask;
  if (effective == 0) return destination;
  const auto result = ((destination >> effective) | (source << (bits - effective))) & mask;
  context->carry_flag = static_cast<std::uint32_t>((destination >> (effective - 1)) & 1);
  context->overflow_flag = 0;
  context->auxiliary_flag = 0;
  update_zero_sign_parity(context, result, width);
  return result;
}

inline std::uint64_t shift_left_double(GuestContext* context, std::uint64_t destination,
                                       std::uint64_t source, std::uint64_t count, int width) {
  const auto bits = static_cast<unsigned>(width * 8);
  const auto effective = static_cast<unsigned>(count % bits);
  const auto mask = value_mask(width);
  destination &= mask;
  source &= mask;
  if (effective == 0) return destination;
  const auto result = ((destination << effective) | (source >> (bits - effective))) & mask;
  context->carry_flag = static_cast<std::uint32_t>((destination >> (bits - effective)) & 1);
  context->overflow_flag = 0;
  context->auxiliary_flag = 0;
  update_zero_sign_parity(context, result, width);
  return result;
}

inline std::uint64_t rotate_left(GuestContext* context, std::uint64_t value, std::uint64_t count, int width) {
  const auto bits = static_cast<unsigned>(width * 8);
  const auto effective = static_cast<unsigned>(count % bits);
  const auto mask = value_mask(width);
  value &= mask;
  if (effective == 0) return value;
  const auto result = ((value << effective) | (value >> (bits - effective))) & mask;
  context->carry_flag = static_cast<std::uint32_t>(result & 1);
  context->overflow_flag = static_cast<std::uint32_t>(((result >> (bits - 1)) ^ context->carry_flag) & 1);
  context->auxiliary_flag = 0;
  return result;
}

inline std::uint64_t rotate_right(GuestContext* context, std::uint64_t value, std::uint64_t count, int width) {
  const auto bits = static_cast<unsigned>(width * 8);
  const auto effective = static_cast<unsigned>(count % bits);
  const auto mask = value_mask(width);
  value &= mask;
  if (effective == 0) return value;
  const auto result = ((value >> effective) | (value << (bits - effective))) & mask;
  context->carry_flag = static_cast<std::uint32_t>((result >> (bits - 1)) & 1);
  context->overflow_flag =
      static_cast<std::uint32_t>(((result >> (bits - 1)) ^ ((result >> (bits - 2)) & 1)) & 1);
  context->auxiliary_flag = 0;
  return result;
}

inline std::uint64_t rotate_left_through_carry(GuestContext* context, std::uint64_t value, std::uint64_t count,
                                               int width) {
  const auto bits = static_cast<unsigned>(width * 8);
  const auto effective = static_cast<unsigned>(count % (bits + 1));
  const auto mask = value_mask(width);
  value &= mask;
  std::uint64_t carry = context->carry_flag;
  for (unsigned index = 0; index < effective; ++index) {
    const auto next_carry = (value >> (bits - 1)) & 1;
    value = ((value << 1) | carry) & mask;
    carry = next_carry;
  }
  context->carry_flag = static_cast<std::uint32_t>(carry);
  return value;
}

inline std::uint64_t rotate_right_through_carry(GuestContext* context, std::uint64_t value, std::uint64_t count,
                                                int width) {
  const auto bits = static_cast<unsigned>(width * 8);
  const auto effective = static_cast<unsigned>(count % (bits + 1));
  const auto mask = value_mask(width);
  value &= mask;
  std::uint64_t carry = context->carry_flag;
  for (unsigned index = 0; index < effective; ++index) {
    const auto next_carry = value & 1;
    value = ((value >> 1) | (carry << (bits - 1))) & mask;
    carry = next_carry;
  }
  context->carry_flag = static_cast<std::uint32_t>(carry);
  return value;
}

void signed_multiply_single(GuestContext* context, std::uint64_t operand, int width);
std::uint64_t signed_multiply_two(GuestContext* context, std::uint64_t left, std::uint64_t right, int width);
void unsigned_multiply_single(GuestContext* context, std::uint64_t operand, int width);
void unsigned_divide(GuestContext* context, std::uint64_t divisor, int width);
void signed_divide(GuestContext* context, std::uint64_t divisor, int width);

inline int evaluate_condition(GuestContext* context, int condition) {
  switch (condition) {
    case ConditionCodeOverflow: return context->overflow_flag != 0;
    case ConditionCodeNotOverflow: return context->overflow_flag == 0;
    case ConditionCodeBelow: return context->carry_flag != 0;
    case ConditionCodeAboveOrEqual: return context->carry_flag == 0;
    case ConditionCodeEqual: return context->zero_flag != 0;
    case ConditionCodeNotEqual: return context->zero_flag == 0;
    case ConditionCodeBelowOrEqual: return context->carry_flag != 0 || context->zero_flag != 0;
    case ConditionCodeAbove: return context->carry_flag == 0 && context->zero_flag == 0;
    case ConditionCodeSign: return context->sign_flag != 0;
    case ConditionCodeNotSign: return context->sign_flag == 0;
    case ConditionCodeParity: return context->parity_flag != 0;
    case ConditionCodeNotParity: return context->parity_flag == 0;
    case ConditionCodeLess: return context->sign_flag != context->overflow_flag;
    case ConditionCodeGreaterOrEqual: return context->sign_flag == context->overflow_flag;
    case ConditionCodeLessOrEqual:
      return context->zero_flag != 0 || context->sign_flag != context->overflow_flag;
    case ConditionCodeGreater:
      return context->zero_flag == 0 && context->sign_flag == context->overflow_flag;
    default: return 0;
  }
}

inline void push_guest_stack(GuestContext* context, std::uint64_t value) {
  context->registers[4] = mask_guest_address(context->registers[4] - static_cast<std::uint64_t>(guest_pointer_width));
  store_guest_memory(context, context->registers[4], value, guest_pointer_width);
}

inline std::uint64_t pop_guest_stack(GuestContext* context) {
  const auto value = load_guest_memory(context, context->registers[4], guest_pointer_width);
  context->registers[4] = mask_guest_address(context->registers[4] + static_cast<std::uint64_t>(guest_pointer_width));
  return value;
}

// Emulates the return address pop for `ret`/`ret imm16`.
inline void return_from_guest_function(GuestContext* context, std::uint32_t extra_bytes) {
  context->registers[4] = mask_guest_address(context->registers[4] +
                                             static_cast<std::uint64_t>(guest_pointer_width) + extra_bytes);
}

// 256-bit forms. A VEX.256 load or store moves all 32 bytes; the 128-bit
// helpers above deliberately still touch only the low 16 so that SSE code is
// unaffected by the wider register file.
inline void load_guest_vector_256(GuestContext* context, std::uint64_t address, int vector_index) {
  if (address + 32 > guest_memory_size) {
    report_guest_memory_fault(context, address, 32, 0);
    return;
  }
  std::memcpy(context->vector_registers[vector_index], guest_memory + address, 32);
}

inline void store_guest_vector_256(GuestContext* context, std::uint64_t address, int vector_index) {
  note_watched_write(context, address, 32);
  if (guest_store_logging) record_guest_vector_store(context != nullptr ? context->instruction_pointer : 0, address, 32);
  if (address + 32 > guest_memory_size) {
    report_guest_memory_fault(context, address, 32, 1);
    return;
  }
  std::memcpy(guest_memory + address, context->vector_registers[vector_index], 32);
}

inline void load_guest_vector(GuestContext* context, std::uint64_t address, int vector_index, int byte_count) {
  if (address + static_cast<std::uint64_t>(byte_count) > guest_memory_size) {
    report_guest_memory_fault(context, address, byte_count, 0);
    return;
  }
  if (byte_count >= 16) {
    std::memcpy(context->vector_registers[vector_index], guest_memory + address, 16);
  } else {
    std::memset(context->vector_registers[vector_index], 0, 16);
    std::memcpy(context->vector_registers[vector_index], guest_memory + address, static_cast<std::size_t>(byte_count));
  }
}

inline void vector_set_low(GuestContext* context, int vector_index, std::uint64_t value, int byte_count) {
  std::memset(context->vector_registers[vector_index], 0, 16);
  std::memcpy(context->vector_registers[vector_index], &value, static_cast<std::size_t>(byte_count));
}

inline std::uint64_t vector_get_low(GuestContext* context, int vector_index, int byte_count) {
  std::uint64_t value = 0;
  std::memcpy(&value, context->vector_registers[vector_index], static_cast<std::size_t>(byte_count));
  return value;
}

inline void vector_set_double(GuestContext* context, int vector_index, double value) {
  std::memcpy(context->vector_registers[vector_index], &value, 8);
}

inline double vector_get_double(GuestContext* context, int vector_index) {
  double value = 0;
  std::memcpy(&value, context->vector_registers[vector_index], 8);
  return value;
}

inline void vector_set_float(GuestContext* context, int vector_index, float value) {
  std::memcpy(context->vector_registers[vector_index], &value, 4);
}

inline float vector_get_float(GuestContext* context, int vector_index) {
  float value = 0;
  std::memcpy(&value, context->vector_registers[vector_index], 4);
  return value;
}

// COMISS / COMISD / UCOMISS / UCOMISD: flags only, no writeback.
inline void compare_scalar_floats(GuestContext* context, double left, double right) {
  context->overflow_flag = context->sign_flag = context->auxiliary_flag = 0;
  if (std::isnan(left) || std::isnan(right)) {
    context->zero_flag = context->parity_flag = context->carry_flag = 1;  // unordered
  } else if (left < right) {
    context->zero_flag = 0; context->parity_flag = 0; context->carry_flag = 1;
  } else if (left > right) {
    context->zero_flag = 0; context->parity_flag = 0; context->carry_flag = 0;
  } else {
    context->zero_flag = 1; context->parity_flag = 0; context->carry_flag = 0;
  }
}

inline double load_guest_double(GuestContext* context, std::uint64_t address) {
  const auto bits = load_guest_memory(context, address, 8);
  double value = 0;
  std::memcpy(&value, &bits, 8);
  return value;
}

inline float load_guest_float(GuestContext* context, std::uint64_t address) {
  const auto bits = static_cast<std::uint32_t>(load_guest_memory(context, address, 4));
  float value = 0;
  std::memcpy(&value, &bits, 4);
  return value;
}

inline void vector_add_doubles(GuestContext* context, int destination, int source) {
  vector_set_double(context, destination, vector_get_double(context, destination) + vector_get_double(context, source));
}
inline void vector_subtract_doubles(GuestContext* context, int destination, int source) {
  vector_set_double(context, destination, vector_get_double(context, destination) - vector_get_double(context, source));
}
inline void vector_multiply_doubles(GuestContext* context, int destination, int source) {
  vector_set_double(context, destination, vector_get_double(context, destination) * vector_get_double(context, source));
}
inline void vector_divide_doubles(GuestContext* context, int destination, int source) {
  vector_set_double(context, destination, vector_get_double(context, destination) / vector_get_double(context, source));
}
inline void vector_add_doubles_memory(GuestContext* context, int destination, std::uint64_t address) {
  vector_set_double(context, destination, vector_get_double(context, destination) + load_guest_double(context, address));
}
inline void vector_subtract_doubles_memory(GuestContext* context, int destination, std::uint64_t address) {
  vector_set_double(context, destination, vector_get_double(context, destination) - load_guest_double(context, address));
}
inline void vector_multiply_doubles_memory(GuestContext* context, int destination, std::uint64_t address) {
  vector_set_double(context, destination, vector_get_double(context, destination) * load_guest_double(context, address));
}
inline void vector_divide_doubles_memory(GuestContext* context, int destination, std::uint64_t address) {
  vector_set_double(context, destination, vector_get_double(context, destination) / load_guest_double(context, address));
}
inline void vector_add_floats(GuestContext* context, int destination, int source) {
  vector_set_float(context, destination, vector_get_float(context, destination) + vector_get_float(context, source));
}
inline void vector_subtract_floats(GuestContext* context, int destination, int source) {
  vector_set_float(context, destination, vector_get_float(context, destination) - vector_get_float(context, source));
}
inline void vector_multiply_floats(GuestContext* context, int destination, int source) {
  vector_set_float(context, destination, vector_get_float(context, destination) * vector_get_float(context, source));
}
inline void vector_divide_floats(GuestContext* context, int destination, int source) {
  vector_set_float(context, destination, vector_get_float(context, destination) / vector_get_float(context, source));
}
inline void vector_add_floats_memory(GuestContext* context, int destination, std::uint64_t address) {
  vector_set_float(context, destination, vector_get_float(context, destination) + load_guest_float(context, address));
}
inline void vector_subtract_floats_memory(GuestContext* context, int destination, std::uint64_t address) {
  vector_set_float(context, destination, vector_get_float(context, destination) - load_guest_float(context, address));
}
inline void vector_multiply_floats_memory(GuestContext* context, int destination, std::uint64_t address) {
  vector_set_float(context, destination, vector_get_float(context, destination) * load_guest_float(context, address));
}
inline void vector_divide_floats_memory(GuestContext* context, int destination, std::uint64_t address) {
  vector_set_float(context, destination, vector_get_float(context, destination) / load_guest_float(context, address));
}

inline std::uint64_t bit_scan_reverse(GuestContext* context, std::uint64_t value, int width) {
  value &= value_mask(width);
  if (value == 0) { context->zero_flag = 1; return value; }
  context->zero_flag = 0;
  int index = 0;
  for (std::uint64_t probe = value; probe > 0; probe >>= 1) ++index;
  return static_cast<std::uint64_t>(index - 1);
}

inline std::uint64_t bit_scan_forward(GuestContext* context, std::uint64_t value, int width) {
  value &= value_mask(width);
  if (value == 0) { context->zero_flag = 1; return value; }
  context->zero_flag = 0;
  std::uint64_t index = 0;
  while ((value & 1u) == 0) { value >>= 1; ++index; }
  return index;
}
inline void store_guest_vector(GuestContext* context, std::uint64_t address, int vector_index, int byte_count) {
  note_watched_write(context, address, byte_count);
  // A vector store writes memory directly rather than through
  // store_guest_memory, so without this the store log was missing every SSE
  // store -- which made the log comparison attribute a divergence to the wrong
  // place, and made a 16-byte `movaps` look like a store the candidate never
  // performed.
  if (guest_store_logging) record_guest_vector_store(context != nullptr ? context->instruction_pointer : 0, address, byte_count);
  if (address + static_cast<std::uint64_t>(byte_count) > guest_memory_size) {
    report_guest_memory_fault(context, address, byte_count, 1);
    return;
  }
  std::memcpy(guest_memory + address, context->vector_registers[vector_index], static_cast<std::size_t>(byte_count));
}

inline void vector_bitwise_xor(GuestContext* context, int destination, int source) {
  for (int index = 0; index < 16; ++index)
    context->vector_registers[destination][index] ^= context->vector_registers[source][index];
}

inline void vector_bitwise_and(GuestContext* context, int destination, int source) {
  for (int index = 0; index < 16; ++index)
    context->vector_registers[destination][index] &= context->vector_registers[source][index];
}

inline void vector_bitwise_or(GuestContext* context, int destination, int source) {
  for (int index = 0; index < 16; ++index)
    context->vector_registers[destination][index] |= context->vector_registers[source][index];
}

// ---- SSE2 packed integer --------------------------------------------------
// Element-wise operations over the 128-bit vector registers. The two macros
// below generate a register form and a memory form for each operation, so the
// two can never drift apart; `a` and `b` are the element from the destination
// and from the source respectively.

// EFLAGS as a 32-bit value. The individual flags are the source of truth in the
// context; this packs and unpacks them at their architectural bit positions so
// PUSHFD/POPFD and the reference agree.
inline std::uint32_t eflags_value(const GuestContext* context) {
  std::uint32_t value = 0x00000002u;  // bit 1 reads as 1
  if (context->carry_flag != 0) value |= 1u << 0;
  if (context->parity_flag != 0) value |= 1u << 2;
  if (context->auxiliary_flag != 0) value |= 1u << 4;
  if (context->zero_flag != 0) value |= 1u << 6;
  if (context->sign_flag != 0) value |= 1u << 7;
  if (context->direction_flag != 0) value |= 1u << 10;
  if (context->overflow_flag != 0) value |= 1u << 11;
  return value;
}

inline void set_eflags(GuestContext* context, std::uint32_t value) {
  context->carry_flag = (value >> 0) & 1u;
  context->parity_flag = (value >> 2) & 1u;
  context->auxiliary_flag = (value >> 4) & 1u;
  context->zero_flag = (value >> 6) & 1u;
  context->sign_flag = (value >> 7) & 1u;
  context->direction_flag = (value >> 10) & 1u;
  context->overflow_flag = (value >> 11) & 1u;
}

// CVTDQ2PD: the low two signed dwords become two doubles. Not the same as
// CVTDQ2PS, which converts four dwords into four floats.
inline void vector_convert_dwords_to_doubles(GuestContext* context, int destination, int source) {
  std::int32_t values[2];
  std::memcpy(values, context->vector_registers[source], 8);
  const double result[2] = {static_cast<double>(values[0]), static_cast<double>(values[1])};
  std::memcpy(context->vector_registers[destination], result, 16);
}

inline void vector_convert_dwords_to_doubles_memory(GuestContext* context, int destination,
                                                    std::uint64_t address) {
  if (address + 8 > guest_memory_size) {
    report_guest_memory_fault(context, address, 8, 0);
    return;
  }
  std::int32_t values[2];
  std::memcpy(values, guest_memory + address, 8);
  const double result[2] = {static_cast<double>(values[0]), static_cast<double>(values[1])};
  std::memcpy(context->vector_registers[destination], result, 16);
}

// VZEROUPPER/VZEROALL. AVX state is 256 bits wide, so the upper halves are real
// guest state that these instructions clear.
inline void vector_zero_upper(GuestContext* context) {
  for (int index = 0; index < 16; ++index) std::memset(context->vector_registers[index] + 16, 0, 16);
}

inline void vector_zero_all(GuestContext* context) {
  for (int index = 0; index < 16; ++index) std::memset(context->vector_registers[index], 0, 32);
}

// PMULUDQ is not a uniform element-wise multiply: it multiplies the low 32 bits
// of dwords 0 and 2 and writes two *64-bit* results. An element-wise uint32
// helper would truncate the product back to 32 bits and lose the high half.
inline void vector_multiply_unsigned_dwords(GuestContext* context, int destination, int source) {
  std::uint32_t left[4];
  std::uint32_t right[4];
  std::memcpy(left, context->vector_registers[destination], 16);
  std::memcpy(right, context->vector_registers[source], 16);
  const std::uint64_t result[2] = {static_cast<std::uint64_t>(left[0]) * right[0],
                                   static_cast<std::uint64_t>(left[2]) * right[2]};
  std::memcpy(context->vector_registers[destination], result, 16);
}

inline void vector_multiply_unsigned_dwords_memory(GuestContext* context, int destination,
                                                   std::uint64_t address) {
  if (address + 16 > guest_memory_size) {
    report_guest_memory_fault(context, address, 16, 0);
    return;
  }
  std::uint32_t left[4];
  std::uint32_t right[4];
  std::memcpy(left, context->vector_registers[destination], 16);
  std::memcpy(right, guest_memory + address, 16);
  const std::uint64_t result[2] = {static_cast<std::uint64_t>(left[0]) * right[0],
                                   static_cast<std::uint64_t>(left[2]) * right[2]};
  std::memcpy(context->vector_registers[destination], result, 16);
}

// Whole-register byte shifts: PSRLDQ/PSLLDQ move the 128-bit value by N bytes.
inline void vector_shift_right_bytes_immediate(GuestContext* context, int destination, int count) {
  if (count <= 0) return;
  if (count >= 16) {
    std::memset(context->vector_registers[destination], 0, 16);
    return;
  }
  auto* bytes = context->vector_registers[destination];
  for (int index = 0; index < 16 - count; ++index) bytes[index] = bytes[index + count];
  for (int index = 16 - count; index < 16; ++index) bytes[index] = 0;
}

inline void vector_shift_left_bytes_immediate(GuestContext* context, int destination, int count) {
  if (count <= 0) return;
  if (count >= 16) {
    std::memset(context->vector_registers[destination], 0, 16);
    return;
  }
  auto* bytes = context->vector_registers[destination];
  for (int index = 15; index >= count; --index) bytes[index] = bytes[index - count];
  for (int index = 0; index < count; ++index) bytes[index] = 0;
}

// Interleave the low or high halves of two registers: PUNPCK*BW / PUNPCK*WD.
inline void vector_unpack_bytes(GuestContext* context, int destination, int source, int high) {
  std::uint8_t left[16];
  std::uint8_t right[16];
  std::memcpy(left, context->vector_registers[destination], 16);
  std::memcpy(right, context->vector_registers[source], 16);
  const int offset = high != 0 ? 8 : 0;
  std::uint8_t result[16];
  for (int index = 0; index < 8; ++index) {
    result[index * 2] = left[offset + index];
    result[index * 2 + 1] = right[offset + index];
  }
  std::memcpy(context->vector_registers[destination], result, 16);
}

inline void vector_unpack_words(GuestContext* context, int destination, int source, int high) {
  std::uint16_t left[8];
  std::uint16_t right[8];
  std::memcpy(left, context->vector_registers[destination], 16);
  std::memcpy(right, context->vector_registers[source], 16);
  const int offset = high != 0 ? 4 : 0;
  std::uint16_t result[8];
  for (int index = 0; index < 4; ++index) {
    result[index * 2] = left[offset + index];
    result[index * 2 + 1] = right[offset + index];
  }
  std::memcpy(context->vector_registers[destination], result, 16);
}

// PACKSSWB/PACKSSDW/PACKUSWB: saturate two registers down into one.
inline void vector_pack_signed_words(GuestContext* context, int destination, int source) {
  std::int16_t left[8];
  std::int16_t right[8];
  std::memcpy(left, context->vector_registers[destination], 16);
  std::memcpy(right, context->vector_registers[source], 16);
  std::int8_t result[16];
  for (int index = 0; index < 8; ++index) {
    result[index] = static_cast<std::int8_t>(left[index] > 127 ? 127 : (left[index] < -128 ? -128 : left[index]));
    result[index + 8] = static_cast<std::int8_t>(right[index] > 127 ? 127 : (right[index] < -128 ? -128 : right[index]));
  }
  std::memcpy(context->vector_registers[destination], result, 16);
}

inline void vector_pack_unsigned_words(GuestContext* context, int destination, int source) {
  std::int16_t left[8];
  std::int16_t right[8];
  std::memcpy(left, context->vector_registers[destination], 16);
  std::memcpy(right, context->vector_registers[source], 16);
  std::uint8_t result[16];
  for (int index = 0; index < 8; ++index) {
    result[index] = static_cast<std::uint8_t>(left[index] < 0 ? 0 : (left[index] > 255 ? 255 : left[index]));
    result[index + 8] = static_cast<std::uint8_t>(right[index] < 0 ? 0 : (right[index] > 255 ? 255 : right[index]));
  }
  std::memcpy(context->vector_registers[destination], result, 16);
}

inline void vector_pack_signed_dwords(GuestContext* context, int destination, int source) {
  std::int32_t left[4];
  std::int32_t right[4];
  std::memcpy(left, context->vector_registers[destination], 16);
  std::memcpy(right, context->vector_registers[source], 16);
  std::int16_t result[8];
  for (int index = 0; index < 4; ++index) {
    result[index] = static_cast<std::int16_t>(left[index] > 32767 ? 32767 : (left[index] < -32768 ? -32768 : left[index]));
    result[index + 4] = static_cast<std::int16_t>(right[index] > 32767 ? 32767 : (right[index] < -32768 ? -32768 : right[index]));
  }
  std::memcpy(context->vector_registers[destination], result, 16);
}

// PMOVMSKB: the sign bit of each byte, packed into a general-purpose register.
inline std::uint32_t vector_move_byte_mask(const GuestContext* context, int source) {
  std::uint32_t mask = 0;
  for (int index = 0; index < 16; ++index)
    if ((context->vector_registers[source][index] & 0x80u) != 0) mask |= (1u << index);
  return mask;
}

// PSHUFB: destination bytes selected by the source; a source byte with bit 7
// set produces zero instead.
inline void vector_shuffle_bytes(GuestContext* context, int destination, int source) {
  std::uint8_t indices[16];
  std::uint8_t values[16];
  std::memcpy(indices, context->vector_registers[source], 16);
  std::memcpy(values, context->vector_registers[destination], 16);
  std::uint8_t result[16];
  for (int index = 0; index < 16; ++index)
    result[index] = (indices[index] & 0x80u) != 0 ? 0 : values[indices[index] & 0x0fu];
  std::memcpy(context->vector_registers[destination], result, 16);
}

// PSHUFLW/PSHUFHW: shuffle the low or high four words by an immediate.
inline void vector_shuffle_low_words(GuestContext* context, int destination, int control) {
  std::uint16_t words[8];
  std::memcpy(words, context->vector_registers[destination], 16);
  std::uint16_t result[8];
  for (int index = 0; index < 4; ++index) result[index] = words[(control >> (index * 2)) & 3];
  for (int index = 4; index < 8; ++index) result[index] = words[index];
  std::memcpy(context->vector_registers[destination], result, 16);
}

inline void vector_shuffle_high_words(GuestContext* context, int destination, int control) {
  std::uint16_t words[8];
  std::memcpy(words, context->vector_registers[destination], 16);
  std::uint16_t result[8];
  for (int index = 0; index < 4; ++index) result[index] = words[index];
  for (int index = 0; index < 4; ++index) result[index + 4] = words[4 + ((control >> (index * 2)) & 3)];
  std::memcpy(context->vector_registers[destination], result, 16);
}

// PMADDWD: multiply signed words pairwise and add the 32-bit products.
inline void vector_multiply_add_words_memory(GuestContext* context, int destination, std::uint64_t address) {
  if (address + 16 > guest_memory_size) {
    report_guest_memory_fault(context, address, 16, 0);
    return;
  }
  std::int16_t left[8];
  std::int16_t right[8];
  std::memcpy(left, context->vector_registers[destination], 16);
  std::memcpy(right, guest_memory + address, 16);
  std::int32_t result[4];
  for (int index = 0; index < 4; ++index)
    result[index] = static_cast<std::int32_t>(left[index * 2]) * right[index * 2] +
                    static_cast<std::int32_t>(left[index * 2 + 1]) * right[index * 2 + 1];
  std::memcpy(context->vector_registers[destination], result, 16);
}

inline void vector_multiply_add_words(GuestContext* context, int destination, int source) {
  std::int16_t left[8];
  std::int16_t right[8];
  std::memcpy(left, context->vector_registers[destination], 16);
  std::memcpy(right, context->vector_registers[source], 16);
  std::int32_t result[4];
  for (int index = 0; index < 4; ++index)
    result[index] = static_cast<std::int32_t>(left[index * 2]) * right[index * 2] +
                    static_cast<std::int32_t>(left[index * 2 + 1]) * right[index * 2 + 1];
  std::memcpy(context->vector_registers[destination], result, 16);
}

// PSADBW: sum of absolute differences, one result per eight-byte half.
inline void vector_sum_absolute_differences_memory(GuestContext* context, int destination,
                                                   std::uint64_t address) {
  if (address + 16 > guest_memory_size) {
    report_guest_memory_fault(context, address, 16, 0);
    return;
  }
  const std::uint8_t* left = context->vector_registers[destination];
  std::uint8_t right[16];
  std::memcpy(right, guest_memory + address, 16);
  std::uint64_t result[2] = {0, 0};
  for (int index = 0; index < 16; ++index) {
    const int difference = static_cast<int>(left[index]) - static_cast<int>(right[index]);
    result[index / 8] += static_cast<std::uint64_t>(difference < 0 ? -difference : difference);
  }
  std::memcpy(context->vector_registers[destination], result, 16);
}

inline void vector_sum_absolute_differences(GuestContext* context, int destination, int source) {
  const std::uint8_t* left = context->vector_registers[destination];
  const std::uint8_t* right = context->vector_registers[source];
  std::uint64_t result[2] = {0, 0};
  for (int index = 0; index < 16; ++index) {
    const int difference = static_cast<int>(left[index]) - static_cast<int>(right[index]);
    result[index / 8] += static_cast<std::uint64_t>(difference < 0 ? -difference : difference);
  }
  std::memcpy(context->vector_registers[destination], result, 16);
}

#define RECOMP_PACKED_BINARY(name, element, expression)                                        \
  inline void name(GuestContext* context, int destination, int source) {                        \
    element left[16 / sizeof(element)];                                                         \
    element right[16 / sizeof(element)];                                                        \
    std::memcpy(left, context->vector_registers[destination], 16);                              \
    std::memcpy(right, context->vector_registers[source], 16);                                  \
    for (std::size_t index = 0; index < 16 / sizeof(element); ++index) {                        \
      const element a = left[index];                                                            \
      const element b = right[index];                                                           \
      left[index] = static_cast<element>(expression);                                           \
    }                                                                                           \
    std::memcpy(context->vector_registers[destination], left, 16);                              \
  }                                                                                             \
  inline void name##_memory(GuestContext* context, int destination, std::uint64_t address) {    \
    if (address + 16 > guest_memory_size) {                                                     \
      report_guest_memory_fault(context, address, 16, 0);                                       \
      return;                                                                                   \
    }                                                                                           \
    element left[16 / sizeof(element)];                                                         \
    element right[16 / sizeof(element)];                                                        \
    std::memcpy(left, context->vector_registers[destination], 16);                              \
    std::memcpy(right, guest_memory + address, 16);                                             \
    for (std::size_t index = 0; index < 16 / sizeof(element); ++index) {                        \
      const element a = left[index];                                                            \
      const element b = right[index];                                                           \
      left[index] = static_cast<element>(expression);                                           \
    }                                                                                           \
    std::memcpy(context->vector_registers[destination], left, 16);                              \
  }

// Wrapping arithmetic.
RECOMP_PACKED_BINARY(vector_add_bytes, std::uint8_t, a + b)
RECOMP_PACKED_BINARY(vector_add_words, std::uint16_t, a + b)
RECOMP_PACKED_BINARY(vector_add_qwords, std::uint64_t, a + b)
RECOMP_PACKED_BINARY(vector_subtract_bytes, std::uint8_t, a - b)
RECOMP_PACKED_BINARY(vector_subtract_words, std::uint16_t, a - b)
RECOMP_PACKED_BINARY(vector_subtract_qwords, std::uint64_t, a - b)
RECOMP_PACKED_BINARY(vector_multiply_low_words, std::uint16_t, a * b)
RECOMP_PACKED_BINARY(vector_multiply_high_words, std::int16_t,
                     static_cast<std::int32_t>(a) * static_cast<std::int32_t>(b) >> 16)
RECOMP_PACKED_BINARY(vector_multiply_high_unsigned_words, std::uint16_t,
                     (static_cast<std::uint32_t>(a) * static_cast<std::uint32_t>(b)) >> 16)
RECOMP_PACKED_BINARY(vector_bitwise_and_not, std::uint8_t, static_cast<std::uint8_t>(~a) & b)

// Saturating arithmetic, signed and unsigned.
RECOMP_PACKED_BINARY(vector_add_saturated_signed_bytes, std::int8_t,
                     static_cast<int>(a) + static_cast<int>(b) > 127
                         ? 127
                         : (static_cast<int>(a) + static_cast<int>(b) < -128
                                ? -128
                                : static_cast<int>(a) + static_cast<int>(b)))
RECOMP_PACKED_BINARY(vector_add_saturated_unsigned_bytes, std::uint8_t,
                     static_cast<int>(a) + static_cast<int>(b) > 255 ? 255 : a + b)
RECOMP_PACKED_BINARY(vector_subtract_saturated_signed_bytes, std::int8_t,
                     static_cast<int>(a) - static_cast<int>(b) > 127
                         ? 127
                         : (static_cast<int>(a) - static_cast<int>(b) < -128
                                ? -128
                                : static_cast<int>(a) - static_cast<int>(b)))
RECOMP_PACKED_BINARY(vector_subtract_saturated_unsigned_bytes, std::uint8_t, a < b ? 0 : a - b)
RECOMP_PACKED_BINARY(vector_add_saturated_signed_words, std::int16_t,
                     static_cast<int>(a) + static_cast<int>(b) > 32767
                         ? 32767
                         : (static_cast<int>(a) + static_cast<int>(b) < -32768
                                ? -32768
                                : static_cast<int>(a) + static_cast<int>(b)))
RECOMP_PACKED_BINARY(vector_add_saturated_unsigned_words, std::uint16_t,
                     static_cast<int>(a) + static_cast<int>(b) > 65535 ? 65535 : a + b)
RECOMP_PACKED_BINARY(vector_subtract_saturated_signed_words, std::int16_t,
                     static_cast<int>(a) - static_cast<int>(b) > 32767
                         ? 32767
                         : (static_cast<int>(a) - static_cast<int>(b) < -32768
                                ? -32768
                                : static_cast<int>(a) - static_cast<int>(b)))
RECOMP_PACKED_BINARY(vector_subtract_saturated_unsigned_words, std::uint16_t, a < b ? 0 : a - b)

// Comparisons produce an all-ones or all-zero element, as the instruction does.
RECOMP_PACKED_BINARY(vector_compare_equal_bytes, std::uint8_t, a == b ? 0xff : 0x00)
RECOMP_PACKED_BINARY(vector_compare_equal_words, std::uint16_t, a == b ? 0xffff : 0x0000)
RECOMP_PACKED_BINARY(vector_compare_greater_signed_bytes, std::int8_t, a > b ? 0xff : 0x00)
RECOMP_PACKED_BINARY(vector_compare_greater_signed_words, std::int16_t, a > b ? 0xffff : 0x0000)
RECOMP_PACKED_BINARY(vector_compare_greater_signed_dwords, std::int32_t,
                     a > b ? 0xffffffffu : 0x00000000u)

// Shift each element by the low 64 bits of the corresponding source element.
RECOMP_PACKED_BINARY(vector_shift_left_words, std::uint16_t,
                     b > 15 ? 0 : static_cast<std::uint16_t>(a << b))
RECOMP_PACKED_BINARY(vector_shift_left_dwords, std::uint32_t,
                     b > 31 ? 0 : static_cast<std::uint32_t>(a << b))
RECOMP_PACKED_BINARY(vector_shift_left_qwords, std::uint64_t, b > 63 ? 0 : a << b)
RECOMP_PACKED_BINARY(vector_shift_right_logical_words, std::uint16_t,
                     b > 15 ? 0 : static_cast<std::uint16_t>(a >> b))
RECOMP_PACKED_BINARY(vector_shift_right_logical_dwords, std::uint32_t,
                     b > 31 ? 0 : static_cast<std::uint32_t>(a >> b))
RECOMP_PACKED_BINARY(vector_shift_right_logical_qwords, std::uint64_t, b > 63 ? 0 : a >> b)
RECOMP_PACKED_BINARY(vector_shift_right_arithmetic_words, std::int16_t,
                     b > 15 ? (a < 0 ? -1 : 0) : static_cast<std::int16_t>(a >> b))
RECOMP_PACKED_BINARY(vector_shift_right_arithmetic_dwords, std::int32_t,
                     b > 31 ? (a < 0 ? -1 : 0) : static_cast<std::int32_t>(a >> b))


// Immediate-count shifts: same expressions as the variable forms, with the count
// as a constant instead of a source element.
#define RECOMP_PACKED_SHIFT_IMMEDIATE(name, element, expression)                  \
  inline void name(GuestContext* context, int destination, std::uint64_t count) { \
    element values[16 / sizeof(element)];                                         \
    std::memcpy(values, context->vector_registers[destination], 16);              \
    for (std::size_t index = 0; index < 16 / sizeof(element); ++index) {          \
      const element a = values[index];                                            \
      const std::uint64_t b = count;                                              \
      values[index] = static_cast<element>(expression);                           \
    }                                                                             \
    std::memcpy(context->vector_registers[destination], values, 16);              \
  }

RECOMP_PACKED_SHIFT_IMMEDIATE(vector_shift_left_words_immediate, std::uint16_t, b > 15 ? 0 : a << b)
RECOMP_PACKED_SHIFT_IMMEDIATE(vector_shift_left_dwords_immediate, std::uint32_t, b > 31 ? 0 : a << b)
RECOMP_PACKED_SHIFT_IMMEDIATE(vector_shift_left_qwords_immediate, std::uint64_t, b > 63 ? 0 : a << b)
RECOMP_PACKED_SHIFT_IMMEDIATE(vector_shift_right_logical_words_immediate, std::uint16_t, b > 15 ? 0 : a >> b)
RECOMP_PACKED_SHIFT_IMMEDIATE(vector_shift_right_logical_dwords_immediate, std::uint32_t, b > 31 ? 0 : a >> b)
RECOMP_PACKED_SHIFT_IMMEDIATE(vector_shift_right_logical_qwords_immediate, std::uint64_t, b > 63 ? 0 : a >> b)
RECOMP_PACKED_SHIFT_IMMEDIATE(vector_shift_right_arithmetic_words_immediate, std::int16_t,
                              b > 15 ? (a < 0 ? -1 : 0) : static_cast<std::int16_t>(a >> b))
RECOMP_PACKED_SHIFT_IMMEDIATE(vector_shift_right_arithmetic_dwords_immediate, std::int32_t,
                              b > 31 ? (a < 0 ? -1 : 0) : static_cast<std::int32_t>(a >> b))


// Variable-count shifts take ONE count: the low 64 bits of the source operand,
// applied to every element. They are not an element-wise shift by the
// corresponding source element, which is what an element-wise helper computes.
inline std::uint64_t vector_shift_count(const GuestContext* context, int source) {
  std::uint64_t count = 0;
  std::memcpy(&count, context->vector_registers[source], 8);
  return count;
}

inline std::uint64_t vector_shift_count_memory(GuestContext* context, std::uint64_t address) {
  if (address + 8 > guest_memory_size) {
    report_guest_memory_fault(context, address, 8, 0);
    return 0;
  }
  std::uint64_t count = 0;
  std::memcpy(&count, guest_memory + address, 8);
  return count;
}

#define RECOMP_PACKED_SHIFT_BY_SOURCE(name, immediate_helper)                       \
  inline void name(GuestContext* context, int destination, int source) {            \
    immediate_helper(context, destination, vector_shift_count(context, source));    \
  }                                                                                \
  inline void name##_memory(GuestContext* context, int destination,                 \
                            std::uint64_t address) {                                \
    immediate_helper(context, destination, vector_shift_count_memory(context, address)); \
  }

RECOMP_PACKED_SHIFT_BY_SOURCE(vector_shift_left_words_by_source, vector_shift_left_words_immediate)
RECOMP_PACKED_SHIFT_BY_SOURCE(vector_shift_left_dwords_by_source, vector_shift_left_dwords_immediate)
RECOMP_PACKED_SHIFT_BY_SOURCE(vector_shift_left_qwords_by_source, vector_shift_left_qwords_immediate)
RECOMP_PACKED_SHIFT_BY_SOURCE(vector_shift_right_logical_words_by_source,
                              vector_shift_right_logical_words_immediate)
RECOMP_PACKED_SHIFT_BY_SOURCE(vector_shift_right_logical_dwords_by_source,
                              vector_shift_right_logical_dwords_immediate)
RECOMP_PACKED_SHIFT_BY_SOURCE(vector_shift_right_logical_qwords_by_source,
                              vector_shift_right_logical_qwords_immediate)
RECOMP_PACKED_SHIFT_BY_SOURCE(vector_shift_right_arithmetic_words_by_source,
                              vector_shift_right_arithmetic_words_immediate)
RECOMP_PACKED_SHIFT_BY_SOURCE(vector_shift_right_arithmetic_dwords_by_source,
                              vector_shift_right_arithmetic_dwords_immediate)

#undef RECOMP_PACKED_SHIFT_BY_SOURCE

#undef RECOMP_PACKED_SHIFT_IMMEDIATE

RECOMP_PACKED_BINARY(vector_add_dwords, std::uint32_t, a + b)
RECOMP_PACKED_BINARY(vector_subtract_dwords, std::uint32_t, a - b)
RECOMP_PACKED_BINARY(vector_compare_equal_dwords, std::uint32_t, a == b ? 0xffffffffu : 0u)

#undef RECOMP_PACKED_BINARY




inline void vector_shuffle_dwords(GuestContext* context, int destination, int source, int control) {
  std::uint32_t lanes[4];
  const auto* input = reinterpret_cast<const std::uint32_t*>(context->vector_registers[source]);
  for (int index = 0; index < 4; ++index) lanes[index] = input[(control >> (index * 2)) & 3];
  std::memcpy(context->vector_registers[destination], lanes, 16);
}

inline void vector_unpack_dwords(GuestContext* context, int destination, int source, int high) {
  std::uint32_t lanes[4];
  const auto* left = reinterpret_cast<const std::uint32_t*>(context->vector_registers[destination]);
  const auto* right = reinterpret_cast<const std::uint32_t*>(context->vector_registers[source]);
  lanes[0] = left[high ? 2 : 0];
  lanes[1] = right[high ? 2 : 0];
  lanes[2] = left[high ? 3 : 1];
  lanes[3] = right[high ? 3 : 1];
  std::memcpy(context->vector_registers[destination], lanes, 16);
}

inline void vector_unpack_qwords(GuestContext* context, int destination, int source, int high) {
  std::uint64_t lanes[2];
  const auto* left = reinterpret_cast<const std::uint64_t*>(context->vector_registers[destination]);
  const auto* right = reinterpret_cast<const std::uint64_t*>(context->vector_registers[source]);
  lanes[0] = left[high ? 1 : 0];
  lanes[1] = right[high ? 1 : 0];
  std::memcpy(context->vector_registers[destination], lanes, 16);
}

inline void vector_bitwise_xor_memory(GuestContext* context, int destination, std::uint64_t address, int byte_count) {
  for (int index = 0; index < byte_count; ++index)
    context->vector_registers[destination][index] ^= static_cast<std::uint8_t>(load_guest_memory(context, address + index, 1));
}

inline void vector_bitwise_and_memory(GuestContext* context, int destination, std::uint64_t address, int byte_count) {
  for (int index = 0; index < byte_count; ++index)
    context->vector_registers[destination][index] &= static_cast<std::uint8_t>(load_guest_memory(context, address + index, 1));
}

inline void vector_bitwise_or_memory(GuestContext* context, int destination, std::uint64_t address, int byte_count) {
  for (int index = 0; index < byte_count; ++index)
    context->vector_registers[destination][index] |= static_cast<std::uint8_t>(load_guest_memory(context, address + index, 1));
}

// ---- x87 floating point ------------------------------------------------
// The x87 stack lives in the guest context. Arithmetic is modelled with
// `double`: on arm64 `long double` is 64-bit, so true 80-bit extended
// precision is not natively available. Values that need more than 53 bits of
// mantissa can therefore differ from the original; this is a documented
// fidelity limit, not a silent substitution of single precision.
inline constexpr int kX87StackSize = 8;
inline constexpr std::uint32_t kX87PrecisionFlag = 1u << 5;

inline int x87_rounding_mode(const GuestContext* context) {
  return static_cast<int>((context->x87_control_word >> 10) & 3);
}

inline double x87_read(GuestContext* context, int index) {
  return context->x87_registers[(context->x87_top + index) & 7];
}

inline void x87_write(GuestContext* context, int index, double value) {
  context->x87_registers[(context->x87_top + index) & 7] = value;
}

inline void x87_push(GuestContext* context, double value) {
  context->x87_top = (context->x87_top - 1) & 7;
  context->x87_registers[context->x87_top] = value;
}

inline double x87_pop(GuestContext* context) {
  const auto value = context->x87_registers[context->x87_top];
  context->x87_top = (context->x87_top + 1) & 7;
  return value;
}

inline double x87_load_extended80(GuestContext* context, std::uint64_t address) {
  const auto mantissa = load_guest_memory(context, address, 8);
  const auto sign_exponent = static_cast<std::uint32_t>(load_guest_memory(context, address + 8, 2));
  const int sign = static_cast<int>(sign_exponent >> 15);
  const int exponent = static_cast<int>(sign_exponent & 0x7fff);
  double value;
  if (exponent == 0 && mantissa == 0) value = 0.0;
  else if (exponent == 0x7fff) value = (mantissa << 1) != 0 ? NAN : INFINITY;
  else value = std::ldexp(static_cast<double>(mantissa), exponent - 16383 - 63);
  return sign != 0 ? -value : value;
}

inline void x87_store_extended80(GuestContext* context, std::uint64_t address, double value) {
  std::uint64_t mantissa = 0;
  std::uint32_t sign_exponent = 0;
  if (std::signbit(value)) sign_exponent = 0x8000u;
  const auto magnitude = std::fabs(value);
  if (std::isnan(magnitude)) {
    sign_exponent |= 0x7fffu;
    mantissa = 0xc000000000000000ull;
  } else if (std::isinf(magnitude)) {
    sign_exponent |= 0x7fffu;
    mantissa = 0x8000000000000000ull;
  } else if (magnitude != 0.0) {
    int exponent = 0;
    const auto fraction = std::frexp(magnitude, &exponent);
    mantissa = static_cast<std::uint64_t>(std::ldexp(fraction, 64));
    sign_exponent |= static_cast<std::uint32_t>(exponent - 1 + 16383) & 0x7fffu;
  }
  store_guest_memory(context, address, mantissa, 8);
  store_guest_memory(context, address + 8, sign_exponent, 2);
}

// Rounds a double to single precision under the x87 control-word rounding mode.
inline float x87_round_to_float(GuestContext* context, double value) {
  const auto nearest = static_cast<float>(value);
  if (static_cast<double>(nearest) == value) return nearest;
  context->x87_status_word |= kX87PrecisionFlag;
  float lower = nearest;
  float upper = nearest;
  if (static_cast<double>(nearest) < value) upper = std::nextafterf(nearest, INFINITY);
  else lower = std::nextafterf(nearest, -INFINITY);
  switch (x87_rounding_mode(context)) {
    case 1: return lower;
    case 2: return upper;
    case 3: return value > 0 ? lower : upper;
    default: return nearest;
  }
}

// fld m32 / m64 / m80
inline void x87_load_real(GuestContext* context, std::uint64_t address, int size) {
  if (size == 4) {
    const auto bits = static_cast<std::uint32_t>(load_guest_memory(context, address, 4));
    float value = 0;
    std::memcpy(&value, &bits, 4);
    x87_push(context, static_cast<double>(value));
  } else if (size == 8) {
    const auto bits = load_guest_memory(context, address, 8);
    double value = 0;
    std::memcpy(&value, &bits, 8);
    x87_push(context, value);
  } else {
    x87_push(context, x87_load_extended80(context, address));
  }
}

// fild m16 / m32 / m64
inline void x87_load_integer(GuestContext* context, std::uint64_t address, int size) {
  std::int64_t value;
  if (size == 2) value = static_cast<std::int16_t>(load_guest_memory(context, address, 2));
  else if (size == 4) value = static_cast<std::int32_t>(load_guest_memory(context, address, 4));
  else value = static_cast<std::int64_t>(load_guest_memory(context, address, 8));
  x87_push(context, static_cast<double>(value));
}

// fst / fstp m32 / m64 / m80 (pop != 0 for fstp)
inline void x87_store_real(GuestContext* context, std::uint64_t address, int size, int pop) {
  const auto value = x87_read(context, 0);
  if (size == 4) {
    const auto narrowed = x87_round_to_float(context, value);
    std::uint32_t bits = 0;
    std::memcpy(&bits, &narrowed, 4);
    store_guest_memory(context, address, bits, 4);
  } else if (size == 8) {
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, 8);
    store_guest_memory(context, address, bits, 8);
  } else {
    x87_store_extended80(context, address, value);
  }
  if (pop) (void)x87_pop(context);
}

// fcom / fucom: sets the x87 condition codes C3, C2, C0.
inline void x87_compare(GuestContext* context, double operand) {
  const auto value = x87_read(context, 0);
  std::uint32_t status = context->x87_status_word & ~(0x0100u | 0x0400u | 0x4000u);
  if (std::isnan(value) || std::isnan(operand)) {
    status |= 0x0100u | 0x0400u | 0x4000u;  // unordered: C0 = C2 = C3 = 1
  } else if (value < operand) {
    status |= 0x0100u;                      // C0: ST(0) < operand
  } else if (value == operand) {
    status |= 0x4000u;                      // C3: equal
  }
  context->x87_status_word = status;
}

// fcomi / fucomi: the same comparison as fcom, but the result goes to the
// EFLAGS rather than to the x87 status word. OF, SF and AF are cleared.
inline void x87_compare_flags(GuestContext* context, double operand, int pop) {
  const auto value = x87_read(context, 0);
  context->overflow_flag = 0;
  context->sign_flag = 0;
  context->auxiliary_flag = 0;
  if (std::isnan(value) || std::isnan(operand)) {
    context->zero_flag = 1;
    context->parity_flag = 1;
    context->carry_flag = 1;
  } else if (value < operand) {
    context->zero_flag = 0;
    context->parity_flag = 0;
    context->carry_flag = 1;
  } else if (value == operand) {
    context->zero_flag = 1;
    context->parity_flag = 0;
    context->carry_flag = 0;
  } else {
    context->zero_flag = 0;
    context->parity_flag = 0;
    context->carry_flag = 0;
  }
  if (pop != 0) (void)x87_pop(context);
}

// FCMOVcc: ST(0) := ST(source) when the condition on the EFLAGS holds. The
// conditions are the unsigned ones, because fcomi sets CF/ZF/PF.
inline void x87_conditional_move(GuestContext* context, int source, int condition) {
  bool take = false;
  switch (condition) {
    case 0: take = context->carry_flag != 0; break;                                  // fcmovb
    case 1: take = context->zero_flag != 0; break;                                   // fcmove
    case 2: take = context->carry_flag != 0 || context->zero_flag != 0; break;       // fcmovbe
    case 3: take = context->parity_flag != 0; break;                                 // fcmovu
    case 4: take = context->carry_flag == 0; break;                                  // fcmovnb
    case 5: take = context->zero_flag == 0; break;                                   // fcmovne
    case 6: take = context->carry_flag == 0 && context->zero_flag == 0; break;       // fcmovnbe
    default: take = context->parity_flag == 0; break;                                // fcmovnu
  }
  if (take) x87_write(context, 0, x87_read(context, source));
}

// FXAM classifies ST(0) into C3/C2/C0 and puts its sign in C1.
inline void x87_examine(GuestContext* context) {
  const auto value = x87_read(context, 0);
  std::uint32_t status = context->x87_status_word & ~(0x0200u | 0x0100u | 0x0400u | 0x4000u);
  if (std::isnan(value)) status |= 0x0100u;                                        // C0: NaN
  else if (std::isinf(value)) status |= 0x0400u | 0x0100u;                          // C2|C0: infinity
  else if (value == 0.0) status |= 0x4000u;                                         // C3: zero
  else if (std::fpclassify(value) == FP_SUBNORMAL) status |= 0x4000u | 0x0400u;     // C3|C2: denormal
  else status |= 0x0400u;                                                           // C2: normal
  if (std::signbit(value)) status |= 0x0200u;                                       // C1: sign
  context->x87_status_word = status;
}

// TZCNT counts trailing zero bits. Unlike BSF it is defined for a zero input:
// the result is the operand width and CF is set.
inline std::uint64_t count_trailing_zeros(GuestContext* context, std::uint64_t value, int width) {
  if (value == 0) {
    context->carry_flag = 1;
    context->zero_flag = 1;
    return static_cast<std::uint64_t>(width * 8);
  }
  context->carry_flag = 0;
  std::uint64_t count = 0;
  while (((value >> count) & 1ull) == 0) ++count;
  context->zero_flag = count == 0 ? 1 : 0;
  return count;
}

// Rounds ST(0) to an integer under the x87 rounding mode, clamped to int64.
inline std::int64_t x87_round_to_integer(const GuestContext* context, double value) {
  double rounded;
  switch (x87_rounding_mode(context)) {
    case 1: rounded = std::floor(value); break;
    case 2: rounded = std::ceil(value); break;
    case 3: rounded = std::trunc(value); break;
    default: rounded = std::nearbyint(value); break;
  }
  if (rounded >= static_cast<double>(std::numeric_limits<std::int64_t>::max()))
    return std::numeric_limits<std::int64_t>::max();
  if (rounded <= static_cast<double>(std::numeric_limits<std::int64_t>::min()))
    return std::numeric_limits<std::int64_t>::min();
  return static_cast<std::int64_t>(rounded);
}

// fist / fistp m16 / m32 / m64
inline void x87_store_integer(GuestContext* context, std::uint64_t address, int size, int pop) {
  const auto rounded = x87_round_to_integer(context, x87_read(context, 0));
  if (size == 2) store_guest_memory(context, address, static_cast<std::uint16_t>(rounded), 2);
  else if (size == 4) store_guest_memory(context, address, static_cast<std::uint32_t>(rounded), 4);
  else store_guest_memory(context, address, static_cast<std::uint64_t>(rounded), 8);
  if (pop) (void)x87_pop(context);
}

// operation: 0 add, 1 multiply, 2 subtract, 3 reverse subtract, 4 divide, 5 reverse divide
inline void x87_arithmetic(GuestContext* context, int operation, double operand) {
  const auto value = x87_read(context, 0);
  double result = value;
  switch (operation) {
    case 0: result = value + operand; break;
    case 1: result = value * operand; break;
    case 2: result = value - operand; break;
    case 3: result = operand - value; break;
    case 4: result = value / operand; break;
    default: result = operand / value; break;
  }
  x87_write(context, 0, result);
}

// The transcendental and remainder forms the x87 supports but the game paths do
// not exercise often. Each is the exact C library equivalent; the x87 computes
// them in extended precision, which this model does not, so they inherit the
// documented double-precision limit.
inline void x87_partial_remainder(GuestContext* context, int round_quotient) {
  const auto dividend = x87_read(context, 0);
  const auto divisor = x87_read(context, 1);
  if (divisor == 0.0 || std::isnan(dividend) || std::isnan(divisor)) {
    context->x87_status_word |= 0x0001u;  // invalid operation
    return;
  }
  double quotient = dividend / divisor;
  quotient = round_quotient != 0 ? std::nearbyint(quotient) : std::trunc(quotient);
  x87_write(context, 0, dividend - quotient * divisor);
  context->x87_status_word &= ~0x4100u;  // C2 clear: the result is a partial one
}

inline void x87_exponential_minus_one(GuestContext* context) {
  x87_write(context, 0, std::exp2(x87_read(context, 0)) - 1.0);
}

inline void x87_scale(GuestContext* context) {
  x87_write(context, 0, std::ldexp(x87_read(context, 0), static_cast<int>(std::trunc(x87_read(context, 1)))));
}

// FNSTENV/FSTENV store the 28-byte environment; FLDENV loads it. Only the
// control and status words are modelled, so the tag word and the saved
// instruction and data pointers are written as zero and ignored on load.
inline std::uint32_t x87_status_value(const GuestContext* context);

inline void x87_store_environment(GuestContext* context, std::uint64_t address) {
  store_guest_memory(context, address, context->x87_control_word, 4);
  store_guest_memory(context, address + 4, x87_status_value(context), 4);
  store_guest_memory(context, address + 8, 0, 4);   // tag word
  store_guest_memory(context, address + 12, 0, 4);  // instruction pointer
  store_guest_memory(context, address + 16, 0, 4);
  store_guest_memory(context, address + 20, 0, 4);  // data pointer
  store_guest_memory(context, address + 24, 0, 4);
}

inline void x87_load_environment(GuestContext* context, std::uint64_t address) {
  context->x87_control_word = static_cast<std::uint32_t>(load_guest_memory(context, address, 4));
  context->x87_status_word = static_cast<std::uint32_t>(load_guest_memory(context, address + 4, 4));
}

// FXSAVE/FXRSTOR: the 512-byte SSE and x87 state area.
//
// Two modelling limits, both inherited from the context rather than introduced
// here. The x87 registers are held as doubles, so a value needing more than 53
// mantissa bits does not survive the round trip through 80-bit extended; and the
// abridged tag word is written as zero because register tags are not tracked.
// Both are documented limits of the x87 model, not new ones.
inline constexpr int kFxsaveAreaBytes = 512;

inline void x87_save_state(GuestContext* context, std::uint64_t address) {
  note_watched_write(context, address, kFxsaveAreaBytes);
  if (address + kFxsaveAreaBytes > guest_memory_size) {
    report_guest_memory_fault(context, address, kFxsaveAreaBytes, 1);
    return;
  }
  std::memset(guest_memory + address, 0, kFxsaveAreaBytes);
  store_guest_memory(context, address + 0, context->x87_control_word, 2);
  store_guest_memory(context, address + 2, x87_status_value(context), 2);
  store_guest_memory(context, address + 4, 0, 2);              // abridged tag word
  store_guest_memory(context, address + 24, context->mxcsr, 4);
  store_guest_memory(context, address + 28, 0x0000ffbfu, 4);   // MXCSR_MASK
  // The x87 data registers are stored in physical order; FSW.TOP says which one
  // is ST(0), which is why x87_read (TOP-relative) is not used here.
  for (int index = 0; index < 8; ++index)
    x87_store_extended80(context, address + 32 + static_cast<std::uint64_t>(index) * 16,
                         context->x87_registers[index]);
  for (int index = 0; index < 16; ++index)
    std::memcpy(guest_memory + address + 160 + static_cast<std::uint64_t>(index) * 16,
                context->vector_registers[index], 16);
}

inline void x87_restore_state(GuestContext* context, std::uint64_t address) {
  if (address + kFxsaveAreaBytes > guest_memory_size) {
    report_guest_memory_fault(context, address, kFxsaveAreaBytes, 0);
    return;
  }
  context->x87_control_word = static_cast<std::uint32_t>(load_guest_memory(context, address + 0, 2));
  context->x87_status_word = static_cast<std::uint32_t>(load_guest_memory(context, address + 2, 2));
  context->x87_top = (context->x87_status_word >> 11) & 7u;
  context->mxcsr = static_cast<std::uint32_t>(load_guest_memory(context, address + 24, 4));
  for (int index = 0; index < 8; ++index)
    context->x87_registers[index] = x87_load_extended80(context, address + 32 + static_cast<std::uint64_t>(index) * 16);
  for (int index = 0; index < 16; ++index) {
    std::memcpy(context->vector_registers[index],
                guest_memory + address + 160 + static_cast<std::uint64_t>(index) * 16, 16);
    std::memset(context->vector_registers[index] + 16, 0, 16);  // FXSAVE covers 128 bits
  }
}

// FPTAN: ST(0) becomes tan(ST(0)) and 1.0 is pushed above it, which is the
// documented result order and the reason the instruction has no plain "replace"
// form.
// FSINCOS pushes cos(ST(0)) and then sin(ST(0)), so the sine ends up on top.
inline void x87_sine_cosine(GuestContext* context) {
  const auto value = x87_read(context, 0);
  x87_write(context, 0, std::cos(value));
  x87_push(context, std::sin(value));
}

// FYL2XP1: ST(1) * log2(ST(0) + 1), with ST(0) popped.
inline void x87_log2_x_plus_one(GuestContext* context) {
  const auto argument = x87_read(context, 0);
  const auto multiplier = x87_read(context, 1);
  (void)x87_pop(context);
  x87_write(context, 0, multiplier * std::log2(argument + 1.0));
}

inline void x87_partial_tangent(GuestContext* context) {
  const auto value = std::tan(x87_read(context, 0));
  x87_write(context, 0, value);
  x87_push(context, 1.0);
}

// FNSAVE/FRSTOR: the 108-byte x87 environment plus the eight data registers.
// The same modelling limit as FXSAVE applies: registers are held as doubles, so
// a value needing more than 53 mantissa bits does not survive 80-bit extended.
inline constexpr int kX87SaveAreaBytes = 108;

inline void x87_save_state_87(GuestContext* context, std::uint64_t address) {
  if (address + kX87SaveAreaBytes > guest_memory_size) {
    report_guest_memory_fault(context, address, kX87SaveAreaBytes, 1);
    return;
  }
  std::memset(guest_memory + address, 0, kX87SaveAreaBytes);
  store_guest_memory(context, address + 0, context->x87_control_word, 2);
  store_guest_memory(context, address + 4, x87_status_value(context), 2);
  store_guest_memory(context, address + 8, 0, 2);  // tag word, not tracked
  for (int index = 0; index < 8; ++index)
    x87_store_extended80(context, address + 28 + static_cast<std::uint64_t>(index) * 10,
                         context->x87_registers[index]);
}

inline void x87_restore_state_87(GuestContext* context, std::uint64_t address) {
  if (address + kX87SaveAreaBytes > guest_memory_size) {
    report_guest_memory_fault(context, address, kX87SaveAreaBytes, 0);
    return;
  }
  context->x87_control_word = static_cast<std::uint32_t>(load_guest_memory(context, address + 0, 2));
  context->x87_status_word = static_cast<std::uint32_t>(load_guest_memory(context, address + 4, 2));
  context->x87_top = (context->x87_status_word >> 11) & 7u;
  for (int index = 0; index < 8; ++index)
    context->x87_registers[index] =
        x87_load_extended80(context, address + 28 + static_cast<std::uint64_t>(index) * 10);
}

inline void x87_load_control_word(GuestContext* context, std::uint64_t address) {
  context->x87_control_word = static_cast<std::uint32_t>(load_guest_memory(context, address, 2));
}

inline void x87_store_control_word(GuestContext* context, std::uint64_t address) {
  store_guest_memory(context, address, context->x87_control_word, 2);
}

inline std::uint32_t x87_status_value(const GuestContext* context) {
  return (context->x87_status_word & ~0x3800u) | ((context->x87_top & 7u) << 11);
}

inline void x87_store_status_word(GuestContext* context, std::uint64_t address) {
  store_guest_memory(context, address, x87_status_value(context), 2);
}

inline void x87_store_status_word_ax(GuestContext* context) {
  context->registers[0] = (context->registers[0] & ~0xffffull) | (x87_status_value(context) & 0xffffull);
}

// ---- MXCSR ------------------------------------------------------------
// MXCSR is architectural state: it lives in the guest context, not in the host
// FP environment, so a guest rounding-mode change cannot leak into the
// recompiled program's own arithmetic.
inline constexpr std::uint32_t kMxcsrDefaultValue = 0x1f80u;
// MXCSR's exception flags are bits 7..12: IE, DE, ZE, OE, UE, PE. Bit 5 is FTZ,
// which is not an exception flag at all. This constant held 1u << 5, so every
// operation that recorded an inexact result -- cvtdq2ps among them -- set the
// FLUSH-TO-ZERO bit instead of the precision flag. A guest that read MXCSR with
// stmxcsr saw a control bit set that it had never asked for, and two fixtures
// diverged on it.
inline constexpr std::uint32_t kMxcsrPrecisionFlag = 1u << 12;
inline constexpr std::uint32_t kMxcsrRoundingControlShift = 13;
inline constexpr std::uint32_t kMxcsrRoundingControlMask = 3u << kMxcsrRoundingControlShift;

inline int mxcsr_rounding_mode(const GuestContext* context) {
  return static_cast<int>((context->mxcsr & kMxcsrRoundingControlMask) >> kMxcsrRoundingControlShift);
}

inline void load_mxcsr(GuestContext* context, std::uint64_t address) {
  context->mxcsr = static_cast<std::uint32_t>(load_guest_memory(context, address, 4));
}

inline void store_mxcsr(GuestContext* context, std::uint64_t address) {
  store_guest_memory(context, address, context->mxcsr, 4);
}

// Converts one signed 32-bit integer to single precision under the requested
// rounding mode (0 nearest-even, 1 toward -inf, 2 toward +inf, 3 toward zero)
// and reports whether the result is inexact. Every int32 is exact in double, so
// the two neighbouring floats bracket the exact value exactly.
inline float round_integer_to_float(std::int32_t value, int rounding_mode, bool* inexact) {
  const double exact = static_cast<double>(value);
  const float nearest = static_cast<float>(value);  // host default: nearest-even
  if (static_cast<double>(nearest) == exact) {
    *inexact = false;
    return nearest;
  }
  *inexact = true;
  // Bracket the exact value with the two adjacent floats. `nearest` is one of
  // them, but which end it is depends on the value and must not be assumed.
  float lower = nearest;
  float upper = nearest;
  if (static_cast<double>(nearest) < exact) {
    upper = std::nextafterf(nearest, INFINITY);
  } else {
    lower = std::nextafterf(nearest, -INFINITY);
  }
  switch (rounding_mode) {
    case 1: return lower;                      // toward -infinity
    case 2: return upper;                      // toward +infinity
    case 3: return value > 0 ? lower : upper;  // toward zero
    default: return nearest;                   // nearest, ties to even
  }
}

inline void convert_dwords_to_floats_array(GuestContext* context, int destination,
                                           const std::int32_t* values) {
  const int rounding_mode = mxcsr_rounding_mode(context);
  float converted[4];
  bool inexact = false;
  for (int index = 0; index < 4; ++index) {
    bool element_inexact = false;
    converted[index] = round_integer_to_float(values[index], rounding_mode, &element_inexact);
    inexact = inexact || element_inexact;
  }
  std::memcpy(context->vector_registers[destination], converted, 16);
  if (inexact) context->mxcsr |= kMxcsrPrecisionFlag;
}

inline void convert_dwords_to_floats(GuestContext* context, int destination, int source) {
  std::int32_t values[4];
  std::memcpy(values, context->vector_registers[source], 16);
  convert_dwords_to_floats_array(context, destination, values);
}

inline void convert_dwords_to_floats_from_memory(GuestContext* context, int destination,
                                                 std::uint64_t address) {
  if (address + 16 > guest_memory_size) {
    report_guest_memory_fault(context, address, 16, 0);
    return;
  }
  std::int32_t values[4];
  std::memcpy(values, guest_memory + address, 16);
  convert_dwords_to_floats_array(context, destination, values);
}

void string_move(GuestContext* context, int element_size, int repeat);
void string_store(GuestContext* context, int element_size, int repeat);
void string_load(GuestContext* context, int element_size, int repeat);
void string_scan(GuestContext* context, int element_size, int repeat);
void string_compare(GuestContext* context, int element_size, int repeat);
void execute_cpuid(GuestContext* context);

// Win32 calling convention access. x86-64 passes the first four arguments in
// rcx/rdx/r8/r9 and the rest on the stack above 32 bytes of shadow space; x86
// passes every argument on the stack above the return address.
inline std::uint64_t import_argument(GuestContext* context, int index) {
  if (guest_pointer_width >= 8) {
    switch (index) {
      case 0: return context->registers[1];
      case 1: return context->registers[2];
      case 2: return context->registers[8];
      case 3: return context->registers[9];
      default: break;
    }
    return load_guest_memory(context, context->registers[4] + 0x28 + static_cast<std::uint64_t>(index - 4) * 8, 8);
  }
  // 32-bit x86: a C++ member function passes `this` in ECX, so argument 0 is
  // ECX and the stack arguments begin at argument 1.
  if (win32_import_this_call() && index == 0) return context->registers[1];
  return load_guest_memory(
      context, context->registers[4] + win32_import_argument_offset(index, win32_import_this_call()), 4);
}

inline void set_import_result(GuestContext* context, std::uint64_t value) {
  context->registers[0] = guest_pointer_width >= 8 ? value : (value & 0xffffffffull);
}

void invoke_guest_indirect(GuestContext* context, std::uint64_t target, std::uint64_t return_address);
void jump_guest_indirect(GuestContext* context, std::uint64_t target);
void invoke_win32_import_tail(GuestContext* context, const char* library_name, const char* symbol_name);

void invoke_win32_import(GuestContext* context, const char* library_name, const char* symbol_name,
                         std::uint64_t return_address);
bool lookup_win32_import(const char* library_name, const char* symbol_name, void (**function)(GuestContext*));
bool register_import_thunk(std::uint64_t address, void (*function)(GuestContext*),
                           const char* library_name, const char* symbol_name);

struct GuestFunctionDescriptor {
  std::uint64_t address;
  void (*function)(GuestContext*);
};

struct GuestImportDescriptor {
  std::uint32_t import_address_table_rva;
  std::uint32_t slot_size;
  const char* library_name;
  const char* symbol_name;
};

struct RecompiledImage {
  std::uint64_t image_base;
  std::uint32_t pointer_width;   // 4 for PE32/x86, 8 for PE32+/x86-64
  std::uint32_t image_size;
  std::uint32_t entry_point_rva;
  std::uint64_t stack_top;
  std::uint64_t heap_base;
  const unsigned char* image_blob;
  std::uint32_t image_blob_size;
  std::uint32_t function_count;
  const GuestFunctionDescriptor* functions;
  std::uint32_t import_count;
  const GuestImportDescriptor* imports;
};

int run_recompiled_image(const RecompiledImage* image);

}  // namespace recomp
