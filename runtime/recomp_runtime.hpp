#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

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
  std::uint8_t vector_registers[16][16];
  double x87_registers[8];
  std::uint32_t x87_top;
  std::uint32_t x87_control_word;
  std::uint32_t x87_status_word;
};

extern std::uint8_t* guest_memory;
extern std::uint64_t guest_memory_size;
extern bool guest_tracing_enabled;

// 4 for a PE32/x86 guest, 8 for a PE32+/x86-64 guest. Set once by
// run_recompiled_image before any translated code executes.
extern int guest_pointer_width;

inline std::uint64_t mask_guest_address(std::uint64_t address) {
  return guest_pointer_width >= 8 ? address : (address & 0xffffffffull);
}

void guest_trace_address(std::uint64_t address);

// Records the current instruction pointer; when tracing is enabled every
// executed guest address is appended to the trace stream for differential
// diagnosis against the reference execution.
inline void trace_instruction(GuestContext* context, std::uint64_t address) {
  context->instruction_pointer = address;
  if (guest_tracing_enabled) guest_trace_address(address);
}

void report_guest_memory_fault(GuestContext* context, std::uint64_t address, int width, int is_write);
void recomp_trap(GuestContext* context, const char* reason);
void recomp_unsupported(GuestContext* context, const char* reason);
void report_divide_error(GuestContext* context);

inline std::uint64_t load_guest_memory(GuestContext* context, std::uint64_t address, int width) {
  if (address + static_cast<std::uint64_t>(width) > guest_memory_size) {
    report_guest_memory_fault(context, address, width, 0);
    return 0;
  }
  std::uint64_t value = 0;
  std::memcpy(&value, guest_memory + address, static_cast<std::size_t>(width));
  return value;
}

inline void store_guest_memory(GuestContext* context, std::uint64_t address, std::uint64_t value, int width) {
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

inline void vector_add_dwords(GuestContext* context, int destination, int source) {
  auto* left = reinterpret_cast<std::uint32_t*>(context->vector_registers[destination]);
  const auto* right = reinterpret_cast<const std::uint32_t*>(context->vector_registers[source]);
  for (int index = 0; index < 4; ++index) left[index] += right[index];
}

inline void vector_subtract_dwords(GuestContext* context, int destination, int source) {
  auto* left = reinterpret_cast<std::uint32_t*>(context->vector_registers[destination]);
  const auto* right = reinterpret_cast<const std::uint32_t*>(context->vector_registers[source]);
  for (int index = 0; index < 4; ++index) left[index] -= right[index];
}

inline void vector_compare_equal_dwords(GuestContext* context, int destination, int source) {
  auto* left = reinterpret_cast<std::uint32_t*>(context->vector_registers[destination]);
  const auto* right = reinterpret_cast<const std::uint32_t*>(context->vector_registers[source]);
  for (int index = 0; index < 4; ++index) left[index] = left[index] == right[index] ? 0xffffffffu : 0u;
}

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
  return load_guest_memory(context, context->registers[4] + 4 + static_cast<std::uint64_t>(index) * 4, 4);
}

inline void set_import_result(GuestContext* context, std::uint64_t value) {
  context->registers[0] = guest_pointer_width >= 8 ? value : (value & 0xffffffffull);
}

void invoke_guest_indirect(GuestContext* context, std::uint64_t target, std::uint64_t return_address);
void jump_guest_indirect(GuestContext* context, std::uint64_t target);
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
