/* EFLAGS fixture.
 *
 * Reads the real condition flags after arithmetic, shifts, logic, negation and
 * multiplication using LAHF/SETO, then prints a checksum over results and
 * flags. Any deviation in carry, parity, auxiliary, zero, sign or overflow
 * computation changes the output. */
#include "fy.h"

/* Flag bits: CF, PF, AF, ZF, SF, OF in that order. */
static u32 compose_flags(u32 captured_register, u8 overflow) {
  const u32 flags = (captured_register >> 8) & 0xffu;
  return ((flags >> 0) & 1u) |        /* CF */
         (((flags >> 2) & 1u) << 1) | /* PF */
         (((flags >> 4) & 1u) << 2) | /* AF */
         (((flags >> 6) & 1u) << 3) | /* ZF */
         (((flags >> 7) & 1u) << 4) | /* SF */
         (((u32)overflow & 1u) << 5); /* OF */
}

static u32 flags_add(u32 left, u32 right, u32* result) {
  u32 sum, captured;
  u8 overflow;
  __asm__ volatile(
      "movl %[a], %%ecx\n\t"
      "addl %[b], %%ecx\n\t"
      "movl %%ecx, %[sum]\n\t"
      "lahf\n\t"
      "movl %%eax, %[flags]\n\t"
      "seto %[of]\n\t"
      : [sum] "=r"(sum), [flags] "=r"(captured), [of] "=q"(overflow)
      : [a] "r"(left), [b] "r"(right)
      : "eax", "ecx", "cc");
  *result = sum;
  return compose_flags(captured, overflow);
}

static u32 flags_sub(u32 left, u32 right, u32* result) {
  u32 difference, captured;
  u8 overflow;
  __asm__ volatile(
      "movl %[a], %%ecx\n\t"
      "subl %[b], %%ecx\n\t"
      "movl %%ecx, %[diff]\n\t"
      "lahf\n\t"
      "movl %%eax, %[flags]\n\t"
      "seto %[of]\n\t"
      : [diff] "=r"(difference), [flags] "=r"(captured), [of] "=q"(overflow)
      : [a] "r"(left), [b] "r"(right)
      : "eax", "ecx", "cc");
  *result = difference;
  return compose_flags(captured, overflow);
}

static u32 flags_increment(u32 value, u32* result) {
  u32 incremented, captured;
  u8 overflow;
  __asm__ volatile(
      "movl %[v], %%ecx\n\t"
      "incl %%ecx\n\t"
      "movl %%ecx, %[out]\n\t"
      "lahf\n\t"
      "movl %%eax, %[flags]\n\t"
      "seto %[of]\n\t"
      : [out] "=r"(incremented), [flags] "=r"(captured), [of] "=q"(overflow)
      : [v] "r"(value)
      : "eax", "ecx", "cc");
  *result = incremented;
  return compose_flags(captured, overflow);
}

static u32 flags_decrement(u32 value, u32* result) {
  u32 decremented, captured;
  u8 overflow;
  __asm__ volatile(
      "movl %[v], %%ecx\n\t"
      "decl %%ecx\n\t"
      "movl %%ecx, %[out]\n\t"
      "lahf\n\t"
      "movl %%eax, %[flags]\n\t"
      "seto %[of]\n\t"
      : [out] "=r"(decremented), [flags] "=r"(captured), [of] "=q"(overflow)
      : [v] "r"(value)
      : "eax", "ecx", "cc");
  *result = decremented;
  return compose_flags(captured, overflow);
}

static u32 flags_shift_left(u32 value, u32 count, u32* result) {
  u32 shifted, captured;
  u8 overflow;
  __asm__ volatile(
      "movl %[v], %%ecx\n\t"
      "movb %[c], %%cl\n\t"
      "shll %%cl, %%ecx\n\t"
      "movl %%ecx, %[out]\n\t"
      "lahf\n\t"
      "movl %%eax, %[flags]\n\t"
      "seto %[of]\n\t"
      : [out] "=r"(shifted), [flags] "=r"(captured), [of] "=q"(overflow)
      : [v] "r"(value), [c] "r"((u8)count)
      : "eax", "ecx", "cc");
  *result = shifted;
  return compose_flags(captured, overflow);
}

static u32 flags_logic_and(u32 left, u32 right, u32* result) {
  u32 combined, captured;
  u8 overflow;
  __asm__ volatile(
      "movl %[a], %%ecx\n\t"
      "andl %[b], %%ecx\n\t"
      "movl %%ecx, %[out]\n\t"
      "lahf\n\t"
      "movl %%eax, %[flags]\n\t"
      "seto %[of]\n\t"
      : [out] "=r"(combined), [flags] "=r"(captured), [of] "=q"(overflow)
      : [a] "r"(left), [b] "r"(right)
      : "eax", "ecx", "cc");
  *result = combined;
  return compose_flags(captured, overflow);
}

static u32 flags_compare(u32 left, u32 right) {
  u32 captured;
  u8 overflow;
  __asm__ volatile(
      "movl %[a], %%ecx\n\t"
      "cmpl %[b], %%ecx\n\t"
      "lahf\n\t"
      "movl %%eax, %[flags]\n\t"
      "seto %[of]\n\t"
      : [flags] "=r"(captured), [of] "=q"(overflow)
      : [a] "r"(left), [b] "r"(right)
      : "eax", "ecx", "cc");
  return compose_flags(captured, overflow);
}

static u32 flags_negate(u32 value, u32* result) {
  u32 negated, captured;
  u8 overflow;
  __asm__ volatile(
      "movl %[v], %%ecx\n\t"
      "negl %%ecx\n\t"
      "movl %%ecx, %[out]\n\t"
      "lahf\n\t"
      "movl %%eax, %[flags]\n\t"
      "seto %[of]\n\t"
      : [out] "=r"(negated), [flags] "=r"(captured), [of] "=q"(overflow)
      : [v] "r"(value)
      : "eax", "ecx", "cc");
  *result = negated;
  return compose_flags(captured, overflow);
}

static u32 flags_multiply(u32 left, u32 right, u32* result) {
  u32 product, captured;
  u8 overflow;
  __asm__ volatile(
      "movl %[a], %%ecx\n\t"
      "imull %[b], %%ecx\n\t"
      "movl %%ecx, %[out]\n\t"
      "lahf\n\t"
      "movl %%eax, %[flags]\n\t"
      "seto %[of]\n\t"
      : [out] "=r"(product), [flags] "=r"(captured), [of] "=q"(overflow)
      : [a] "r"(left), [b] "r"(right)
      : "eax", "ecx", "cc");
  *result = product;
  return compose_flags(captured, overflow);
}

static const u32 kOperands[6] = {0u, 1u, 0x7fffffffu, 0x80000000u, 0xffffffffu, 0x12345678u};

int app_main(void) {
  out("eflags:start"); crlf();

  u64 checksum = 0;
  u32 result = 0;

  for (int left = 0; left < 6; left++) {
    for (int right = 0; right < 6; right++) {
      const u32 a = kOperands[left];
      const u32 b = kOperands[right];
      checksum = checksum * 131 + flags_add(a, b, &result) + result;
      checksum = checksum * 131 + flags_sub(a, b, &result) + result;
      checksum = checksum * 131 + flags_increment(a, &result) + result;
      checksum = checksum * 131 + flags_decrement(a, &result) + result;
      checksum = checksum * 131 + flags_logic_and(a, b, &result) + result;
      checksum = checksum * 131 + flags_compare(a, b);
      checksum = checksum * 131 + flags_negate(a, &result) + result;
      checksum = checksum * 131 + flags_multiply(a, b, &result) + result;
    }
    for (u32 count = 0; count < 4; count++) {
      u32 flags = flags_shift_left(kOperands[left], count, &result);
      /* Shift by zero leaves flags unchanged. AF is architecturally undefined
       * for shifts, and OF is undefined for counts greater than one, so both are
       * masked out before the comparison. */
      if (count == 0) continue;
      flags &= ~(1u << 2);
      if (count > 1) flags &= ~(1u << 5);
      checksum = checksum * 131 + flags + result;
    }
  }

  out("flags_checksum="); outi((i64)checksum); crlf();
  out("flags_checksum_hi="); outi((i64)(checksum >> 32)); crlf();

  out("eflags:done"); crlf();
  return 0;
}
