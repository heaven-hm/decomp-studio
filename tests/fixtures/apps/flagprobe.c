/* Per-operation flag probe: prints one line per (operation, operands) so a
 * mismatch can be localised to a single flag computation. */
#include "fy.h"

static u32 compose_flags(u32 captured, u8 overflow) {
  const u32 f = (captured >> 8) & 0xffu;
  return ((f >> 0) & 1u) | (((f >> 2) & 1u) << 1) | (((f >> 4) & 1u) << 2) |
         (((f >> 6) & 1u) << 3) | (((f >> 7) & 1u) << 4) | (((u32)overflow & 1u) << 5);
}

#define PROBE_BINOP(name, instruction)                                                        \
  static u32 name(u32 a, u32 b, u32* out) {                                                   \
    u32 result, captured;                                                                     \
    u8 overflow;                                                                              \
    __asm__ volatile("movl %[a], %%ecx\n\t" instruction " %[b], %%ecx\n\t"                    \
                     "movl %%ecx, %[r]\n\tlahf\n\tmovl %%eax, %[f]\n\tseto %[o]\n\t"          \
                     : [r] "=r"(result), [f] "=r"(captured), [o] "=q"(overflow)               \
                     : [a] "r"(a), [b] "r"(b)                                                 \
                     : "eax", "ecx", "cc");                                                   \
    *out = result;                                                                            \
    return compose_flags(captured, overflow);                                                 \
  }

PROBE_BINOP(probe_add, "addl")
PROBE_BINOP(probe_sub, "subl")
PROBE_BINOP(probe_and, "andl")
PROBE_BINOP(probe_xor, "xorl")
PROBE_BINOP(probe_or, "orl")
PROBE_BINOP(probe_imul, "imull")

static u32 probe_inc(u32 a, u32* out) {
  u32 result, captured;
  u8 overflow;
  __asm__ volatile("movl %[a], %%ecx\n\tincl %%ecx\n\tmovl %%ecx, %[r]\n\tlahf\n\t"
                   "movl %%eax, %[f]\n\tseto %[o]\n\t"
                   : [r] "=r"(result), [f] "=r"(captured), [o] "=q"(overflow)
                   : [a] "r"(a) : "eax", "ecx", "cc");
  *out = result;
  return compose_flags(captured, overflow);
}

static u32 probe_dec(u32 a, u32* out) {
  u32 result, captured;
  u8 overflow;
  __asm__ volatile("movl %[a], %%ecx\n\tdecl %%ecx\n\tmovl %%ecx, %[r]\n\tlahf\n\t"
                   "movl %%eax, %[f]\n\tseto %[o]\n\t"
                   : [r] "=r"(result), [f] "=r"(captured), [o] "=q"(overflow)
                   : [a] "r"(a) : "eax", "ecx", "cc");
  *out = result;
  return compose_flags(captured, overflow);
}

static u32 probe_neg(u32 a, u32* out) {
  u32 result, captured;
  u8 overflow;
  __asm__ volatile("movl %[a], %%ecx\n\tnegl %%ecx\n\tmovl %%ecx, %[r]\n\tlahf\n\t"
                   "movl %%eax, %[f]\n\tseto %[o]\n\t"
                   : [r] "=r"(result), [f] "=r"(captured), [o] "=q"(overflow)
                   : [a] "r"(a) : "eax", "ecx", "cc");
  *out = result;
  return compose_flags(captured, overflow);
}

static u32 probe_shl1(u32 a, u32* out) {
  u32 result, captured;
  u8 overflow;
  __asm__ volatile("movl %[a], %%ecx\n\tshll $1, %%ecx\n\tmovl %%ecx, %[r]\n\tlahf\n\t"
                   "movl %%eax, %[f]\n\tseto %[o]\n\t"
                   : [r] "=r"(result), [f] "=r"(captured), [o] "=q"(overflow)
                   : [a] "r"(a) : "eax", "ecx", "cc");
  *out = result;
  return compose_flags(captured, overflow);
}


static u32 probe_shl_count(u32 a, u32 count, u32* out) {
  u32 result, captured;
  u8 overflow;
  __asm__ volatile("movl %[a], %%edx\n\tmovb %[c], %%cl\n\tshll %%cl, %%edx\n\t"
                   "movl %%edx, %[r]\n\tlahf\n\tmovl %%eax, %[f]\n\tseto %[o]\n\t"
                   : [r] "=r"(result), [f] "=r"(captured), [o] "=q"(overflow)
                   : [a] "r"(a), [c] "r"((u8)count)
                   : "eax", "ecx", "edx", "cc");
  *out = result;
  return compose_flags(captured, overflow);
}

static u32 probe_cmp(u32 a, u32 b) {
  u32 captured;
  u8 overflow;
  __asm__ volatile("movl %[a], %%ecx\n\tcmpl %[b], %%ecx\n\tlahf\n\tmovl %%eax, %[f]\n\tseto %[o]\n\t"
                   : [f] "=r"(captured), [o] "=q"(overflow)
                   : [a] "r"(a), [b] "r"(b)
                   : "eax", "ecx", "cc");
  return compose_flags(captured, overflow);
}

static const u32 kOperands[6] = {0u, 1u, 0x7fffffffu, 0x80000000u, 0xffffffffu, 0x12345678u};

static void emit(const char* operation, u32 a, u32 b, u32 result, u32 flags) {
  out(operation); outc(' ');
  outi(a); outc(' ');
  outi(b); out(" -> ");
  outi(result); outc(' ');
  outi(flags); crlf();
}

static void probe_all(u32 a, u32 b) {
  u32 result = 0, flags;
  flags = probe_add(a, b, &result);  emit("add", a, b, result, flags);
  flags = probe_sub(a, b, &result);  emit("sub", a, b, result, flags);
  flags = probe_and(a, b, &result);  emit("and", a, b, result, flags);
  flags = probe_xor(a, b, &result);  emit("xor", a, b, result, flags);
  flags = probe_or(a, b, &result);   emit("or", a, b, result, flags);
  flags = probe_imul(a, b, &result); emit("imul", a, b, result, flags);
  flags = probe_inc(a, &result);     emit("inc", a, 0, result, flags);
  flags = probe_dec(a, &result);     emit("dec", a, 0, result, flags);
  flags = probe_neg(a, &result);     emit("neg", a, 0, result, flags);
  flags = probe_shl1(a, &result);    emit("shl1", a, 0, result, flags);
  flags = probe_cmp(a, b);           emit("cmp", a, b, 0, flags);
  for (u32 count = 1; count <= 3; count++) {
    flags = probe_shl_count(a, count, &result);
    emit("shln", a, count, result, flags);
  }
}

int app_main(void) {
  for (int left = 0; left < 6; left++)
    for (int right = 0; right < 6; right++) probe_all(kOperands[left], kOperands[right]);
  return 0;
}
