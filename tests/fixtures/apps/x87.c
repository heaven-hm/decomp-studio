/* x87 / direction-flag / counted-loop fixture.
 *
 * Exercises the x87 stack (fld, fild, fst, fstp, fistp, arithmetic, compares,
 * fsqrt/fabs/fchs/fsin/fcos/fpatan/fyl2x, fldcw/fnstcw, fnstsw), the direction
 * flag with `std`/`rep movsb`/`cld`, `loop`, and `jecxz`.
 *
 * Exact values are printed as raw double bit patterns. Transcendental results
 * are scaled and rounded to integers so a one-ULP difference between the
 * reference's 80-bit computation and our 64-bit model cannot masquerade as a
 * semantic bug; the stack effects are still validated by the pops and by the
 * status word.
 */
#include "fy.h"

static u64 double_bits(double value) {
  u64 bits;
  __builtin_memcpy(&bits, &value, 8);
  return bits;
}

static void emit_double(const char* label, double value) {
  out(label);
  outc(' ');
  outi((i64)double_bits(value));
  crlf();
}

static void emit_int(const char* label, i64 value) {
  out(label);
  outc(' ');
  outi(value);
  crlf();
}

/* x87 helpers driven from memory so the instructions are guaranteed present. */
static void fsin_x87(double input, double* output) {
  __asm__ volatile("fldl %1\n\tfsin\n\tfstpl %0" : "=m"(*output) : "m"(input) : "st");
}
static void fcos_x87(double input, double* output) {
  __asm__ volatile("fldl %1\n\tfcos\n\tfstpl %0" : "=m"(*output) : "m"(input) : "st");
}
static void fsqrt_x87(double input, double* output) {
  __asm__ volatile("fldl %1\n\tfsqrt\n\tfstpl %0" : "=m"(*output) : "m"(input) : "st");
}
static void fabs_x87(double input, double* output) {
  __asm__ volatile("fldl %1\n\tfabs\n\tfstpl %0" : "=m"(*output) : "m"(input) : "st");
}
static void fchs_x87(double input, double* output) {
  __asm__ volatile("fldl %1\n\tfchs\n\tfstpl %0" : "=m"(*output) : "m"(input) : "st");
}
static void fpatan_x87(double y, double x, double* output) {
  __asm__ volatile("fldl %1\n\tfldl %2\n\tfpatan\n\tfstpl %0"
                   : "=m"(*output) : "m"(x), "m"(y) : "st");
}
static void fyl2x_x87(double value, double multiplier, double* output) {
  __asm__ volatile("fldl %1\n\tfldl %2\n\tfyl2x\n\tfstpl %0"
                   : "=m"(*output) : "m"(multiplier), "m"(value) : "st");
}

/* fcompp + fnstsw: returns condition codes and TOP, without exception flags. */
static u32 compare_status_x87(double left, double right) {
  u16 status = 0;
  __asm__ volatile("fldl %1\n\tfldl %2\n\tfcompp\n\tfnstsw %0"
                   : "=m"(status) : "m"(left), "m"(right) : "st");
  return status & 0x7f00u;
}

static u16 control_word_x87(void) {
  u16 value = 0;
  __asm__ volatile("fnstcw %0" : "=m"(value));
  return value;
}

static void set_control_word_x87(u16 value) {
  __asm__ volatile("fldcw %0" : : "m"(value) : "memory");
}

/* Store a long double to single precision, exercising x87 rounding. */
static u32 store_long_double_as_float(long double value) {
  float narrowed = (float)value;
  u32 bits;
  __builtin_memcpy(&bits, &narrowed, 4);
  return bits;
}

/* std + rep movsb + cld. */
static u32 copy_bytes_with_direction(const u8* source, u8* destination, u32 count) {
  const u8* input = source + count - 1;
  u8* output = destination + count - 1;
  __asm__ volatile("std\n\trep movsb\n\tcld"
                   : "+S"(input), "+D"(output), "+c"(count)
                   :
                   : "memory");
  u32 checksum = 0;
  for (u32 index = 0; index < count; index++) checksum = checksum * 31 + destination[index];
  return checksum;
}

static u32 loop_sum(u32 count) {
  u32 total = 0;
  __asm__ volatile("xorl %%eax, %%eax\n\t"
                   "1:\n\t"
                   "addl %%ecx, %%eax\n\t"
                   "loop 1b\n\t"
                   : "=&a"(total)
                   : "c"(count)
                   : "cc");
  return total;
}

static u32 jecxz_target(u32 selector) {
  u32 taken = 0;
  __asm__ volatile("movl %1, %%ecx\n\t"
                   "jecxz 1f\n\t"
                   "jmp 2f\n\t"
                   "1:\n\t"
                   "movl $1, %0\n\t"
                   "2:\n\t"
                   : "+r"(taken)
                   : "r"(selector)
                   : "ecx", "cc");
  return taken;
}

int app_main(void) {
  out("x87:start"); crlf();

  /* Exact arithmetic: every result is representable in a double. */
  volatile long double a = 1.5L;
  volatile long double b = 4.0L;
  emit_double("add", (double)(a + b));
  emit_double("sub", (double)(a - b));
  emit_double("mul", (double)(a * b));
  emit_double("div", (double)(a / b));

  /* fild / fistp around an integer. */
  i32 integer = -123456;
  volatile long double loaded = (long double)integer;
  emit_int("fistp", (i64)(i32)loaded);

  /* fld m32 / fstp m32. */
  volatile float single = 1.25f;
  volatile long double from_single = (long double)single;
  emit_double("fld_m32", (double)from_single);
  emit_int("fst_m32", (i64)store_long_double_as_float((long double)single));

  /* Unary operations on exact operands. */
  double result = 0;
  fsqrt_x87(4.0, &result);
  emit_double("sqrt", result);
  fabs_x87(-2.5, &result);
  emit_double("fabs", result);
  fchs_x87(2.5, &result);
  emit_double("fchs", result);

  /* Compares: less, equal, greater, then the stack must be balanced. */
  emit_int("cmp_lt", (i64)compare_status_x87(1.0, 2.0));
  emit_int("cmp_eq", (i64)compare_status_x87(2.0, 2.0));
  emit_int("cmp_gt", (i64)compare_status_x87(3.0, 2.0));

  /* Transcendentals: scaled and rounded so 64-bit vs 80-bit cannot differ. */
  fsin_x87(1.0, &result);
  emit_int("sin", (i64)(result * 1000000.0 + (result < 0 ? -0.5 : 0.5)));
  fcos_x87(1.0, &result);
  emit_int("cos", (i64)(result * 1000000.0 + (result < 0 ? -0.5 : 0.5)));
  fpatan_x87(1.0, 2.0, &result);
  emit_int("atan2", (i64)(result * 1000000.0 + (result < 0 ? -0.5 : 0.5)));
  fyl2x_x87(3.0, 8.0, &result);
  emit_int("yl2x", (i64)(result * 1000.0 + (result < 0 ? -0.5 : 0.5)));

  /* Control word round-trip and directed rounding on an inexact store.
   * The reset value is intentionally not printed: the Unicorn reference does
   * not initialise FCW (it reads 0), while the architectural default is
   * 0x027f. Every value written explicitly is compared. */
  set_control_word_x87(0x0f7f); /* round toward zero */
  emit_int("cw_trunc", (i64)control_word_x87());
  emit_int("store_trunc", (i64)store_long_double_as_float(16777217.0L));
  set_control_word_x87(0x1f7f);
  emit_int("store_up", (i64)store_long_double_as_float(16777217.0L));
  set_control_word_x87(0x1f80);

  /* Direction flag with rep movsb, plus loop and jecxz. */
  const u8 source[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  u8 destination[8];
  emit_int("rep_std", (i64)copy_bytes_with_direction(source, destination, 8));
  emit_int("loop", (i64)loop_sum(5));
  emit_int("jecxz_zero", (i64)jecxz_target(0));
  emit_int("jecxz_nonzero", (i64)jecxz_target(1));

  out("x87:done"); crlf();
  return 0;
}
