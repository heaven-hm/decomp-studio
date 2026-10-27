/* PE32/x86 calling-convention and addressing fixture.
 *
 * Exercises the four 32-bit conventions (cdecl, stdcall, fastcall, thiscall),
 * relocation-backed function-pointer tables, structure access through
 * pointers, and 32-bit address wrapping. Compiled as a real PE32 (i686)
 * executable, so a mistake in stack handling, argument order or address width
 * changes the printed results. */
#include "fy.h"

/* cdecl: the caller removes the arguments from the stack. */
static i32 cdecl_sum(i32 a, i32 b, i32 c, i32 d, i32 e) { return a + b + c + d + e; }

/* stdcall: the callee removes the arguments. */
static i32 __stdcall stdcall_product(i32 a, i32 b, i32 c, i32 d) { return a * b * c * d; }

/* fastcall: the first two arguments arrive in ecx and edx. */
static i32 __attribute__((fastcall)) fastcall_mix(i32 a, i32 b, i32 c, i32 d) {
  return a * 3 + b * 5 + c * 7 + d * 11;
}

/* thiscall: the first argument (the object pointer) arrives in ecx. */
typedef struct {
  i32 value;
  i32 scale;
} Accumulator;

static i32 __attribute__((thiscall)) accumulator_apply(Accumulator* self, i32 input) {
  return self->value + input * self->scale;
}

/* A table of function pointers in initialised data. These are backed by
 * relocations, so they are only reachable if relocation-derived code pointers
 * are recovered. */
typedef i32 (*BinaryOperation)(i32, i32);
static i32 add_integers(i32 left, i32 right) { return left + right; }
static i32 xor_integers(i32 left, i32 right) { return left ^ right; }
static i32 multiply_integers(i32 left, i32 right) { return left * right; }

static BinaryOperation operations[3] = {add_integers, xor_integers, multiply_integers};

int app_main(void) {
  out("pe32:start"); crlf();

  out("cdecl="); outi(cdecl_sum(1, 2, 3, 4, 5)); crlf();
  out("stdcall="); outi(stdcall_product(2, 3, 4, 5)); crlf();
  out("fastcall="); outi(fastcall_mix(1, 2, 3, 4)); crlf();

  Accumulator accumulator;
  accumulator.value = 100;
  accumulator.scale = 3;
  out("thiscall="); outi(accumulator_apply(&accumulator, 7)); crlf();

  /* Indirect calls through the relocation-backed table. */
  i32 folded = 5;
  for (i32 index = 0; index < 3; index++) folded = operations[index](folded, index + 2);
  out("dispatch="); outi(folded); crlf();

  /* 32-bit pointer arithmetic must wrap at 2^32. */
  u32 wrapped = (u32)((u8*)0xfffffff0u + 0x20u);
  out("wrapped="); outi(wrapped); crlf();

  /* Pointer-sized values are 4 bytes here: a byte-wise checksum over an array. */
  u32 bytes[4] = {0x11223344u, 0xaabbccddu, 0x00000001u, 0xffffff00u};
  u64 checksum = 0;
  for (i32 index = 0; index < 16; index++) checksum = checksum * 31 + ((u8*)bytes)[index];
  out("checksum="); outi((i64)checksum); crlf();

  out("pe32:done"); crlf();
  return 0;
}
