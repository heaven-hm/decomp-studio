/* PINSRW regression fixture.
 *
 * Remill's Apache-2.0 X86 MMX semantics define PINSRW as replacing one 16-bit
 * lane in the previous XMM value, with the immediate reduced modulo the eight
 * lanes. Exercise register and memory sources, and deliberately use immediate
 * 13 to pin the modulo behaviour (13 % 8 == 5).
 */
#include "fy.h"

static int lane_is(const u16* values, int lane, u16 expected) {
  return values[lane] == expected;
}

int app_main(void) {
  u16 initial[8] = {0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007};
  u16 from_memory = 0xabcd;
  u16 register_result[8] = {0};
  u16 memory_result[8] = {0};

  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "mov $0x55aa, %%eax\n\t"
                   "pinsrw $13, %%eax, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(*(u16(*)[8])register_result)
                   : "m"(*(u16(*)[8])initial)
                   : "eax", "xmm0");

  __asm__ volatile("movdqu %1, %%xmm1\n\t"
                   "pinsrw $2, %2, %%xmm1\n\t"
                   "movdqu %%xmm1, %0"
                   : "=m"(*(u16(*)[8])memory_result)
                   : "m"(*(u16(*)[8])initial), "m"(from_memory)
                   : "xmm1");

  const int register_ok = lane_is(register_result, 5, 0x55aa) &&
                          lane_is(register_result, 4, initial[4]) &&
                          lane_is(register_result, 6, initial[6]);
  const int memory_ok = lane_is(memory_result, 2, 0xabcd) &&
                        lane_is(memory_result, 1, initial[1]) &&
                        lane_is(memory_result, 3, initial[3]);
  out("pinsrw_register_ok="); outi(register_ok); crlf();
  out("pinsrw_memory_ok="); outi(memory_ok); crlf();
  return register_ok && memory_ok ? 0 : 1;
}
