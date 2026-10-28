/* VPBROADCASTB regression fixture.
 *
 * Remill's Apache-2.0 AVX semantics clear the destination and fill every lane
 * from the source's low byte. Exercise the YMM register form used by fd.exe
 * and its byte-memory counterpart.
 */
#include "fy.h"

static int all_bytes_are(const u8* values, u8 expected) {
  for (int index = 0; index < 32; ++index)
    if (values[index] != expected) return 0;
  return 1;
}

int app_main(void) {
  u8 scalar = 0xa5;
  u8 register_result[32] = {0};
  u8 memory_result[32] = {0};

  __asm__ volatile("vmovd %1, %%xmm0\n\t"
                   "vpbroadcastb %%xmm0, %%ymm1\n\t"
                   "vmovdqu %%ymm1, %0"
                   : "=m"(*(u8(*)[32])register_result)
                   : "r"((u32)scalar)
                   : "xmm0", "ymm1");

  __asm__ volatile("vpbroadcastb %1, %%ymm2\n\t"
                   "vmovdqu %%ymm2, %0"
                   : "=m"(*(u8(*)[32])memory_result)
                   : "m"(scalar)
                   : "ymm2");

  const int register_ok = all_bytes_are(register_result, 0xa5);
  const int memory_ok = all_bytes_are(memory_result, 0xa5);
  out("vpbroadcast_register_ok="); outi(register_ok); crlf();
  out("vpbroadcast_memory_ok="); outi(memory_ok); crlf();
  return register_ok && memory_ok ? 0 : 1;
}
