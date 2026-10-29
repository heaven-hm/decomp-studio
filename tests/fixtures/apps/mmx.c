/* Regression for MMX register moves. rRootage's remaining unsupported
 * instructions were all `movd`, whose mm-register forms the lifter accepted only
 * for xmm/ymm operands. The MMX file aliases the low 64 bits of vector registers,
 * so these tests pin the move widths: MOVD clears bits 63:32 of the destination,
 * while MOVQ copies all 64 bits. */
#include "fy.h"

u32 mmx_movd_source = 0x55667788;
u64 mmx_movq_source __attribute__((aligned(8))) = 0x0123456789abcdefULL;

u32 mmx_movd_gpr;
u32 mmx_movd_memory;
u32 mmx_movd_from_memory;
u64 mmx_movq_mm;
u64 mmx_movd_clear;
u64 mmx_movq_roundtrip;

__attribute__((naked, noinline)) void perform_mmx_moves(void) {
  __asm__ volatile("movl $0x89abcdef, %eax\n\t"
                   "movd %eax, %mm0\n\t"
                   "movd %mm0, %ecx\n\t"
                   "movl %ecx, _mmx_movd_gpr\n\t"
                   "movd %mm0, _mmx_movd_memory\n\t"
                   "movd _mmx_movd_source, %mm1\n\t"
                   "movd %mm1, %edx\n\t"
                   "movl %edx, _mmx_movd_from_memory\n\t"
                   "movq %mm0, %mm3\n\t"
                   "movq %mm3, _mmx_movq_mm\n\t"
                   "movl $0x11223344, %eax\n\t"
                   "movd %eax, %mm4\n\t"
                   "movq %mm4, _mmx_movd_clear\n\t"
                   "movq _mmx_movq_source, %mm5\n\t"
                   "movq %mm5, _mmx_movq_roundtrip\n\t"
                   "emms\n\t"
                   "ret");
}

int app_main(void) {
  perform_mmx_moves();
  const int movd_gpr_ok = mmx_movd_gpr == 0x89abcdef;
  const int movd_memory_ok = mmx_movd_memory == 0x89abcdef;
  const int movd_from_memory_ok = mmx_movd_from_memory == 0x55667788;
  const int movq_mm_ok = mmx_movq_mm == 0x0000000089abcdefULL;
  const int movd_clear_ok = mmx_movd_clear == 0x0000000011223344ULL;
  const int movq_roundtrip_ok = mmx_movq_roundtrip == 0x0123456789abcdefULL;

  out("mmx_movd_gpr="); outi(movd_gpr_ok); crlf();
  out("mmx_movd_memory="); outi(movd_memory_ok); crlf();
  out("mmx_movd_from_memory="); outi(movd_from_memory_ok); crlf();
  out("mmx_movq_mm="); outi(movq_mm_ok); crlf();
  out("mmx_movd_clear="); outi(movd_clear_ok); crlf();
  out("mmx_movq_roundtrip="); outi(movq_roundtrip_ok); crlf();
  return movd_gpr_ok && movd_memory_ok && movd_from_memory_ok && movq_mm_ok &&
                 movd_clear_ok && movq_roundtrip_ok
             ? 0
             : 1;
}
