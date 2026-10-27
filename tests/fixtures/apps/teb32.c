/* 32-bit TEB access fixture.
 *
 * A 32-bit Windows guest reaches its thread environment block through fs:.
 * Unicorn 2.1.4 cannot set FS_BASE in 32-bit mode — the write returns
 * UC_ERR_OK and is silently ignored — so the differential reference relocates
 * the TEB to address 0, where `fs:[offset]` resolves without a base. This
 * fixture reads the TEB fields a real program reads, so that workaround is
 * covered: without it the reference dies with an unmapped read on the very
 * first `fs:` access, exactly as it did on a real 2001 game executable.
 *
 * The self-pointer is deliberately not compared by absolute value; only fields
 * whose contents are the same on both sides are printed. */
#include "fy.h"

int app_main(void) {
  out("teb32:start"); crlf();

  u32 stack_base = 0;
  u32 stack_limit = 0;
  u32 peb = 0;
  u32 self = 0;
  __asm__ volatile("movl %%fs:0x04, %0" : "=r"(stack_base));
  __asm__ volatile("movl %%fs:0x08, %0" : "=r"(stack_limit));
  __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
  __asm__ volatile("movl %%fs:0x18, %0" : "=r"(self));

  out("teb_readable=1"); crlf();
  out("stack_base_nonzero="); outi(stack_base != 0 ? 1 : 0); crlf();
  out("stack_limit_below_base="); outi(stack_limit < stack_base ? 1 : 0); crlf();
  out("peb_nonzero="); outi(peb != 0 ? 1 : 0); crlf();
  out("self_nonzero="); outi(self != 0 ? 1 : 0); crlf();

  /* Reading through the segment must not disturb ordinary addressing. */
  u32 value = 0x1234abcd;
  u32* pointer = &value;
  out("pointer_roundtrip="); outi(*pointer == 0x1234abcd ? 1 : 0); crlf();

  out("teb32:done"); crlf();
  return 0;
}
