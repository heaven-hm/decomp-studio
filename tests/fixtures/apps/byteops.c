/* Direction-flag and byte-swap fixture.
 *
 * Covers instructions real MSVC binaries use for structure initialisation and
 * endian conversion that a compiler will not emit from ordinary C: BSWAP, and
 * the CLD/STD direction flag that the runtime's string-operation helpers depend
 * on. A wrong byte order, or a direction flag that never reaches those helpers,
 * changes the printed values.
 *
 * The two copies are the interesting part: the first runs with DF=1 and the
 * second with DF=0, so a direction flag that is ignored (or stuck set) makes the
 * second copy print "gfedcba" instead of "abcdefg". */
#include "fy.h"

int app_main(void) {
  out("byteops:start"); crlf();

  /* BSWAP r32: reverses four bytes and zero-extends into the 64-bit register. */
  u32 value32 = 0x12345678u;
  u32 swapped32 = 0;
  __asm__ volatile("bswap %0" : "=r"(swapped32) : "0"(value32));
  out("bswap32="); outi((i64)swapped32); crlf();

  /* BSWAP r64: all eight bytes, which also proves the width was not narrowed. */
  u64 value64 = 0x0123456789abcdefull;
  u64 swapped64 = 0;
  __asm__ volatile("bswap %0" : "=r"(swapped64) : "0"(value64));
  out("bswap64="); outi((i64)swapped64); crlf();
  out("bswap64_hi="); outi((i64)(swapped64 >> 32)); crlf();

  char source[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 0};
  char backward[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  char forward[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  /* STD then REP MOVSB from the last byte: copies down to index 0, so the
   * result is still "abcdefg". CLD restores the ABI-mandated DF=0. */
  __asm__ volatile(
      "std\n\t"
      "lea 6(%1), %%rsi\n\t"
      "lea 6(%0), %%rdi\n\t"
      "mov $7, %%rcx\n\t"
      "rep movsb\n\t"
      "cld\n\t"
      :
      : "r"(backward), "r"(source)
      : "rsi", "rdi", "rcx", "memory");
  out("backward="); out(backward); crlf();

  /* The same copy with DF=0. If CLD did not take effect this prints
   * "gfedcba". */
  __asm__ volatile(
      "lea 0(%1), %%rsi\n\t"
      "lea 0(%0), %%rdi\n\t"
      "mov $7, %%rcx\n\t"
      "rep movsb\n\t"
      :
      : "r"(forward), "r"(source)
      : "rsi", "rdi", "rcx", "memory");
  out("forward="); out(forward); crlf();

  out("byteops:done"); crlf();
  return 0;
}
