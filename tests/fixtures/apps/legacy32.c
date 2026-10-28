/* Regressions for legacy x86 sign extension and decimal-adjust instructions. */
#include "fy.h"

int app_main(void) {
  unsigned short value = 0x0080;
  __asm__ volatile("cbw" : "+a"(value));
  out("cbw="); outi((i16)value); crlf();

  unsigned char adjusted = 0;
  unsigned char carry = 0;
  unsigned char flags = 0;
  __asm__ volatile("movb $0x9b, %%al\n\t"
                   "clc\n\t"
                   "daa\n\t"
                   "setc %1\n\t"
                   "lahf\n\t"
                   "movb %%ah, %2\n\t"
                   "movb %%al, %0"
                   : "=m"(adjusted), "=q"(carry), "=m"(flags)
                   :
                   : "eax", "cc");
  out("daa="); outi(adjusted); crlf();
  out("daa_cf="); outi(carry); crlf();
  out("daa_af="); outi((flags >> 4) & 1); crlf();

  unsigned char into_continues = 0;
  __asm__ volatile("movb $1, %%al\n\t"
                   "addb $1, %%al\n\t"
                   "into\n\t"
                   "movb $1, %0"
                   : "=m"(into_continues)
                   :
                   : "eax", "cc");
  out("into_clear_continues="); outi(into_continues); crlf();
  return value == 0xff80 && adjusted == 1 && carry == 1 && ((flags >> 4) & 1) == 1 &&
                 into_continues == 1
             ? 0
             : 1;
}
