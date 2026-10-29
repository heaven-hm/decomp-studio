/* Regressions for legacy x86 sign extension, decimal-adjust and flag
 * instructions. IRETD lives in iretd32.c because the reference cannot run it. */
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

  unsigned char adjusted_sub = 0;
  unsigned char carry_sub = 0;
  unsigned char flags_sub = 0;
  __asm__ volatile("movb $0x9b, %%al\n\t"
                   "clc\n\t"
                   "das\n\t"
                   "setc %1\n\t"
                   "lahf\n\t"
                   "movb %%ah, %2\n\t"
                   "movb %%al, %0"
                   : "=m"(adjusted_sub), "=q"(carry_sub), "=m"(flags_sub)
                   :
                   : "eax", "cc");
  out("das="); outi(adjusted_sub); crlf();
  out("das_cf="); outi(carry_sub); crlf();
  out("das_af="); outi((flags_sub >> 4) & 1); crlf();

  unsigned char salc_set = 0;
  unsigned char salc_clear = 1;
  __asm__ volatile("stc\n\t"
                   "salc\n\t"
                   "movb %%al, %0\n\t"
                   "clc\n\t"
                   "salc\n\t"
                   "movb %%al, %1"
                   : "=m"(salc_set), "=m"(salc_clear)
                   :
                   : "eax", "cc");
  out("salc_set="); outi(salc_set); crlf();
  out("salc_clear="); outi(salc_clear); crlf();

  unsigned short aad_value = 0;
  unsigned char aad_flags = 0;
  __asm__ volatile("movw $0x0705, %%ax\n\t"
                   "aad\n\t"
                   "movw %%ax, %0\n\t"
                   "lahf\n\t"
                   "movb %%ah, %1"
                   : "=m"(aad_value), "=m"(aad_flags)
                   :
                   : "eax", "cc");
  out("aad="); outi(aad_value); crlf();
  out("aad_pf="); outi((aad_flags >> 2) & 1); crlf();

  unsigned short arpl_changed = 0;
  unsigned short arpl_unchanged = 0;
  unsigned char arpl_changed_flags = 0;
  unsigned char arpl_unchanged_flags = 0xff;
  __asm__ volatile("movw $0x0001, %%ax\n\t"
                   "movw $0x0003, %%bx\n\t"
                   "arpl %%bx, %%ax\n\t"
                   "movw %%ax, %0\n\t"
                   "lahf\n\t"
                   "movb %%ah, %2\n\t"
                   "movw $0x0007, %%ax\n\t"
                   "movw $0x0002, %%bx\n\t"
                   "arpl %%bx, %%ax\n\t"
                   "movw %%ax, %1\n\t"
                   "lahf\n\t"
                   "movb %%ah, %3"
                   : "=m"(arpl_changed), "=m"(arpl_unchanged), "=m"(arpl_changed_flags),
                     "=m"(arpl_unchanged_flags)
                   :
                   : "eax", "ebx", "cc");
  out("arpl_changed="); outi(arpl_changed); crlf();
  out("arpl_changed_zf="); outi((arpl_changed_flags >> 6) & 1); crlf();
  out("arpl_unchanged="); outi(arpl_unchanged); crlf();
  out("arpl_unchanged_zf="); outi((arpl_unchanged_flags >> 6) & 1); crlf();

  /* ECX=0x10000 has a zero low half, so JCXZ must branch; ECX=0x10001 must not.
   * Testing the whole register would take the first branch and miss the second. */
  unsigned char jcxz_taken = 0;
  unsigned char jcxz_not_taken = 0;
  __asm__ volatile("movl $0x10000, %%ecx\n\t"
                   "jcxz 1f\n\t"
                   "movb $0, %0\n\t"
                   "jmp 2f\n\t"
                   "1:\n\t"
                   "movb $1, %0\n\t"
                   "2:\n\t"
                   "movl $0x10001, %%ecx\n\t"
                   "jcxz 3f\n\t"
                   "movb $1, %1\n\t"
                   "jmp 4f\n\t"
                   "3:\n\t"
                   "movb $0, %1\n\t"
                   "4:"
                   : "=m"(jcxz_taken), "=m"(jcxz_not_taken)
                   :
                   : "ecx", "cc");
  out("jcxz_taken="); outi(jcxz_taken); crlf();
  out("jcxz_not_taken="); outi(jcxz_not_taken); crlf();

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
                 adjusted_sub == 0x35 && carry_sub == 1 && ((flags_sub >> 4) & 1) == 1 &&
                 salc_set == 0xff && salc_clear == 0 && aad_value == 75 &&
                 ((aad_flags >> 2) & 1) == 1 && arpl_changed == 3 &&
                 ((arpl_changed_flags >> 6) & 1) == 1 && arpl_unchanged == 7 &&
                 ((arpl_unchanged_flags >> 6) & 1) == 0 && jcxz_taken == 1 &&
                 jcxz_not_taken == 1 && into_continues == 1
             ? 0
             : 1;
}
