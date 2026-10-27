/* Bit test and manipulate fixture: BT, BTS, BTR, BTC in their register forms.
 *
 * These four share one lifter path but differ in what they write back, and CF
 * always receives the bit's previous value. The values below are chosen so that
 * a wrong write-back is visible rather than plausible: BTR clears one bit of an
 * all-ones operand (a wrong `and` mask collapses it to a single bit), BTS sets a
 * bit in zero, and BTC toggles a set bit off. */
#include "fy.h"

int app_main(void) {
  out("bitops:start"); crlf();

  /* BTR clears bit 5 and reports that it had been set. */
  u64 cleared = 0xffffffffffffffffull;
  u8 carry = 0;
  __asm__ volatile("btr %2, %0\n\t"
                   "setc %b1"
                   : "+r"(cleared), "=r"(carry)
                   : "r"((u64)5)
                   : "cc");
  out("btr="); outi((i64)cleared); crlf();
  out("btr_cf="); outi((i64)carry); crlf();

  /* BTS sets bit 3 of zero and reports that it had been clear. */
  u64 set = 0;
  carry = 0;
  __asm__ volatile("bts %2, %0\n\t"
                   "setc %b1"
                   : "+r"(set), "=r"(carry)
                   : "r"((u64)3)
                   : "cc");
  out("bts="); outi((i64)set); crlf();
  out("bts_cf="); outi((i64)carry); crlf();

  /* BTC toggles bit 0 of one, which clears it, and reports it had been set. */
  u64 toggled = 1ull;
  carry = 0;
  __asm__ volatile("btc %2, %0\n\t"
                   "setc %b1"
                   : "+r"(toggled), "=r"(carry)
                   : "r"((u64)0)
                   : "cc");
  out("btc="); outi((i64)toggled); crlf();
  out("btc_cf="); outi((i64)carry); crlf();

  /* BT only reads: bit 63 of a value whose low bit is also set. */
  u64 tested = 0x8000000000000001ull;
  carry = 0;
  __asm__ volatile("bt %2, %0\n\t"
                   "setc %b1"
                   : "+r"(tested), "=r"(carry)
                   : "r"((u64)63)
                   : "cc");
  out("bt="); outi((i64)tested); crlf();
  out("bt_cf="); outi((i64)carry); crlf();

  /* A 32-bit operand must stay 32 bits wide and must not disturb the upper
   * half of the 64-bit register. */
  u32 narrow = 0x0000ffffu;
  carry = 0;
  __asm__ volatile("btr %2, %0\n\t"
                   "setc %b1"
                   : "+r"(narrow), "=r"(carry)
                   : "r"((u32)15)
                   : "cc");
  out("btr32="); outi((i64)narrow); crlf();
  out("btr32_cf="); outi((i64)carry); crlf();

  out("bitops:done"); crlf();
  return 0;
}
