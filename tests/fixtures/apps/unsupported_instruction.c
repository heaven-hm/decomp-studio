/* Negative fixture: contains an instruction class the lifter does not support
 * (x87 floating point), so translation must fail explicitly rather than
 * fabricate a result. */
#include "fy.h"

int app_main(void) {
  double value = 0.0;
  out("unsupported-instruction:start"); crlf();
  __asm__ volatile("fld1\n\tfstpl %0" : "=m"(value));
  out("value="); outi((i64)value); crlf();
  out("unsupported-instruction:done"); crlf();
  return 0;
}
