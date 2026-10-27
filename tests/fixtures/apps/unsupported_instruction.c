/* Negative fixture: contains an instruction class the lifter does not
 * implement (RDMSR, a model-specific register read), so translation must fail
 * explicitly rather than fabricate a result. */
#include "fy.h"

int app_main(void) {
  out("unsupported-instruction:start"); crlf();
  /* 0f 32 = rdmsr */
  __asm__ volatile(".byte 0x0f, 0x32");
  out("unsupported-instruction:done"); crlf();
  return 0;
}
