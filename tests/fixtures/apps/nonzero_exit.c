/* A program that exits NON-ZERO on purpose.
 *
 * It exists because the verifier used to treat `exit_code == 0` as the definition of a
 * completed port, so every program that legitimately exits non-zero was reported as a
 * failure. That is not a hypothesis: `dominosasolver` was reported as a failed port while
 * its output matched the reference byte for byte.
 *
 * The correct question is whether the TWO SIDES AGREE, not whether the status is zero.
 * This fixture returns 3 and writes a line first, so a run that compares the status can be
 * told apart from one that only compares output.
 *
 * IT IMMEDIATELY FOUND A SECOND BUG, in the fix itself: the reference run recorded its exit
 * status into the ReferenceRun, but the value was never copied into the DifferentialResult
 * that the caller and the JSON read, so the field was permanently zero and the comparison
 * always saw a disagreement. `dominosasolver` was reported as a failed port for that reason
 * alone. A fixture that exercises a NEW GATE is what caught it; without one, the gate would
 * have looked like it worked while reporting every non-zero-exit program as broken.
 */
#include "fy.h"

int app_main(void) {
  out("nonzero-exit:start"); crlf();
  return 3;
}
