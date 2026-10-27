/* atexit registration.
 *
 * The handlers must actually run, in reverse registration order, when the process
 * exits. The runtime used to accept the registration and report success without
 * keeping the handler, so a program like this one printed its own output and then
 * silently lost the handler's -- the worst of both, since there was neither the
 * behaviour nor a diagnostic saying it was missing.
 */
#include <stdio.h>
#include <stdlib.h>

static void registered_first(void) { printf("atexit:first\n"); }
static void registered_second(void) { printf("atexit:second\n"); }

int main(void) {
  printf("atexit:start\n");
  atexit(registered_first);
  atexit(registered_second);
  printf("atexit:registered\n");
  return 0;
}
