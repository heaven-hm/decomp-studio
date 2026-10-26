/* Negative fixture: imports a Windows API that has no shim, so running the
 * recompiled binary must report the import explicitly instead of returning a
 * fabricated success value. */
#include "fy.h"

__declspec(dllimport) int __stdcall MessageBoxA(void* window, const char* text,
                                                const char* caption, u32 type);

int app_main(void) {
  out("unsupported-import:start"); crlf();
  MessageBoxA(0, "text", "caption", 0);
  out("unsupported-import:done"); crlf();
  return 0;
}
