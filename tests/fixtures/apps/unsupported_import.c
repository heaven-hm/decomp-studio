/* Negative fixture: imports a Windows API that has no shim, so running the
 * recompiled binary must report the import explicitly instead of returning a
 * fabricated success value.
 *
 * The symbol has to be one this runtime genuinely does NOT implement, and that is a
 * moving target: this fixture used `MessageBoxA` until the Win32 window surface was
 * added, at which point the negative test started passing for the right reason and
 * failing as a test. `ShellExecuteA` is a SHELL operation -- launching another program
 * -- which is deliberately out of scope rather than merely not written yet, so it is a
 * stable choice for a fixture whose whole point is that the import is missing. */
#include "fy.h"

__declspec(dllimport) int __stdcall ShellExecuteA(void* window, const char* operation,
                                                  const char* file, const char* parameters,
                                                  const char* directory, int show);

int app_main(void) {
  out("unsupported-import:start"); crlf();
  ShellExecuteA(0, "open", "file.txt", 0, 0, 1);
  out("unsupported-import:done"); crlf();
  return 0;
}
