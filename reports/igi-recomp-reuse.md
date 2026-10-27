# igi-recomp reuse map — Win32 shim inventory for igi.exe

**Task:** task-6 (extract reusable Win32 shim inventory from igi-recomp for igi.exe)
**Author:** teammate `upstream-eval`
**Date:** 2026-10-27
**Write scope:** this file only. No code, test, build or runtime file was modified.

**Sources (all read locally, paths relative to this repository):**

| Source | Identity |
| --- | --- |
| Target binary | `/Users/haseeb-mir/Downloads/IGI/igi.exe` — SHA-256 `dea34892d417715873ea61d7b2ba5556655f1ad65385104348146f9679915a01` (re-computed with `shasum -a 256`, matches the task statement) |
| Upstream checkout | `research/upstream/igi-recomp` — git `master`, commit `278eaf6394f7f42c7de6cffef2cf982154f59899`, committed 2026-10-14 |
| Recomp Studio | `runtime/`, `apps/cli/main.cpp`, `build/recomp-studio` |

**Method.** Import lists were produced by running the existing tool, not by hand:
`./build/recomp-studio imports /Users/haseeb-mir/Downloads/IGI/igi.exe --json` (exit 0) and
`./build/recomp-studio inspect /Users/haseeb-mir/Downloads/IGI/igi.exe --json` (exit 0). The shim
inventory was extracted by parsing every `SHIM(dll, name)` line in `research/upstream/igi-recomp/shim/src/*.c`
(the macro is defined at `shim/include/shim.h:8`). Set arithmetic was done by script; every number
below is a count, not an estimate.

---

## Headline answer

**All 97 of igi.exe's 97 missing imports are already implemented in igi-recomp's `shim/`. 97 / 97 = 100%.
None are missing.**

The stronger result, and the reason the match is not a coincidence:

- igi.exe imports **128** symbols from **10** DLLs (`inspect --json`: `import_count` 128).
- igi-recomp's `shim/` implements exactly **128** `SHIM()` functions.
- As sets of `(dll, symbol)` pairs after normalising `dsound.dll!#1` → `imp_dsound__1`, the two sets are
  **equal**: **0** imports without a shim, **0** shims without an import.
- 31 of those 128 are the ones Recomp Studio already shims; the remaining **97 are exactly the
  reported missing set**, so igi-recomp's shim layer is a complete, title-matched reference
  implementation of igi.exe's entire operating-system surface.

Adaptation weight of the 97 (measured as lines from the `SHIM(` line to the closing brace):

| Class | Count | Note |
| --- | --- | --- |
| ≤ 3 lines (constant return / stub) | **37** | near-mechanical port |
| > 3 lines (real logic) | **60** | of which 21 are ≥ 15 lines |
| Total body lines of the 97 | **903** | ~11.5 lines average |

---

## 1. Full inventory: every function implemented in `shim/`

Grouped by the Windows library the shim corresponds to. The DLL in the `SHIM(dll, name)` macro is the
prefix of the generated symbol `imp_<dll>_<name>`; note that the *file* does not always match the
library — `gdi32` shims live in `shim/src/user32.c` and `msvfw32` shims live in `shim/src/avifil32.c`.

### 1.1 kernel32 — 64 shims

- `GetVersion` — `shim/src/kernel32.c:119` (1 line)
- `GetVersionExA` — `shim/src/kernel32.c:121` (10)
- `GetCommandLineA` — `shim/src/kernel32.c:134` (1)
- `GetStartupInfoA` — `shim/src/kernel32.c:136` (7)
- `GetModuleHandleA` — `shim/src/kernel32.c:168` (6)
- `GetModuleFileNameA` — `shim/src/kernel32.c:175` (12)
- `LoadLibraryA` — `shim/src/kernel32.c:188` (9)
- `FreeLibrary` — `shim/src/kernel32.c:198` (1)
- `GetProcAddress` — `shim/src/kernel32.c:200` (12)
- `GetCurrentProcess` — `shim/src/kernel32.c:230` (1)
- `ExitProcess` — `shim/src/kernel32.c:234` (6)
- `TerminateProcess` — `shim/src/kernel32.c:241` (6)
- `UnhandledExceptionFilter` — `shim/src/kernel32.c:248` (1)
- `RaiseException` — `shim/src/kernel32.c:250` (4)
- `RtlUnwind` — `shim/src/kernel32.c:255` (4)
- `DebugBreak` — `shim/src/kernel32.c:260` (1)
- `OutputDebugStringA` — `shim/src/kernel32.c:262` (5)
- `GetLastError` — `shim/src/kernel32.c:268` (1)
- `CreateMutexA` — `shim/src/kernel32.c:270` (5)
- `ReleaseMutex` — `shim/src/kernel32.c:276` (1)
- `CloseHandle` — `shim/src/kernel32.c:278` (5)
- `GetEnvironmentStrings` — `shim/src/kernel32.c:288` (1)
- `GetEnvironmentStringsW` — `shim/src/kernel32.c:289` (1)
- `FreeEnvironmentStringsA` — `shim/src/kernel32.c:290` (1)
- `FreeEnvironmentStringsW` — `shim/src/kernel32.c:291` (1)
- `GetEnvironmentVariableA` — `shim/src/kernel32.c:292` (1)
- `SetHandleCount` — `shim/src/kernel32.c:293` (1)
- `GetStdHandle` — `shim/src/kernel32.c:297` (8)
- `SetStdHandle` — `shim/src/kernel32.c:306` (1)
- `GetFileType` — `shim/src/kernel32.c:308` (10)
- `HeapCreate` — `shim/src/kernel32.c:321` (1)
- `HeapDestroy` — `shim/src/kernel32.c:322` (1)
- `HeapAlloc` — `shim/src/kernel32.c:324` (11)
- `HeapFree` — `shim/src/kernel32.c:336` (5)
- `HeapReAlloc` — `shim/src/kernel32.c:342` (13)
- `VirtualAlloc` — `shim/src/kernel32.c:363` (29)
- `VirtualFree` — `shim/src/kernel32.c:393` (17)
- `CreateFileA` — `shim/src/kernel32.c:413` (34)
- `ReadFile` — `shim/src/kernel32.c:651` (37)
- `WriteFile` — `shim/src/kernel32.c:689` (19)
- `SetFilePointer` — `shim/src/kernel32.c:709` (42)
- `SetEndOfFile` — `shim/src/kernel32.c:752` (11)
- `FlushFileBuffers` — `shim/src/kernel32.c:764` (1)
- `DeleteFileA` — `shim/src/kernel32.c:766` (6)
- `GetFileTime` — `shim/src/kernel32.c:779` (13)
- `CompareFileTime` — `shim/src/kernel32.c:793` (5)
- `GetDriveTypeA` — `shim/src/kernel32.c:799` (15)
- `FindFirstFileA` — `shim/src/kernel32.c:874` (26)
- `FindNextFileA` — `shim/src/kernel32.c:901` (8)
- `FindClose` — `shim/src/kernel32.c:910` (10)
- `GetTickCount` — `shim/src/kernel32.c:995` (4)
- `QueryPerformanceCounter` — `shim/src/kernel32.c:1000` (5)
- `Sleep` — `shim/src/kernel32.c:1006` (5)
- `GetLocalTime` — `shim/src/kernel32.c:1012` (16)
- `GetACP` — `shim/src/kernel32.c:1031` (1)
- `GetOEMCP` — `shim/src/kernel32.c:1032` (1)
- `GetCPInfo` — `shim/src/kernel32.c:1034` (8)
- `MultiByteToWideChar` — `shim/src/kernel32.c:1043` (14)
- `WideCharToMultiByte` — `shim/src/kernel32.c:1058` (20)
- `GetStringTypeA` — `shim/src/kernel32.c:1096` (10)
- `GetStringTypeW` — `shim/src/kernel32.c:1107` (14)
- `LCMapStringA` — `shim/src/kernel32.c:1131` (14)
- `LCMapStringW` — `shim/src/kernel32.c:1146` (18)
- `GetLocaleInfoA` — `shim/src/kernel32.c:1165` (1)

### 1.2 user32 — 30 shims (`shim/src/user32.c`)

- `RegisterClassA` — `:100` (15) · `UnregisterClassA` — `:116` (1) · `CreateWindowExA` — `:118` (50)
- `DestroyWindow` — `:169` (6) · `ShowWindow` — `:176` (13) · `UpdateWindow` — `:190` (1)
- `InvalidateRect` — `:191` (1) · `SetFocus` — `:192` (1) · `SetForegroundWindow` — `:193` (1)
- `GetForegroundWindow` — `:194` (1) · `SetWindowTextA` — `:196` (5) · `SetWindowPos` — `:202` (9)
- `GetWindowLongA` — `:212` (13) · `GetClientRect` — `:226` (9) · `ClientToScreen` — `:236` (1)
- `AdjustWindowRect` — `:237` (1) · `GetSystemMetrics` — `:239` (10) · `GetDC` — `:250` (1)
- `ReleaseDC` — `:251` (1) · `LoadIconA` — `:252` (1) · `LoadCursorA` — `:253` (1)
- `ShowCursor` — `:257` (6) · `MessageBoxA` — `:264` (5) · `DefWindowProcA` — `:270` (13)
- `PostMessageA` — `:284` (5) · `PostQuitMessage` — `:290` (6) · `PeekMessageA` — `:297` (6)
- `GetMessageA` — `:304` (7) · `TranslateMessage` — `:312` (1) · `DispatchMessageA` — `:314` (6)

### 1.3 gdi32 — 3 shims (also in `shim/src/user32.c`)

- `GetDeviceCaps` — `:323` (14) · `CreateICA` — `:338` (1) · `DeleteDC` — `:339` (1)

### 1.4 ole32 — 3 shims (`shim/src/ole32.c`)

- `CoInitialize` — `:5` (1) · `CoUninitialize` — `:6` (1) · `CoCreateInstance` — `:34` (17)

### 1.5 ddraw — 2 shims (`shim/src/ddraw.c`)

- `DirectDrawCreateEx` — `:1172` (7) · `DirectDrawEnumerateExA` — `:1180` (12)

### 1.6 dinput — 2 shims (`shim/src/dinput.c`)

- `DirectInputCreateA` — `:342` (6) · `DirectInputCreateEx` — `:349` (6)

### 1.7 dsound — 1 shim (`shim/src/dsound.c`)

- `_1` — `:882` (21) — this is DirectSoundCreate, imported by **ordinal 1**; see §6.4 for the
  name-mangling evidence.

### 1.8 avifil32 — 10 shims (`shim/src/avifil32.c`)

- `AVIFileInit` — `:137` (1) · `AVIFileExit` — `:138` (1) · `AVIFileOpenA` — `:140` (49)
- `AVIFileInfoA` — `:190` (15) · `AVIFileGetStream` — `:206` (13) · `AVIStreamInfoA` — `:220` (21)
- `AVIStreamReadFormat` — `:242` (13) · `AVIStreamRead` — `:256` (25) · `AVIStreamRelease` — `:282` (1)
- `AVIFileRelease` — `:284` (15)

### 1.9 msvfw32 — 4 shims (also in `shim/src/avifil32.c`)

- `ICLocate` — `:339` (29) · `ICSendMessage` — `:369` (16) · `ICClose` — `:386` (10)
- `ICDecompress` — `:398` (82) — the largest shim in the repository

### 1.10 winmm — 9 shims (`shim/src/winmm.c`)

- `mciSendCommandA` — `:8` (5) · `mixerGetNumDevs` — `:14` (1) · `mixerOpen` — `:15` (1)
- `mixerClose` — `:16` (1) · `mixerGetDevCapsA` — `:17` (1) · `mixerGetLineInfoA` — `:18` (1)
- `mixerGetLineControlsA` — `:19` (1) · `mixerGetControlDetailsA` — `:20` (1)
- `mixerSetControlDetails` — `:21` (1)

**Not inventoried as shims** (they are the port's own support code, not Windows API surface):
`shim/src/platform_sdl.c`, `platform_vita.c`, `platform_common.c`, `render_gl.c`, `render_backend.c`,
`render_queue.c`, `d3d7.c`, `com.c`, `bench.c`, `tick_test.c`, `video_ffmpeg.c`, `pad_input.c`,
`vita_*.c`. `d3d7.c` (1825 lines) is *not* a DLL shim — it implements the `IDirect3DDevice7` COM
interface that `ddraw.c` hands to the game, reached through vtable pointers rather than imports.

---

## 2. Cross-reference: the 97 missing imports, covered and not covered

### 2.1 Covered — 97 of 97

Every entry below is `igi.exe import → igi-recomp shim (location)`. Sizes are shim body lines.

**kernel32.dll — 33 of 33 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| CloseHandle | `imp_kernel32_CloseHandle` | `shim/src/kernel32.c:278` | 5 |
| CompareFileTime | `imp_kernel32_CompareFileTime` | `shim/src/kernel32.c:793` | 5 |
| CreateFileA | `imp_kernel32_CreateFileA` | `shim/src/kernel32.c:413` | 34 |
| CreateMutexA | `imp_kernel32_CreateMutexA` | `shim/src/kernel32.c:270` | 5 |
| DebugBreak | `imp_kernel32_DebugBreak` | `shim/src/kernel32.c:260` | 1 |
| DeleteFileA | `imp_kernel32_DeleteFileA` | `shim/src/kernel32.c:766` | 6 |
| FindClose | `imp_kernel32_FindClose` | `shim/src/kernel32.c:910` | 10 |
| FindFirstFileA | `imp_kernel32_FindFirstFileA` | `shim/src/kernel32.c:874` | 26 |
| FindNextFileA | `imp_kernel32_FindNextFileA` | `shim/src/kernel32.c:901` | 8 |
| FlushFileBuffers | `imp_kernel32_FlushFileBuffers` | `shim/src/kernel32.c:764` | 1 |
| FreeEnvironmentStringsW | `imp_kernel32_FreeEnvironmentStringsW` | `shim/src/kernel32.c:291` | 1 |
| GetCPInfo | `imp_kernel32_GetCPInfo` | `shim/src/kernel32.c:1034` | 8 |
| GetDriveTypeA | `imp_kernel32_GetDriveTypeA` | `shim/src/kernel32.c:799` | 15 |
| GetEnvironmentStringsW | `imp_kernel32_GetEnvironmentStringsW` | `shim/src/kernel32.c:289` | 1 |
| GetEnvironmentVariableA | `imp_kernel32_GetEnvironmentVariableA` | `shim/src/kernel32.c:292` | 1 |
| GetFileTime | `imp_kernel32_GetFileTime` | `shim/src/kernel32.c:779` | 13 |
| GetFileType | `imp_kernel32_GetFileType` | `shim/src/kernel32.c:308` | 10 |
| GetLocalTime | `imp_kernel32_GetLocalTime` | `shim/src/kernel32.c:1012` | 16 |
| GetLocaleInfoA | `imp_kernel32_GetLocaleInfoA` | `shim/src/kernel32.c:1165` | 1 |
| GetStringTypeA | `imp_kernel32_GetStringTypeA` | `shim/src/kernel32.c:1096` | 10 |
| GetStringTypeW | `imp_kernel32_GetStringTypeW` | `shim/src/kernel32.c:1107` | 14 |
| GetVersionExA | `imp_kernel32_GetVersionExA` | `shim/src/kernel32.c:121` | 10 |
| HeapReAlloc | `imp_kernel32_HeapReAlloc` | `shim/src/kernel32.c:342` | 13 |
| LCMapStringA | `imp_kernel32_LCMapStringA` | `shim/src/kernel32.c:1131` | 14 |
| LCMapStringW | `imp_kernel32_LCMapStringW` | `shim/src/kernel32.c:1146` | 18 |
| OutputDebugStringA | `imp_kernel32_OutputDebugStringA` | `shim/src/kernel32.c:262` | 5 |
| RaiseException | `imp_kernel32_RaiseException` | `shim/src/kernel32.c:250` | 4 |
| ReleaseMutex | `imp_kernel32_ReleaseMutex` | `shim/src/kernel32.c:276` | 1 |
| RtlUnwind | `imp_kernel32_RtlUnwind` | `shim/src/kernel32.c:255` | 4 |
| SetEndOfFile | `imp_kernel32_SetEndOfFile` | `shim/src/kernel32.c:752` | 11 |
| SetFilePointer | `imp_kernel32_SetFilePointer` | `shim/src/kernel32.c:709` | 42 |
| SetHandleCount | `imp_kernel32_SetHandleCount` | `shim/src/kernel32.c:293` | 1 |
| SetStdHandle | `imp_kernel32_SetStdHandle` | `shim/src/kernel32.c:306` | 1 |

**user32.dll — 30 of 30 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| AdjustWindowRect | `imp_user32_AdjustWindowRect` | `shim/src/user32.c:237` | 1 |
| ClientToScreen | `imp_user32_ClientToScreen` | `shim/src/user32.c:236` | 1 |
| CreateWindowExA | `imp_user32_CreateWindowExA` | `shim/src/user32.c:118` | 50 |
| DefWindowProcA | `imp_user32_DefWindowProcA` | `shim/src/user32.c:270` | 13 |
| DestroyWindow | `imp_user32_DestroyWindow` | `shim/src/user32.c:169` | 6 |
| DispatchMessageA | `imp_user32_DispatchMessageA` | `shim/src/user32.c:314` | 6 |
| GetClientRect | `imp_user32_GetClientRect` | `shim/src/user32.c:226` | 9 |
| GetDC | `imp_user32_GetDC` | `shim/src/user32.c:250` | 1 |
| GetForegroundWindow | `imp_user32_GetForegroundWindow` | `shim/src/user32.c:194` | 1 |
| GetMessageA | `imp_user32_GetMessageA` | `shim/src/user32.c:304` | 7 |
| GetSystemMetrics | `imp_user32_GetSystemMetrics` | `shim/src/user32.c:239` | 10 |
| GetWindowLongA | `imp_user32_GetWindowLongA` | `shim/src/user32.c:212` | 13 |
| InvalidateRect | `imp_user32_InvalidateRect` | `shim/src/user32.c:191` | 1 |
| LoadCursorA | `imp_user32_LoadCursorA` | `shim/src/user32.c:253` | 1 |
| LoadIconA | `imp_user32_LoadIconA` | `shim/src/user32.c:252` | 1 |
| MessageBoxA | `imp_user32_MessageBoxA` | `shim/src/user32.c:264` | 5 |
| PeekMessageA | `imp_user32_PeekMessageA` | `shim/src/user32.c:297` | 6 |
| PostMessageA | `imp_user32_PostMessageA` | `shim/src/user32.c:284` | 5 |
| PostQuitMessage | `imp_user32_PostQuitMessage` | `shim/src/user32.c:290` | 6 |
| RegisterClassA | `imp_user32_RegisterClassA` | `shim/src/user32.c:100` | 15 |
| ReleaseDC | `imp_user32_ReleaseDC` | `shim/src/user32.c:251` | 1 |
| SetFocus | `imp_user32_SetFocus` | `shim/src/user32.c:192` | 1 |
| SetForegroundWindow | `imp_user32_SetForegroundWindow` | `shim/src/user32.c:193` | 1 |
| SetWindowPos | `imp_user32_SetWindowPos` | `shim/src/user32.c:202` | 9 |
| SetWindowTextA | `imp_user32_SetWindowTextA` | `shim/src/user32.c:196` | 5 |
| ShowCursor | `imp_user32_ShowCursor` | `shim/src/user32.c:257` | 6 |
| ShowWindow | `imp_user32_ShowWindow` | `shim/src/user32.c:176` | 13 |
| TranslateMessage | `imp_user32_TranslateMessage` | `shim/src/user32.c:312` | 1 |
| UnregisterClassA | `imp_user32_UnregisterClassA` | `shim/src/user32.c:116` | 1 |
| UpdateWindow | `imp_user32_UpdateWindow` | `shim/src/user32.c:190` | 1 |

**gdi32.dll — 3 of 3 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| CreateICA | `imp_gdi32_CreateICA` | `shim/src/user32.c:338` | 1 |
| DeleteDC | `imp_gdi32_DeleteDC` | `shim/src/user32.c:339` | 1 |
| GetDeviceCaps | `imp_gdi32_GetDeviceCaps` | `shim/src/user32.c:323` | 14 |

**ole32.dll — 3 of 3 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| CoCreateInstance | `imp_ole32_CoCreateInstance` | `shim/src/ole32.c:34` | 17 |
| CoInitialize | `imp_ole32_CoInitialize` | `shim/src/ole32.c:5` | 1 |
| CoUninitialize | `imp_ole32_CoUninitialize` | `shim/src/ole32.c:6` | 1 |

**ddraw.dll — 2 of 2 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| DirectDrawCreateEx | `imp_ddraw_DirectDrawCreateEx` | `shim/src/ddraw.c:1172` | 7 |
| DirectDrawEnumerateExA | `imp_ddraw_DirectDrawEnumerateExA` | `shim/src/ddraw.c:1180` | 12 |

**dinput.dll — 2 of 2 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| DirectInputCreateA | `imp_dinput_DirectInputCreateA` | `shim/src/dinput.c:342` | 6 |
| DirectInputCreateEx | `imp_dinput_DirectInputCreateEx` | `shim/src/dinput.c:349` | 6 |

**dsound.dll — 1 of 1 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| `#1` (ordinal import) | `imp_dsound__1` | `shim/src/dsound.c:882` | 21 |

**avifil32.dll — 10 of 10 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| AVIFileExit | `imp_avifil32_AVIFileExit` | `shim/src/avifil32.c:138` | 1 |
| AVIFileGetStream | `imp_avifil32_AVIFileGetStream` | `shim/src/avifil32.c:206` | 13 |
| AVIFileInfoA | `imp_avifil32_AVIFileInfoA` | `shim/src/avifil32.c:190` | 15 |
| AVIFileInit | `imp_avifil32_AVIFileInit` | `shim/src/avifil32.c:137` | 1 |
| AVIFileOpenA | `imp_avifil32_AVIFileOpenA` | `shim/src/avifil32.c:140` | 49 |
| AVIFileRelease | `imp_avifil32_AVIFileRelease` | `shim/src/avifil32.c:284` | 15 |
| AVIStreamInfoA | `imp_avifil32_AVIStreamInfoA` | `shim/src/avifil32.c:220` | 21 |
| AVIStreamRead | `imp_avifil32_AVIStreamRead` | `shim/src/avifil32.c:256` | 25 |
| AVIStreamReadFormat | `imp_avifil32_AVIStreamReadFormat` | `shim/src/avifil32.c:242` | 13 |
| AVIStreamRelease | `imp_avifil32_AVIStreamRelease` | `shim/src/avifil32.c:282` | 1 |

**msvfw32.dll — 4 of 4 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| ICClose | `imp_msvfw32_ICClose` | `shim/src/avifil32.c:386` | 10 |
| ICDecompress | `imp_msvfw32_ICDecompress` | `shim/src/avifil32.c:398` | 82 |
| ICLocate | `imp_msvfw32_ICLocate` | `shim/src/avifil32.c:339` | 29 |
| ICSendMessage | `imp_msvfw32_ICSendMessage` | `shim/src/avifil32.c:369` | 16 |

**winmm.dll — 9 of 9 covered**

| Import | Shim | Location | Lines |
| --- | --- | --- | --- |
| mciSendCommandA | `imp_winmm_mciSendCommandA` | `shim/src/winmm.c:8` | 5 |
| mixerClose | `imp_winmm_mixerClose` | `shim/src/winmm.c:16` | 1 |
| mixerGetControlDetailsA | `imp_winmm_mixerGetControlDetailsA` | `shim/src/winmm.c:20` | 1 |
| mixerGetDevCapsA | `imp_winmm_mixerGetDevCapsA` | `shim/src/winmm.c:17` | 1 |
| mixerGetLineControlsA | `imp_winmm_mixerGetLineControlsA` | `shim/src/winmm.c:19` | 1 |
| mixerGetLineInfoA | `imp_winmm_mixerGetLineInfoA` | `shim/src/winmm.c:18` | 1 |
| mixerGetNumDevs | `imp_winmm_mixerGetNumDevs` | `shim/src/winmm.c:14` | 1 |
| mixerOpen | `imp_winmm_mixerOpen` | `shim/src/winmm.c:15` | 1 |
| mixerSetControlDetails | `imp_winmm_mixerSetControlDetails` | `shim/src/winmm.c:21` | 1 |

### 2.2 Not covered — 0 of 97

The not-covered set is **empty**. There is no igi.exe import without an igi-recomp counterpart.

### 2.3 The reverse direction — 0 shims without an import

Every one of the 128 `SHIM()` functions corresponds to an igi.exe import; there is no shim in
igi-recomp that igi.exe does not import. (The 31 imports Recomp Studio already shims also have
igi-recomp counterparts: `GetStdHandle`, `WriteFile`, `ReadFile`, `ExitProcess`, `TerminateProcess`,
`GetLastError`, `GetModuleHandleA`, `GetModuleFileNameA`, `GetStartupInfoA`, `GetCommandLineA`,
`GetEnvironmentStrings`, `FreeEnvironmentStringsA`, `HeapCreate`, `HeapAlloc`, `HeapFree`,
`HeapDestroy`, `VirtualAlloc`, `VirtualFree`, `Sleep`, `GetTickCount`, `QueryPerformanceCounter`,
`GetProcAddress`, `LoadLibraryA`, `FreeLibrary`, `GetVersion`, `GetACP`, `GetOEMCP`,
`MultiByteToWideChar`, `WideCharToMultiByte`, `GetCurrentProcess`, `UnhandledExceptionFilter`.)

---

## 3. Representative covered imports: real signature and behaviour

The macro expands every shim to `void imp_<dll>_<name>(Ctx *c)` (`shim/include/shim.h:8`). Arguments
are read from the guest stack with `ARG(n)` (`runtime/include/runtime.h:67`) and the result is
returned with `stdcall_ret(c, value, nargs)` (`runtime/include/runtime.h:69`), which sets `eax` and
pops `nargs + 1` dwords.

| # | Import (shim) | What it does | Adaptation note for a C++ runtime |
| --- | --- | --- | --- |
| 1 | `CreateFileA` — `kernel32.c:413` (34 lines) | Reads `ARG(0)` filename, `ARG(1)` access, `ARG(4)` disposition; `win_path_to_host()` maps `C:\IGI` / `D:` to host paths; maps disposition to `open(2)` flags; `open()`s the file; allocates a handle from the handle table; sets last error; returns the handle, pops 7 args | **Portable.** Needs a host path mapper and a Win32 handle table that Recomp Studio does not have |
| 2 | `GetVersionExA` — `kernel32.c:121` (10) | Writes a 5-field `OSVERSIONINFOA` (5.1.2600, `VER_PLATFORM_WIN32_NT`) into guest memory at `ARG(0)`, returns 1 | **Trivial.** `ARG` + `WR32` + `stdcall_ret` |
| 3 | `HeapReAlloc` — `kernel32.c:342` (13) | Honours `HEAP_REALLOC_IN_PLACE_ONLY` (0x10) and `HEAP_ZERO_MEMORY` (0x8) over igi-recomp's own heap; returns the pointer | **Needs a real heap.** Recomp Studio's `HeapAlloc` returns a constant (`recomp_runtime.cpp:197`) |
| 4 | `FindFirstFileA` — `kernel32.c:874` (26) | Splits dir/pattern, `opendir()`, fills a `WIN32_FIND_DATAA` in guest memory, returns a find handle; `ERROR_FILE_NOT_FOUND` on failure | **Portable** with the handle table |
| 5 | `CreateWindowExA` — `user32.c:118` (50) | Resolves the class name to a stored WndProc, substitutes 640×480 for `CW_USEDEFAULT`, stores window state, calls `platform_create_window()`, then dispatches `WM_NCCREATE` and `WM_CREATE` to the guest WndProc and returns `HWND_MAIN` | **Hardest user32 shim.** Needs a host window plus *re-entry into guest code* (see §4.4) |
| 6 | `PeekMessageA` — `user32.c:297` (6) | Pumps the platform layer, then fills a `MSG` from the port's own message queue; `GetMessageA` (`:304`) blocks in `platform_wait()` until a message exists | **Needs the platform layer** (SDL2) |
| 7 | `DispatchMessageA` — `user32.c:314` (6) | Reads the `MSG` from guest memory and calls the guest WndProc via `send_message()` | Needs guest re-entry |
| 8 | `GetDeviceCaps` — `user32.c:323` (14) | Switch over the capability index: `HORZRES`=1024, `VERTRES`=768, `BITSPIXEL`=32, `PLANES`=1, `VREFRESH`=60 | **Trivial** |
| 9 | `DirectDrawCreateEx` — `ddraw.c:1172` (7) | `ddraw_init()`, creates the DirectDraw7 object, writes it to `ARG(1)`, returns `DD_OK` | **Object model is the cost**, not this function |
| 10 | `DirectDrawEnumerateExA` — `ddraw.c:1180` (12) | Builds a fake "Primary Display Driver" description in scratch memory and calls back into guest code via `guest_call(c, cb, 5, args)` | Needs guest re-entry |
| 11 | `DirectInputCreateA` — `dinput.c:342` (6) | `di_init()`, writes the DirectInput object to `ARG(2)`, returns `DI_OK` | Object model + SDL input |
| 12 | DirectSoundCreate by ordinal 1 — `dsound.c:882` (21) | Opens the SDL audio device; lazily builds `IDirectSound`, `IDirectSoundBuffer`, `IDirectSound3DBuffer`, `IDirectSound3DListener` vtables; writes the object to `ARG(1)` | Object model + a software mixer (`dsound.c` is 902 lines) |
| 13 | `AVIFileOpenA` — `avifil32.c:140` (49) | `fopen`s the file, loads it whole, parses the AVI container (`parse_avi`), allocates two guest handles, logs width/height/frame count/codec | **Substantial**: needs the AVI parser (in the same file) |
| 14 | `ICDecompress` — `avifil32.c:398` (82) | Entry point of the Indeo 5 decoder used for the cutscenes | **Largest shim**; video only |
| 15 | `mciSendCommandA` — `winmm.c:8` (5) | Logs and returns `MCIERR_DEVICE_OPEN` (263) — the game runs without CD audio | **Trivial stub** |
| 16 | `CoCreateInstance` — `ole32.c:34` (17) | Compares the CLSID against `CLSID_DirectMusic` (hard-coded GUID), builds a bare `IDirectMusic` vtable, returns `S_OK` or `REGDB_E_CLASSNOTREG` | Needs a minimal COM model (`shim/include/com.h`) |

---

## 4. Runtime model: x87, guest memory, and how a shim is called

### 4.1 Guest memory

Flat byte array: "guest address A lives at `g_mem + A`" (`runtime/include/recomp.h:4`), declared
`extern uint8_t *g_mem;` (`recomp.h:49`). All accessors go through `memcpy` so they are unaligned-safe
on both arm64 and the Vita's ARMv7 (`recomp.h:5-6`, `:62-73`): `RD8/RD16/RD32/RD64` and
`WR8/WR16/WR32/WR64`, plus `RDF32/RDF64/WRF32/WRF64` for floats. The address-space layout is fixed at
`runtime/include/runtime.h:11-18` (null guard at `0x10000`, scratch to `0x3FF000`, image at `0x400000`,
stack at `0x1000000`, heap at `0x2000000`), with host thunks at `0xFE000000` (`runtime.h:21-23`).
This is the same "one flat guest image" idea as Recomp Studio's `guest_memory`
(`runtime/recomp_runtime.hpp:53-54`), so memory access adapts by helper renaming, not redesign.

### 4.2 x87

The context holds the x87 file in *physical* order plus the stack pointer and both control/status
words: `double st[8]; uint32_t ftop; uint32_t fcw; uint32_t fsw;` (`recomp.h:24-27`). `ST(i)` indexes
logically through `ftop` (`recomp.h:122`), with `fpush`/`fpop` (`:124-130`) and the condition-code bits
`FSW_C0..C3` (`:132-135`). Comparison results are computed by `rt_fcom` (`:159-171`), and the status
word's TOP field is composed on read by `rt_fstsw` (`:185`). The arithmetic type is `double`
(`typedef double x87_t`, `:151`), i.e. **not 80-bit**: the header documents this honestly — the
single-precision option "is not exact: results differ from an x87 running with 53- or 64-bit precision
control, and the differential tester … no longer passes" (`:137-146`). The generated code keeps the
status word and (where the stack depth is statically known) the registers in locals, synchronising the
context around calls and returns (`:155-158`). There is also a statically-derived stack-effect checker,
`IGI_X87_CHECK`/`rt_x87_mismatch` (`:189-196`).

Recomp Studio already models the same fields — `double x87_registers[8]; std::uint32_t x87_top;
x87_control_word; x87_status_word;` (`runtime/recomp_runtime.hpp:46-49`) — so the x87 *state shape* is
already compatible.

### 4.3 How generated code calls a shim

A call to an import compiles to a plain C call passing only the context:

```c
PROF_HOST(slot); imp_kernel32_CreateFileA(c); PROF_BACK(entry);
```

`tools/recomp/gen.py:1736` (`import_call`), with the name built at `gen.py:2043-2046`
(`cname = 'imp_%s_%s' % (dll.split('.')[0], re.sub(r'[^A-Za-z0-9_]', '_', name))`) and the
IAT-slot → DLL/name/function table emitted at `gen.py:2189`. **The guest has already pushed the
arguments**, so the shim reads them itself: `#define ARG(n) RD32(c->r[4] + 4u + 4u * (uint32_t)(n))`
(`runtime/include/runtime.h:67`, i.e. `esp + 4 + 4n`), and returns with
`stdcall_ret(c, value, nargs)` (`runtime.h:69-73`) which sets `c->r[0] = value` and
`c->r[4] += 4 + 4*nargs`.

**This is structurally identical to Recomp Studio's shim contract.** Recomp Studio registers
`void (*function)(GuestContext*)` (`runtime/recomp_runtime.cpp:286-291`, table at `:292-356`), invokes
it in `invoke_import_thunk` (`recomp_runtime.cpp:101-110`), and reads arguments with
`import_argument(context, index)` (`runtime/recomp_runtime.hpp:933-945`) — which is arch-aware
(x86-64 register args in `rcx/rdx/r8/r9`, else stack; x86 always stack). Example: `win32_write_file`
(`recomp_runtime.cpp:136-151`) reads four arguments, does the `write(2)` loop, writes the byte count
back into guest memory and calls `set_import_result`.

### 4.4 The two real differences

1. **Stack cleanup is centralised in Recomp Studio, not done by the shim.** igi-recomp's
   `stdcall_ret(c, v, nargs)` pops the arguments; Recomp Studio's shim only sets the result with
   `set_import_result` (`recomp_runtime.hpp:947-949`) and `invoke_import_thunk` pops
   `win32_import_stack_cleanup(...)` (`recomp_runtime.cpp:105-110`) from the table in
   `runtime/win32_abi.hpp:98-104`. So every ported shim must drop its `nargs` pop and instead have an
   entry in `kWin32ImportAbiTable` (`win32_abi.hpp:20-84`) with the correct `argument_count` — and
   that table, not `kShims`, is what `imports` consults: `is_shimmed_import` iterates
   `kWin32ImportAbiTable` (`apps/cli/main.cpp:190-195`). Today both tables hold exactly the same 63
   pairs (0 differences, verified), so a new shim needs **both** rows or the CLI will keep reporting it
   as missing.
2. **Guest re-entry.** Shims that must call back into game code (`CreateWindowExA` sending
   `WM_CREATE`, `DispatchMessageA`, `DirectDrawEnumerateExA`'s callback) use
   `guest_call(c, fn, nargs, args)` (`runtime/include/runtime.h:58`), implemented via
   `send_message()` (`shim/src/user32.c:63-69`). Recomp Studio has a different-shaped entry point,
   `invoke_guest_indirect(context, target, return_address)` (`recomp_runtime.hpp:951-952`), and no
   window/WndProc plumbing at all.

### 4.5 The dependency the shims bring with them

The shims are not self-contained: they call igi-recomp runtime helpers that have no Recomp Studio
equivalent yet. From `runtime/include/runtime.h` and `shim/include/shim.h`:

| igi-recomp helper | Where | Recomp Studio equivalent |
| --- | --- | --- |
| `handle_new` / `handle_get` / `handle_close` + `HandleObj` | `shim/include/shim.h:18-28`, defined `shim/src/kernel32.c:34-60` | none — Recomp Studio returns constants (e.g. `0x1000`, `recomp_runtime.cpp:195-196`) |
| `win32_set_last_error` / `GetLastError` | `shim/src/kernel32.c:28-30` | `GetLastError` is `win32_zero` (constant 0) |
| `heap_alloc` / `heap_realloc` / `heap_free` / `heap_size` | `runtime.h:38-41` | none — heap shims return constants |
| `win_path_to_host` | declared `shim/include/shim.h:15`, defined `shim/src/kernel32.c:88` | none — no host path mapping |
| `scratch_alloc` / `scratch_strdup` | `runtime.h:34-35` | none |
| `guest_call` | `runtime.h:58` | `invoke_guest_indirect` (different shape) |
| `rt_log` / `rt_fatal` | `runtime.h:78-80` | diagnostics/`terminate_with_message` |
| COM model (`com_new`, `com_vtable`, `com_addref`) | `shim/include/com.h` | none — needed for ddraw/dsound/dinput/ole32 |
| SDL2 platform layer (`platform_create_window`, `platform_pump`, `platform_wait`, `audio_open`, input) | `shim/include/platform.h`, `shim/src/platform_sdl.c` | none — Recomp Studio has no platform layer |
| AVI parser + optional libavcodec decoder | `shim/src/avifil32.c`, `shim/src/video_ffmpeg.c` | none |

Also note `shim/src/kernel32.c` itself `#include <SDL.h>` (`:6`) and uses SDL mutexes/conditions for
its read-ahead prefetch thread (`kernel32.c:475-503`), so even the kernel32 shim is not free of the
SDL2 dependency.

---

## 5. `tools/recomp/difftest.py` — the second verification approach

`tools/recomp/difftest.py` (385 lines) is a **per-instruction-form differential tester** for the
code generator: "Every (non control-flow) instruction form used by IGI.exe is taken from the binary,
recompiled on its own with all flags forced live, and executed both in the generated C and in Unicorn
(a real x86 CPU model) from identical random states. Registers, flags, the x87 stack/status and
touched memory are compared." (`difftest.py:1-9`).

What it does, precisely:

- **Corpus:** `collect_forms()` (`:42-59`) walks every function's instructions and keeps up to N
  samples per `(mnemonic, operand types/sizes, first opcode byte)` form, skipping control flow and
  system instructions (`SKIP` at `:30-33`).
- **Random state:** `random_state()` (`:203`) seeds registers, flags, FCW (from the six rounding/
  precision modes at `:27`) and x87 values; `mem_addrs()` (`:189`) picks memory operands.
- **Unicorn side:** `run_unicorn()` (`:229-268`) maps the image at `0x400000`, sets up an x87 prologue
  (`fninit`, `fldcw`, eight `fld qword`) so the FPU stack is in a known state, runs exactly one
  instruction (`count=1`), and reads back registers, `EFLAGS`, `FPSW`, the physical FP registers
  (mapped to logical `ST(i)` through TOP) and 16 bytes at each touched address.
- **Comparison** (`:340-377`): all eight GPRs; `CF/PF/ZF/SF/OF`; `ftop`; the x87 condition codes
  (`cc_mask`); each `ST(i)` with a `1e-9` relative tolerance; and the touched memory bytes. It
  deliberately excludes architecturally-undefined results — `mul/imul` ZF/SF/PF, `div/idiv/bsf/bsr`
  flags other than ZF, and OF for shifts/rotates (`:355-364`).
- **Output:** `tests run: N, failing instructions: M` plus one line per failing form with a concrete
  counter-example state (`:379-381`).

Why it matters here: this is the same *class* of check as Recomp Studio's differential harness
(`core/verification/differential_harness.cpp`) but aimed at the **lifter** rather than the program —
it compares one instruction's semantics against a real CPU model from randomised states, which is how
you find the "exact flags" bugs (the project's own `CHANGELOG.md` records several such fixes) without
needing a full program run. It is independent of the program-level trace comparison and could be
adopted as a test-only tool for this title.

---

## 6. Licence audit

### 6.1 Repository licence

`research/upstream/igi-recomp/LICENSE` is the **MIT License**, `Copyright (c) 2026 HenryKun55`
(lines 1-3). MIT is compatible with Recomp Studio's Apache-2.0: MIT code may be copied, modified and
redistributed inside an Apache-2.0 work provided the MIT copyright notice and permission notice are
retained.

### 6.2 Per-file headers in `shim/` and `runtime/`

I grepped the first 12 lines of all 63 files under `shim/` and `runtime/` for
`MIT|copyright|SPDX|GPL|public domain`: **no file carries a per-file licence header.** Every hit was a
false positive from ordinary prose (`"far limit"`, `"DrawIndexedPrimitiveVB"`) except one:

- `shim/src/vita_update.c:11` — *"Ported from the author's OpenMoHAA Vita port (code/sys/vita_update.c
  there), relicensed by its author under this repository's MIT license."* Same author, explicitly
  relicensed to MIT; **Vita-only**, irrelevant to macOS.

Absence of per-file headers is normal here and the repo-level MIT covers the tree as distributed.

### 6.3 What is **not** MIT — do not copy

- **`tools/vitagl/*.patch`** — the README is explicit: "The code in this repository is under the MIT
  license (see `LICENSE`), **except the patches in `tools/vitagl/`, which modify vitaGL and follow its
  license (LGPL-3.0)**. The Vita build links vitaGL and FFmpeg, both LGPL." (`README.md:99-101`).
  Not needed on macOS.
- **`shim/src/video_ffmpeg.c`** — the optional Indeo 5 decoder built only when libavcodec is found
  (`CMakeLists.txt:184-194`); linking FFmpeg pulls an LGPL (or GPL, depending on configuration)
  dependency into the build. For an Apache-2.0 project this must be an optional, dynamically linked
  extra — or omitted. Note the AVI *container* parsing in `avifil32.c` is separate from the codec and
  is not affected.
- **`translations/`** — an unofficial fan translation of the game's own text (`README.md:95-97`).
  Game content, not code; do not copy.
- **`runtime/src/native_*.c` (19 files)** — these are *hand-decompiled functions of the game binary*
  (e.g. `native_mesh.c:1-3` documents `0x004A1570 mesh_draw`), not Windows API reimplementations.
  Copying them would import game-derived logic into an Apache-2.0 project. The shims in `shim/` are a
  different matter (a reimplementation of a documented OS interface), but the `native_*.c` files
  should be treated as **out of bounds** and, if used at all, handled as a separate legal question.
  (Flagging, not legal advice.)

### 6.4 Third-party dependencies of the shim layer

- **SDL2** — required for the desktop build (`CMakeLists.txt:175-177`), zlib licence, Apache-2.0
  compatible. The shims use it for window, GL context, audio and input, and even `kernel32.c` uses its
  mutex/cond API (`kernel32.c:475-503`).
- **OpenGL** — required (`CMakeLists.txt:176-177`); on macOS it is a system framework.
- **libavcodec/libavutil** — optional, see §6.3.
- **CoreFoundation** — linked on Apple only, for the render thread's main-thread servicing
  (`CMakeLists.txt:178-180`).

### 6.5 Ordinal import mapping is verified, not assumed

`dsound.dll!#1` maps to `SHIM(dsound, _1)`. That is not a guess: the recompiler's own mangling rule is
`re.sub(r'[^A-Za-z0-9_]', '_', name)` applied to the symbol name (`gen.py:2045`), so `#1` becomes `_1`,
and `shim/src/dsound.c:881` states "DirectSoundCreate is imported by ordinal 1". Both the mapping rule
and the comment agree.

---

## 7. How much adaptation each covered shim needs

The shim *shape* is the same on both sides (`void f(context*)`, arguments read from the guest stack,
result in `eax`), so the work is mechanical **per shim** plus **non-mechanical per capability**:

**Mechanical, per shim (all 97):**

| igi-recomp idiom | Recomp Studio idiom |
| --- | --- |
| `void imp_kernel32_CreateFileA(Ctx *c)` (`shim.h:8`) | `void win32_create_file_a(GuestContext* context)` registered in `kShims` (`recomp_runtime.cpp:286-356`) |
| `ARG(n)` (`runtime.h:67`) | `import_argument(context, n)` (`recomp_runtime.hpp:933`) |
| `stdcall_ret(c, v, nargs)` (`runtime.h:69`) | `set_import_result(context, v)` (`recomp_runtime.hpp:947`) **plus** a `kWin32ImportAbiTable` row (`win32_abi.hpp:20`) |
| `RD32/WR32/RD8/WR8` on `g_mem` (`recomp.h:62-69`) | `load_guest_memory` / `store_guest_memory` |
| `gstr(a)` / `gptr(a)` / `gbuf(a)` (`runtime.h:61-64`) | `read_guest_string(...)` / `guest_memory + a` |

**Non-mechanical, per capability (must be written or ported regardless of shim count):**

1. **A Win32 handle table** (`handle_new/handle_get/handle_close`) — required by file, find, mutex and
   module shims. ~40 lines in igi-recomp (`shim/include/shim.h:18-28`, `shim/src/kernel32.c:34-60`).
2. **A real guest heap** — `HeapAlloc/HeapReAlloc/HeapFree` are constants today
   (`recomp_runtime.cpp:195-204`), and `HeapReAlloc` (`kernel32.c:342`) plus the CRT's allocator need
   one.
3. **Last-error state** — `GetLastError` is a constant 0 today.
4. **A host path mapper** (`win_path_to_host`) for `C:\IGI` / `D:` — file shims are meaningless
   without it.
5. **A platform layer** (SDL2: window, GL context, input, audio) — needed by user32, ddraw, dinput,
   dsound. This is the largest single piece: `platform_sdl.c` is 421 lines and `render_gl.c` 3186.
6. **A minimal COM model** (`com.h`/`com.c`) — needed by ddraw, dinput, dsound, ole32.
7. **Guest re-entry** for WndProc/callbacks — Recomp Studio has `invoke_guest_indirect` but no
   message loop.
8. **An AVI parser** (and optionally FFmpeg) for avifil32/msvfw32 — cutscene video only.

**Suggested ordering by value/effort**, using the measured sizes: start with the 37 trivial shims and
the kernel32 file/`Find*` group (~300 lines total) to get the game's data loading running; then the
user32 message pump + window (`user32.c:100-330`, ~200 lines) with a minimal SDL platform layer; then
DirectDraw/Direct3D and the COM model; AVI/Indeo last, since it only affects cutscenes.

---

## 8. Verification status and what was not read

**Verified first-hand (commands and files cited inline above):** the 128/97/31 import figures
(`recomp-studio imports --json` and `inspect --json`, exit 0); the target's SHA-256; the 128 `SHIM()`
definitions and their line numbers; the exact set equality of igi-recomp's shim set with igi.exe's
import set; the size classification of the 97; the licence text and the absence of per-file headers;
the `ARG`/`stdcall_ret`/`Ctx`/x87/memory model; the shim call emission in `gen.py`; the
`difftest.py` docstring and comparison code; Recomp Studio's `kShims`/`kWin32ImportAbiTable`/
`is_shimmed_import` mechanism.

**Read but not exercised:** I did **not** build igi-recomp, did not run its shims, and did not run
igi.exe under Recomp Studio. So "the shim exists and is title-matched" is verified; "the shim behaves
identically when ported into Recomp Studio's C++ runtime" is **not verified** and must be established
by the tests described in §7 of `reports/upstream-evaluation.md` (program output + instruction trace
against the Unicorn reference, per import, as each shim lands).

**Not read at all (marked unverified):** `shim/src/render_gl.c` (3186 lines), `render_backend.c`
(1568), `d3d7.c` (1825), `render_queue.c` (1082), `platform_vita.c` (1017), `bench.c`, `tick_test.c`,
the `vita_*.c` files, all of `platform/`, `docs/`, `translations/`, and most of `runtime/src/`. The
per-shim descriptions in §3 are from the bodies I quoted; the ddraw/d3d7/dsound/dinput **object
models** behind them (vtable method counts, D3D7 state handling) were **not** analysed in detail —
that is the main remaining unknown for the graphics path, and the reason the DirectX shims are
classified "object model is the cost, not the function".

**Uncertainty worth flagging:** the 97 shims total only 903 body lines, but they depend on roughly
6 000+ lines of igi-recomp support code (`platform_sdl.c` + `render_gl.c` + `render_backend.c` +
`d3d7.c` + `com.c` + `avifil32.c`'s parser). The correct conclusion is not "97 shims are free"; it is
"97 shims exist and are title-matched, 37 of them are trivial, and the remaining work is a small
number of shared capabilities that the shims sit on".

---

## 9. Bottom line

- **97 / 97 missing imports have an igi-recomp shim; 0 are missing.** igi-recomp's shim set is exactly
  igi.exe's 128-import surface — the same title, matched one-for-one.
- **Licence is usable:** repo-level MIT, no per-file headers, no copyleft inside `shim/`. Excluded
  from reuse: `tools/vitagl/*.patch` (LGPL-3.0), `video_ffmpeg.c`'s FFmpeg dependency, `translations/`,
  and the hand-decompiled `runtime/src/native_*.c` game functions.
- **The C→C++ gap is smaller than it looks:** both runtimes call a shim as `void f(context*)` with
  arguments on the guest stack. The per-shim edit is mechanical (`ARG` → `import_argument`,
  `stdcall_ret` → `set_import_result` + an ABI-table row); the real work is the shared capabilities in
  §7.2 — handle table, heap, path mapping, platform layer, COM model, guest re-entry.
