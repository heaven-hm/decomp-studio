#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace recomp {

// Calling-convention metadata for the emulated Win32 imports.
//
// A 32-bit x86 stdcall callee pops its own arguments, so the emulator and the
// runtime must both know how many bytes to remove after the call; getting this
// wrong corrupts the guest stack. The table is shared by the runtime and the
// differential reference so the two can never disagree.
struct Win32ImportAbi {
  const char* library_name;
  const char* symbol_name;
  int argument_count;
  bool callee_cleans_stack;
  // A C++ member function passes `this` in ECX and its arguments on the stack
  // from [esp+4], so the first *stack* argument is argument 1. GCC emits this
  // convention for every member function it calls through an import, which is
  // what `mov ecx, eax` before the call means at the call site.
  bool this_call = false;
};

// The convention of the import currently being dispatched. A shim asks for its
// arguments by index and does not need to know which convention brought it here.
inline bool& win32_import_this_call() {
  static bool value = false;
  return value;
}

// Where an argument sits relative to the stack pointer, counting the return
// address at [esp]. In thiscall the argument index is offset by one because
// `this` is in ECX rather than on the stack.
inline std::uint64_t win32_import_argument_offset(int index, bool this_call) {
  const auto slot = this_call ? index - 1 : index;
  return 4 + static_cast<std::uint64_t>(slot < 0 ? 0 : slot) * 4;
}

inline constexpr Win32ImportAbi kWin32ImportAbiTable[] = {
    {"kernel32.dll", "GetStdHandle", 1, true},
    {"kernel32.dll", "WriteFile", 5, true},
    {"kernel32.dll", "ReadFile", 5, true},
    {"kernel32.dll", "ExitProcess", 1, true},
    {"kernel32.dll", "TerminateProcess", 2, true},
    {"kernel32.dll", "GetLastError", 0, true},
    {"kernel32.dll", "SetLastError", 1, true},
    {"kernel32.dll", "GetCurrentProcessId", 0, true},
    {"kernel32.dll", "GetCurrentThreadId", 0, true},
    {"kernel32.dll", "GetThreadPriority", 1, true},
    {"kernel32.dll", "GetCurrentProcess", 0, true},
    {"kernel32.dll", "GetCurrentThread", 0, true},
    {"kernel32.dll", "DuplicateHandle", 7, true},
    {"kernel32.dll", "SetThreadPriority", 2, true},
    {"kernel32.dll", "IsDebuggerPresent", 0, true},
    {"kernel32.dll", "GetModuleHandleA", 1, true},
    {"kernel32.dll", "GetModuleHandleW", 1, true},
    {"kernel32.dll", "SetUnhandledExceptionFilter", 1, true},
    {"kernel32.dll", "UnhandledExceptionFilter", 1, true},
    {"kernel32.dll", "IsProcessorFeaturePresent", 1, true},
    {"kernel32.dll", "VirtualAlloc", 4, true},
    {"kernel32.dll", "VirtualFree", 3, true},
    {"kernel32.dll", "VirtualQuery", 3, true},
    {"kernel32.dll", "VirtualProtect", 4, true},
    // User32 message-loop calls used by legacy GUI startup. These are stdcall on
    // PE32 and register-based on PE32+, so the table still documents x86 cleanup.
    {"user32.dll", "DefWindowProcA", 4, true},
    {"user32.dll", "DispatchMessageA", 1, true},
    {"user32.dll", "GetMessageA", 4, true},
    {"user32.dll", "MessageBeep", 1, true},
    {"user32.dll", "PostQuitMessage", 1, true},
    {"user32.dll", "ShowWindow", 2, true},
    {"user32.dll", "SetForegroundWindow", 1, true},
    {"user32.dll", "TranslateMessage", 1, true},
    {"user32.dll", "LoadIconA", 2, true},
    // libstdc++ is cdecl: the caller pops. The mangled names are the ABI, so
    // they are reproduced exactly as the linker records them.
    {"libstdc++-6.dll", "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode", 3, false, true},
    {"libstdc++-6.dll", "_ZNSt14basic_ifstreamIcSt11char_traitsIcEE5closeEv", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt14basic_ifstreamIcSt11char_traitsIcEE7is_openEv", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt14basic_ifstreamIcSt11char_traitsIcEED1Ev", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode", 3, false, true},
    {"libstdc++-6.dll", "_ZNSt14basic_ofstreamIcSt11char_traitsIcEE5closeEv", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt14basic_ofstreamIcSt11char_traitsIcEE7is_openEv", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt14basic_ofstreamIcSt11char_traitsIcEED1Ev", 1, false, true},
    {"libstdc++-6.dll", "__gxx_personality_v0", 5, false},
    {"libstdc++-6.dll", "__gxx_personality_sj0", 5, false},
    {"libstdc++-6.dll", "__cxa_begin_catch", 1, false},
    {"libstdc++-6.dll", "__cxa_end_catch", 0, false},
    {"libstdc++-6.dll", "__cxa_rethrow", 0, false},
    {"libgcc_s_dw2-1.dll", "_Unwind_Resume", 1, false},
    {"libgcc_s_dw2-1.dll", "__register_frame_info", 2, false},
    {"libgcc_s_dw2-1.dll", "__deregister_frame_info", 1, false},
    {"libstdc++-6.dll", "_ZSt4cout", 0, false},
    {"libstdc++-6.dll", "_ZSt3cin", 0, false},
    {"libstdc++-6.dll", "_ZNSaIcEC1Ev", 1, false, true},
    {"libstdc++-6.dll", "_ZNSaIcED1Ev", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt8ios_base4InitC1Ev", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt8ios_base4InitD1Ev", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_", 3, false, true},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1ERKS4_", 2, false, true},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSERKS4_", 2, false, true},
    {"libstdc++-6.dll", "_Znwj", 1, false},
    {"libstdc++-6.dll", "_Znaj", 1, false},
    {"libstdc++-6.dll", "_ZdlPv", 1, false},
    {"libstdc++-6.dll", "_ZdaPv", 1, false},
    {"libstdc++-6.dll", "_ZSt17__throw_bad_allocv", 0, false},
    {"libstdc++-6.dll", "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc", 2, false},
    {"libstdc++-6.dll", "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE", 2, false},
    {"libstdc++-6.dll", "_ZNSolsEi", 2, false, true},
    {"libstdc++-6.dll", "_ZNSirsERi", 2, false, true},
    {"libstdc++-6.dll", "_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE", 2, false},
    {"libstdc++-6.dll", "_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3_", 2, false},
    {"kernel32.dll", "Beep", 2, true},
    {"kernel32.dll", "SetConsoleCursorPosition", 2, true},
    {"kernel32.dll", "SetConsoleTextAttribute", 2, true},
    {"kernel32.dll", "SetConsoleCursorInfo", 2, true},
    {"kernel32.dll", "FindFirstFileA", 2, true},
    {"kernel32.dll", "FindNextFileA", 2, true},
    {"kernel32.dll", "FindClose", 1, true},
    {"kernel32.dll", "GetProcessHeap", 0, true},
    {"kernel32.dll", "GetVersionExA", 1, true},
    {"kernel32.dll", "GetFileType", 1, true},
    {"kernel32.dll", "GetEnvironmentStringsW", 0, true},
    {"kernel32.dll", "HeapReAlloc", 4, true},
    {"kernel32.dll", "DebugBreak", 0, true},
    {"kernel32.dll", "GetStringTypeA", 5, true},
    {"kernel32.dll", "GetStringTypeW", 4, true},
    {"kernel32.dll", "LCMapStringA", 6, true},
    {"kernel32.dll", "LCMapStringW", 6, true},
    {"kernel32.dll", "GetLocaleInfoA", 4, true},
    // msvcrt is cdecl: the caller pops, so callee_cleans_stack is false and the
    // emulated call removes only the return address.
    {"msvcrt.dll", "_initterm", 2, false},
    {"msvcrt.dll", "_initterm_e", 2, false},
    {"msvcrt.dll", "__acrt_iob_func", 1, false},
    {"msvcrt.dll", "__stdio_common_vfprintf", 5, false},
    {"msvcrt.dll", "__stdio_common_vfscanf", 6, false},
    {"msvcrt.dll", "memcmp", 3, false},
    {"msvcrt.dll", "fflush", 1, false},
    {"msvcrt.dll", "setvbuf", 4, false},
    {"msvcrt.dll", "_set_new_mode", 1, false},
    {"msvcrt.dll", "_configthreadlocale", 1, false},
    {"msvcrt.dll", "__setusermatherr", 1, false},
    {"msvcrt.dll", "_set_invalid_parameter_handler", 1, false},
    {"msvcrt.dll", "_configure_narrow_argv", 1, false},
    {"msvcrt.dll", "_initialize_narrow_environment", 0, false},
    {"msvcrt.dll", "_crt_atexit", 1, false},
    {"msvcrt.dll", "_exit", 1, false},
    {"msvcrt.dll", "__p___argc", 0, false},
    {"msvcrt.dll", "__p___argv", 0, false},
    {"msvcrt.dll", "__p__commode", 0, false},
    {"msvcrt.dll", "__p__acmdln", 0, false},
    {"libgcc_s_sjlj-1.dll", "_Unwind_SjLj_Register", 1, false},
    {"libgcc_s_sjlj-1.dll", "_Unwind_SjLj_Unregister", 1, false},
    {"libgcc_s_sjlj-1.dll", "_Unwind_SjLj_Resume", 1, false},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_disposeEv", 1, false, true},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE15_M_replace_coldEPcjPKcjj", 6, false, true},
    {"libstdc++-6.dll", "_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_i", 3, false},
    {"libstdc++-6.dll", "_ZSt19__throw_logic_errorPKc", 1, false},
    {"libstdc++-6.dll", "_ZSt20__throw_length_errorPKc", 1, false},
    {"libstdc++-6.dll", "_ZdlPvj", 2, false},
    {"msvcrt.dll", "system", 1, false},
    {"msvcrt.dll", "time", 1, false},
    {"msvcrt.dll", "_time64", 1, false},
    {"msvcrt.dll", "puts", 1, false},
    {"msvcrt.dll", "getchar", 0, false},
    {"msvcrt.dll", "fgetc", 1, false},
    {"msvcrt.dll", "getc", 1, false},
    {"msvcrt.dll", "fgets", 3, false},
    {"msvcrt.dll", "putchar", 1, false},
    {"msvcrt.dll", "signal", 2, false},
    {"msvcrt.dll", "strcoll", 2, false},
    {"msvcrt.dll", "_stricoll", 2, false},
    {"msvcrt.dll", "_fullpath", 3, false},
    {"msvcrt.dll", "wcstombs", 3, false},
    {"msvcrt.dll", "wcrtomb", 3, false},
    {"msvcrt.dll", "vfprintf", 3, false},
    {"msvcrt.dll", "printf", 1, true},
    {"msvcrt.dll", "fprintf", 3, true},
    {"msvcrt.dll", "sprintf", 3, true},
    {"msvcrt.dll", "snprintf", 4, true},
    {"msvcrt.dll", "_snprintf", 4, true},
    {"msvcrt.dll", "_iob_func", 0, true},
    {"msvcrt.dll", "__iob_func", 0, true},
    {"msvcrt.dll", "__lconv_init", 0, true},
    {"msvcrt.dll", "_lock", 1, true},
    {"msvcrt.dll", "_unlock", 1, true},
    {"msvcrt.dll", "_amsg_exit", 1, true},
    {"msvcrt.dll", "strerror", 2, true},
    {"msvcrt.dll", "isspace", 1, true},
    {"msvcrt.dll", "clock", 0, true},
    {"msvcrt.dll", "getenv", 1, true},
    {"msvcrt.dll", "cos", 1, true},
    {"msvcrt.dll", "sin", 1, true},
    {"msvcrt.dll", "sqrt", 1, true},
    {"msvcrt.dll", "log", 1, true},
    {"msvcrt.dll", "exp", 1, true},
    {"msvcrt.dll", "fabs", 1, true},
    {"msvcrt.dll", "atan", 1, true},
    {"msvcrt.dll", "tan", 1, true},
    {"msvcrt.dll", "floor", 1, true},
    {"msvcrt.dll", "ceil", 1, true},
    {"msvcrt.dll", "strspn", 2, true},
    {"msvcrt.dll", "strcspn", 2, true},
    {"msvcrt.dll", "wcslen", 1, true},
    {"msvcrt.dll", "_assert", 3, true},
    {"msvcrt.dll", "MulDiv", 3, true},
    {"kernel32.dll", "MulDiv", 3, true},
    // Legacy comctl32 exports InitCommonControls by ordinal #17. Registration is
    // process-global on Windows; the native runtime has no control class registry,
    // so a successful no-op is the compatible startup behavior for console-safe paths.
    {"comctl32.dll", "#17", 0, false},
    {"kernel32.dll", "GlobalAlloc", 2, true},
    {"kernel32.dll", "GlobalLock", 1, true},
    {"kernel32.dll", "GlobalUnlock", 1, true},
    {"kernel32.dll", "GlobalFree", 1, true},
    {"kernel32.dll", "LocalFree", 1, true},
    {"msvcrt.dll", "vsprintf", 3, true},
    {"msvcrt.dll", "_vsnprintf", 4, true},
    {"msvcrt.dll", "vsnprintf", 4, true},
    {"msvcrt.dll", "_vscprintf", 2, true},
    {"msvcrt.dll", "__stdio_common_vsprintf", 5, true},
    {"msvcrt.dll", "__getmainargs", 5, false},
    {"msvcrt.dll", "strlen", 1, false},
    {"msvcrt.dll", "strtol", 3, false},
    {"msvcrt.dll", "strtoul", 3, false},
    {"msvcrt.dll", "strtoll", 3, false},
    {"msvcrt.dll", "_strtoi64", 3, false},
    {"msvcrt.dll", "_strtoui64", 3, false},
    {"msvcrt.dll", "strtoull", 3, false},
    {"msvcrt.dll", "strtod", 2, false},
    {"msvcrt.dll", "atof", 1, false},
    {"msvcrt.dll", "atol", 1, false},
    {"msvcrt.dll", "_set_fmode", 1, false},
    {"msvcrt.dll", "strcmp", 2, false},
    {"msvcrt.dll", "strncmp", 3, false},
    {"msvcrt.dll", "strcpy", 2, false},
    {"msvcrt.dll", "strncpy", 3, false},
    {"msvcrt.dll", "strcat", 2, false},
    {"msvcrt.dll", "strchr", 2, false},
    {"msvcrt.dll", "strrchr", 2, false},
    {"msvcrt.dll", "strstr", 2, false},
    {"msvcrt.dll", "strtol", 3, false},
    {"msvcrt.dll", "atoi", 1, false},
    {"msvcrt.dll", "toupper", 1, false},
    {"msvcrt.dll", "tolower", 1, false},
    {"msvcrt.dll", "_stricmp", 2, false},
    {"msvcrt.dll", "_strcmpi", 2, false},
    {"msvcrt.dll", "_errno", 0, false},
    {"msvcrt.dll", "__p__environ", 0, false},
    {"msvcrt.dll", "__p__fmode", 0, false},
    {"msvcrt.dll", "_iob", 0, false},
    {"msvcrt.dll", "_pctype", 0, false},
    {"msvcrt.dll", "__mb_cur_max", 0, false},
    {"msvcrt.dll", "___mb_cur_max_func", 0, false},
    {"msvcrt.dll", "malloc", 1, false},
    {"msvcrt.dll", "calloc", 2, false},
    {"msvcrt.dll", "realloc", 2, false},
    {"msvcrt.dll", "free", 1, false},
    {"msvcrt.dll", "memcpy", 3, false},
    {"msvcrt.dll", "memmove", 3, false},
    {"msvcrt.dll", "memset", 3, false},
    {"vcruntime140.dll", "memcmp", 3, false},
    {"vcruntime140.dll", "memcpy", 3, false},
    {"vcruntime140.dll", "memset", 3, false},
    {"vcruntime140.dll", "strchr", 2, false},
    {"vcruntime140.dll", "strrchr", 2, false},
    {"msvcrt.dll", "_strdup", 1, false},
    {"msvcrt.dll", "srand", 1, false},
    {"msvcrt.dll", "rand", 0, false},
    {"msvcrt.dll", "fwrite", 4, false},
    {"msvcrt.dll", "__set_app_type", 1, false},
    {"msvcrt.dll", "_set_app_type", 1, false},
    {"msvcrt.dll", "_fpreset", 0, false},
    {"msvcrt.dll", "_setmode", 2, false},
    {"msvcrt.dll", "atexit", 1, false},
    {"msvcrt.dll", "_onexit", 1, false},
    {"msvcrt.dll", "_cexit", 0, false},
    {"msvcrt.dll", "_getch", 0, false},
    {"msvcrt.dll", "_kbhit", 0, false},
    {"msvcrt.dll", "abort", 0, false},
    {"msvcrt.dll", "exit", 1, false},
    {"msvcrt.dll", "_isctype", 2, false},
    {"msvcrt.dll", "wctype", 1, false},
    {"msvcrt.dll", "iswctype", 2, false},
    {"msvcrt.dll", "mbstowcs", 3, false},
    {"msvcrt.dll", "mbrtowc", 4, false},
    {"msvcrt.dll", "mbsrtowcs", 4, false},
    {"msvcrt.dll", "setlocale", 2, false},
    {"ole32.dll", "CoInitialize", 1, true},
    {"ole32.dll", "CoUninitialize", 0, true},
    {"kernel32.dll", "OutputDebugStringA", 1, true},
    {"kernel32.dll", "GetDriveTypeA", 1, true},
    {"kernel32.dll", "CompareFileTime", 2, true},
    {"kernel32.dll", "CloseHandle", 1, true},
    {"kernel32.dll", "SetStdHandle", 2, true},
    {"kernel32.dll", "CreateMutexA", 3, true},
    {"kernel32.dll", "CreateEventA", 4, true},
    {"kernel32.dll", "SetEvent", 1, true},
    {"kernel32.dll", "ResetEvent", 1, true},
    {"kernel32.dll", "CreateSemaphoreA", 4, true},
    {"kernel32.dll", "ReleaseSemaphore", 3, true},
    {"kernel32.dll", "WaitForSingleObject", 2, true},
    {"kernel32.dll", "WaitForMultipleObjects", 4, true},
    {"kernel32.dll", "SetHandleCount", 1, true},
    {"kernel32.dll", "ReleaseMutex", 1, true},
    {"kernel32.dll", "FlushFileBuffers", 1, true},
    {"kernel32.dll", "FreeEnvironmentStringsW", 1, true},
    {"kernel32.dll", "GetEnvironmentVariableA", 3, true},
    {"kernel32.dll", "GetCPInfo", 2, true},
    {"kernel32.dll", "HeapCreate", 3, true},
    {"kernel32.dll", "HeapAlloc", 3, true},
    {"kernel32.dll", "HeapFree", 3, true},
    {"kernel32.dll", "HeapDestroy", 1, true},
    {"kernel32.dll", "Sleep", 1, true},
    {"kernel32.dll", "GetTickCount", 0, true},
    {"kernel32.dll", "GetTickCount64", 0, true},
    {"kernel32.dll", "QueryPerformanceCounter", 1, true},
    {"kernel32.dll", "QueryPerformanceFrequency", 1, true},
    {"kernel32.dll", "InitializeCriticalSection", 1, true},
    {"kernel32.dll", "DeleteCriticalSection", 1, true},
    {"kernel32.dll", "EnterCriticalSection", 1, true},
    {"kernel32.dll", "LeaveCriticalSection", 1, true},
    {"kernel32.dll", "InitializeCriticalSectionAndSpinCount", 2, true},
    {"kernel32.dll", "InitializeCriticalSectionEx", 3, true},
    {"kernel32.dll", "GetSystemTimeAsFileTime", 1, true},
    {"kernel32.dll", "GetStartupInfoA", 1, true},
    {"kernel32.dll", "GetStartupInfoW", 1, true},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_get_narrow_winmain_command_line", 0, true},
    {"kernel32.dll", "GetCommandLineA", 0, true},
    {"kernel32.dll", "GetCommandLineW", 0, true},
    {"kernel32.dll", "GetEnvironmentStrings", 0, true},
    {"kernel32.dll", "FreeEnvironmentStringsA", 1, true},
    {"kernel32.dll", "lstrlenA", 1, true},
    {"kernel32.dll", "lstrlenW", 1, true},
    {"kernel32.dll", "lstrcpyA", 2, true},
    {"kernel32.dll", "GetACP", 0, true},
    {"kernel32.dll", "GetLocalTime", 1, true},
    {"kernel32.dll", "IsDBCSLeadByte", 1, true},
    {"kernel32.dll", "GetOEMCP", 0, true},
    {"kernel32.dll", "GetConsoleOutputCP", 0, true},
    {"kernel32.dll", "SetConsoleOutputCP", 1, true},
    {"kernel32.dll", "GetVersion", 0, true},
    {"kernel32.dll", "GetSystemInfo", 1, true},
    {"kernel32.dll", "FlsAlloc", 1, true},
    {"kernel32.dll", "FlsFree", 1, true},
    {"kernel32.dll", "FlsSetValue", 2, true},
    {"kernel32.dll", "FlsGetValue", 1, true},
    {"kernel32.dll", "FlsGetValue2", 1, true},
    {"kernel32.dll", "TlsAlloc", 0, true},
    {"kernel32.dll", "TlsFree", 1, true},
    {"kernel32.dll", "TlsSetValue", 2, true},
    {"kernel32.dll", "TlsGetValue", 1, true},
    {"kernel32.dll", "WideCharToMultiByte", 8, true},
    {"kernel32.dll", "MultiByteToWideChar", 6, true},
    {"kernel32.dll", "GetProcAddress", 2, true},
    {"kernel32.dll", "LoadLibraryA", 1, true},
    {"kernel32.dll", "LoadLibraryW", 1, true},
    {"kernel32.dll", "LoadLibraryExW", 3, true},
    {"kernel32.dll", "FreeLibrary", 1, true},
    // kernel32 file services. CreateFileA is stdcall with seven arguments, and
    // the seventh is the one a program that does not care about template files
    // passes as NULL; getting the count wrong corrupts the guest stack from the
    // next call onwards, which looks nothing like the mistake that caused it.
    {"kernel32.dll", "CreateFileA", 7, true},
    {"kernel32.dll", "CreateFileW", 7, true},
    {"kernel32.dll", "SetFilePointer", 4, true},
    {"kernel32.dll", "SetFilePointerEx", 3, true},
    {"kernel32.dll", "GetFileSize", 2, true},
    {"kernel32.dll", "GetFileSizeEx", 2, true},
    {"kernel32.dll", "SetEndOfFile", 1, true},
    {"kernel32.dll", "DeleteFileA", 1, true},
    {"kernel32.dll", "DeleteFileW", 1, true},
    {"kernel32.dll", "CreateDirectoryA", 2, true},
    {"kernel32.dll", "CreateDirectoryW", 2, true},
    {"kernel32.dll", "RemoveDirectoryA", 1, true},
    {"kernel32.dll", "RemoveDirectoryW", 1, true},
    {"kernel32.dll", "MoveFileA", 2, true},
    {"kernel32.dll", "MoveFileW", 2, true},
    {"kernel32.dll", "MoveFileExA", 3, true},
    {"kernel32.dll", "MoveFileExW", 3, true},
    {"kernel32.dll", "GetFileAttributesA", 1, true},
    {"kernel32.dll", "GetFileAttributesW", 1, true},
    {"kernel32.dll", "GetModuleFileNameA", 3, true},
    {"kernel32.dll", "GetModuleFileNameW", 3, true},
    {"kernel32.dll", "GetDiskFreeSpaceA", 5, true},
    {"kernel32.dll", "GetDiskFreeSpaceW", 5, true},
    // The CRT stream family. cdecl throughout: the caller pops.
    {"msvcrt.dll", "fopen", 2, false},
    {"msvcrt.dll", "_wfopen", 2, false},
    {"msvcrt.dll", "_fsopen", 3, false},
    {"msvcrt.dll", "fclose", 1, false},
    {"msvcrt.dll", "fread", 4, false},
    {"msvcrt.dll", "fseek", 3, false},
    {"msvcrt.dll", "_fseeki64", 3, false},
    {"msvcrt.dll", "ftell", 1, false},
    {"msvcrt.dll", "feof", 1, false},
    {"msvcrt.dll", "ferror", 1, false},
    {"msvcrt.dll", "clearerr", 1, false},
    {"msvcrt.dll", "rewind", 1, false},
    {"msvcrt.dll", "fgetc", 1, false},
    {"msvcrt.dll", "getc", 1, false},
    {"msvcrt.dll", "fputc", 2, false},
    {"msvcrt.dll", "putc", 2, false},
    {"msvcrt.dll", "fgets", 3, false},
    {"msvcrt.dll", "fputs", 2, false},
    {"msvcrt.dll", "ungetc", 2, false},
    {"msvcrt.dll", "_fileno", 1, false},
    {"msvcrt.dll", "_open", 2, false},
    {"msvcrt.dll", "_wopen", 2, false},
    {"msvcrt.dll", "_close", 1, false},
    {"msvcrt.dll", "_read", 3, false},
    {"msvcrt.dll", "_write", 3, false},
    {"msvcrt.dll", "_lseek", 3, false},
    {"msvcrt.dll", "_open_osfhandle", 2, false},
    {"msvcrt.dll", "_fdopen", 2, false},
    {"msvcrt.dll", "_wfdopen", 2, false},
    {"msvcrt.dll", "remove", 1, false},
    {"msvcrt.dll", "rename", 2, false},
};

// The distinct library names the table knows, in declaration order.
//
// Used when a guest asks for a symbol without naming a module -- GetProcAddress
// with a NULL handle, which means "search what the process already has". The
// table's own order is the only search order that cannot drift: a separate list
// would silently stop including the next library somebody implements.
inline std::vector<const char*> win32_known_libraries() {
  std::vector<const char*> libraries;
  for (const auto& entry : kWin32ImportAbiTable) {
    bool seen = false;
    for (const auto* known : libraries)
      if (std::strcmp(known, entry.library_name) == 0) { seen = true; break; }
    if (!seen) libraries.push_back(entry.library_name);
  }
  return libraries;
}

// The Universal CRT is shipped as API sets, one per area, but the symbols are the
// standard C library functions under their usual names. A program built against
// it therefore resolves to the same implementations as one built against msvcrt,
// so an API-set name that is not in the table is retried as msvcrt.
inline bool win32_is_universal_crt_library(const char* library_name) {
  return library_name != nullptr && std::strncmp(library_name, "api-ms-win-crt", 14) == 0;
}

inline const Win32ImportAbi* win32_import_abi(const char* library_name, const char* symbol_name) {
  if (symbol_name == nullptr) return nullptr;
  for (const auto& entry : kWin32ImportAbiTable) {
    if (std::strcmp(entry.symbol_name, symbol_name) != 0) continue;
    if (library_name != nullptr && std::strcmp(entry.library_name, library_name) != 0) continue;
    return &entry;
  }
  if (win32_is_universal_crt_library(library_name)) return win32_import_abi("msvcrt.dll", symbol_name);
  return nullptr;
}

// Byte count removed from the guest stack after a 32-bit import call: the
// return address always, plus the arguments for stdcall.
inline std::uint64_t win32_import_stack_cleanup(const char* library_name, const char* symbol_name) {
  const auto* abi = win32_import_abi(library_name, symbol_name);
  std::uint64_t bytes = 4;  // return address
  if (abi != nullptr && abi->callee_cleans_stack)
    bytes += static_cast<std::uint64_t>(abi->argument_count) * 4;
  return bytes;
}

}  // namespace recomp
