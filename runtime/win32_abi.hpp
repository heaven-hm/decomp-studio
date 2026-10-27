#pragma once

#include <cstring>

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
};

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
    {"kernel32.dll", "GetCurrentProcess", 0, true},
    {"kernel32.dll", "GetCurrentThread", 0, true},
    {"kernel32.dll", "IsDebuggerPresent", 0, true},
    {"kernel32.dll", "GetModuleHandleA", 1, true},
    {"kernel32.dll", "GetModuleHandleW", 1, true},
    {"kernel32.dll", "GetModuleFileNameA", 3, true},
    {"kernel32.dll", "SetUnhandledExceptionFilter", 1, true},
    {"kernel32.dll", "UnhandledExceptionFilter", 1, true},
    {"kernel32.dll", "IsProcessorFeaturePresent", 1, true},
    {"kernel32.dll", "VirtualAlloc", 4, true},
    {"kernel32.dll", "VirtualFree", 3, true},
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
    {"ole32.dll", "CoInitialize", 1, true},
    {"ole32.dll", "CoUninitialize", 0, true},
    {"kernel32.dll", "OutputDebugStringA", 1, true},
    {"kernel32.dll", "GetDriveTypeA", 1, true},
    {"kernel32.dll", "CompareFileTime", 2, true},
    {"kernel32.dll", "CloseHandle", 1, true},
    {"kernel32.dll", "SetStdHandle", 2, true},
    {"kernel32.dll", "CreateMutexA", 3, true},
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
    {"kernel32.dll", "GetSystemTimeAsFileTime", 1, true},
    {"kernel32.dll", "GetStartupInfoA", 1, true},
    {"kernel32.dll", "GetCommandLineA", 0, true},
    {"kernel32.dll", "GetEnvironmentStrings", 0, true},
    {"kernel32.dll", "FreeEnvironmentStringsA", 1, true},
    {"kernel32.dll", "lstrlenA", 1, true},
    {"kernel32.dll", "lstrlenW", 1, true},
    {"kernel32.dll", "lstrcpyA", 2, true},
    {"kernel32.dll", "GetACP", 0, true},
    {"kernel32.dll", "GetOEMCP", 0, true},
    {"kernel32.dll", "GetConsoleOutputCP", 0, true},
    {"kernel32.dll", "SetConsoleOutputCP", 1, true},
    {"kernel32.dll", "GetVersion", 0, true},
    {"kernel32.dll", "GetSystemInfo", 1, true},
    {"kernel32.dll", "FlsAlloc", 1, true},
    {"kernel32.dll", "FlsFree", 1, true},
    {"kernel32.dll", "FlsSetValue", 2, true},
    {"kernel32.dll", "FlsGetValue", 1, true},
    {"kernel32.dll", "TlsAlloc", 0, true},
    {"kernel32.dll", "TlsFree", 1, true},
    {"kernel32.dll", "TlsSetValue", 2, true},
    {"kernel32.dll", "TlsGetValue", 1, true},
    {"kernel32.dll", "WideCharToMultiByte", 8, true},
    {"kernel32.dll", "MultiByteToWideChar", 6, true},
    {"kernel32.dll", "GetProcAddress", 2, true},
    {"kernel32.dll", "LoadLibraryA", 1, true},
    {"kernel32.dll", "LoadLibraryW", 1, true},
    {"kernel32.dll", "FreeLibrary", 1, true},
};

inline const Win32ImportAbi* win32_import_abi(const char* library_name, const char* symbol_name) {
  if (symbol_name == nullptr) return nullptr;
  for (const auto& entry : kWin32ImportAbiTable) {
    if (std::strcmp(entry.symbol_name, symbol_name) != 0) continue;
    if (library_name != nullptr && std::strcmp(entry.library_name, library_name) != 0) continue;
    return &entry;
  }
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
