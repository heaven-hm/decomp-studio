# Honesty audit — fabricated values, silent swallows, and verification bypasses

**Task:** audit `runtime/recomp_runtime.cpp`, `runtime/recomp_runtime.hpp`, `runtime/win32_abi.hpp`
and `core/semantics/x86_64_lifter.cpp` for places that return a value or report success without
doing the work, invent a constant where a real value exists, discard a host result, or swallow a
failure the caller should learn about. Read-only except this file.

**Revision audited:** commit `c2a836c` (`feature/x86-x64-arm64-mvp`). **The tree was being edited by
other agents while this audit ran.** When the citations were pinned, all six files below matched
`HEAD` (`git diff HEAD --` empty). Since then `core/semantics/x86_64_lifter.cpp` has been changed by
another agent (20 insertions / 1 deletion adding `unpck*`/`movq` vector handling — unrelated to
anything in this report), which moved four of its line numbers; both states are recorded so the
Lead can re-check. `runtime/recomp_runtime.cpp` also changed mtime mid-session and was transiently
different from `HEAD`.

| file | sha256 (first 16) | citations valid for |
| --- | --- | --- |
| `runtime/recomp_runtime.cpp` | `f4f5c336817cd82d` | this hash (= `HEAD`) |
| `runtime/recomp_runtime.hpp` | `f064c792c3881f96` | this hash (= `HEAD`) |
| `runtime/win32_abi.hpp` | `1db432f081589b3b` | this hash (= `HEAD`) |
| `core/semantics/x86_64_lifter.cpp` | `af99a05da8f974f3` (audited) → `30dba8ca3dc69a64` (current) | both, see F9 |
| `core/verification/differential_harness.hpp` | `49c9c63b66f0e1e8` | this hash (= `HEAD`) |
| `core/verification/differential_harness.cpp` | `8b1dc4fb34c33081` | this hash (= `HEAD`) |

A programmatic check of all 95 citations (file, line, expected substring) passes against the audited
hashes; the three that failed on the first pass were corrected (`apps/cli/main.cpp:502`, harness
`:447-448`, lifter `:469-471`). The only lifter lines that moved are F9's stub block
(`1771-1773` → `1790-1792`) and the fail-closed fallback (`1782` → `1801`); lines 130 and 469-471 are
unchanged in both. **Lifter line numbers are a moving target: re-verify against the hash before
editing.**

**Method.** Full read of `recomp_runtime.cpp` (2441 lines) and `win32_abi.hpp`; targeted read of
`recomp_runtime.hpp` (helpers, `import_argument`, `set_import_result`, image descriptors),
`x86_64_lifter.cpp` (failure paths, stub emission, VEX table), and
`core/verification/differential_harness.{hpp,cpp}` (the reference side, because item 3 of the brief
names `uc_reg_write`). Every finding below was then **cross-checked against the upstream reference
the runtime claims to port from** — `research/upstream/igi-recomp/shim/src/kernel32.c` (MIT), which
is checked into this repo — because "deliberate and faithful to the reference" and "genuine bug"
are different verdicts. That check changed the classification of six findings (noted inline).

**Verdict vocabulary used here**
- `[a]` deliberate **and** documented by a comment in the code that explains it → OK.
- `[b]` deliberate but **undocumented** in the code (a reader cannot tell it from a bug) → finding.
- `[c]` genuine bug — the code does not do what its own structure and comments say it does.

**Counts:** `[a]` 15 documented-and-OK items · `[b]` 20 deliberate-but-undocumented
simplifications · `[c]` 26 genuine bugs. **46 findings** (45 numbered plus F1b), grouped below as
2 critical / 9 high / 20 medium / 15 low.

**What would change a verdict** is stated for every finding I am not fully sure of.

---

## CRITICAL

### F1 `[c]` A verification run with zero checkpoints compared is reported as PASS

```
core/verification/differential_harness.hpp:59    if (checkpoints_compared == 0) return true;
runtime/recomp_runtime.cpp:2267                  if (file == nullptr) return;
```

`DifferentialResult::verified()` returns **true** when no guest-state checkpoint was compared, and
the CLI turns that into `VERIFY: PASS (identical output)` (`apps/cli/main.cpp:502`) and exit 0.
The justification comment above it says *"Checkpoints are only required when some were actually
compared: a run with capture disabled is not evidence of disagreement"* — but `compare_project`
**enables capture itself** and deletes the file first:

```
core/verification/differential_harness.cpp:447   ::setenv("RECOMP_CHECKPOINT", checkpoint_path.string().c_str(), 1);
core/verification/differential_harness.cpp:448   ::setenv("RECOMP_CHECKPOINT_INTERVAL", std::to_string(kCheckpointInterval).c_str(), 1);
```

So "capture disabled" is not the case being measured. Zero checkpoints means the candidate side
produced no file, and the only reasons are failures that are all swallowed:

- `write_guest_checkpoints_if_requested` cannot create the file → silent `return` (F1b);
- the guest never exits through `guest_request_exit`, so the file is never written at all — only
  `guest_request_exit` calls `write_guest_checkpoints_if_requested` (line 2294), and
  `win32_terminate_process` exits via `std::exit(1)` (line 303) without it;
- `RECOMP_CHECKPOINT_INTERVAL` is unparsable → `guest_checkpoint_interval` stays 0 → nothing
  captured.

**Why it matters:** this is the exact claim the project forbids — a pass on output equality alone,
labelled `VERIFIED`, while the machine-state comparison that would have caught a wrong register,
flag or store never happened. The `checkpoints_compared` number is printed, so the evidence is
visible, but the verdict and the exit code already say PASS. `pipeline::run` spawns the candidate
with `environ` (`core/pipeline.cpp:60`, `popen` at :84), so the env vars do reach it; a
checkpoint-file write failure is reachable on any read-only or full project directory.

**Settled by:** making `verified()` require `checkpoints_compared > 0` and making the checkpoint
write failure a hard error. Both are one-line changes.

### F1b `[c]` The checkpoint write failure is swallowed

```
runtime/recomp_runtime.cpp:2266-2267   std::FILE* file = std::fopen(path, "wb");
                                       if (file == nullptr) return;
```

The only consumer of the file is the verdict above, so a failed write converts "we could not
measure" into "we measured nothing to disagree with". Same class:
`if (path == nullptr || guest_checkpoints.empty()) return;` (line 2265) silently discards a
requested capture when the guest exited before the first checkpoint.

---

## HIGH

### F2 `[c]` `WriteFile` invents the byte count and always reports success

```
runtime/recomp_runtime.cpp:276-283
  while (written < length) {
    write_guest_output(descriptor, reinterpret_cast<const char*>(guest_memory + buffer + written), ...);
    const auto count = static_cast<ssize_t>(length - written);   // <-- not what write() returned
    if (count <= 0) break;
    written += static_cast<std::uint64_t>(count);
  }
  if (written_pointer != 0) store_guest_memory(context, written_pointer, written, 4);
  set_import_result(context, 1);
```

`count` is computed from the *request*, not from the write. `write_guest_output` returns `void`
(F4), so the loop body always sets `written = length` on the first iteration and the `if (count <= 0)
break;` guard is dead code. The guest is handed `lpNumberOfBytesWritten = length` and
`BOOL = TRUE` even if the underlying `write()` wrote zero bytes or failed with `EPIPE`/`EBADF`.

The reference does it correctly:

```
research/upstream/igi-recomp/shim/src/kernel32.c:695   put = (ssize_t)fwrite(gptr(buf), 1, n, stderr);
research/upstream/igi-recomp/shim/src/kernel32.c:705   WR32(out, put < 0 ? 0u : (uint32_t)put);
```

**Why it matters:** a program that logs or saves data is told its bytes were written; the file or
pipe stays empty and the program reports success. This is the canonical "plausible-looking value
the runtime did not compute".

### F3 `[c]` `fwrite` reports items written regardless, and an unknown stream is written to fd 0

```
runtime/recomp_runtime.cpp:1083-1087
  const auto index = msvcrt_stream_index(stream);
  const int descriptor = index == 0 ? STDIN_FILENO : index == 1 ? STDOUT_FILENO : STDERR_FILENO;
  if (total != 0 && buffer + total <= guest_memory_size)
    write_guest_output(descriptor, ...);
  set_import_result(context, count);
```

Three fabrications in five lines: (i) the return value is the requested item count, never what was
written; (ii) if `buffer + total` is out of range nothing is written and the count is still
returned; (iii) `msvcrt_stream_index` returns `0` for any stream below or outside the three fake
`FILE` objects (`recomp_runtime.cpp:990`), so `fwrite(..., f)` on a stream the runtime does not know
writes to **stdin** (fd 0, which fails with `EBADF`) and returns success.

**Why it matters:** output silently disappears while the program believes it was written — the same
failure mode as F2, on the other CRT path.

### F4 `[c]` The one place the host write result exists is discarded

```
runtime/recomp_runtime.cpp:2309   (void)::write(descriptor, data, size);
```

`write_guest_output` is `void` (declared `recomp_runtime.hpp:98`), so no caller *can* learn about a
short write or an error. This is the root cause of F2 and F3, and the reason `WriteFile`'s loop had
to invent its count. The reference returns the count up to its callers. Severity on its own:
medium — as the enabler of F2/F3: high.

### F5 `[c]` `cin >> int` converts a parse failure into the value `0`

```
runtime/recomp_runtime.cpp:876-880
  try {
    store_guest_memory(context, target, static_cast<std::uint64_t>(std::stol(token)), 4);
  } catch (...) {
    store_guest_memory(context, target, 0, 4);
  }
```

The `catch (...)` swallows the exception *and* writes a plausible value into the guest's variable,
then returns the stream object (truthy), so `if (cin >> x)` succeeds. The stream state is not
modelled at all — `GuestStreamState` holds only a descriptor (`recomp_runtime.cpp:724-727`), so
failbit is never set and EOF is never signalled either.

**Why it matters:** the guest proceeds with a fabricated `0` where no parse happened. A broken port
that mis-reads input looks like a program that read a zero.

### F6 `[b]` `atexit` / `_crt_atexit` report success; the handlers never run

```
runtime/recomp_runtime.cpp:1868    {"msvcrt.dll", "atexit", msvcrt_noop},
runtime/recomp_runtime.cpp:1809    {"msvcrt.dll", "_crt_atexit", msvcrt_return_zero},
runtime/recomp_runtime.cpp:1870    {"msvcrt.dll", "_cexit", msvcrt_noop},
runtime/recomp_runtime.cpp:1203    void msvcrt_noop(GuestContext* context) { set_import_result(context, 0); }
```

`atexit` returns 0 ("registered") and `_crt_atexit` likewise; nothing is recorded, and
`guest_request_exit` (lines 2293-2301) goes straight to `std::exit(code)`, which runs *host*
handlers. `_cexit` — whose whole job is to run exit handlers and flush — returns success without
doing either. The comment at 1205-1208 explains the *return convention* of `_onexit` but never says
the registration is dropped.

**Why it matters:** a program that registers cleanup (`fflush` of a log, `remove` of a temp file,
`free` of a lock file) is told it succeeded and gets no cleanup. Silent data loss at exit; also the
classic "reports success while doing nothing". Contrast the *documented* flush no-op at line 383-388
(F-a1), which is exactly what this pattern is supposed to look like.

### F7 `[b]` TLS: the store reports success and the load returns NULL

```
runtime/recomp_runtime.cpp:1924   {"kernel32.dll", "TlsAlloc", win32_zero},
runtime/recomp_runtime.cpp:1926   {"kernel32.dll", "TlsSetValue", win32_one},
runtime/recomp_runtime.cpp:1927   {"kernel32.dll", "TlsGetValue", win32_zero},
```

`TlsAlloc` returns 0, which is a *valid* index (`TLS_OUT_OF_INDEXES` is `0xFFFFFFFF`), so the guest
believes it has a slot. `TlsSetValue(slot, p)` returns TRUE and stores nothing; `TlsGetValue(slot)`
returns NULL. Same for `FlsAlloc`/`FlsSetValue`/`FlsGetValue` (lines 1920-1923). None of these has
a comment, and igi-recomp implements no TLS shim at all (`grep -n "Tls" research/upstream/igi-recomp/shim/src/*.c`
→ no matches), so there is no reference behaviour to match.

**Why it matters:** set-succeeds/get-returns-nothing is a fabrication the guest cannot detect; a
program that caches a lazily built object in TLS rebuilds it every call and can repeat side effects.

### F8 `[c]` CRT tables handed to the guest are zeroed memory that is never written

```
runtime/recomp_runtime.cpp:976     std::memset(guest_memory + msvcrt_data_block, 0, 0x1000);
runtime/recomp_runtime.cpp:1096    void msvcrt_pctype(GuestContext* context) { set_import_result(context, msvcrt_data_block + 0x300); }
runtime/recomp_runtime.cpp:1092    void msvcrt_errno(GuestContext* context) { set_import_result(context, msvcrt_data_block + 0x000); }
runtime/recomp_runtime.cpp:1542    void msvcrt_p_argc(GuestContext* context) { msvcrt_crt_global(context, 0x400); }
```

Nothing in the file writes offsets `+0x000`, `+0x300`, `+0x400`, `+0x410`, `+0x420` after the
`memset` (verified by grepping every `msvcrt_data_block +` offset: only `0x100`, `0x110`, `0x200`,
`0x320`, `0x800` are ever written). Consequences:

- `_pctype` is a **ctype table of all zeros**: every `_pctype[c]` lookup classifies every character
  as none-of-the-above. `isdigit`/`isalpha` via the table are always false, while the *function*
  `_isctype` (line 1216) is correctly implemented — the two disagree.
- `errno` is permanently `0`. `msvcrt_strtol`/`atoi`/`malloc` never set it (F16), so a program that
  checks `errno` after a failed conversion or allocation is told there was no error.
- `__p___argc`, `__p___argv`, `__p__commode` return pointers to slots that `__getmainargs`
  (line 1599) does not fill — it writes through the *caller's* pointers instead — so a program using
  the documented accessors reads `argc == 0`, `argv == NULL`.

**Why it matters:** these are reads of memory that was never written, handed out as if computed, and
they are reachable from ordinary C code. **What would settle `_pctype`'s practical impact:** grep the
guest image for a read of `_pctype`/`__pctype_func`; mingw code that inlines the table lookup is
affected, code that calls `isdigit` is not.

### F9 `[b]` `stub_function` emits a fabricated return value and is invisible to `verify`

```
core/semantics/x86_64_lifter.cpp:1790-1792   (was 1771-1773 at the audited hash af99a05d)
    if (stubbed_functions_.count(address) != 0) {
      definitions += "static void " + guest_function_name(address) +
                     "(GuestContext* context) { context->registers[4] += 8; context->registers[0] = 0; return; }\n\n";
```

The knob itself is documented — `MANUAL.md:614` *"replace a guest function with a no-op"*,
`README.md:134`, `ARCHITECTURE.md:78`, `core/semantics/x86_64_lifter.hpp:49` — so `[a]` for the
existence of the feature. What is **not** documented anywhere:

1. the stub **returns 0 in EAX**, i.e. every caller of that function receives a plausible value the
   runtime did not compute (this is precisely "no fabricated results");
2. it **pops 8 bytes** (`registers[4] += 8`) — correct for a 32-bit `call`+one stdcall argument, but
   applied unconditionally, including for PE32+ guests where the return address is 8 bytes and
   stdcall does not exist, and for cdecl functions with a different argument count. That is a stack
   corruption waiting for the first 64-bit stubbed function;
3. the stub is **not surfaced** in the manifest, the coverage report, the `verify` output or the
   `report` JSON (grep for `stub` in `apps/cli/`, `core/pipeline.cpp`, `core/verification/` finds
   only `configure_overrides`). A build with stubs in it can therefore be reported as `VERIFIED`.

**Why it matters:** the design spec in this repo states the rule the feature breaks —
`docs/superpowers/specs/2026-10-27-pe32-macos-mvp-design.md:49`: *"no API is falsely stubbed as
successful."* Minimum fix: make the stub call `recomp_unsupported(context, "stubbed function")`
(or at least return an unmistakable sentinel), and list stubbed functions in the manifest so
`verify` can refuse a verdict for a build that has them.

### F10 `[c]` A write to an ofstream that never opened goes to stdout

```
runtime/recomp_runtime.cpp:828-830
  const auto found = guest_streams.find(object);
  if (found != guest_streams.end()) return static_cast<std::uint64_t>(found->second.descriptor);
  return for_output ? STDOUT_FILENO : STDIN_FILENO;
```

`cxx_file_stream_construct` erases the entry when `::open` fails (line 915, with the comment
"is_open() reports false, as it should"), but the write path then falls back to the **console**
descriptor instead of failing. So `ofstream f("readonly/path"); f << "log";` prints to stdout and the
stream reports no error. The same fallback means a read on a failed ifstream reads stdin.

**Why it matters:** the guest's data lands somewhere it did not ask for, and nothing reports the
failure. `is_open()` is honest; the write is not.

---

## MEDIUM

### F11 `[c]` An unrecognised handle is silently treated as stdout

```
runtime/recomp_runtime.cpp:195-199
  const auto* entry = guest_handle_lookup(handle);
  if (entry != nullptr && entry->host_descriptor >= 0) return entry->host_descriptor;
  return STDOUT_FILENO;
```

`WriteFile(0xDEADBEEF, ...)` writes to the host's stdout and returns TRUE (F2). The reference
rejects it: `win32_set_last_error(ERROR_INVALID_HANDLE); stdcall_ret(c, 0, 5);`
(`research/upstream/igi-recomp/shim/src/kernel32.c:700-702`). So this is a deviation from the
reference, not a simplification shared with it.

### F12 `[c]` `ReadFile` maps a read error onto success-with-zero-bytes

```
runtime/recomp_runtime.cpp:292-295
  auto count = ::read(descriptor, guest_memory + buffer, static_cast<std::size_t>(length));
  if (count < 0) count = 0;
  if (read_pointer != 0) store_guest_memory(context, read_pointer, static_cast<std::uint64_t>(count), 4);
  set_import_result(context, 1);
```

The reference does the same for the count (`got < 0 → 0`, `kernel32.c:662-663`) but still returns 0
for an invalid handle, which the runtime cannot because of F11. Mapping an I/O error onto EOF is a
swallow: the guest cannot distinguish "no more data" from "the read failed".

### F13 `[c]` `GetVersion` returns a value that decodes to the wrong version

```
runtime/recomp_runtime.cpp:314   void win32_get_version(GuestContext* context) { set_import_result(context, 0x0a000000); }
```

`GetVersion` packs major in the **low** byte and minor in the next, build in the high word. As
written the result is major 0, minor 0, build 10 — i.e. pre-NT — not the "Windows 10" the constant
appears to spell. The reference returns the correctly encoded `0x0A280105` (XP 5.1.2600):

```
research/upstream/igi-recomp/shim/src/kernel32.c:119   SHIM(kernel32, GetVersion) { stdcall_ret(c, 0x0A280105u, 0); }
```

**Settled by:** any reference trace of the guest's use of `GetVersion`; the encoding itself is
unambiguous.

### F14 `[c]` `GetCommandLineA` writes into the wide environment block

```
runtime/recomp_runtime.cpp:531     offset = guest_memory_size - 0x100000;
runtime/recomp_runtime.cpp:548     environment_block_w = guest_memory_size - 0x100000;
```

Both are the same address. `build_environment_blocks` fills `[environment_block_w, +0x100000)` with
the host environment in UTF-16, and the first guest call to `GetCommandLineA` then `memcpy`s
`"recomp-guest"` over the first environment variable. `GetEnvironmentStringsW` (line 568) hands out
that same block, so a program that reads the wide environment after asking for its command line gets
a corrupted first entry. The two reserved regions (`-0x200000` for ANSI, `-0x100000` for wide) also
collide with the CRT block at `-0x300000` in no case, but the "reserved region" comment at 537-539
does not reserve anything.

### F15 `[c]` `VirtualAlloc` can hand back memory that is already in use

```
runtime/recomp_runtime.cpp:319-324
  if (requested != 0) { set_import_result(context, requested); return; }
  const auto aligned = (size + 0xfff) & ~0xfffull;
  if (next_heap_address + aligned > guest_memory_size) { set_import_result(context, 0); return; }
  set_import_result(context, next_heap_address);
  next_heap_address += aligned;
```

and the bump pointer starts on top of the guest heap:

```
runtime/recomp_runtime.cpp:2320-2321
  next_heap_address = heap_base;
  heap_initialize(heap_base, stack_top);
```

So `VirtualAlloc(NULL, n, ...)` returns addresses inside the region the boundary-tag allocator
(`heap_allocate`, line 434) hands out for `malloc`/`HeapAlloc`/`operator new`; the two allocators
alias. A requested address is returned with no reservation check at all, where the reference
validates it against its region table and logs when it does not belong to one
(`research/upstream/igi-recomp/shim/src/kernel32.c:367-373`). **Not a fabricated value in the
"returns a constant" sense, but an invented mapping** — the guest is told it owns memory it does not.
Also `size` is unbounded: `(size + 0xfff)` wraps for `size >= 0xFFFFFFFFFFFFF000`, yielding a
successful zero-size allocation.

### F16 `[c]` `strtol` swallows the conversion failure and forces base 10

```
runtime/recomp_runtime.cpp:1167-1172
  try {
    value = std::stol(text, &consumed, base == 0 ? 10 : base);
  } catch (...) {
    value = 0;
    consumed = 0;
  }
```

Overflow or a non-numeric string yields `0` with no `errno` (which is a permanently-zero slot, F8)
and no `LONG_MAX`/`ERANGE`. `base == 0` is also wrong: the real `strtol` auto-detects `0x`/`0`
prefixes, so `"0x10"` parses as 0 instead of 16. `msvcrt_atoi` has the same `catch (...) → 0`
(line 1179-1183).

### F17 `[c]` `_fullpath` returns the relative input as the absolute answer

```
runtime/recomp_runtime.cpp:1390-1396
  const auto absolute = std::filesystem::absolute(source, error);
  const auto text = error ? source : absolute.lexically_normal().string();
  if (destination != 0) { ... set_import_result(context, destination); }
```

On error the unconverted input is copied out and the function reports success (returns
`destination`). A program that stores the result believes it has an absolute path.

### F18 `[c]` `read_guest_string` silently truncates at 4096 bytes

```
runtime/recomp_runtime.cpp:131   while (value.size() < 4096 && address < guest_memory_size && guest_memory[address] != 0) {
```

Every string shim is built on this helper, so `strlen`, `strcmp`, `strcpy`, `strstr`, `lstrlenA`,
`vfprintf`'s `%s`, `fwrite`'s format strings etc. operate on a truncated prefix of any longer string
with no diagnostic — the opposite of the fail-closed policy used everywhere else in the runtime
(`store_guest_memory`/`load_guest_memory` call `report_guest_memory_fault`, which terminates).
A guest whose buffer is unterminated is also silently truncated rather than faulted.
`win32_lstrlen_w` (line 1673) has the same shape for wide strings.

### F19 `[b]` `GetSystemTimeAsFileTime` returns a zero timestamp

```
runtime/recomp_runtime.cpp:522   if (out != 0) { store_guest_memory(context, out, 0, 4); store_guest_memory(context, out + 4, 0, 4); }
```

A real value exists and the runtime already reads the host clock elsewhere (`msvcrt_time` uses
`std::time`, line 1368), so the inconsistency is not a determinism policy consistently applied. The
guest is handed 1601-01-01 as "now" with no comment saying so.

### F20 `[b]` `GetSystemInfo` fills the structure with zeros

```
runtime/recomp_runtime.cpp:1665   if (out != 0 && out + 48 <= guest_memory_size) std::memset(guest_memory + out, 0, 48);
```

`dwPageSize == 0`, `dwNumberOfProcessors == 0`, and both application-address limits are 0. A program
that divides by the page size or computes the addressable range from the limits gets a fabricated
answer. The `VirtualQuery` shim right above it takes the opposite approach and explicitly fills
"the fields a program actually inspects" (comment at 335-338) — the two are inconsistent.

### F21 `[b]` `GetLastError` is a constant 0 and `SetLastError` is ignored

```
runtime/recomp_runtime.cpp:1721   {"kernel32.dll", "GetLastError", win32_zero},
runtime/recomp_runtime.cpp:1722   {"kernel32.dll", "SetLastError", win32_ignore},
```

The reference tracks a real per-run `last_error` and its shims set it (`ERROR_INVALID_HANDLE` at
`kernel32.c:700`, `win32_set_last_error(203)` at `kernel32.c:292`,
`SHIM(kernel32, GetLastError) { stdcall_ret(c, last_error, 0); }` at `kernel32.c:268`). So this is a
**deviation from the reference**, not a shared simplification: after any failed call the guest that
checks `GetLastError()` is told `ERROR_SUCCESS`. The deviation is known to the project
(`reports/igi-recomp-reuse.md:464`) but is not stated in the code.

### F22 `[b]` `SetStdHandle` reports success and redirects nothing

```
runtime/recomp_runtime.cpp:419-422
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  set_import_result(context, 1);
```

The reference does the same (`kernel32.c:306`), so it is deliberate — but no comment says so, and a
guest that redirects stdout to a file for logging is told it worked while its output keeps going to
the console. This is the "flush that does not flush" pattern, undocumented, and the contrast with
the *documented* `FlushFileBuffers` (F-a1) is the point.

### F23 `[c]` `CloseHandle` returns TRUE for a handle that does not exist

```
runtime/recomp_runtime.cpp:415-417
  guest_handle_close(import_argument(context, 0));
  set_import_result(context, 1);
```

`guest_handle_close` (line 187-193) returns early for an unknown handle or a standard handle, and
the shim reports success either way. The reference also returns 1 unconditionally
(`kernel32.c:278-282`), so this is faithful — but `guest_handle_close` additionally **never closes
the three standard handles** and nothing documents that (the handle-table comment at 138-143
describes the values, not the close policy). Double-close and bogus-close both look like success.

### F24 `[b]` `GetStdHandle` fabricates a handle for an unrecognised request

```
runtime/recomp_runtime.cpp:266   set_import_result(context, which == -10 ? 10 : which == -12 ? 12 : 11);
```

`GetStdHandle(anything else)` — including a garbage value — returns 11 (stdout) instead of
`INVALID_HANDLE_VALUE`. The reference range-checks and returns `INVALID_HANDLE_VALUE` otherwise
(`kernel32.c:297-304`). A guest that validates its handle is told a bogus request succeeded, and by
F11 the subsequent `WriteFile` really does write to stdout.

### F25 `[c]` `_getch`/`_kbhit` invent console input

```
runtime/recomp_runtime.cpp:1871   {"msvcrt.dll", "_getch", msvcrt_noop},
runtime/recomp_runtime.cpp:1872   {"msvcrt.dll", "_kbhit", msvcrt_noop},
```

Both return 0. `_kbhit() == 0` means "no key waiting" forever, and `_getch() == 0` returns a NUL
character that was never typed. A "press any key" loop spins forever; a menu that reads a key acts
on a fabricated NUL. No comment; there is no reference implementation of these (igi-recomp ships no
msvcrt shim file at all).

### F26 `[c]` Unchecked Unicorn writes/reads in the reference harness

```
core/verification/differential_harness.cpp:124    uc_reg_write(engine, register_id, &value);
core/verification/differential_harness.cpp:132    uc_reg_write(engine, register_id, &value);
core/verification/differential_harness.cpp:119    uc_reg_read(engine, register_id, &value);
core/verification/differential_harness.cpp:200    uc_mem_read(engine, stack_pointer, &return_address, static_cast<std::size_t>(state.pointer_width));
```

The file already knows this failure mode and has a checked helper for it — `write_register_checked`
with the comment *"an unchecked write would surface later as a baffling unmapped-read divergence
instead of the real cause"* (lines 127-136) — but it is used only for `FS_BASE` (line 358). The
generic `write_register` (used by `sync_context_to_engine`, lines 169-173, and by `emulate_shim`,
lines 203-204) and the `uc_mem_read` that fetches the return address are unchecked. If the read
fails, `return_address` stays 0 and the reference jumps to address 0 — which is then reported as a
*candidate/reference divergence*, i.e. a harness failure is attributed to the translated code.
This is the one place where the verification machinery can manufacture a result instead of
measuring one; severity medium because `uc_mem_read` on a mapped stack is expected to succeed.

### F27 `[c]` A failed trace open silently disables tracing

```
runtime/recomp_runtime.cpp:2350-2353
  if (const char* trace_path = std::getenv("RECOMP_TRACE")) {
    guest_trace_stream = std::fopen(trace_path, "wb");
    guest_tracing_enabled = guest_trace_stream != nullptr;
  }
```

`RECOMP_TRACE` set but unwritable ⇒ no trace, no error, and `compare_execution_traces` reads an
empty `candidate.trace` and compares it against the reference (all sizes equal ⇒ no divergence
reported). Same class as F1b: a measurement that did not happen reads as a measurement that agreed.

### F28 `[c]` A find-handle exhaustion is not reported, contrary to the code's own comment

```
runtime/recomp_runtime.cpp:184     return 0;  // exhausted; the shim reports the failure
runtime/recomp_runtime.cpp:1335-1337
  const auto handle = guest_handle_new(kGuestHandleFind);
  guest_finds[handle] = std::move(state);
  set_import_result(context, handle);
```

`FindFirstFileA` does not check for 0: it stores the state under key 0 and returns 0 as the find
handle. 0 is not `INVALID_HANDLE_VALUE` (`0xFFFFFFFF`, which the same function does return on a
directory error, line 1328), so the guest sees a "handle" that is neither valid nor the documented
failure value. The comment at 184 asserts a caller contract that this caller does not honour.

### F29 `[c]` A failed `file_size` becomes a 0-byte file in `WIN32_FIND_DATAA`

```
runtime/recomp_runtime.cpp:1301-1303
  std::error_code error;
  const auto measured = std::filesystem::file_size(std::filesystem::path(directory) / name, error);
  if (!error) size = measured;
```

On error the search result reports size 0 rather than failing or reporting unknown; nothing tells the
guest the measurement did not happen.

### F30 `[c]` A heap-exhaustion failure inside `std::string` assignment is invisible

```
runtime/recomp_runtime.cpp:751-752
  const auto block = heap_allocate(text.size() + 1);
  if (block == 0) { set_import_result(context, 0); return; }
```

The caller (`cxx_string_construct_from_c`, line 776) then does `set_import_result(context, object)`,
overwriting the failure with success. The string object is left untouched — for a *constructor*, that
means an uninitialised object returned as if constructed. Reachable only under heap exhaustion, hence
medium rather than high.

---

## LOW

### F31 `[b]` `GetProcessHeap` and `HeapCreate` return the same invented handle

```
runtime/recomp_runtime.cpp:431   void win32_get_process_heap(GuestContext* context) { set_import_result(context, 0x1000); }
runtime/recomp_runtime.cpp:432   void win32_heap_create(GuestContext* context) { set_import_result(context, 0x1000); }
```

A private heap is indistinguishable from the process heap, and `HeapAlloc` ignores its handle
argument entirely (line 462 reads only argument 2), so `HeapCreate`+`HeapDestroy` isolation is
fiction. The reference allocates a real handle (`kernel32.c:321`).

### F32 `[b]` `CreateMutexA` returns a synthetic handle with no mutex behind it

```
runtime/recomp_runtime.cpp:428   set_import_result(context, guest_handle_new(kGuestHandleMutex));
```

Nothing in the runtime ever waits on, owns or releases a mutex; `ReleaseMutex` returns 1 regardless
(F33). A guest that uses a named mutex for single-instance detection is told it created one. Faithful
to the reference (`kernel32.c:270-276`), but undocumented here.

### F33 `[b]` The free/destroy family reports success unconditionally

```
runtime/recomp_runtime.cpp:358    void win32_virtual_free(GuestContext* context) { set_import_result(context, 1); }
runtime/recomp_runtime.cpp:496    set_import_result(context, 1);          // HeapFree
runtime/recomp_runtime.cpp:1895   {"kernel32.dll", "HeapDestroy", win32_one},
runtime/recomp_runtime.cpp:1933   {"kernel32.dll", "FreeLibrary", win32_one},
runtime/recomp_runtime.cpp:381    set_import_result(context, 1);          // ReleaseMutex
```

`HeapFree` returns TRUE even when `heap_release` (line 466-492) rejected the pointer as out of range;
`VirtualFree` frees nothing (the reference decommits/releases, `kernel32.c:393-407`); `HeapDestroy`
destroys nothing and the guest keeps allocating from the "destroyed" heap. Low because the failure
mode is a leak rather than a wrong value, but none is documented.

### F34 `[b]` `GetModuleFileNameA` returns failure and leaves the buffer untouched

```
runtime/recomp_runtime.cpp:1730   {"kernel32.dll", "GetModuleFileNameA", win32_zero},
```

Returning 0 is an honest failure code (the guest can detect it) — the least-bad option — but the
reference fills the real path (`kernel32.c:175-186`), and nothing in the code says the module path is
unavailable. A program that derives a data directory from its own path gets nothing.

### F35 `[b]` Code-page shims are internally inconsistent

```
runtime/recomp_runtime.cpp:315   void win32_code_page(GuestContext* context) { set_import_result(context, 65001); }
runtime/recomp_runtime.cpp:403   store_guest_memory(context, info, 1, 4);          // MaxCharSize
```

`GetACP`/`GetOEMCP`/`GetConsoleOutputCP` all claim 65001 (UTF-8), while `GetCPInfo` describes that
code page as single-byte (`MaxCharSize = 1`) — UTF-8's `MaxCharSize` is 4. A guest sizing a
conversion buffer from `GetCPInfo` under-allocates. Also `GetConsoleOutputCP` claiming UTF-8 while
the runtime writes raw bytes to fd 1 is a claim it does not implement.

### F36 `[b]` `GetDriveTypeA` guesses from one character

```
runtime/recomp_runtime.cpp:1649-1651
  const auto letter = static_cast<char>(load_guest_memory(context, root, 1));
  if (letter == 'C' || letter == 'c') type = 3;  // DRIVE_FIXED
```

Every other drive is `DRIVE_NO_ROOT_DIR` (1). The reference also maps only `C` and the CD drive but
treats a null root as fixed (`kernel32.c:799-813`). A guest that probes `D:\` for its data directory
is told the drive does not exist.

### F37 `[b]` `GetTickCount64` is the 32-bit shim

```
runtime/recomp_runtime.cpp:504    set_import_result(context, static_cast<std::uint32_t>(milliseconds));
runtime/recomp_runtime.cpp:1898   {"kernel32.dll", "GetTickCount64", win32_get_tick_count},
```

The value is truncated to 32 bits for both entry points, so the 64-bit API wraps every 49.7 days and
its whole reason for existing is not honoured. Low in practice (short runs), but the binding asserts
something the shim does not do.

### F38 `[c]` `mbstowcs` writes a NUL word at the destination when asked to measure

```
runtime/recomp_runtime.cpp:1231-1232
  if (maximum == 0 || written < maximum) {
    store_guest_memory(context, destination + written * 2, 0, 2);
```

`mbstowcs(NULL, src, 0)` is the measure-only form; here `destination` is 0 and the code writes a
16-bit zero at guest address 0 (the low page is deliberately zeroed, so the effect is benign today).
The width written is right; the write should not happen at all.

### F39 `[c]` `strchr(s, 0)` returns NULL instead of the terminator

```
runtime/recomp_runtime.cpp:1144-1148
  const auto found = text.find(character);
  set_import_result(context, found == std::string::npos ? 0 : import_argument(context, 0) + found);
```

`strchr(s, '\0')` must return a pointer to the terminating NUL. `std::string::find('\0')` finds a
NUL only if one is stored, and `read_guest_string` strips it, so the answer is always NULL. Same
shape in `strrchr` (line 1153). Low impact, unambiguous bug.

### F40 `[c]` The IAT slot width falls back to 8 bytes

```
runtime/recomp_runtime.cpp:2384-2385
  store_guest_memory(nullptr, image->image_base + imported.import_address_table_rva, thunk_address,
                     imported.slot_size != 0 ? static_cast<int>(imported.slot_size) : 8);
```

`GuestImportDescriptor::slot_size` is **never assigned anywhere in the source** (`grep -rn slot_size
core tools apps runtime` → only the declaration at `recomp_runtime.hpp:1717` and this read); the code
generator always emits `(is_64_bit ? 8 : 4)` (`core/codegen/project_generator.cpp:84`), so today the
fallback is unreachable. It is still the wrong default: a hand-built or older image with a zeroed
field would get an 8-byte store into a 4-byte PE32 IAT slot, and the "0 means unknown" encoding hides
the distinction the comment at 67-70 says must be respected. Report as a latent defect, not an
active one.

### F41 `[b]` `GetStartupInfoA` does not set `cb`

```
runtime/recomp_runtime.cpp:526   if (out != 0 && out + 68 <= guest_memory_size) std::memset(guest_memory + out, 0, 68);
```

`STARTUPINFOA.cb` must be `sizeof(STARTUPINFOA)`; the reference sets it (`WR32(p, 68)`,
`kernel32.c:140`). A guest that checks `cb` sees an invalid structure.

### F42 `[b]` `SetHandleCount` echoes its argument

```
runtime/recomp_runtime.cpp:377   set_import_result(context, import_argument(context, 0));
```

Faithful to the reference (`kernel32.c:293`), undocumented here, and it means "success" for any
request, including counts the runtime cannot provide.

### F43 `[b]` `__acrt_iob_func` accepts any index

```
runtime/recomp_runtime.cpp:1508   set_import_result(context, msvcrt_iob + (import_argument(context, 0) & 0xffu) * kMsvcrtFileObjectBytes);
```

The address is computed for index 255 as happily as for index 2, yielding a `FILE*` past the three
modelled objects into unrelated CRT data. Low: the CRT only asks for 0..2.

### F44 `[b]` `TerminateProcess` ignores its argument and the checkpoints

```
runtime/recomp_runtime.cpp:300-303
  (void)context;
  std::fflush(stdout);
  std::exit(1);
```

The exit code argument is discarded in favour of a constant 1, the process handle is ignored, and
(unlike `guest_request_exit`) the requested checkpoint file is never written — which feeds F1's
zero-checkpoint path. Undocumented.

### F45 `[b]` The `flush` argument of `cxx_ostream_write` is dead

```
runtime/recomp_runtime.cpp:833-836
  void cxx_ostream_write(GuestContext* context, std::uint64_t object, const std::string& text, bool flush) {
    ...
    (void)flush;
```

Always called with `false`, so `std::endl`'s flush is a no-op. Benign (guest output goes straight to
the descriptor with no buffering), but a parameter that promises behaviour it never performs is
exactly the pattern this audit is looking for.

---

## Deliberate and documented — reported as OK `[a]`

| # | Location | The comment that documents it |
| --- | --- | --- |
| a1 | `recomp_runtime.cpp:383-388` `win32_flush_file_buffers` | *"Deliberately reports success without flushing, as igi-recomp does; the reference has to take the same branch or the traces diverge."* |
| a2 | `recomp_runtime.cpp:326-356` `VirtualProtect`/`VirtualQuery` | *"The guest address space is one flat region that is always readable, writable and executable, so every protection change already holds."* |
| a3 | `recomp_runtime.cpp:1244-1252` console + `Beep` | *"A recompiled port has no Windows console, so the console calls succeed without drawing anything… Beep is silent for the same reason."* |
| a4 | `recomp_runtime.cpp:1618-1626` `CoInitialize`/`CoUninitialize` | *"COM apartment initialisation is a no-op in a single-process port: S_OK, and nothing to unwind."* |
| a5 | `recomp_runtime.cpp:365-375` `GetVersionExA` | *"The values are igi-recomp's, kept identical so the two sides of a differential comparison observe the same thing."* |
| a6 | `recomp_runtime.cpp:1372-1377` `signal` | *"the guest gets SIG_ERR … rather than a success that would imply one was registered."* |
| a7 | `recomp_runtime.cpp:1546-1552` `_Unwind_SjLj_Register/Unregister` | *"The registration calls are pure bookkeeping and have no observable effect here; actually resuming an unwind is not implemented and fails loudly."* |
| a8 | `recomp_runtime.cpp:937-944`, `1588-1595` exception traps | *"a propagating exception fails loudly rather than being silently swallowed."* |
| a9 | `recomp_runtime.cpp:1495` `_initterm` | an initialiser that was not recovered terminates with a named diagnostic. |
| a10 | `recomp_runtime.cpp:1691-1699` `GetProcAddress` | the NULL-for-unknown rationale: *"programs probe for optional symbols precisely because that is allowed."* |
| a11 | `recomp_runtime.cpp:456-458` heap exhaustion | *"Returning null is what the real API does, and the guest is entitled to see it rather than being handed a wild pointer."* |
| a12 | `recomp_runtime.cpp:1639-1644` `OutputDebugStringA` | *"The text goes to the debugger, not to standard output, so it is not part of what a differential comparison observes."* |
| a13 | `recomp_runtime.cpp:138-143` handle table | the standard-handle values (10/11/12) and why the table does not change what a comparison can observe. |
| a14 | `recomp_runtime.cpp:696-710` stream model | *"The stream objects are opaque here: their state is held host-side and keyed by the object's guest address."* |
| a15 | `core/verification/differential_harness.cpp:127-136` `write_register_checked` | *"an unchecked write would surface later as a baffling unmapped-read divergence instead of the real cause."* (Documented — but see F26: the helper is applied in only one place.) |

Also `[a]`, in the lifter: unknown instructions fail closed via `LiftError` →
`recomp_unsupported` (lines 469-471, 1801; 1782 at the audited hash), the VEX table only maps
mnemonics whose SSE form is
implemented (*"deliberately absent, so it still fails closed rather than being silently
mistranslated"*, lines 129-131), and `nop`/`endbr`/`pause`/`wait` emit nothing because they have no
architectural effect. The `stub_function` knob is documented as a knob (F9) — only its fabricated
return value and its invisibility to `verify` are findings.

---

## Where I am not sure, and what would settle it

1. **F8 `_pctype` reachability.** The table is definitely all zeros. Whether any guest *reads* it
   depends on whether the compiler inlined a table lookup instead of calling `isdigit`. Settle by
   grepping the guest image for a load from `_pctype` (or by running a fixture that calls
   `isdigit`/`isalpha` through the CRT and comparing against the reference).
2. **F9 stub semantics.** I cannot tell from the code whether `registers[4] += 8` was chosen for the
   32-bit fixtures only, or is believed to be correct for PE32+ as well. Settle by checking whether
   `stub_function` is ever combined with a 64-bit input (the config parser at
   `core/common/configuration.cpp:79` has no bitness guard).
3. **F13 `GetVersion`.** The encoding argument is unambiguous; whether any guest branches on it is
   not. Settle with a reference trace of `GetVersion` call sites.
4. **F15 VirtualAlloc/heap aliasing.** The two allocators provably start at the same base. Whether a
   given guest uses both is unknown to me; the IGI target does import `VirtualAlloc`
   (`runtime/win32_abi.hpp:59`). Settle by running a fixture that interleaves `VirtualAlloc` and
   `malloc` and checking for corruption, or by reading the guest's allocation sites.
5. **F23 CloseHandle.** The reference is equally permissive, so this may be intentional fidelity
   rather than an oversight. I report it as `[c]` on the narrower ground that `guest_handle_close`
   silently ignores an unknown handle *and* never closes the standard handles, and no comment says
   either.
6. **F1 reachability.** The bypass is real in the code; I did not reproduce it end-to-end (read-only
   task, and it needs a run with an unwritable checkpoint path). Settle by pointing `RECOMP_CHECKPOINT`
   at a non-existent directory and confirming `verify` still prints `PASS` with
   `checkpoints_compared: 0`.

---

## Top 5 to fix first

1. **F1 + F1b — `verified()` passes with zero checkpoints compared.**
   `core/verification/differential_harness.hpp:59` `if (checkpoints_compared == 0) return true;`
   with the enabling swallow at `runtime/recomp_runtime.cpp:2267` `if (file == nullptr) return;`.
   A verification verdict can be issued without the state comparison that is the whole point of the
   harness — a fabricated result by the project's own definition.
2. **F2 — `WriteFile` fabricates the byte count and always returns TRUE.**
   `runtime/recomp_runtime.cpp:278` `const auto count = static_cast<ssize_t>(length - written);`.
   Output loss is invisible; the reference records the real count, so this is a bug, not a port.
3. **F3 + F4 — `fwrite` reports items written and `write_guest_output` throws the host result away.**
   `runtime/recomp_runtime.cpp:1087` `set_import_result(context, count);` and `:2309`
   `(void)::write(descriptor, data, size);`. The second is the root cause of the first and of F2;
   fixing the helper fixes the class.
4. **F9 — the `stub_function` stub returns a fabricated 0 in EAX and is invisible to `verify`.**
   `core/semantics/x86_64_lifter.cpp:1792` `context->registers[4] += 8; context->registers[0] = 0;`
   (1773 at the audited hash).
   A user-requested stub currently makes a build that skips real work look like a verified port;
   the design spec forbids exactly this.
5. **F6 — `atexit`/`_crt_atexit`/`_cexit` report success while exit handlers never run.**
   `runtime/recomp_runtime.cpp:1868` `{"msvcrt.dll", "atexit", msvcrt_noop},` with `msvcrt_noop`
   returning 0 (`:1203`). The guest is told its cleanup is registered and gets silent data loss at
   exit — and it is the only member of the flush/close/exit family here without the comment that
   makes `FlushFileBuffers` acceptable.

*Runner-up worth a line in the same change: F8's zeroed `_pctype`/`errno` block, because it hands
the guest a table and a variable that were never written.*
