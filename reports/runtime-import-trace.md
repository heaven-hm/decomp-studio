# Runtime import trace: what actually stops `imgview64.exe` and `igi.exe`

**Task:** task-10. **Write scope:** this file only. No code, test or other report was modified.
**Tool:** `recomp-studio 0.4.0` (`/Users/haseeb-mir/Documents/Code/recomp-studio/build/recomp-studio`).
**Host:** macOS arm64. **Unicorn:** 2.1.4 (`brew list --versions unicorn` → `unicorn 2.1.4`).

Every claim below is attached to a command I ran, quoted verbatim with its output. Anything I did
not run is marked **not verified**.

---

## 1. Headline

Two things were assumed going in, and both are wrong:

1. **The `recomp: unimplemented Win32 import <library>!<symbol>` message is not the first thing the
   program prints about imports.** The runtime prints a **complete, static list of every unshimmed
   import at startup**, before executing a single guest instruction
   (`runtime/recomp_runtime.cpp:732-755`). That banner is *not* call-order information — it is the
   static import table, ranked by nothing. The call-order message is a *second*, separate line
   (`runtime/recomp_runtime.cpp:686`) that only appears if the program actually reaches an
   unshimmed import.

2. **`imgview64.exe` never reaches any import at all.** It is **UPX-packed**, and the section that
   holds the real unpacked code has **zero bytes in the file**. It dies inside the UPX unpacker on
   an indirect call. Its "first unshimmed import" does not exist, and cannot be made to exist by any
   amount of shim work.

Measured answers:

| Program | First unshimmed import actually called | What actually kills it | Structural? |
|---|---|---|---|
| `imgview64.exe` | **none — never reaches an import** | `indirect call to unmapped guest address 0x14000a170 (ip=0x14000a1e2)` | **Yes** — UPX-packed, `UPX0` has `rawsize = 0` |
| `igi.exe` | **`kernel32.dll!GetVersionExA` at `ip=0x4a665e`** | the above; exit 3 | No — but 97 shims + a reference-harness fix needed |

And the second data point the task asked for turned up a third, independent blocker: **the Unicorn
reference cannot execute `igi.exe` past its 6th instruction**, because on Unicorn 2.1.4 a
`UC_X86_REG_FS_BASE` write in 32-bit mode is a **silent no-op**. Proven with an isolated probe in §5.

---

## 2. Method

The two projects already existed from a prior task, so no re-translation was needed for the
measurements:

* `imgview64.exe` → `/tmp/ar-imgview` (translated **and built**; `recomp-guest`, 9 408 320 bytes,
  built 07:14).
* `igi.exe` → `/tmp/gapcensus-translate/igi.exe` (translated only). I built it:

```
$ ./build/recomp-studio build /tmp/gapcensus-translate/igi.exe
built /tmp/gapcensus-translate/igi.exe/recomp-guest
BUILD_EXIT=0
```

Trace capture uses the runtime's own `RECOMP_TRACE` facility, which writes every executed guest
address as a little-endian `uint64_t` (`runtime/recomp_runtime.cpp:27-29`, enabled at `:712-715`).
Import thunks are host bridges and never appear in the trace
(`core/verification/differential_harness.cpp:197-199`), so import calls are identified by
disassembling the call sites in the trace.

---

## 3. `imgview64.exe` — UPX-packed; the first import does not exist

### 3.1 Verbatim run

```
$ cd /tmp/ar-imgview && ./recomp-guest
EXIT=3
stdout: 0 bytes
stderr:
recomp: 3/11 imports implemented; UNSUPPORTED: comctl32.dll!InitCommonControlsEx gdi32.dll!DeleteDC gdiplus.dll!GdiplusStartup kernel32.dll!VirtualProtect ole32.dll!CoTaskMemFree shell32.dll!#25 shlwapi.dll!#12 user32.dll!GetDC
recomp: indirect call to unmapped guest address 0x14000a170 (ip=0x14000a1e2)
```

Note what is **not** there: no `unimplemented Win32 import ...` line. The first line is the startup
banner listing all 8 unshimmed imports (`runtime/recomp_runtime.cpp:732-755`); the second line is the
real failure, and it is a **lift/discovery** failure, not an import failure.

### 3.2 The binary is UPX-packed

```
$ r2 -q -c "iS" /Users/haseeb-mir/Downloads/recomp-apps/imgview64.exe
nth paddr         size vaddr         vsize perm flags      type name
0   0x00000400     0x0 0x140001000  0x7000 -rwx 0xe0000080 ---- UPX0
1   0x00000400  0x2400 0x140008000  0x3000 -rwx 0xe0000040 ---- UPX1
2   0x00002800   0x600 0x14000b000  0x1000 -rw- 0xc0000040 ---- .rsrc

$ r2 -q -c "izz~UPX" /Users/haseeb-mir/Downloads/recomp-apps/imgview64.exe
7   0x000003e0 0x000003e0  6   7            ascii   UPX!\r$
```

`UPX0` — the section the unpacker decompresses **into** — has `rawsize = 0x0`. Confirmed at the byte
level:

```
$ python3 -c "import pefile; pe=pefile.PE('.../imgview64.exe');
  [print(s.Name.rstrip(b'\x00').decode(), hex(s.SizeOfRawData), len(s.get_data())) for s in pe.sections]"
UPX0 0x0 0
UPX1 0x2400 9216
.rsrc 0x600 1536
```

`UPX0` yields **0 raw bytes**. The 0x7000-byte region is zero-filled in memory and **the real code is
not in the file**.

### 3.3 The recompiler translated the zero padding as code

The entry region is the classic UPX stub (r2, `pd` at `0x14000a150`):

```
0x14000a154  488d35a5de..  lea rsi, section.UPX1
0x14000a16b  e850000000    call 0x14000a1c0
0x14000a170  01db          add ebx, ebx        <-- never executed
...
0x14000a1c0  fc            cld
0x14000a1c1  415b          pop r11             <-- recovers 0x14000a170
...
0x14000a1e2  41ffd3        call r11            <-- dies here
```

The trace shows what the candidate actually executed:

```
$ RECOMP_TRACE=/tmp/t10-imgview.trace ./recomp-guest
EXIT=3
guest instructions executed before death: 19913
first 5: ['0x140003284', '0x140003286', '0x140003288', '0x14000328a', '0x14000328c']
last 5 : ['0x14000a1cf', '0x14000a1d1', '0x14000a1dd', '0x14000a1df', '0x14000a1e2']
trace by section: {'UPX0': 19836, 'UPX1': 77}
0x14000a150 in trace: yes at index 9920
0x14000a170 in trace: NO
```

Two things stand out:

* **19836 of 19913 executed instructions are inside `UPX0`** — the section with no bytes in the file.
  The addresses are **2 bytes apart** (`0x140003284`, `0x140003286`, `0x140003288`, …), which is
  exactly what you get decoding `00 00` (`add byte [eax], al`) repeatedly. The lifter dutifully
  translated the zero padding as code — `guest.cpp` contains 30299 `trace_instruction` lines, one per
  lifted instruction, including `0x140003284`, `0x140003286`, …
* **`0x14000a170` was never executed and is not a recovered function.** The tool recovered three
  "functions" (`functions` command: `0x14000a150 instructions=10120`, `0x14000a182
  instructions=10101`, `0x14000a1c0 instructions=10078`) — none of them `0x14000a170`.

### 3.4 Why it dies, precisely

`call r11` at `0x14000a1e2` targets `0x14000a170` — a **return address** recovered by the
`call`/`pop` idiom, i.e. a **mid-function address**, not a function entry. The runtime's indirect
dispatch only knows function entries and import thunks
(`runtime/recomp_runtime.cpp:653-668` → `lookup_guest_function`, then `lookup_import_thunk`, then
`terminate_with_message("indirect call to unmapped guest address ...")`). `0x14000a170` is neither,
so it aborts.

It is **not** an IAT slot — the IAT slots are at `0x14000b2xx`:

```
$ python3 -c "import pefile; ... print slots"
COMCTL32.dll InitCommonControlsEx slot=0x14000b298
KERNEL32.DLL LoadLibraryA          slot=0x14000b2c8
USER32.dll   GetDC                 slot=0x14000b320
target 0x14000a170 -> RVA 0xa170   inside section UPX1 (RVA 0x8000..0xb000)
```

### 3.5 Verdict for `imgview64.exe`

**There is no "first unshimmed import" to report, and no shim work can change that.**

Even if the dispatch granularity were fixed (make `invoke_guest_indirect` able to target any known
intra-function address, not just function entries), the program would then run the UPX decompressor
to completion, write the real code into `UPX0`, and jump into it — at which point the host binary
would execute its translation of **zeros**, because that is all the file contains for that region.

`imgview64.exe` must be **unpacked before translation**. This is a pipeline prerequisite, not a
runtime capability.

For completeness, the Unicorn reference gets further because Unicorn is a real emulator with
writable, executable code memory — it can genuinely unpack:

```
$ ./build/recomp-studio verify /tmp/ar-imgview
executed instructions (reference): 369198
reference completed: no
VERIFY: FAIL
reference execution did not complete: reference does not model kernel32.dll!LoadLibraryA
```

369 198 reference instructions vs. 19 913 candidate instructions: the reference unpacked and ran the
real program until it hit an import it does not model. The static recompiler cannot follow.

---

## 4. `igi.exe` — a real, measurable first blocker

### 4.1 The binary is not packed and lifts completely

```
$ ./build/recomp-studio inspect /Users/haseeb-mir/Downloads/IGI/igi.exe
format:      PE32 (x86)
entry point: 0x000a50f5
image base:  0x000400000
sections:    4
imports:     128

$ r2 -q -c "iS" /Users/haseeb-mir/Downloads/IGI/igi.exe
0   0x00001000  0x132000 0x00401000  0x132000 -r-x  .text
1   0x00133000    0x3000 0x00533000    0x3000 -r--  .rdata
2   0x00136000   0x1a000 0x00536000  0x6fd000 -rw-  .data
3   0x00150000    0x2000 0x00c33000    0x2000 -r--  .rsrc
(no UPX/ASPack/PECompact/Themida/VMProtect strings)

$ ./build/recomp-studio coverage /Users/haseeb-mir/Downloads/IGI/igi.exe
functions:      971
instructions:   51518
lifted:         51518 (100.00%)
unsupported:    0
coverage:       complete — every recovered instruction lifts
```

So `igi.exe` is a clean, fully-lifted PE32 — the opposite of `imgview64.exe`.

### 4.2 Verbatim run — the measured first blocker

```
$ cd /tmp/gapcensus-translate/igi.exe && ./recomp-guest
EXIT=3
stdout: 0 bytes
stderr (2 lines):
recomp: 31/128 imports implemented; UNSUPPORTED: kernel32.dll!FreeEnvironmentStringsW ... (97 symbols) ... msvfw32.dll!ICDecompress
recomp: unimplemented Win32 import kernel32.dll!GetVersionExA (ip=0x4a665e)
```

**The first unshimmed import actually called is `kernel32.dll!GetVersionExA`, at guest IP
`0x4a665e`.** This is the answer the task asked for, and it is a measurement, not an inference.

### 4.3 The call order before death

```
$ RECOMP_TRACE=/tmp/t10-igi.trace ./recomp-guest
EXIT=3
entries: 65
  0  0x004a50f5   entry
  ...
  5  0x004a5104   mov eax, dword fs:[0]
  ...
 28  0x004a6787
 34  0x004a6798   call dword [HeapCreate]
 35  0x004a679e   <- returned
 38  0x004a67a7   call 0x4a663f
 39  0x004a663f
 ...
 64  0x004a665e   call dword [GetVersionExA]   <- dies
```

Disassembling the call sites confirms which imports those are:

```
$ r2 -q -c "e asm.bits=32; pd 14 @ 0x4a6780" .../igi.exe
0x004a6798  ff1584305300  call dword [sym.imp.KERNEL32.dll_HeapCreate]
0x004a67a7  e893feffff    call 0x4a663f

$ r2 -q -c "e asm.bits=32; pd 20 @ 0x4a6630" .../igi.exe
0x004a665e  ff1508315300  call dword [sym.imp.KERNEL32.dll_GetVersionExA]
```

So the **measured import call sequence before death is exactly two entries**:

| # | Import | Call site | Outcome |
|---|---|---|---|
| 1 | `kernel32.dll!HeapCreate` | `0x4a6798` | **shimmed** — returns, execution continues to `0x4a679e` |
| 2 | `kernel32.dll!GetVersionExA` | `0x4a665e` | **not shimmed** — `terminate_with_message`, exit 3 |

The candidate also handled `mov eax, dword fs:[0]` at `0x4a5104` correctly, because the runtime models
`fs_base` as a `GuestContext` field (`runtime/recomp_runtime.hpp:40-41`) — worth noting, because it is
the exact instruction that kills the Unicorn reference (§5).

### 4.4 The one-symbol limit, stated plainly

**A single run reveals exactly one unshimmed import, and no more.** The program terminates at the
first one, so there is no way to observe symbol *N+1* from one execution. I observed exactly two
import calls in total, and only one of them is a blocker.

To reveal the next symbol you must make `GetVersionExA` succeed and re-run. Two routes exist, and
**both are code changes, which are outside my write scope**:

1. **Add a shim to the runtime.** `find_win32_shim` walks a single static table, `kShims`
   (`runtime/recomp_runtime.cpp:468-474`), and there is **no registration hook** — no
   `register_win32_shim`, no config key, nothing reachable from `recomp-config.toml`. So the only way
   is to edit `runtime/recomp_runtime.cpp`. From `igi-recomp` this is a 9-line function (§7).
2. **Override the guest wrapper with `native_override`.** This *is* reachable from configuration
   (`core/common/configuration.cpp:92-97`, wired at `core/pipeline.cpp:110` and
   `core/semantics/x86_64_lifter.cpp:1413-1416`), and needs no repo change — but it replaces the
   guest function at `0x4a663f`, so I would have to reimplement its ABI (prologue, `_chkstk` call,
   epilogue) by hand. Any sequence it produced would reflect **my stub's behaviour**, not the real
   program's, and would take a different path.

I did **not** do either. **I therefore cannot report the sequence beyond `GetVersionExA`, and I am
not going to construct one.** What is needed is the loop: *shim → rebuild → re-run*, one symbol per
iteration, ~2 minutes per igi iteration (the `build` step above). The honest characterisation is that
the remaining order is **unmeasured**, and the igi-recomp shim set (§7) is the best available proxy
for *which* imports matter — not for *when*.

---

## 5. Second data point: the Unicorn reference — and its own blocker

### 5.1 Verbatim

```
$ ./build/recomp-studio verify /tmp/gapcensus-translate/igi.exe
executed instructions (reference): 6
reference completed: no
reference output: 0 bytes
VERIFY: FAIL
reference execution did not complete: unicorn: Invalid memory read (UC_ERR_READ_UNMAPPED)

$ ./build/recomp-studio verify /tmp/ar-imgview
executed instructions (reference): 369198
VERIFY: FAIL
reference execution did not complete: reference does not model kernel32.dll!LoadLibraryA
```

For `igi.exe` the reference dies after **6 instructions**. Those 6 instructions are:

```
$ r2 -q -c "e asm.bits=32; pd 12 @ 0x4a50f5" .../igi.exe
0x004a50f5  push ebp
0x004a50f6  mov ebp, esp
0x004a50f8  push 0xffffffffffffffff
0x004a50fa  push 0x534308
0x004a50ff  push 0x4a67ec
0x004a5104  mov eax, dword fs:[0]     <-- instruction 6
```

`fs:[0]` is the SEH chain head. The reference sets up a TEB and writes `FS_BASE`
(`core/verification/differential_harness.cpp:239,274`), so this *should* work. It does not.

### 5.2 Root cause, proven with an isolated probe

I wrote a standalone probe in `/tmp` that does exactly what the harness does — map a TEB at
`0x7ffd0000`, write `UC_X86_REG_FS_BASE`, execute `mov eax, dword ptr fs:[0]` — plus a control that
reads the same address absolutely (`/tmp/t10-fs-probe.c`, compiled with
`clang -o t10-fs-probe t10-fs-probe.c -I/opt/homebrew/include -L/opt/homebrew/lib -lunicorn`):

```
$ ./t10-fs-probe
  uc_open(UC_MODE_32)                            UC_ERR_OK
  uc_mem_map CODE 0x1000                         UC_ERR_OK
  uc_mem_map STACK 0x10000                       UC_ERR_OK
  uc_mem_map TEB 0x2000                          UC_ERR_OK
  uc_reg_write(UC_X86_REG_FS_BASE, 0x7ffd0000)   UC_ERR_OK
  uc_reg_read(UC_X86_REG_FS_BASE)                UC_ERR_OK
  -> FS_BASE readback = 0x0 (expected 0x7ffd0000)  MISMATCH
  uc_emu_start(mov eax, fs:[0])                  Invalid memory read (UC_ERR_READ_UNMAPPED)
  -> EAX = 0x00000000 (expected 0xdeadbeef)  FS SEGMENT BROKEN
  control: uc_emu_start(mov eax, [0x7ffd0000])   UC_ERR_OK
  -> EAX = 0xdeadbeef (expected 0xdeadbeef)  MAPPING IS FINE
RESULT: FS_BASE IS THE PROBLEM (2 failed check(s))

[stderr]
WARNING: Your register accessing on id 250 is deprecated and will get UC_ERR_ARG in the future
release (2.2.0) because the accessing is either no-op or not defined. ...
```

**`uc_reg_write(UC_X86_REG_FS_BASE, ...)` returns `UC_ERR_OK` but does not change the register.**
Unicorn 2.1.4 warns that register id 250 is a no-op; `UC_X86_REG_FS_BASE` is documented in the header
as "Base regs for **x86_64**" (`/opt/homebrew/include/unicorn/x86.h:320`). The 64-bit path *does*
work — the same probe in `UC_MODE_64` (`/tmp/t10-gs64-probe.c`) shows
`GS_BASE readback = 0x164000000 MATCH` and `RAX = 0xdeadbeefcafef00d … 64-BIT GS SEGMENT WORKS`.

The harness never checks the return value of `write_register`
(`core/verification/differential_harness.cpp:111-113` discards it), so the failure is silent.

### 5.3 Consequence

* **`igi.exe` can never pass `verify`** until this is fixed, regardless of shim work: the oracle
  cannot execute 7 instructions of the program.
* **No fixture exercises `fs:`** (`grep -ln "fs:" tests/fixtures/apps/*.c` → no matches), so this was
  invisible to the suite. `pe32_arith` passes `verify` (`executed instructions (reference): 188370 …
  VERIFY: PASS (identical output)`), which is why the 32-bit path *looked* healthy.
* The candidate is **ahead of the reference** for `igi.exe`: 65 guest instructions vs 6.

### 5.4 The reference models 4 symbols; the runtime has 63

```
$ grep -n 'symbol == "' core/verification/differential_harness.cpp
144:  if (symbol == "GetStdHandle") {
147:  } else if (symbol == "WriteFile") {
156:  } else if (symbol == "ReadFile") {
162:  } else if (symbol == "ExitProcess") {
```

Four symbols. The runtime's `kShims` table has **63 entries, every one of them `kernel32.dll`**:

```
$ grep -o '{"[a-zA-Z0-9_]*\.[dD][lL][lL]",' runtime/recomp_runtime.cpp | ... | sort | uniq -c
  63 kernel32.dll
```

So **59 of 63 runtime shims are unmodelled in the reference**, which is exactly what the code comment
at `core/verification/differential_harness.cpp:166-169` says. Everything else stops the reference with
`reference does not model <library>!<symbol>` (`:173`).

**This is the structural cost the task's framing missed: every shim must be written twice** — once in
`runtime/recomp_runtime.cpp` for the candidate, and once in the `emulate_shim` if-else chain for the
oracle. They share no code. A shim that exists only in the runtime moves the candidate forward but
does not move `verify` at all; it just changes which symbol the *reference* stops at.

Also note `compare_execution_traces` returns early when the reference did not complete
(`core/verification/differential_harness.cpp:376-377`, `if (!reference.completed) return comparison;`),
so the trace comparison is **unavailable** for both programs here — the diagnostic the task hoped to
use does not run.

---

## 6. What the runtime already has

`runtime/recomp_runtime.cpp` provides:

* **No handle table.** Only a std-handle→fd mapping: `standard_handle_to_descriptor` (`:122-126`)
  maps 10/11/12 to stdin/stdout/stderr. There is no allocator, no typed handles, no lookup.
* **No file I/O.** `WriteFile`/`ReadFile` go to the std descriptors; there is no `CreateFileA`,
  `SetFilePointer`, `FindFirstFileA` or path translation.
* **No window system, no message pump, no graphics, audio, video or COM.** All 63 shims are
  `kernel32.dll`.
* **A flat guest memory image** with `VirtualAlloc`/`VirtualFree`, and a `GuestContext` carrying
  `fs_base`/`gs_base` (`runtime/recomp_runtime.hpp:40-41`) — which is why the candidate handles
  `fs:[0]` and the Unicorn reference does not.

---

## 7. What each early import needs — measured from `igi-recomp`

I measured cost from `research/upstream/igi-recomp/shim/src/*.c` by extracting each `SHIM(dll, name)`
body and counting its lines, then tagging the shared infrastructure it references. `igi-recomp` is a
**working** recompilation of this exact game, so it is the authoritative reference for what each shim
actually requires.

**Coverage: 96 of the 97 imports `igi.exe` is missing are implemented in `igi-recomp`.**
The only gap is `dsound.dll!#1` (an ordinal-only import, so the symbol name is unavailable).

### 7.1 The shared infrastructure pieces, and their cost

| Piece | Where | Size | Unlocks |
|---|---|---|---|
| **Handle table** | `kernel32.c:34-86` (`HandleObj`, `handle_new`, `handle_get`, `handle_close`) | ~53 lines | 10 file/handle imports |
| **Win32→host path translation** | `kernel32.c:88-117` (`win_path_to_host`) | ~30 lines | `DeleteFileA`, `CreateFileA`, `FindFirstFileA`, `AVIFileOpenA` |
| **Message pump** | `user32.c:50-98` (`user32_post_message`, `send_message`, `get_message`) | ~49 lines | `PeekMessageA`, `GetMessageA`, `DispatchMessageA`, `DestroyWindow` |
| **Window + SDL platform** | `user32.c:118-168` (`CreateWindowExA`, 49 lines) + `platform_sdl.c` (421 lines) | ~470 lines | the 30 `user32.dll` imports, `gdi32` |
| **DirectDraw + render backend** | `ddraw.c` (36 KB), `render_backend.c` (54 KB), `render_gl.c` (117 KB) | ~3 000 lines | `DirectDrawCreateEx`, `ICDecompress` |
| **COM** | `ole32.c` + `com.c` | ~90 lines | `CoCreateInstance` |

### 7.2 The first ten by how much runtime support they need (cheapest first)

Cost is measured lines in `igi-recomp`. "Infra" is what must exist first.

| Rank | Import | Lines | Infra needed | Notes |
|---|---|---|---|---|
| **1** | `kernel32.dll!GetVersionExA` | **9** | **none** | **The measured first blocker.** Fills 5 fields of the guest `OSVERSIONINFOA` and returns 1 (`kernel32.c:121-130`). Cheapest possible real win. |
| 2 | `kernel32.dll!SetHandleCount` | 1 | none | `stdcall_ret(c, ARG(0), 1)` — returns its own argument. |
| 3 | `kernel32.dll!FreeEnvironmentStringsW` | 1 | none | returns 1. |
| 4 | `kernel32.dll!GetEnvironmentStringsW` | 1 | none | returns a pointer to a static wide block. |
| 5 | `kernel32.dll!GetEnvironmentVariableA` | 1 | none | sets last-error 203, returns 0. |
| 6 | `kernel32.dll!ReleaseMutex` | 1 | none | returns 1. |
| 7 | `kernel32.dll!FlushFileBuffers` | 1 | none | returns 1. |
| 8 | `kernel32.dll!CloseHandle` | 4 | **handle table** | `handle_close` (`kernel32.c:278-287`). |
| 9 | `kernel32.dll!CreateMutexA` | 4 | **handle table** | `handle_new(H_MUTEX)` (`:270-275`). |
| 10 | `kernel32.dll!GetFileType` | 9 | **handle table** | `handle_get` (`kernel32.c:308-317`). |

**Ranks 1–7 need nothing at all** — seven of the 97 blockers are pure value returns with zero
infrastructure. **Ranks 8–10 are the first to need the handle table**, the first piece of shared
infrastructure (~53 lines).

The next tiers, for planning: the handle table unlocks 10 imports; path translation (on top of it)
unlocks 4 more; `SetFilePointer` (41 lines) and `CreateFileA` (33 lines) are the two most expensive
kernel32 file shims. Beyond kernel32 the cliff is steep — `CreateWindowExA` (49 lines) drags in the
whole SDL window system, and `ICDecompress` (81 lines) drags in DirectDraw.

**Caveat, stated plainly:** this ranking is by **cost**, which I measured from source. The **order**
in which `igi.exe` reaches these is **unmeasured** beyond rank 1 (see §4.4). Rank 1 is the only row
whose position is a measurement; ranks 2–10 are the cheapest items in the missing set, not a
predicted call order.

---

## 8. Verdict

### 8.1 Can `imgview64.exe` reach `verify` with shim work alone?

**No — and it cannot be reached with shim work plus any other runtime feature either.**

`imgview64.exe` is UPX-packed, `UPX0` has `rawsize = 0`, and the 19 913 instructions the candidate
executed are overwhelmingly (19 836) a translation of **zero padding**. The code the program actually
runs is written into guest memory at runtime by the decompressor and **does not exist in the file**.
Nothing in `runtime/` can change what the host binary was compiled from. This needs a
**pre-translation unpacking step**, which is a pipeline change, not a runtime one.

### 8.2 Can `igi.exe` reach `verify` with shim work alone?

**No.** Three independent blockers, and shim work addresses only the first:

1. **97 missing imports** (§7). Ranks 1–7 are near-free; the full set is a large but bounded job.
2. **Every shim must be written twice** (§5.4). The Unicorn reference models 4 symbols; the runtime
   has 63. `verify` only passes when *both* sides run the program to completion and agree. A shim
   added only to `runtime/recomp_runtime.cpp` moves the candidate forward and leaves `verify` exactly
   where it is. This roughly doubles the cost of blocker 1 and is the single biggest thing the task
   framing did not account for.
3. **The reference cannot execute 32-bit `fs:[0]`** (§5.2). Unicorn 2.1.4's `UC_X86_REG_FS_BASE` write
   is a silent no-op in `UC_MODE_32`. `igi.exe` needs it at instruction 6. Until that is fixed — by
   mapping a segment base another way, or by patching `fs:` accesses the way the runtime does —
   `igi.exe` cannot pass `verify` no matter how many shims exist.

So `igi.exe` needs **a harness fix first, then a shim programme that is written twice**. It is not
"shim work alone".

### 8.3 What is the smallest app that *could* reach `verify`?

The binding constraint is **the reference's 4-symbol model**, not the runtime's 63. An app can verify
today only if its entire import set is a subset of
`{GetStdHandle, WriteFile, ReadFile, ExitProcess}`.

That is precisely what the existing fixtures are. Measured:

```
$ ./build/recomp-studio imports tests/fixtures/apps/bin/arith.exe
imports:        3
implemented:    3 (100.00%)
compatibility:  complete — every import has a shim

$ ./build/recomp-studio verify /tmp/t10-pe32      # pe32_arith, built from tests/fixtures/apps/arith.c
executed instructions (reference): 188370
reference completed: yes
candidate completed: yes
reference output: 172 bytes
candidate output: 172 bytes
VERIFY: PASS (identical output)
```

**The smallest app that can reach `verify` is a console program that writes to stdout and exits —
and the fixtures already are that app.** `arith.exe` (3 imports, 100 % shimmed) verifies PASS today;
`pe32_arith.exe` proves the same holds in 32-bit mode.

**No real-world binary in the corpus qualifies:**

| Binary | Why not |
|---|---|
| `luhn.exe`, `TicTacToe.exe` | .NET — 1 import, `mscoree.dll!_CorExeMain`. Not native code. |
| `tetris/Tetris.exe` | 99 imports, 83 missing; also instruction gaps (`fxrstor`, `fxsave`, `fldenv`). |
| `snake/snake-windows-x86_64.exe` | 152 imports, 140 missing; instruction gaps (`btr`, `xgetbv`, `int`). |
| `imgview64.exe` | UPX-packed (§3). |
| `igi.exe` | 97 missing imports + reference cannot start (§4, §5). |

So the smallest app that could verify is **not a new app at all** — it is the fixture set that
already does. If a *real-world* one is wanted, it must be a console program whose imports are a
subset of the reference's four symbols and which lifts completely; nothing in the current corpus is
that, and finding or building one is the cheapest way to widen `verify` coverage beyond the fixtures.

---

## 9. Explicitly not verified

* **The import call sequence for `igi.exe` beyond `GetVersionExA`.** One run reveals one symbol; the
  next requires a shim or a `native_override`, both of which are code changes outside my write scope
  (§4.4). Not guessed.
* **Which of the 97 missing imports `igi.exe` actually reaches, and in what order.** §7.2 ranks by
  *cost*, measured from `igi-recomp` source; the *order* is unmeasured beyond rank 1.
* **Whether fixing the 32-bit `FS_BASE` no-op is possible on Unicorn 2.1.4 without patching guest
  code.** I proved the write is a no-op; I did **not** find a working alternative API, and I did not
  test a GDT-based approach or a code-patching approach.
* **Whether `imgview64.exe` unpacks cleanly and then lifts.** I did not unpack it. I proved only that
  its `UPX0` section has no bytes in the file and that the candidate executes a translation of zeros.
* **The `native_override` experiment.** I verified the option exists and is wired
  (`core/common/configuration.cpp:92-97`, `core/pipeline.cpp:110`,
  `core/semantics/x86_64_lifter.cpp:1413-1416`) but did **not** run it.
* **`igi-recomp` itself.** I read `shim/src/*.c`; I did not build or run it.

---

## 10. Commands run (for reproduction)

```sh
./build/recomp-studio build /tmp/gapcensus-translate/igi.exe
./build/recomp-studio inspect /Users/haseeb-mir/Downloads/recomp-apps/imgview64.exe
./build/recomp-studio inspect /Users/haseeb-mir/Downloads/IGI/igi.exe
./build/recomp-studio functions /Users/haseeb-mir/Downloads/recomp-apps/imgview64.exe
./build/recomp-studio coverage  /Users/haseeb-mir/Downloads/IGI/igi.exe
./build/recomp-studio imports   /Users/haseeb-mir/Downloads/IGI/igi.exe --json
./build/recomp-studio verify /tmp/ar-imgview
./build/recomp-studio verify /tmp/gapcensus-translate/igi.exe
./build/recomp-studio verify /tmp/t10-pe32                  # 32-bit control, PASS
cd /tmp/ar-imgview && ./recomp-guest
cd /tmp/ar-imgview && RECOMP_TRACE=/tmp/t10-imgview.trace ./recomp-guest
cd /tmp/gapcensus-translate/igi.exe && ./recomp-guest
cd /tmp/gapcensus-translate/igi.exe && RECOMP_TRACE=/tmp/t10-igi.trace ./recomp-guest
r2 -q -c "iS" ...                       # section tables
r2 -q -c "e asm.bits=32; pd N @ 0x..." ...   # call-site identification
clang -o /tmp/t10-fs-probe /tmp/t10-fs-probe.c -I/opt/homebrew/include -L/opt/homebrew/lib -lunicorn
clang -o /tmp/t10-gs64-probe /tmp/t10-gs64-probe.c -I/opt/homebrew/include -L/opt/homebrew/lib -lunicorn
```

Scratch files created outside the repo: `/tmp/t10-fs-probe.c`, `/tmp/t10-gs64-probe.c`,
`/tmp/t10-imgview.trace`, `/tmp/t10-igi.trace`, `/tmp/t10-igi-imports.json`, `/tmp/t10-missing.txt`,
`/tmp/t10-pe32/`. No repository file other than this report was written.

---

*Report prepared by teammate `sr-analyst` for task-10.*
