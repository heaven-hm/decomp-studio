# SR (M-HT/SR) — static recompiler analysis for Recomp Studio

**Source analysed:** `/Users/haseeb-mir/Documents/Code/recomp-studio/research/upstream/SR`
**Revision:** `ac690ddf3010bc3d2c875cb1b5e8da4f53a8d5b3` (2026-08-27, "Merge pull request #87 from IS4Code/fix/3d-scaling")
**Upstream:** <https://github.com/M-HT/SR.git>
**Author:** Roman Pauer (all first-party sources carry `Copyright (C) 2016-2026 Roman Pauer`, MIT).

Every path below is relative to that checkout. Line numbers were re-verified with `sed -n`/`grep -n`
before writing; anything I did not read is explicitly marked **not verified**.

---

## 0. Orientation: which subproject matters

The repo is a family of recompilers, not one program:

| Subproject | Purpose | Guest | Emits |
|---|---|---|---|
| `SR/` | static recompiler for **DOS** executables | DOS LE/16-bit MZ | x86 / arm / llasm / x64 **assembly** |
| `SRW/` | static recompiler for **Windows** executables | **PE32 (i386) only** | x86 / llasm / x64 **assembly** |
| `llasm/` | `.llasm` → **LLVM IR** converter (written in D) | — | LLVM IR → native |
| `SR-games/`, `SRW-games/` | per-title annotations (`.sci` files) + build scripts | — | — |
| `games/` | hand-written C that replaces the OS/API layer | — | — |
| `SR64-loader/` | obsolete 64-bit loader | — | — |

`README.md:24-31` and `SRW/README.md:3-5` state this. **`SRW` is the subproject with the same problem
shape as Recomp Studio** (Windows PE guest → native host). I focus on it and use `SR/` only where it
holds the shared runtime (the `llasm` backend and `*-support/` runtime are common to both:
`SRW/README.md:5` says the non-specific files live in `SR`'s subdirectories).

---

## 1. Architecture: guest formats, host targets, and what it emits

### Guest

`SRW/SRW_loader.c:641-646` — the loader's hard accept/reject gate:

```c
if ( Header->FileHeader.Machine != 0x014c || // 386 or later
     Header->FileHeader.SizeOfOptionalHeader < sizeof(_IMAGE_OPTIONAL_HEADER) ||
     Header->OptionalHeader.Magic != 0x10b || // normal (PE32) executable
     (Header->OptionalHeader.Subsystem != 2 && Header->OptionalHeader.Subsystem != 3) ||
     Header->OptionalHeader.NumberOfRvaAndSizes < 16 )
```

* MZ signature check at `SRW/SRW_loader.c:608`, PE signature at `:633`.
* **Only `IMAGE_FILE_MACHINE_I386` and only `PE32` (`0x10b`). PE32+ (`0x20b`) / AMD64 is rejected.**
  This is a real gap for us: Recomp Studio targets PE32 *and* PE32+ x64.
* Sections are modelled in `SRW/SR_defs.h:155-183` (`section_data`), with Win32-specific section
  kinds `ST_IDATA/ST_RSRC/ST_RELOC/ST_RDATA/ST_EDATA` at `SRW/SR_defs.h:83-93`. The loader *splits*
  import/export tables into their own sections (`SRW/SRW_loader.c:888`) and relocates per
  `LoadRelocations` (`SRW/SRW_loader.c:465`).
* Imports are parsed into `import_data { num, DllName, ProcAdrName, ProcName }`
  (`SRW/SR_defs.h:185-190`), filled at `SRW/SRW_loader.c:1078-1130`.

### Host targets

`OUTPUT_TYPE` is a **compile-time** switch, not a runtime flag — `SRW/SR_defs.h:41-47`:

```c
#define OUT_ORIG 0
#define OUT_WINDOWS 1
#define OUT_X86 2
#define OUT_LLASM 7
#define OUT_X64 8
#define OUTPUT_TYPE  OUT_X86
```

To build a different backend you edit the header and rebuild the recompiler
(`SRW/README.md:17`, `SR/README.md:17`). The banner at `SRW/SR_main.c:276-288` confirms the five
modes. `SR` has two more (`OUT_DOS`, `OUT_ARM_LINUX`) — `SR/SR_defs.h:41-48`.

Build: SCons, one executable — `SRW/SConstruct:81-83` (`sources = Glob('*.c') + Glob(udis86_path + '/libudis86/*.c')`),
`SR/SConstruct:81-85`.

Host targets actually reachable:

* `OUT_X86` → 32-bit x86 NASM assembly; assembled with `nasm -felf32`
  (`SRW-games/Septerra Core/SRW/build-x86.sh:7`).
* `OUT_X64` → 64-bit x86 NASM assembly.
* `OUT_LLASM` → an `.llasm` text DSL, converted by the D program `llasm/llasm.d`
  (`llasm/README.md:3`) to LLVM IR, then to **any LLVM triple**.
* `OUT_WINDOWS` → a "Windows version" (re-linked original, not recompiled); `SR_disassemble_offset_windows`
  at `SRW/SR_full_dos.c:321` and the `OUT_WINDOWS` guards in `SRW/SR_output.c:43,88,168,256,279,313,451,546,556,590,783`.

The host platform list is in `games/Septerra Core/SR-Septerra/SConstruct:33`:
`pc-windows, pc-linux, arm-linux, pyra, pc64-linux, arm64-linux, riscv64-linux, pc64-windows,
pc64-darwin, arm64-darwin`. **macOS arm64 is a first-class target**: `SConstruct:276-280` sets
`-arch arm64 -fpie -DPTROFS_64BIT` and `-mtriple=arm64-apple-darwin --relocation-model=pic`.
So SR does exactly our job — Windows x86 guest → macOS arm64 host — via the `llasm` route.

### What it emits

**Assembly, not C.** `SRW-games/README.md:9` ("The generated assembler version consists of *.asm* and
*.inc* files (or *.llasm* and *.llinc* files)"). There is no C backend anywhere.

The `llasm` IR is structurally close to C, though: each recompiled guest procedure becomes

```
define private fastcc void @proc(%_cpu* %cpu) nounwind {
```

`llasm/llasm.d:5197`. The whole guest CPU state is one opaque struct pointer, and every guest jump is
a `musttail call` (`llasm/llasm.d:2979`). This is the single most important architectural fact in SR
— see §3 and the borrow list.

---

## 2. Decoding

**It uses a vendored, modified disassembler: udis86.** Not Capstone, not Zydis.

* `SRW/README.md:9`: "uses files from [udis86] library (version 1.7.2) -- the source is in the
  *udis86-1.7.2* subdirectory." (`SR` uses 1.6 and calls it "modified", `SR/README.md:9`.)
* Vendored tree: `SRW/udis86-1.7.2/libudis86/` — `decode.c` (1112 lines), `itab.c` (8401 lines,
  generated instruction table), `itab.h`, `syn-intel.c`, `syn-att.c`, `udis86.c`.
  Marked vendored in `.gitattributes:15`.
* Build wiring: `SRW/SConstruct:25` (`udis86_path = './udis86-1.7.2/'`), `:81`.

**The integration layer is the interesting part**, not udis86 itself:

* `SRW/udis86_dep.h:39-73` declares `flags_needed[MAX_MNEMONICS]` / `flags_modified[MAX_MNEMONICS]`,
  a per-mnemonic table of which EFLAGS bits each instruction reads and writes.
* `SRW/udis86_dep.c:29-32` defines the table-populating macro:
  ```c
  #define SET_FLAGS(x, y, z) { \
      if ((x) >= MAX_MNEMONICS) return -1; \
      flags_needed[x] = (y); \
      flags_modified[x] = (z); }
  ```
  and `init_udis86_dep()` at `:35-262` fills it for every supported mnemonic, e.g.
  `SET_FLAGS(UD_Iadd, FL_NONE, FL_COND)` at `:47`, `SET_FLAGS(UD_Icmp, FL_NONE, FL_COND_SUB)` at `:64`,
  `SET_FLAGS(UD_Idec, FL_NONE, FL_PARITY|FL_ADJUST|FL_ZERO|FL_SIGN|FL_OVERFLOW)` at `:70`.
  Initialised to `FL_UNKNOWN` for everything else (`:39-43`) — an unlisted mnemonic is a hard error
  downstream, never a silent guess.
* Decoder configuration: `SRW/SR_main.c:260-262` — `ud_init`, `ud_set_mode(&ud_obj, 32)`,
  `ud_set_syntax(&ud_obj, UD_SYN_INTEL)`. Note: **32-bit mode is hardcoded**; there is no 64-bit
  decode path even for `OUT_X64` (the *host* is 64-bit, the guest is not).
* Per-instruction decode during codegen: `SRW/SR_full_llasm.c:127-131`
  (`ud_set_input_buffer` / `ud_set_pc` / `ud_disassemble`).

**Two-pass structure.** `SRW/SR_main.c:360-385`:

1. `SR_initial_disassembly()` — linear sweep of every code section.
2. `SR_apply_fixup_info()` — turn data references that look like code addresses into new code entries.
3. `SR_full_disassembly()` — recursive descent to fixpoint over the `entry_list` worklist
   (`SRW/SR_full.c:432-460`; note `while (!finished)` with `finished = 0` set whenever an entry is
   consumed, so newly discovered targets are drained in the same loop).

Two diagnostics turn the fixpoint into an auditable artefact: `--list_invalid_code_fixups=` and
`--list_data_to_code_fixups=` (`SRW/SR_main.c:307-316`), written from `SRW/SR_basic.c:503-546`. These
dump every place the recompiler had to *guess* that data was code (or vice versa). See §6.

---

## 3. CPU state and flags in generated code

### CPU state

`SR/llasm-support/llasm_cpu.h:29-40` — the entire guest CPU for the `llasm` backend:

```c
typedef struct {
    uint32_t _eax, _ecx, _edx, _ebx, _esp, _ebp, _esi, _edi, _eflags;
    uint32_t _st_top, _st_sw_cond, _st_cw;
    double _st[8];
#ifdef PTROFS_64BIT
    uint64_t _pointer_offset;
#else
    uint64_t _reserved1;
#endif
    int64_t _st_result;
    void *stack_bottom, *stack_top;
} _cpu;
```

* GPRs are **32-bit guest registers stored as 32-bit host fields** — no 64-bit widening, which is why
  the whole thing survives being passed as one pointer.
* `#define CPU _cpu *cpu` at `:42` and the `eax`/`ebx`/… aliases at `:44-52` let the runtime helpers
  read like plain C.
* **Flags are stored materialised, in real x86 EFLAGS bit positions** — `llasm_cpu.h:54-72`:
  `CF_SHIFT 0, PF_SHIFT 2, AF_SHIFT 4, ZF_SHIFT 6, SF_SHIFT 7, OF_SHIFT 11, IF_SHIFT 9, DF_SHIFT 10`,
  with masks `CF 0x01, PF 0x04, AF 0x10, ZF 0x40, SF 0x80, OF 0x0800`. This is deliberate: it makes
  `lahf`/`sahf`/`pushfd`/`popfd` trivial (SRW `UD_Ilahf` emits `ins8hl eax, eax, eflags`,
  `SRW/SR_full_llasm_instr.c:4078-4083`) at the cost of doing more work per arithmetic instruction.
* The 32-bit guest address space is mapped at a fixed offset: `REG2PTR`/`PTR2REG` at
  `llasm_cpu.h:74-84`. See §5 for why this is the keystone of indirect-jump handling.
* x87 lives in the same struct as `double _st[8]` + `_st_top` (§5).

In the x86/x64 assembly backends the same state is instead mapped onto **host registers**: e.g.
`SR/x64-support/asm_call.inc:25-40` uses `r11d` as the guest `ESP`, `ebp` as guest `EBP`, `r8d`/`r9d`
as scratch, and pushes guest arguments onto the *guest* stack before `jmp`ing to the target.

### Flag liveness / optimisation — yes, and it is the core of the design

**(a) A per-mnemonic read/write table** (§2), giving a conservative but precise summary of each
instruction's flag effects. `SRW/udis86_dep.h:39-70` defines the vocabulary, including:

```c
FL_CARRY 0x01, FL_PARITY 0x02, FL_ADJUST 0x04, FL_ZERO 0x08,
FL_SIGN 0x10, FL_OVERFLOW 0x20, FL_DIRECTION 0x40, FL_INTERRUPT 0x80, FL_TASK 0x0100,
FL_AH = FL_CARRY|FL_PARITY|FL_ADJUST|FL_ZERO|FL_SIGN,
FL_COND_SUB = FL_CARRY|FL_PARITY|FL_ADJUST|FL_ZERO|FL_SIGN|FL_OVERFLOW,
FL_WEAK = 0x10000000, FL_SPECIFIC = 0x80000000,
FL_INST_MASK = 0x00070000   // "instruction flags" (condition-code of a specific jump)
```

`FL_WEAK` / `FL_SPECIFIC` are the escape hatches: `SET_FLAGS(UD_Ilahf, FL_AH | FL_WEAK, FL_NONE)`
(`SRW/udis86_dep.c:160`), `SET_FLAGS(UD_Imov, FL_NONE, FL_SPECIFIC)` (`:177`),
`SET_FLAGS(UD_Ipushfd, FL_ALL | FL_WEAK, FL_NONE)` (`:203`). `FL_SPECIFIC` means "I cannot summarise
this in the bitmask" and is a hard error if it survives to codegen
(`SRW/SR_full_llasm.c:224-230`) — i.e. the table is deliberately **fail-closed, not best-effort**.

**(b) A backward liveness pass per region.** `SRW/SR_full_llasm.c:32-316` is the whole algorithm.
The loop walks the region *backwards* (`cur_ofs` starts at `region->end_ofs` and decrements,
`SRW/SR_full_llasm.c:43,260-268`), carrying `flags_to_write` (`:35`, `:45`). After each instruction:

```c
flags_to_write &= ~flags_write;                       // this instr just defined them → dead
if (flags_to_write == FL_WEAK) flags_to_write = FL_NONE;
flags_to_write |= flags_read;                         // live-in from here on
if (iflags) flags_to_write &= ~((uint32_t) iflags->end);
```
`SRW/SR_full_llasm.c:248-255`

At the end of the region, any surviving non-weak flags are a **compile error**
(`SRW/SR_full_llasm.c:305-310`), because that would mean the region's entry state is unconstrained.
That is the key discipline: liveness is proved, not assumed.

Regions themselves are basic-block-ish, derived from the bound list — `SR_disassemble_create_regions`
at `SRW/SR_full.c:341-388`, driven at `SRW/SR_full.c:482-540`. Bounds are opened/closed by
`section_bound_list_Insert` calls in the instruction walkers (e.g. `SRW/SR_full_win32.c:689-690`).

**(c) Per-procedure dead-register elimination in the llasm compiler.**
`llasm/llasm.d:2642-2745` ("optimization pass") runs another backward pass over each procedure's
*instruction list*, tracking `last_reg_write[reg]` (`:2646-2654`). A write is tagged
`last_reg_write[i] = true` only if no later read/write exists (`:2685-2700`), which lets the emitter
store a register only when it is genuinely the final definition. Any `call` invalidates all
registers (`:2719-2725`), and float-stack state is handled the same way (`:2701-2718`, `:2726-2732`).
Register values otherwise live as **LLVM SSA values** and are written back to the `_cpu` struct only
when forced — `writeback_registers()` at `llasm/llasm.d:1925`, called before `tcall`/`call`
(`llasm/llasm.d:2964-2968`, `:2994-2997`, `:3064`, `:3102`, `:3186`).

**(d) Two optimisation levels.** `llasm.d -O1` / `-O2` map to `global_optimization_level`
(`llasm/llasm.d:3783-3796`), copied into `procedure_optimization_level` per procedure at
`llasm/llasm.d:1999`. `-O1` allocas the used registers (`llasm.d:2755-2780`); `-O2` keeps them
purely in SSA and relies on LLVM. At `-O2` the compiler also does static branch folding when the
condition was just materialised by a `mov` (`llasm.d:2381-2383`, `:2323`).

**(e) `instruction_flags.sci`** — a human override file, loaded at
`SRW/SR_source_code_information.c:766-780` via `SR_LoadSCI_instruction_flags` (`:521-560`), which
parses `loc_XXXX,to_set,to_clear` lines. It lets the author tell the recompiler which condition bits a
hand-written `instruction_replacements.sci` block will leave live — closing the loop when generated
code is replaced by hand. Applied at `SRW/SR_full_llasm.c:151-162`; mixing it with the automatic
`FL_INST_MASK` path is an error (`:154-159`).

**(f) Unaligned-stack special cases.** `SR.cfg` carries `esp_dword_aligned` / `ebp_dword_aligned`
(parsed at `SRW/SR_main.c:184-205`; example config `SRW-games/Septerra Core/SRW/SR.cfg`). When a
program violates the assumption in a bounded area, the `unaligned_ebp_areas.sci` /
`unaligned_esp_areas.sci` overrides (`SRW/SR_source_code_information.c:738-751`, tracked at
`SRW/SR_full_llasm.c:49-86` and `:165-219`) locally switch alignment off. This is a nice pattern:
**a global fast assumption plus a sparse, evidence-driven exception list**, rather than paying the
slow path everywhere.

---

## 4. Windows API / OS compatibility

**SR reimplements Win32 in hand-written C, calling the host OS/SDL underneath. It does not call
Win32 and does not forward to a host API by name.**

The mechanism, end to end:

1. **Imports are parsed from the PE** (`SRW/SRW_loader.c:1078-1130`) into `import_data`
   (`SRW/SR_defs.h:185-190`). The loader special-cases some entries, e.g. forcing
   `comctl32!InitCommonControls` for ordinal 17 (`SRW/SRW_loader.c:1114-1117`).
2. **At a call site, an import becomes a tail call to a named host symbol.** In the llasm backend,
   `SRW/SR_full_llasm_instr.c:2528-2541`:
   ```c
   else if (ud_obj.operand[0].type == UD_OP_MEM && ud_obj.operand[0].size == 32)
   {
       if (extrn[0] != NULL && extrn[0]->is_import)
       {
           if (ud_obj.operand[0].base == UD_NONE && ud_obj.operand[0].index == UD_NONE)
           {
               OUTPUT_PARAMSTRING("PUSH %s\n", cLabel);
               OUTPUT_PARAMSTRING("tcall %s\n", extrn[0]->proc);
           }
       }
   ```
   So the *guest* `call dword [__imp__CreateFileA@16]` becomes "push the guest return address, then
   tail-call the host function `CreateFileA`". The guest stack discipline is preserved across the
   boundary; the host function reads its arguments from the guest stack.
3. **Non-imported, guest-resident procedures can be redirected too.** `external_procedures.sci` maps a
   guest address to a host symbol plus an optional replacement body
   (`SRW/SR_source_code_information.c:221-274`, `extrn_data { ofs, is_import, is_used, altaction, proc }`
   at `SRW/SR_defs.h:121-127`). Example, `SRW-games/Septerra Core/SRW/x64/external_procedures.sci:1-5`:
   ```
   loc_48e480,ASI_startup_asm2c
   loc_48e4e0,ASI_shutdown_asm2c
   ```
   The `_asm2c` suffix marks "guest procedure implemented in C". Consulted during codegen at
   `SRW/SR_full_llasm_instr.c:2495-2502` and `:2577-2584`; the optional `altaction` **replaces** the
   instruction sequence entirely (`:2522-2526`).
4. **The C side is a real Win32 reimplementation**, not a shim. `games/Septerra Core/SR-Septerra/`
   contains `WinApi-kernel32.c`, `WinApi-user32.c`, `WinApi-gdi32.c`, `WinApi-ddraw.c`,
   `WinApi-dsound.c`, `WinApi-winmm.c`, `WinApi.c`, `WinApi.h`, plus `CLIB.c` (CRT) and
   `MSS.c` (Miles Sound System). Functions are named `<Win32Name>_c` and use the guest calling
   convention macro `CCALL`, e.g. `WinApi-kernel32.c:344`
   `uint32_t CCALL Beep_c(uint32_t dwFreq, uint32_t dwDuration)`, `:474 CreateFileA_c`,
   `:948 FindFirstFileA_c`, `:1716 QueryPerformanceCounter_c`. They call `fopen`, `stat`, `opendir`,
   `clock_gettime`, `pthread_*` directly (`WinApi-kernel32.c:44-70`).
5. **A 32-bit pointer type bridges the guest's 4-byte pointers into a 64-bit host.**
   `games/Septerra Core/SR-Septerra/ptr32.h:31-60` defines `template<class T,int A=4> class ptr32_t`
   whose storage is a packed/aligned `uint32_t` and whose conversion is
   `value = (uint32_t)((uintptr_t)p - pointer_offset)`. This is the same `pointer_offset` trick as
   `REG2PTR`/`PTR2REG` in `llasm_cpu.h:74-84`.
6. **Handles are typed, not raw pointers** — `WinApi.h:75-79` (`HT_NONE/HT_FILE/HT_SEARCH/HT_PIPE`)
   with `INVALID_HANDLE32_VALUE` (`WinApi.h:69-71`), and `GetLastError` is a thread-local
   (`WinApi.h:22-46`), which matters because the recompiled game is multi-threaded.
7. **The C→guest direction** is handled by an explicit macro library keyed on stack-argument count:
   `games/Septerra Core/SR-Septerra/llasm/asm-calls.llinc:23-80`
   (`Call_Asm_Return`, `Call_Asm_Stack0`, `Call_Asm_Stack1`, `Call_Asm_Stack2`, … `_void` variants).
   `Call_Asm_Stack2` is:
   ```
   add tmp0, esp, 4
   load tmp0, tmp0, 4
   add tmp1, esp, 2*4
   load tmp1, tmp1, 4
   call \proc_name tmp0, tmp1
   mov eax, tmp0
   ```
   i.e. read the guest stack, call the C function, put the result back in guest `eax`. The host
   symbols are declared with `func`/`funcp`/`funcv` (`games/…/llasm/CLIB-asm.llasm:26-52`), which
   `llasm.d:4132-4163` turns into LLVM declarations
   (`has_return_value` for `func`/`funcp`, `return_value_is_pointer` for `funcp`).
8. **Threads.** Guest `_beginthread` is bridged by a hand-written `proc run_thread_c2asm` in
   `games/Septerra Core/SR-Septerra/llasm/CLIB-asm.llasm:61-71`, which pulls the start address and argument off the guest
   stack and `tcall`s it. `SR/llasm-support/llasm_int.llinc` and
   `SR/x86-support/asm_int.inc` handle `int`/`cli`/`sti` (`X86_InterruptFlag`, see
   `SR/llasm-support/llasm_xti.llinc:25-35`).

**Verdict for us:** SR proves the "reimplement the OS surface, don't call the host OS by name" model
scales to real Win32 games (Septerra Core is a DirectDraw + DirectSound + QuickTime title). It also
shows the cost: the API layer is hand-written per title family, and each recompiled program needs a
`.sci` annotation set.

---

## 5. SIMD/VEX, x87, indirect jumps and jump tables

### SSE / MMX / VEX (AVX) — effectively **not supported**

* udis86 1.7.2 **declares** VEX tables but does not implement them:
  `SRW/udis86-1.7.2/libudis86/itab.h:11-12` contains `UD_TAB__OPC_VEX_M` / `UD_TAB__OPC_VEX_P`, but
  `grep -rn "vex" libudis86/*.c libudis86/*.h` returns **no hit in any `.c` file**. There is no VEX
  prefix decode path in `decode.c`.
* No AVX mnemonics exist: `grep -o "UD_Iv[a-z0-9]*" libudis86/itab.h` yields only VMX instructions
  (`UD_Ivmcall`, `UD_Ivmclear`, …). There is no `UD_Ivaddps`/`UD_Ivmovaps`/`UD_Ivzeroupper`.
* The SSE mnemonics that *are* in the table (`UD_Iaddps`, `UD_Imovaps`, `UD_Iblendps`,
  `UD_Iinsertps`, `UD_Idpps`, … — SSE through SSE4.1) are **not lowered by any backend**. Counting
  distinct `UD_I*` mnemonics in each code generator: `SRW/SR_full_llasm_instr.c` = 178,
  `SRW/SR_full_x64_instr.c` = 179. Filtering for SSE-shaped suffixes (`ps$|pd$|ss$|sd$`) yields only
  `UD_Ilss`, `UD_Imovsd`, `UD_Ilodsd`, `UD_Istosd` — i.e. **string instructions, not SSE**.
* Consequence: hitting any SSE instruction lands in the `default:` arm —
  `SRW/SR_full_llasm_instr.c:7749-7753`:
  ```c
  default:
      fprintf(stderr, "Error: unknown instruction - %i - %i - %s\n", Entry, (unsigned int)cur_ofs, output->str);
      return 5;
  ```
  The recompiler **aborts**, it does not fall back to an interpreter. This is a strong design stance:
  *every* executed byte is either recompiled or explicitly replaced by an `.sci` override. It is why
  SR only supports games that predate SSE-heavy code, and why `instruction_replacements.sci` exists.

### x87 — emulated in software

* `EMULATE_FPU` is forced on for the `llasm` output (`SRW/SR_defs.h:49-51`, `SR/SR_defs.h:56-61`).
* The FPU state lives in the CPU struct as host doubles with a software top-of-stack:
  `double _st[8]; uint32_t _st_top, _st_sw_cond, _st_cw; int64_t _st_result;`
  (`SR/llasm-support/llasm_cpu.h:30-38`).
* The instruction set is redirected to a helper library: `SRW/SR_full_llasm_instr.c:6990`
  (`#if (EMULATE_FPU)`) opens the `UD_Ifadd`/`UD_Ifmul`/… cases, which emit calls to `FADD`/`FMUL`/…
  macros mapping onto `x87_*` functions declared at `SR/llasm-support/llasm_float.llinc:25-90`
  (`x87_fadd_float`, `x87_fadd_double`, `x87_fld_st`, `x87_fldcw_uint16`, `x87_frstor_void`, …).
* Implementation: `SR/llasm-support/llasm_float.c`. Top-of-stack arithmetic macros at
  `llasm_float.c:151-158` (`ST(i) st[(st_top+i) & 7]`, `PUSH_REGS`, `POP_REGS`), comparison-flag
  macros at `:136-149` (`X87_CF 0x0100`, `X87_ZF 0x4000`, `X87_CMP`).
* **Precision tradeoff, documented in code:** `frstor` down-converts the guest's 80-bit extended
  values into host `double` — `llasm_float.c:666-687` extracts the 64-bit mantissa and 15-bit
  exponent, re-biases (`exponent = (exponent & 0x7fff) + 1023 - 16383`), clamps to the double range,
  and packs. So x87 is emulated at **64-bit, not 80-bit, precision**. The helper API does carry
  separate `x87_*_float` and `x87_*_double` entry points plus 80-bit `num_low, num_high` pairs
  (`llasm_float.llinc:27-28`), so the boundary is explicit.

### Indirect jumps and jump tables — handled by *address identity*, not by analysis

This is the most elegant thing in SR. **There is no static jump-table recovery anywhere in `SRW`.**
`grep -n "table" SRW/SR_full_win32.c` returns nothing; the only occurrence of the phrase "jump table"
in the tree is `SRW/SR_full.c:196-200`, and that is about *alignment*:

```c
if (item->type == OT_OFFSET && item->has_label && (item->align == 0 || item->align == 4))
{
    // jump table after instructions
    DATA->isregion = 3;
}
```

Instead:

1. The recompiled image is linked so that **a guest 32-bit address is a host pointer plus a constant
   offset**. `SR/llasm-support/llasm_cpu.h:74-84`:
   ```c
   #define REG2PTR(x) ((void *)((uintptr_t)(x) + cpu->_pointer_offset))
   #define PTR2REG(x) ((nullptr == (x)) ? 0 : (uint32_t)((uintptr_t)(x) - cpu->_pointer_offset))
   ```
   The llasm compiler emits the equivalent at IR level: `get_int32_to_ptr` /
   `get_addr_to_int32` at `llasm/llasm.d:1377-1445`, e.g.
   `addr1 = zext i32 %v to i64; addr2 = add i64 addr1, %ptrofs; addr3 = inttoptr i64 addr2 to T*`
   (`llasm.d:1386-1388`), with a null-preserving `select` when `nullable_pointer` is set.
2. Therefore an indirect jump is just a tail call to a computed pointer.
   `SRW/SR_full_llasm_instr.c:4044-4066` (memory operand):
   ```
   SR_disassemble_get_madr(...); SR_disassemble_read_mem_word(cOutput, &memadr, LR_TMP1);
   OUTPUT_STRING("tcall tmp1\n");
   ```
   and `:4068-4075` (register operand): `OUTPUT_PARAMSTRING("tcall %s\n", X86REGSTR(...))`.
3. `tcall` lowers to a guaranteed tail call — `llasm/llasm.d:2962-2990`:
   `musttail call fastcc void @target(%_cpu* %cpu) nounwind` (`:2979`), or, with `-no-tail-calls`,
   `ret i8* <addr>` (`:2971-2974`). `llasm.d:2269-2275` even asserts `tcall` is the last instruction
   in its block.
4. Direct jumps/calls use the same primitive with a static target: `UD_Ijmp` at
   `SRW/SR_full_llasm_instr.c:3987-4043` emits `tcall <label>`, `UD_Icall` at `:2478-2527` emits
   `PUSH <return-label>` then `tcall <target>`.

**What this buys:** an indirect jump needs zero static knowledge. The jump table's entries are just
32-bit guest addresses, which *are* host code pointers once the offset is applied, so the `tcall`
lands on a real recompiled procedure with no dispatcher, no hash lookup and no interpreter. It also
means the generated code has **no fallback for a target that was never disassembled** — if the
recursive-descent pass missed it, that address contains data and the program crashes. That is why the
`--list_data_to_code_fixups` report and the `.sci` overrides are load-bearing, and why
`fixup_interpret_as_code.sci` / `fixup_do_not_interpret_as_code.sci` exist
(`SRW/SR_source_code_information.c:584-588`, loaders at `:605` and `:657`).

Two supporting mechanisms for code/data ambiguity:

* **Displaced labels** — a jump target that is not an instruction boundary.
  `SR_LoadSCI_displaced_labels` at `SRW/SR_source_code_information.c:66-110` parses
  `loc_XXXX,displacement` and stores it in `label_list`; example
  `SRW-games/Battle Isle 3/SRW-sdi_1r/x86/displaced_labels.sci:1` = `loc_4B6FA8,32`.
* **Ignored areas** — regions proven to be data inside a code section;
  `SRW/SR_source_code_information.c:697-709`, example
  `SRW-games/Battle Isle 3/SRW-sdi_1r/x86/ignored_areas.sci:1-3`.
* **Instruction replacements** — replace N bytes of guest code with hand-written llasm;
  loader at `SRW/SR_source_code_information.c:710-737`, applied at
  `SRW/SR_full.c:131-156`. Example `SRW-games/Battle Isle 3/SRW-sdi_1r/x86/instruction_replacements.sci:1-3`:
  ```
  loc_477BD1,18, ; isalnum macro
  loc_477BF6,52,call ms_isalnum_asm2c|add esp, byte 4 ; isalnum macro
  ```
  Note the `|` separator: one guest instruction replaced by *several* host instructions. Also used to
  neuter copy protection: `loc_403AD9,104, ; skip CDROM check` (`:4`).

---

## 6. Correctness verification

**There is no automated verification of generated-code semantics. None. Not an emulator differential
harness, not a unit test of the lifter.**

Evidence of absence:

* `grep -rni "unicorn|qemu|dosbox|differential|validate|regression" SRW/*.c SRW/*.h SR/*.c SR/*.h`
  → **no matches**.
* The only test directories are vendored inside udis86: `SR/udis86-1.6/tests/` (test32/64.asm,
  randtest\*.ref) and `SRW/udis86-1.7.2/tests/` (`asm/{16,32,64}/*.asm`, `difftest.sh.in`). These
  test the *disassembler*, not the recompiler.
* `README.md:27,31` explicitly says the generated assembler version of the executable is
  "not part of the project" — the correctness signal is the author running the game.

What *does* exist is **self-consistency checking plus a human-driven annotation loop**:

1. **Re-decode agreement.** In the `llasm` backend every instruction is decoded a second time and the
   length must match the length recorded during the initial pass —
   `SRW/SR_full_llasm.c:130-139`:
   ```c
   ret = ud_disassemble(&ud_obj);
   if (ret == 0 || ret != output->len + 1)
   {
       fprintf(stderr, "Error: wrong disassembly - ...");
   ```
   This catches an instruction whose *extent* was mis-attributed by the first pass.
2. **Flag-liveness must close.** A region that ends with live, non-weak flags is an error
   (`SRW/SR_full_llasm.c:305-310`); so is mixing automatic and hand-declared instruction flags
   (`:154-159`) or leaving `FL_SPECIFIC` unresolved (`:224-230`).
3. **Unknown instructions abort.** `SRW/SR_full_llasm_instr.c:7749-7753` — fail closed.
4. **Two fixup reports as a work list.** `--list_invalid_code_fixups=<file>` and
   `--list_data_to_code_fixups=<file>` (`SRW/SR_main.c:307-316`) dump every ambiguous data↔code
   decision (`SRW/SR_basic.c:503-546`). The workflow is: run, inspect the list, add
   `fixup_interpret_as_code.sci` / `fixup_do_not_interpret_as_code.sci` / `ignored_areas.sci` entries,
   re-run until the list is empty. This is *recompiler-side* validation of the code/data partition,
   not validation of semantics.
5. **Optional tracing.** `--add_tracing` (`SRW/SR_main.c:317-320`) emits a `TRACE_LABEL 0x…` marker
   before every instruction (`SRW/SR_output.c:138-141`), giving a guest-PC trace from a run. Useful
   for eyeballing against a debugger; there is no comparison tool in-tree.
6. **A disabled dev harness.** `SR/SR_defs.h:51-54` has `_CHK_HACK` commented out, and
   `SR/SR_output.c:55-70,148-172` shows what it did: emit an aligned `{ address, "sub_…" }` table and
   route calls through an external `SR___CHK` symbol so a reference implementation could be compared
   per call. It exists only in the **DOS** recompiler and is off. `SRW` has no equivalent.

**For Recomp Studio this is the clearest differentiator.** SR substitutes *author discipline and a
curated annotation set* for automated verification; our Unicorn differential harness is strictly
stronger, and is the reason we can iterate faster than SR's per-title manual loop.

---

## 7. Licence, and what is reusable in an Apache-2.0 project

### Findings

* **There is no top-level `LICENSE` file in the repository root.** `find . -iname "*licen*" -o -iname
  "*copying*"` returns only `SR/udis86-1.6/LICENSE`, `SR/udis86-1.6/COPYING`,
  `scaler-plugins/xbrz/License.txt`, `midi-plugins/xcom12/src/nuked_opl3/LICENSE`, and two
  `COPYING.LESSER.txt` under `midi-plugins/`. **Not verified**: I did not inspect the midi/scaler
  plugin licences, which are irrelevant to the recompiler.
* `README.md:17-18` states the terms:
  > The source code is released with MIT license (except libraries, etc. by other people, which have
  > their own license). For the purpose of using the code in GPL projects, the source code is also
  > released with GPLv2 or later and LGPLv2.1 or later.
* **Every first-party source file carries the full MIT text in its header** — verified on
  `SRW/SR_defs.h:1-23`, `SRW/SR_main.c:1-23`, `SRW/SConstruct:1-21`, `SRW/udis86_dep.h:1-23`,
  `SR/llasm-support/llasm_cpu.h:3-25`, `SR/llasm-support/llasm_float.c` (header), `SR_defs.h:1-23`.
  This is what actually matters: the grant is per-file, and it is present.
* **Vendored udis86 is BSD-2-Clause**, not MIT: `SRW/udis86-1.7.2/udis86.h:1-21` and
  `libudis86/decode.c:1-24` — "Copyright (c) 2002-2009 Vivek Thampi, All rights reserved.
  Redistribution and use in source and binary forms … provided that the following conditions are
  met: [retain notice; reproduce notice in binary form]". Note `SRW/udis86-1.7.2/README:15` claims
  "A copy of the license is included with the source in LICENSE", but **no LICENSE file exists in
  that directory** — the per-file headers are the authoritative text.
  `.gitattributes:14-15` marks both udis86 trees `linguist-vendored`.
* `SR/SR_defs.h:64-82` and similar show only portable `__GNUC__`/`_MSC_VER` shims; no GPL-only
  constructs are used anywhere in the recompiler or runtime.

### Can code be reused in an Apache-2.0 project?

**Yes, for the first-party code, subject to attribution.** The chain:

* MIT → Apache-2.0: allowed. Apache-2.0 §4 requires you to retain copyright/attribution notices and
  state changes; including the MIT-licensed files in a `third_party/` tree with their headers intact
  and an entry in `NOTICE` satisfies this. MIT is not on Apache's Category-X (incompatible) list.
* BSD-2-Clause (udis86) → Apache-2.0: allowed, same obligation (retain the notice; reproduce it in
  binary distributions).
* The **GPLv2+/LGPLv2.1+ grant is an alternative, not an obligation** — `README.md:18` says "for the
  purpose of using the code in GPL projects". We elect MIT and are unaffected.
* Practical caveat: SR's recompiler is C (C99 + a little C++ for the container helpers —
  `SRW/SConstruct:81-83` adds `*.cpp` when Judy is off), 2-clause BSD/MIT throughout, so it is
  licence-clean to copy. **But it is also large and written against a different architecture** (it
  emits NASM/llasm text, we emit C++), so the realistic reuse is *technique and small data tables*,
  not wholesale file copying. See the next section.

If we do copy anything verbatim, record it in a `THIRD_PARTY_NOTICES.md` with the source revision
(`ac690dd`) and the MIT text from the file header.

---

## 8. What to borrow

Five techniques, ranked by value to a C++-emitting lifter. "Directly reusable" means the *code* can
be lifted with attribution; "reimplementable in a day" means the *idea* is a day's work.

### 1. Backward flag-liveness so dead flag computation disappears — **(b) reimplementable in a day**

*Source:* `SRW/SR_full_llasm.c:32-316` (the pass), `SRW/udis86_dep.c:35-262` (the per-mnemonic
read/write table), `SRW/udis86_dep.h:39-73` (the flag vocabulary), `SRW/SR_full.c:341-388` (regions).

Walk each region backwards carrying a `flags_to_write` set; on each instruction
`flags_to_write &= ~flags_write; flags_to_write |= flags_read;` (`SRW/SR_full_llasm.c:248-250`).
If the set is non-empty at region entry, **error out** (`:305-310`) rather than emitting a
conservative full-flags recompute.

Why it matters for us: our lifter almost certainly computes CF/PF/AF/ZF/SF/OF eagerly for every
arithmetic instruction. Most are dead within a few instructions (a `cmp` immediately followed by a
`jcc` consumes only the specific bits; the `add` before it is fully dead). This pass removes the flag
work *before* clang++ ever sees it, and it is pure bookkeeping over the instruction list — no
dataflow framework required. The paired discipline (error, don't guess, when liveness does not close)
is what makes it safe. Adopt the `FL_WEAK`/`FL_SPECIFIC` escape hatches too: `FL_SPECIFIC` =
"cannot summarise" and must be a hard error (`SRW/SR_full_llasm.c:224-230`).

### 2. Materialise flags at real EFLAGS bit positions — **(b) reimplementable in an afternoon**

*Source:* `SR/llasm-support/llasm_cpu.h:54-72` (positions/masks), `:29-40` (the struct),
`SRW/SR_full_llasm_instr.c:1161-1260` (`SR_disassemble_change_flags` emits
`and/or/xor eflags, eflags, mask`), `SRW/SR_full_llasm_instr.c:4078-4083` (`lahf` becomes
`ins8hl eax, eax, eflags`).

Keep CF at bit 0, PF at 2, AF at 4, ZF at 6, SF at 7, OF at 11, IF at 9, DF at 10 — exactly x86.
Then `lahf`/`sahf`/`pushfd`/`popfd`/`pushfw`/`popfw`/`int`-return are one load or store, with no
per-flag packing code, and the same mask constants (`CF 0x01, PF 0x04, AF 0x10, ZF 0x40, SF 0x80,
OF 0x0800`) are shared between the generated code and the runtime helpers
(`SR/llasm-support/llasm.llinc:28-46` mirrors them). We already need `pushfd`-accurate flags for
Unicorn differential comparison, so this representation is a prerequisite for technique 1 anyway.

### 3. Tail-call guest control flow with a single CPU-state argument — **(c) partly not applicable, but adopt the *shape***

*Source:* `llasm/llasm.d:5197` (`define … fastcc void @proc(%_cpu* %cpu) nounwind`),
`:2979` (`musttail call fastcc void @…(%_cpu* %cpu) nounwind`),
`SR/llasm-support/llasm_cpu.h:29-42` (the struct and `#define CPU _cpu *cpu`),
`llasm/llasm.d:1925` (`writeback_registers`).

Every recompiled procedure has the signature `void f(CPU*)`, every guest jump is a guaranteed tail
call, and registers live as SSA values that are written back to the `CPU` struct only when a call
forces it. LLVM then does register allocation, inlining and — crucially — keeps the guest state in
host registers across straight-line code.

For a C++-emitting lifter this is **(c) not applicable verbatim**: clang++ will not give you
guaranteed tail calls for mutually recursive `void f(CPU*)` functions, and the ABI (one pointer
argument) prevents it. But two parts transfer directly:

* The **`void proc(CPU*)` shape plus a shared CPU struct** is exactly right for us; it keeps the
  guest state addressable so the differential harness can snapshot and compare it.
* `writeback_registers()` before calls (`llasm/llasm.d:1925`, called at `:2964-2968`) is the rule we
  need: hold guest registers in local variables between calls, flush to the struct only at call
  boundaries and on any address-taken path. clang++ will do the SSA promotion for us if we emit
  `uint32_t eax = cpu->eax; … ; cpu->eax = eax;` around each basic block.

Also borrow the **entry-point trampoline** from `llasm/llasm.d:5273-5301`: pushing a return address
of `@__return_procedure` onto the guest stack and tail-calling the real entry, so a recompiled
`main`/`WinMain` returns cleanly into host code.

### 4. Guest address ≡ host address + fixed offset, making indirect jumps free — **(b) reimplementable in a day; (c) the *linking* part is not applicable**

*Source:* `SR/llasm-support/llasm_cpu.h:74-84` (`REG2PTR`/`PTR2REG`),
`llasm/llasm.d:1377-1445` (`get_int32_to_ptr`/`get_addr_to_int32`, `ptrofs` arithmetic),
`SRW/SR_full_llasm_instr.c:4044-4075` (indirect `jmp`/`call` → `tcall <computed>`),
`games/Septerra Core/SR-Septerra/ptr32.h:31-60` (the C-side `ptr32_t`).

SR never recovers jump tables statically. Instead the recompiled image is placed at a fixed offset
from the guest's virtual addresses, so a 32-bit guest address *is* a usable host pointer and
`jmp [table + eax*4]` becomes a tail call to that pointer (`SRW/SR_full_llasm_instr.c:4061-4065`).
`grep -n "table" SRW/SR_full_win32.c` returns nothing — there is no table analysis at all.

**For us: (c) for the linking trick** — a C++-emitting lifter compiled by clang++ cannot pin its own
code at guest addresses. **But (b) for the consequence**: this tells us we can stop trying to
statically enumerate jump tables and instead emit, for an indirect jump, a call into a
guest-address → C++-function dispatcher, with the table left as data. That is a much smaller and
more robust feature than jump-table recovery, and it is the same design our Unicorn harness can
validate directly (compare the resolved target address against Unicorn's). We should also copy the
*companion* mechanisms that make it safe: the ambiguous-code/data work list
(`SRW/SR_basic.c:503-546`, `SRW/SR_main.c:307-316`), `ignored_areas.sci`-style data-in-code regions,
and displaced labels for non-instruction-boundary targets
(`SRW/SR_source_code_information.c:66-110`).

### 5. Per-mnemonic flag/behaviour table generated once, fail-closed — **(a) directly reusable as a design, (b) as a table**

*Source:* `SRW/udis86_dep.h:39-73`, `SRW/udis86_dep.c:29-43` (`SET_FLAGS` + `FL_UNKNOWN` default),
`:45-262` (the table), `SRW/SR_full_llasm.c:143-149` (unknown ⇒ hard error).

A flat `flags_needed[mnemonic]` / `flags_modified[mnemonic]` array, defaulting every entry to
`FL_UNKNOWN`, populated by an explicit alphabetical list, with `FL_UNKNOWN` treated as a fatal error
at codegen (`SRW/SR_full_llasm.c:143-149`) rather than silently treated as "no flags". The same
`SET_FLAGS` entries are a ready-made, hand-audited summary of x86 flag semantics for ~180 mnemonics
— directly useful as a cross-check against whatever flag model we write, and small enough to
transcribe with attribution to `SRW/udis86_dep.c:44-262` under MIT.

Honourable mentions, cheap and worth copying:

* **Unaligned-stack fast path with sparse overrides** — `SR.cfg`'s `esp_dword_aligned` /
  `ebp_dword_aligned` (`SRW/SR_main.c:184-205`) plus `unaligned_esp_areas.sci` /
  `unaligned_ebp_areas.sci` (`SRW/SR_source_code_information.c:738-751`,
  `SRW/SR_full_llasm.c:49-86`). A global assumption plus an evidence-driven exception list is exactly
  the right ergonomics for a recompiler.
* **`instruction_replacements.sci` with multi-instruction replacements** —
  `SRW/SR_source_code_information.c:710-737`, `SRW/SR_full.c:131-156`; the `a|b|c` syntax (see
  `SRW-games/Battle Isle 3/SRW-sdi_1r/x86/instruction_replacements.sci:2`) lets one guest instruction
  expand into several host statements, and the `instruction_flags.sci` companion
  (`SRW/SR_source_code_information.c:521-560`) declares the flags the replacement leaves live.

---

## 9. Direct comparison to Recomp Studio

| Dimension | SR / SRW | Recomp Studio (per task brief) |
|---|---|---|
| Guest | PE32 i386 only (`SRW/SRW_loader.c:641-646`) | PE32 **and PE32+** x86/x64 |
| Output | NASM asm, or `.llasm` → LLVM IR | **C++** |
| Decoder | vendored udis86 1.6/1.7.2 (`SRW/README.md:9`) | (not verified here) |
| SSE/VEX | **none**; hard abort (`SRW/SR_full_llasm_instr.c:7749`) | required (x64 MVP) |
| x87 | software-emulated at **64-bit** precision (`SR/llasm-support/llasm_float.c:666-687`) | (not verified) |
| Indirect jumps | free, via address identity (`llasm_cpu.h:74-84`) | (not verified) |
| Win32 | hand-written reimplementation (`games/…/WinApi-*.c`) | (not verified) |
| Flags | eager, at real EFLAGS bits, with backward liveness | (not verified) |
| Verification | **none automated**; self-consistency + fixup reports | **Unicorn differential** |
| Licence | MIT per-file; BSD-2 udis86 | Apache-2.0 |

**The two things SR does better than a naive lifter:** (1) it never computes a flag nobody reads, and
(2) it never has to understand a jump table. **The two things we do better:** (1) real differential
verification against Unicorn, and (2) emitting C++ rather than hand-rolled asm, so we inherit
clang++'s optimiser instead of SR's bespoke `llasm.d` passes (`llasm.d:2642-2745`) — though note that
inheriting clang++ means we must *not* rely on guaranteed tail calls the way SR does
(`llasm.d:2979`).

---

*Report prepared by teammate `sr-analyst`. Write scope: `reports/sr-analysis.md` only; no other file
in the repository was modified.*
