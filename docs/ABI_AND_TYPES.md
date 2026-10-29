# ABI and types

How the guest's calling conventions are represented, how arguments are read, and what is
**not** recovered. The first half is implemented and cited; the second half is a gap and says
so.

## The problem, stated exactly

A recovered function is ordinary C++ compiled by clang for the host. The guest is x86 or
x86-64 Windows. **The host compiler's default convention is not the guest's**, so every
crossing between generated code and the runtime has to state which convention applies rather
than hope. On AArch64 in particular there is no register that corresponds to ECX, so
"`this` is in ECX" has to be modelled, not inherited.

## The two guest ABIs, as implemented

### x86 (PE32) -- arguments on the stack

`win32_import_argument_offset` (`runtime/win32_abi.hpp`) computes where an argument sits
relative to the stack pointer, **counting the return address at `[esp]`**:

```cpp
inline std::uint64_t win32_import_argument_offset(int index, bool this_call) {
  const auto slot = this_call ? index - 1 : index;
  return 4 + static_cast<std::uint64_t>(slot < 0 ? 0 : slot) * 4;
}
```

Three conventions are distinguished:

| convention | where the arguments are | who cleans the stack |
|---|---|---|
| `cdecl` | on the stack from `[esp+4]` | the caller |
| `stdcall` | on the stack from `[esp+4]` | the **callee**, via `ret N` |
| `thiscall` | `this` in **ECX**, the rest on the stack | the callee |

`thiscall` is the one worth naming, because its offset arithmetic is not obvious: with `this`
in ECX rather than on the stack, **the first *stack* argument is argument 1**, so the index is
shifted by one. The header records why this matters in practice -- "GCC emits this convention
for every member function it calls through an import, which is what `mov ecx, eax` before the
call means at the call site."

### x86-64 (PE32+) -- the Microsoft register order

`import_argument` (`runtime/recomp_runtime.hpp`) reads the first four arguments from the
registers the Microsoft x64 ABI assigns:

| argument | register | index in `GuestContext::registers` |
|---|---|---|
| 1 | RCX | 1 |
| 2 | RDX | 2 |
| 3 | **R8** | **8** |
| 4 | **R9** | **9** |

The third and fourth are `R8` and `R9`, not `RBX` and `RCX` or any consecutive run -- a
detail that a test-harness bug in this project got wrong before the ABI was written down.

## How a shim asks for its arguments

A shim calls `import_argument(context, index)` and **does not need to know which convention
brought it there**. The dispatcher sets the convention for the import being dispatched
(`win32_import_this_call()`) and the accessor applies it. That is the reason the 655-entry
table in `runtime/win32_abi.hpp` can be a plain data table rather than 655 functions that
each re-derive their own calling convention.

Each entry is:

```cpp
struct Win32ImportAbi {
  const char* library_name;
  const char* symbol_name;
  int argument_count;
  bool callee_cleans_stack;   // stdcall: the callee pops
  bool this_call = false;     // `this` in ECX; the first stack argument is argument 1
};
```

`argument_count` and `callee_cleans_stack` are what let the dispatcher pop the right number
of bytes after a shim returns, so a stdcall import does not corrupt the guest stack.

## Return values

- **x86-64**: the low half of RAX for integers and pointers; XMM0 for floating point, and the
  single-precision math shims write a float's **bit pattern** into the low half of the result
  register, which is where the guest reads XMM0 from.
- **x86**: EAX, and x87 ST(0) for floating point, which this project models as doubles.
- **Struct returns**: **not modelled.** A function returning a struct by hidden pointer is
  treated as returning a pointer-sized value. This is a gap, not a decision, and it is
  reachable by any program whose imports return structures by value.

## What is NOT recovered -- the type gap

**There is no type recovery.** The directive's §12 asks for recovered structures, field
offsets, packing and alignment, with compile-time assertions such as
`static_assert(sizeof(GameVector) == EXPECTED_SIZE)`. **None of that exists.**

Concretely, what the project has and does not have:

| capability | state |
|---|---|
| calling conventions of imports | **implemented** (the table above) |
| calling conventions of *recovered guest functions* | **partially** -- derived from `ret N` and reported by `ghidra-reconcile`, but **not applied** to code generation |
| integer and pointer widths | implemented (`guest_pointer_width`, 4 or 8) |
| struct layout, field offsets, packing | **not implemented** |
| recovered types from Ghidra | **imported as text, not reconciled** |
| compile-time layout assertions | **not implemented** |

A consequence worth stating: the delivered source contains **no recovered type names**. A
reader sees `context->registers[1]` and `load_guest_memory(context, address, 4)`, not a
`GameVector`. That is honest low-level recompilation -- `docs/ARCHITECTURE.md` classifies it
as such -- and it is **not** the "readable source" the long-term objective describes. Closing
that gap is what the type-recovery work is for, and it is not started.

## The rule that governs changes here

From the reconciliation rules, and enforced in `ghidra-reconcile`: **a calling convention is
not changed without an ABI test.** The reconciler therefore *reports* the convention it
derived and applies nothing. A wrong convention does not fail to compile -- it corrupts the
stack at run time, which is the kind of defect that survives a build and dies in a
differential run.
