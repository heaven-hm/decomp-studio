# IR migration surface: every emitted shape, its weight, and where it maps

**Owner:** `ir-migration-analyst` (teammate)
**Deliverable:** this file. Write scope was exactly `reports/ir-migration-surface.md`; no source,
test, fixture or other report was modified. No state-changing git command was run.

**Revision:** analysis run at `87a8aa1` (`87a8aa1f78e623530d636c23bff25012fc97121d`), branch
`feature/x86-x64-arm64-mvp`. HEAD has since moved to `db505ba` (verification/runtime/CLI work by
other members); the four files below were re-hashed afterwards and are **unchanged**, and the
golden test still reports `22 passed, 0 failed`, so every line number and weight here is still
valid. Files the line numbers below are pinned to:

| file | sha256 |
|---|---|
| `core/semantics/x86_64_lifter.cpp` | `a25863b571c24cdd43ca01dbf1dca938cb58b387d6bb393da20d802bedd0a665` |
| `core/ir/ir.hpp` | `6487da2ddbdbf52c7f13934a9dd2771ebe5b9d60f2aede8a82c053bad0f9dcc6` |
| `core/ir/cpp_backend.cpp` | `737c339cc63e2995d8c8bbc034a9119f5143f2dedf92114e73d120c2b60e045e` |
| `core/ir/ir.cpp` | `7569550b0d4b13f656f13666409b6f4b06d596fbebcf262adc874cf87423e398` |

The lifter is a moving target; a change to it invalidates every line number here.

---

## 1. Headline

* **178** `emit(...)` call sites in `core/semantics/x86_64_lifter.cpp`, plus **3** `push_back`
  sites and **9** calls to the `emit_trap`/`emit_return` lambdas = **190 statement-producing
  sites**.
* The 22 fixtures the golden test pins contain **24,518 IR statements**, of which **911 are
  structured today (3.72%)** — 710 `Label`, 201 `Return`, 0 `Trap`. The `1461 / 71 / 4.86%`
  line quoted for `arith.exe` is the same corpus scaled down to one binary.
* The **single largest shape is not an `emit(...)` site at all**: the trace line pushed at
  `x86_64_lifter.cpp:1680` is one statement per instruction — **11,830 statements, 48.25%** of
  everything.
* The **top three shapes are 19,902 statements = 81.17%**, and between them they need **one new
  `StatementKind`** (`Trace`) and touch **three helper functions**.
* Four shapes do **not** render what the lifter currently emits: `CallImport` and
  `CallIndirect` are missing the return-address argument the lifter passes, `CallImportTail`
  has no kind at all, and `Trap` has one site (`:964`) that bypasses `emit_trap`.
* **22,824 of 24,518 statements (93.1%)** were proved to round-trip byte-identically through a
  structured field decomposition, with **0 failures** (§2.3).
* **Exactly one** statement in the whole corpus fuses two effects onto one line
  (`x87.exe:1061`, from `:1656`); it is the only place where a naive Assign+JumpIf migration
  would change bytes.

---

## 2. Method and evidence

### 2.1 Commands

```
# corpus: the golden test's own scope, target macos-arm64 (what the baseline pins)
for f in tests/fixtures/apps/bin/*.exe; do
  n=$(basename "$f" .exe)
  ./build/recomp-studio translate "$f" --target macos-arm64 --output /tmp/irscan/out/$n
done
# -> 22 succeeded, 1 failed:
#    unsupported_instruction: error: unsupported instruction 'rdmsr' at 0x1400010beull

./build/recomp-studio coverage tests/fixtures/apps/bin/arith.exe
# architecture:   x86_64
# functions:      5
# instructions:   688
# lifted:         688 (100.00%)
# unsupported:    0
# ir statements:  1461 (71 structured, 4.86%)

python3 tests/golden/golden_code_test.py ./build/recomp-studio tests/fixtures/apps \
        tests/golden/generated_code.sha256
# checked 22 fixtures against the golden baseline
# 22 passed, 0 failed
```

The golden run is the control: the binary in `build/` still produces byte-identical `guest.cpp`,
so every weight below is measured on **the same output the golden test pins**.

`tests/fixtures/apps/bin/*.exe` were already present and current
(`cd tests/fixtures/apps/bin && shasum -a 256 -c fixtures.sha256` → all `OK`, newest `.exe`
16:14 vs newest source 14:30), so `build.sh` was **not** re-run — it would have rewritten
`bin/*.exe` and `fixtures.sha256`, outside this task's write scope.

### 2.2 Weight measurement, and its reconciliation

Weights are counted from the generated `guest.cpp` **function bodies only** (the
`recompiled_image_blob[]` byte array accounts for hundreds of lines that are not IR statements
and was excluded), grouping continuation lines into one statement.

Reconciliation against the product's own census:

| | statements |
|---|---:|
| sum of `coverage` `ir statements:` over the 22 translated fixtures | **24,518** |
| statements parsed out of those 22 `guest.cpp` bodies | **24,518** |
| per-fixture disagreement | **0 of 22** |
| `unsupported_instruction.exe` (not translatable under `strict`) | 14 (outside the golden scope) |

So the shape table in §4 is not an estimate: it partitions the census exactly.

### 2.3 Byte-identity proof per shape

For every statement whose text decomposes into structured fields, the fields were re-rendered
with the exact `cpp_backend.cpp` format strings and compared to the original line:

| shape | round-trip OK | not round-trippable |
|---|---:|---:|
| `Trace` | 11,830 | 0 |
| `Assign` (`context->… = <expr>;`) | 6,093 | 0 |
| `StoreMemory` | 1,979 | 0 |
| `CallIndirect(+ret)` | 866 | 0 |
| `Label` | 710 | 0 |
| `JumpIf` | 516 | 0 |
| `CallGuest` | 443 | 0 |
| `Return` | 201 | 0 |
| `Jump` | 118 | 0 |
| `CallImport(+ret)` | 50 | 0 |
| `CallImportTail` | 18 | 0 |
| **total** | **22,824** | **0** |

This says a structured form *can* reproduce the current bytes; it does not say the current
backend renders them (see §5.2 — `CallImport`/`CallIndirect` currently render **fewer**
arguments than the lifter emits).

---

## 3. The `emit(...)` call sites, by shape family

Site counts are static; they are a poor proxy for weight (20 `operand_write_statement` sites
produce 8,068 of the 24,518 statements) and are given here only so the migration can be sized
by edit count.

| # | shape family | emit sites | lines in lifter |
|---|---|---:|---|
| 1 | `operand_write_statement(...)` → *either* `context->registers[N] = <expr>;` *or* `store_guest_memory(...)` | 20 | 621, 673, 779, 789, 801, 806, 821, 850, 857, 868, 885, 893, 922, 982, 992, 1222, 1231, 1248, 1252, 1569 |
| 2 | `register_write_statement(...)` → `context->registers[N] = <expr>;` | 2 | 1154, 1159 |
| 3 | literal `context->registers[N] = <expr>;` | 12 | 915, 928, 932, 936, 949, 953, 986, 987, 1086, 1535, 1536, 1656 |
| 4 | literal `context-><flag> = <expr>;` | 6 | 1112, 1113, 1482, 1483, 1484, 1640 |
| 5 | runtime helper call `name(context, …);` — x87 45, vector/scalar 18, table-driven 13, vector load/store 4, mul/div 3, mxcsr 2, flag 2, cpuid 1, set_eflags 1 | 89 | e.g. 486, 555, 830, 1123, 1288, 1451, 1479, 1635 |
| 6 | `(void)name(context);` | 6 | 1314, 1370, 1404, 1467, 1609, 1615 |
| 7 | multi-statement block `{ … }` (14 one-shot, the `enter` display-frame block at 1529–1533, and 2 `emit(body)` at 769/1077) | 20 calls / 16 sites | 813, 942, 1264, 1269, 1334, 1338, 1366, 1456, 1459, 1490, 1515, 1529–1533, 1541, 1602, 769, 1077 |
| 8 | `push_guest_stack(context, <expr>);` | 5 | 970, 974, 1013, 1136, 1525 |
| 9 | `std::memcpy(context->vector_registers[..], …, N);` | 4 | 508, 534, 614, 1168 |
| 10 | `invoke_guest_indirect(context, <expr>, <retaddr>);` | 1 | 1017 |
| 11 | `invoke_win32_import(context, "lib", "sym", <retaddr>);` | 1 | 1006 |
| 12 | `invoke_win32_import_tail(context, "lib", "sym");` | 1 | 1026 |
| 13 | `jump_guest_indirect(context, <expr>);` | 1 | 1041 |
| 14 | `if (<cond>) goto label_N;` | 2 | 1050, 1648 |
| 15 | `if (<cond>) <assign>;` (no goto) | 2 | 999, 1052 |
| 16 | `guest_function_<addr>(context);` | 2 | 1014, 1034 |
| 17 | `goto label_N;` | 1 | 1037 |
| 18 | `return_from_guest_function(context, <n>);` | 2 | 1094, 1099 |
| 19 | `recomp_trap(context, "…");` emitted as text (bypasses `emit_trap`) | 1 | 964 |
| — | **subtotal, `emit(...)` sites** | **178** | |
| 20 | `emit_trap(...)` / `emit_return()` lambda calls | 3 / 6 | 1104, 1500, 1579 / 965, 1028, 1035, 1043, 1095, 1100 |
| 21 | `push_back` sites that are not `emit` | 3 | 1678 (`Label`), 1680 (`Trace`), 1687 (epilogue `Return`) |
| — | **total statement-producing sites** | **190** | |

Row 1's 20 sites are shared between `Assign` and `StoreMemory`: `operand_write_statement`
(`:408`) returns a register write for a register operand and a `store_guest_memory` call for a
memory operand. Row 3's `:1656` is the fused Assign+JumpIf line of §7.

---

## 4. Generated-statement weight table

Measured over the 22 golden fixtures, 24,518 statements. Shares sum to 100.00%.

| emitted shape | statements | % | example |
|---|---:|---:|---|
| `trace_instruction(context, 0x…ull); // <asm text>` | 11,830 | 48.25 | `trace_instruction(context, 0x140001000ull); // push rsi` |
| `context->registers[N] = <expr>;` | 6,089 | 24.83 | `context->registers[1] = static_cast<std::uint32_t>(0xfffffff5ull);` |
| `context-><flag> = <expr>;` | 4 | 0.02 | `context->direction_flag = 1;` |
| `store_guest_memory(context, <addr>, <val>, <w>);` | 1,979 | 8.07 | `store_guest_memory(context, mask_guest_address(context->registers[4] + 60), 0x0ull, 4);` |
| `invoke_guest_indirect(context, <expr>, <ret>);` | 866 | 3.53 | `invoke_guest_indirect(context, context->registers[6], 0x140001021ull);` |
| `name(context, <a>, <b>, …);` (helper family) | 918 | 3.74 | `compare_with_flags(context, context->registers[0], 0x9ull, 8);` |
| `(void)name(context);` | 12 | 0.05 | `(void)x87_pop(context);` |
| `label_N:;` | 710 | 2.90 | `label_5368713216:;` |
| `push_guest_stack(context, <expr>);` | 653 | 2.66 | `push_guest_stack(context, context->registers[6]);` |
| `if (<cond>) goto label_N;` | 516 | 2.10 | `if (evaluate_condition(context, ConditionCodeSign)) goto label_5368713561;` |
| `guest_function_<addr>(context);` | 443 | 1.81 | `guest_function_140001000(context);` |
| `return;` | 201 | 0.82 | `return;` |
| `goto label_N;` | 118 | 0.48 | `goto label_5368713561;` |
| `return_from_guest_function(context, <n>);` | 86 | 0.35 | `return_from_guest_function(context, 0);` |
| `invoke_win32_import(context, "lib", "sym", <ret>);` | 50 | 0.20 | `invoke_win32_import(context, "kernel32.dll", "GetStdHandle", 0x140001118ull);` |
| `invoke_win32_import_tail(context, "lib", "sym");` | 18 | 0.07 | `invoke_win32_import_tail(context, "kernel32.dll", "ExitProcess");` |
| `{ <multi-statement, C++ temporaries> }` | 9 | 0.04 | `{ const std::uint64_t bit = …; context->carry_flag = …; context->registers[13] = …; }` |
| `std::memcpy(context->vector_registers[a], …, N);` | 8 | 0.03 | `std::memcpy(context->vector_registers[2], context->vector_registers[0], 16);` |
| `if (<cond>) <assign>;` | 8 | 0.03 | `if (evaluate_condition(context, ConditionCodeLess)) context->registers[12] = …;` |
| `recomp_trap(context, "…");` | 0 | 0.00 | not reached by any fixture (paths at `:1104`, `:1500`, `:1579`) |
| **total** | **24,518** | **100.00** | |

The 6,089 `context->registers[N] = …;` statements decompose as: register copy 1,077 · address
(`lea`) 967 · `*_with_flags` result 887 · other expression 857 · helper call 775 · constant 706 ·
memory load 575 · stack pop 222 · partial byte/word write 23 (sums to 6,089). The remaining 4
assignment-shaped statements are `context-><flag> = …;`.

Per-fixture sanity check (`arith.exe`, the number quoted in the task): 688 `Trace` (47.09%),
426 `Assign` (29.16%), 78 `StoreMemory` (5.34%), 61 `Label`, 46 `JumpIf`, 31 `PushStack`,
30 `CallIndirect`, 23 `CallGuest`, 13 `Jump`, 10 `Return`, 4 `ReturnFromGuest` = 1,461.

---

## 5. Mapping decisions

### 5.1 Maps to an EXISTING `StatementKind`, no IR change

| shape | stmts | kind | render in `cpp_backend.cpp` | note |
|---|---:|---|---|---|
| `context->registers[N] = <expr>;` + `context-><flag> = <expr>;` | 6,093 | `Assign` | `dest + " = " + expr + ";"` | exact; 6,093/6,093 round-trip as `dest = expr;` text, of which 6,092 are pure assignments and 1 (`x87.exe:1061`) is the fused line of §7 |
| `store_guest_memory(context, <addr>, <val>, <w>);` | 1,979 | `StoreMemory` | `store_guest_memory(context, addr, expr, width);` | exact |
| `label_N:;` | 710 | `Label` | `label + ":;"` | **already migrated** |
| `if (<cond>) goto label_N;` | 516 | `JumpIf` | `if (expr) goto label;` | exact |
| `guest_function_<addr>(context);` | 443 | `CallGuest` | `symbol + "(context);"` | exact |
| `return;` | 201 | `Return` | `return;` | **already migrated** |
| `goto label_N;` | 118 | `Jump` | `goto label;` | exact |
| `recomp_trap(context, "…");` | 0 here | `Trap` | `recomp_trap(context, "text");` | **already migrated**; site `:964` still bypasses `emit_trap` |

Implementation note for `Assign`: do **not** recover `destination`/`expression` by splitting the
finished string at the first `" = "` — a block statement (`:1530`) contains
`for (std::uint32_t nesting = 1; …)`, so text surgery is not safe in general. `register_write_statement`
(`:332`) already builds both halves; make it return them (or fill a `Statement`) and let the
four width variants keep their exact RHS wrapping.

### 5.2 Maps to an existing kind but needs a NEW FIELD on `Statement`

| shape | stmts | kind | what is missing |
|---|---:|---|---|
| `invoke_guest_indirect(context, <expr>, <retaddr>);` | 866 | `CallIndirect` | backend renders **2** args (`invoke_guest_indirect(context, expr);`); the lifter passes the return address `instruction.address + instruction.size` as a 3rd. Needs `std::uint64_t return_address` (or `expression2`). |
| `invoke_win32_import(context, "lib", "sym", <retaddr>);` | 50 | `CallImport` | same: backend renders 3 args, the lifter passes 4. Needs `return_address`. |
| `invoke_win32_import_tail(context, "lib", "sym");` | 18 | `CallImport` + flag, or a new kind | `CallImport` renders the *non*-tail callee; a tail call must not push a return address. Needs `bool tail` (or `CallImportTail`). |

### 5.3 Needs a NEW `StatementKind`

| proposed kind | fields | shape | stmts | notes |
|---|---|---:|---|---|
| `Trace` | `text` (asm text); `address_of_instruction` already carries the address | `trace_instruction(context, 0x…ull); // <asm>` | 11,830 | **not** `Comment`: `ir::census` explicitly excludes `Comment` from `structured`, so migrating the trace as a comment would move the number by 0. Backend needs the `0x…ull` formatter — `format_hex` is currently file-local (`x86_64_lifter.cpp:246`) and already duplicated in `project_generator.cpp:11` and `repair_harness.cpp:17`, so a fourth copy is the established pattern. |
| `PushStack` | `expression` | `push_guest_stack(context, <expr>);` | 653 | 5 sites; `pop_guest_stack` is an expression, not a statement, so it stays inside `Assign`/helper calls. |
| `ReturnGuest` | `immediate` (`int`) | `return_from_guest_function(context, <n>);` | 86 | 2 sites; not the same as `Return` (it also unwinds the guest frame by `n`). |
| `HelperCall` | `symbol` (`std::string`), `arguments` (`std::vector<std::string>`), `discard_result` (`bool`) | `name(context, <a>, <b>, …);` and `(void)name(context);` | 930 | callee names are fixed at lift time even when chosen from a table (`helper->second`, `arithmetic_helpers().at(mnemonic)`), so `symbol` is a plain string; the arguments remain opaque expression text, which the model already allows (`Assign.expression` is a string). |
| `CopyVectorRegister` | `destination_index`, `source_index`, `width` | `std::memcpy(context->vector_registers[a], context->vector_registers[b], N);` | 8 | a register-file copy, **not** guest memory: it must not become `StoreMemory`. |
| `Block` | `body` (`std::vector<Statement>`) | `{ … }` | 9 | see §5.4 — the current instances also need C++ temporaries, so this kind alone is not enough. |
| `IfThen` | `condition`, `body` | `if (<cond>) <statement>;` | 8 | `JumpIf` requires a label, so this cannot be expressed today. |
| `JumpIndirect` | `expression` | `jump_guest_indirect(context, <expr>);` | 0 | 2 sites (`:1041`, `:1052`), **not exercised by any fixture** — unmeasurable weight, and untestable against the golden baseline. |

### 5.4 Cannot be structured with the current model

| shape | stmts | why |
|---|---:|---|
| `{ const std::uint64_t bit = …; const std::uint64_t original = …; context->carry_flag = …; context->registers[13] = …; }` | 9 | embeds **C++ local temporaries** (`const std::uint64_t bit = …`) and a braced scope. `Statement` has no notion of a local or of a nested statement list; structuring it means adding both `Block` and a `Local`/temporary concept, i.e. modelling host-language SSA temporaries in an architecture-neutral IR. |
| `if (<cond>) context->registers[12] = …;` | 8 | a conditional whose body is a statement, not a label. Needs `IfThen` (§5.3) or a rewrite into labels, which would change bytes. |
| `name(context, …)` helper family | 930 | the *statement* is structurable (§5.3 `HelperCall`) but every argument is an arbitrary C++ expression, including nested calls (`x87_write(context, 0, std::sqrt(x87_read(context, 0)));`). If a second backend must understand these, the arguments have to become IR expressions too — that is a second, much larger migration (an expression IR), not a statement migration. |
| `context->registers[0] = 0x1ull; context->registers[2] = 0;` (`:1086`, `xgetbv`) | 0 in corpus | two effects on one line. Splitting it into two `Assign` statements is the correct model and **changes the generated bytes**; because no fixture executes `xgetbv`, the golden test will *not* catch it. |

---

## 6. Ranked migration order

Ranking rule: percentage points moved per unit of risk (number of sites, new IR fields, new
kinds, hazards). Cumulative percentages are measured on the 24,518-statement corpus.

| rank | shape | kind work | stmts | +% | cumulative | risk / why here |
|---:|---|---|---:|---:|---:|---|
| **1** | `Trace` | 1 new kind, 1 site (`:1680`) | 11,830 | +48.25 | **51.97%** | Biggest single move in the codebase for one edit. Fixed template, no interaction with any other shape, 11,830/11,830 round-trip verified. |
| **2** | `Assign` (incl. flag writes) | existing `Assign`, 2 helpers + 18 literal sites | 6,093 | +24.85 | **76.82%** | Existing kind, exact render. Only hazard is the fused line at `:1656` (§7) — keep that one site Verbatim. |
| **3** | `StoreMemory` | existing `StoreMemory`, 20 sites via 1 helper | 1,979 | +8.07 | **84.89%** | The three fields are already separate parameters of `operand_write_statement` (`:408–418`) — no string surgery, no new field, no hazard. |
| 4 | `CallIndirect` (+`return_address`) | existing kind + 1 IR field | 866 | +3.53 | 88.42% | Additive field; `cpp_backend.cpp:25` must render the 3-arg form. |
| 5 | `PushStack` | 1 new kind, 5 sites | 653 | +2.66 | 91.08% | Trivial shape, one expression. |
| 6 | `JumpIf`, `Jump`, `CallGuest` | existing kinds | 1,077 | +4.39 | 95.48% | Pure mechanical conversion, exact renders. |
| 7 | `HelperCall` family | 1 new generic kind, 95 sites (89 + 6 discarded) | 930 | +3.79 | 99.27% | High site count, low per-site risk; the kind is a general escape hatch for the remaining runtime helpers. |
| 8 | `ReturnGuest` | 1 new kind, 2 sites | 86 | +0.35 | 99.62% | Small, self-contained. |
| 9 | `CallImport`, `CallImportTail` | `return_address` + tail flag | 68 | +0.28 | 99.90% | Same field as rank 4; only 68 statements, so it can ride along with rank 4. |
| 10 | `Block`, `IfThen`, `CopyVectorRegister`, `JumpIndirect` | new kinds, some not expressible | 25 | +0.10 | 100.00% | Not worth doing before the above; `Block` needs a temporaries concept and `JumpIndirect` is untestable against the current fixtures. |

**Recommended first three: `Trace`, then `Assign`, then `StoreMemory` — 84.89% structured,
reaching the same 84.89% whether or not `StoreMemory` is done first.**

* `StoreMemory` first is the better *dry run* if the team wants to exercise the whole pipeline
  (lifter edit → backend render → golden) on a shape with zero hazards before touching the
  48% one; the set and the cumulative result are identical.
* `Trace` first is the better *value* ordering: it is one call site and one new kind, and it
  alone takes the reported number from 3.72% to 51.97%.
* What must **not** be done first: `CallImport`/`CallIndirect`. They look like free wins (the
  kinds already exist) but the kinds currently render the **wrong arity**, so migrating them
  without adding `return_address` would either fail the golden test or, worse, silently change
  the call ABI.

---

## 7. Hazards found

1. **`x86_64_lifter.cpp:1656` fuses two effects on one line** —
   `context->registers[1] = mask_guest_address(context->registers[1] - 1); if (context->registers[1] != 0) goto label_…;`
   It is the only such line in the corpus (`x87.exe:1061`). Migrating it as `Assign` + `JumpIf`
   emits two lines and **breaks the golden test**; leave that site Verbatim until the baseline
   is deliberately regenerated. Because the line is inside a `rep`-prefixed loop path, it is
   reached by exactly one fixture.
2. **`x86_64_lifter.cpp:1086` (`xgetbv`) emits two statements on one line and no fixture
   executes it.** Splitting it is correct modelling but changes bytes that the golden test does
   not cover. Either keep it Verbatim or regenerate the baseline with a note.
3. **`CallImport`/`CallIndirect` render the wrong arity** (§5.2). `cpp_backend.cpp` lines 22 and
   26 must gain the return-address argument, otherwise the existing kinds are a trap.
4. **`recomp_trap` has a second, unstructured path**: `:964` (`push <register>`) emits the text
   directly instead of calling `emit_trap`. One site, no fixture reaches it.
5. **`Trap` count in the census is 0 for the golden corpus.** The "3 traps" in the task
   description are not reproducible against this revision: no fixture emits `recomp_trap`, and
   the 911 structured statements are 710 `Label` + 201 `Return`. The only traps live on paths
   (`:1104` `x87`-disabled, `:1500`, `:1579`) that these fixtures do not take.
6. **The census counts non-`Comment` statements as structured.** Any new kind counts, including
   `Trace`; conversely a `Comment` migration would count as zero progress. Decide deliberately
   whether a debug trace is "structured semantics" — if it is not, the honest fix is to change
   `ir::census` (exclude `Trace`) rather than to leave 48% of the metric on an instrumentation
   line.

---

## 8. Caveats

* Weights are from the 22 fixture binaries the golden test pins. `packed.exe` alone contributes
  4,249 statements (17%), and `unsupported_instruction.exe` (14 statements) cannot be
  translated under `strict`, so it is outside both the golden baseline and the weight table.
* `jump_guest_indirect` (`:1041`, `:1052`) has **zero** occurrences in the corpus: its weight is
  unknown and any migration of it is unverifiable against the current golden test.
* Site counts in §3 are a static reading of the source at revision `87a8aa1`; several families
  (`x87`, vector, table-driven helpers) multiply at runtime, which is why §4 counts statements.
* The round-trip proof in §2.3 shows a structured form *can* reproduce the current bytes; it is
  not a statement that any particular implementation will.

---

## 9. Reproduce

```
cd /Users/haseeb-mir/Documents/Code/recomp-studio
mkdir -p /tmp/irscan/out
for f in tests/fixtures/apps/bin/*.exe; do
  n=$(basename "$f" .exe); mkdir -p /tmp/irscan/out/$n
  ./build/recomp-studio translate "$f" --target macos-arm64 --output /tmp/irscan/out/$n
done
./build/recomp-studio coverage tests/fixtures/apps/bin/arith.exe
python3 tests/golden/golden_code_test.py ./build/recomp-studio tests/fixtures/apps \
        tests/golden/generated_code.sha256
```

The analysis scripts used here (`extract_emits.py`, `analyze_lines.py`, `detail.py`,
`site_families.py`, `roundtrip.py`) are in `/tmp/irscan/` and are throwaway; they read only the
lifter source and the generated `guest.cpp` under `/tmp/irscan/out/`.
