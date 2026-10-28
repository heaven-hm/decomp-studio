# Design boundaries and integration policy

Recomp Studio is a static recompiler for authorized Windows PE inputs. Its
correctness boundary is deliberately narrow: recover guest code, emit a native
host program, and compare that program with an independent execution model where
the configured verifier supports it.

## Why the project does not glue in every existing OSS project

The project keeps the lifter, guest address space, Win32 shim boundary, and
differential harness under one controlled model because those pieces must agree
on guest pointers, calling conventions, error propagation, and observable state.
Dropping in a complete operating-system runtime or a second decompiler would
change those contracts rather than automatically improve them.

The current policy is:

- Reuse external projects as research references and optional tools when their
  license and interface fit are documented.
- Copy only small, license-compatible implementations when the provenance,
  attribution, and behavioral contract can be preserved in isolation.
- Keep the generated guest runtime fail-closed: unsupported instructions,
  imports, formats, and runtime behavior must remain explicit failures.
- Do not vendor proprietary game files or make Wine, Ghidra, Remill, QEMU, or
  another large runtime a mandatory dependency of the core build.
- Keep third-party notices and source URLs next to any reused implementation.

This preserves a small, reviewable native runtime while leaving room for
optional providers behind stable interfaces.

## Integration backlog

| Area | Status | Tracking |
| --- | --- | --- |
| Wine-derived Win32 shim provider | Evaluation only; LGPL boundary and flat guest-memory ABI need a design | [#4](https://github.com/heaven-hm/recomp-studio/issues/4) |
| Remill or alternate lifter backend | Deferred; requires an IR adapter and Capstone/XED mapping | [#5](https://github.com/heaven-hm/recomp-studio/issues/5) |
| Full verification provenance/oracle/memory gates | In progress; shared Unicorn shims are not an independent OS oracle | [#11](https://github.com/heaven-hm/recomp-studio/issues/11) |
| Deterministic semantic naming | Not started; correctness-neutral readable C++ pass | [#3](https://github.com/heaven-hm/recomp-studio/issues/3) |
| User32/GDI/common-controls/graphics runtime | Incremental targeted shims; no broad GUI compatibility claim | Application audit report |

The backlog is intentionally explicit: a project may borrow a proven technique
without claiming that the entire upstream runtime has been integrated.

## Approved IGI runtime source inventory

The following local sources were audited for the unresolved IGI import groups.
Both repositories are MIT licensed; retain their copyright and license notices
with any substantial copied implementation. They use a different guest-context
ABI, so each adoption must be a small, tested adapter rather than a wholesale
file drop.

| Import family | Primary source | Fallback/reference | License | Adoption boundary |
| --- | --- | --- | --- | --- |
| DirectDraw / Direct3D 7 | `recomp-research/igi-recomp/shim/src/ddraw.c` | `project-igi-browser/host/ddraw7.c` | MIT | COM object and renderer-provider adapter |
| DirectSound | `recomp-research/igi-recomp/shim/src/dsound.c` | `project-igi-browser/host/dsound.c` | MIT | COM object and host-audio provider |
| DirectInput | `recomp-research/igi-recomp/shim/src/dinput.c` | `project-igi-browser/host/dinput.c` | MIT | COM object and host-input provider |
| AVI / video | `recomp-research/igi-recomp/shim/src/avifil32.c` | `project-igi-browser/host/mm.c` | MIT | file parser or explicit headless error path |
| WinMM / MCI | `recomp-research/igi-recomp/shim/src/winmm.c` | `project-igi-browser/host/mm.c` | MIT | audio-device and mixer adapter |
| OLE COM activation | `recomp-research/igi-recomp/shim/src/ole32.c` | `project-igi-browser/host/mm.c` | MIT | CLSID/IID dispatch adapter |

The audit source roots are `/Users/haseeb-mir/Downloads/recomp-research/igi-recomp`
and `/Users/haseeb-mir/Downloads/recomp-research/project-igi-browser`; their
licenses are at each repository's `LICENSE` file. This table is not a claim
that these subsystems have already been imported.
