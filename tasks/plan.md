# Implementation Plan: General Windows PE Runtime for `autorecomp`

## Goal

Make `recomp-studio autorecomp <Windows.exe> --buildrun` produce a native
macOS executable, and later a `.app` bundle, by combining the existing x86/x64
static lifter with a general host runtime. The runtime must be shared by every
generated project, pass differential verification where the reference supports
the API, and fail with a precise unsupported capability when it does not.

The local `igi-recomp`, `cricket07-browser`, `project-igi-browser`, and
`N64Recomp` projects provide patterns and selectively reusable code. Their
game-specific profiles, assets, renderer assumptions, and unrelated ISA code
remain outside the general runtime.

## Feature-branch audit

`origin/feature/x86-x64-arm64-mvp` currently contributes commit `26ab924`, a
documentation-only import-report measurement. It does not contain the runtime
services below. The current audit branch already includes the feature branch's
architecture and verification merges through `76a39ec`.

Existing useful planning evidence:

- `reports/shim-port-plan.md` ranks the Win32 imports and records prerequisites.
- `reports/igi-recomp-reuse.md` inventories the MIT `igi-recomp` shim bodies.
- `reports/runtime-import-trace.md` records the candidate/reference coverage gap.
- `reports/reusable-runtime-patterns.md` maps the four local projects to
  general runtime boundaries.

## Architecture decisions

1. Keep translation, guest state, host services, and game profiles separate.
   `autorecomp` copies the shared runtime and a generated manifest into every
   project.
2. Use a typed guest handle table for files, windows, menus, device contexts,
   cursors, icons, and synchronization objects. Never expose host pointers as
   guest handles.
3. Make import ABI metadata data-driven and shared by the runtime and reference
   harness. Every new import gets a PE32 and PE32+ ABI test.
4. Port focused upstream implementations only when their license, revision,
   dependencies, and guest-memory assumptions are recorded. Use MIT/Apache
   sources directly where compatible; isolate LGPL/GPL components and their
   obligations.
5. Keep the native macOS backend independent from browser backends. The host
   contract should allow SDL/CoreGraphics/Metal on macOS and a future WebGPU
   backend without changing lifted guest code.
6. Treat an app as verified only when it builds, runs, completes, and matches
   the reference or has an explicitly documented reference limitation.

## Ordered task list

### Phase 1: Runtime foundation

1. Add a guest handle table with typed entries, allocation, lookup, close, and
   invalid-handle diagnostics. Verify both guest widths and reuse it in the
   existing handle-returning shims.
2. Add guest path translation and a sandboxed host-file policy. Preserve Windows
   drive/path behavior while preventing accidental access outside the selected
   app directory.
3. Add CRT stream objects and implement `fopen`, `fclose`, `fread`, `fwrite`,
   `fseek`, `ftell`, `feof`, and `ferror` through the handle table. Adapt only
   the relevant Wine/igi-recomp logic and add deterministic fixture files.
4. Extend the differential reference with the same stream model or mark stream
   calls as an explicit reference limitation; never report a false comparison.

Checkpoint A: `cube.exe` gets past `fopen`, a file-backed PE fixture passes on
PE32 and PE32+, focused runtime tests pass, and the generated project contains
the runtime changes automatically.

### Phase 2: General user32 platform

5. Add a platform interface for window creation, destruction, sizing, focus,
   visibility, and host event polling. Use the Cricket 07 and igi-recomp host
   split as the boundary.
6. Add a guest window-class registry. Port `RegisterClassA/W`,
   `CreateWindowExA/W`, `DestroyWindow`, and class lookup with validated guest
   callback addresses.
7. Add a message queue and guest callback dispatch for `GetMessage`,
   `PeekMessage`, `DispatchMessage`, `TranslateMessage`, `PostMessage`, and
   `PostQuitMessage`.
8. Add resource-backed `LoadIcon`/`LoadCursor` and stable menu handles. Remove
   the current temporary success/null adapters once real registries exist.

Checkpoint B: a small window fixture opens a native macOS window, receives a
keyboard event, calls its lifted window procedure, and exits deterministically.

### Phase 3: GDI and common controls

9. Add device-context and GDI object handles. Port the smallest Wine-backed
   operations needed by the corpus: pens, brushes, fonts, selection, clipping,
   rectangles, text, pixels, and blits.
10. Add common-control initialization and the controls actually used by the
    corpus. Keep Wine's initialization semantics and license notices separate
    from any host rendering implementation.
11. Add common dialogs only after file/path and window services exist; return
    documented failure values for unsupported dialogs rather than fake success.

Checkpoint C: `cube.exe` reaches its first rendering/message loop or reports the
next missing API after GDI with a trace and no fabricated divergence.

### Phase 4: Media, input, and timing

12. Generalize the Cricket 07/project-igi-browser host interfaces for input,
    timers, threads, audio, DirectInput, DirectSound, DirectDraw, and D3D8.
13. Add a deterministic scheduler and render-command recording where host APIs
    require main-thread access. Keep this optional for console-only binaries.
14. Add resource copying and app-directory configuration to the generated
    manifest.

### Phase 5: Native packaging and corpus validation

15. Add macOS `.app` packaging with executable, copied resources, manifest,
    and optional asset directory. Preserve the existing standalone executable
    output.
16. Run the exact win32 and win64 corpus loops in isolated per-app output
    directories, recording SHA-256, build, run, differential result, first
    blocker, and command logs.
17. Re-run the full test suite on a stable revision, then test representative
    console, CRT/file, GUI, and x64 applications end to end.
18. Merge the current feature branch again, review the diff, and create the PR
    against `feature/x86-x64-arm64-mvp` only after all required checks pass.

## Verification per task

Every runtime service requires:

- a focused unit test for ABI and guest memory behavior;
- a real PE32 and/or PE32+ fixture where applicable;
- a native run and differential comparison when the reference can model it;
- a retained `autorecomp.log` and first-blocker trace for real corpus apps;
- license/source revision entry before copied code is committed.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| GUI APIs require a real event loop and guest callback re-entry | Implement the platform/message contract before porting large control libraries. |
| Host handles and guest pointers are confused | Use typed handle tables and reject invalid handles. |
| Wine code pulls in large LGPL dependencies | Port only the measured function and isolate larger libraries behind an optional backend. |
| Candidate and reference shims diverge | Share ABI metadata and add reference support or explicit limitations per import. |
| Large generated apps consume disk and compile time | Use per-app output directories, incremental builds, and corpus slices. |
| A fake success lets startup continue incorrectly | Return documented failure values and retain first-call traces. |

## Definition of done

The plan is complete only when at least one small GUI app and one non-GUI app
produce native outputs through `autorecomp`, run from their generated output,
and pass the applicable verification gates. The final PR must include source
provenance, licenses, corpus evidence, and clear unsupported-capability reports.
