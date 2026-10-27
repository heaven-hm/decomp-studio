# Runtime generalization checklist

- [ ] Merge/review feature-branch changes before each phase.
- [ ] Implement typed guest handles.
- [ ] Implement guest path translation and file sandbox.
- [ ] Implement CRT stream imports and PE32/PE32+ tests.
- [ ] Align differential reference stream behavior.
- [ ] Implement the native window platform interface.
- [ ] Implement window classes and guest callback dispatch.
- [ ] Implement message queue imports.
- [ ] Implement resource-backed icons, cursors, and menus.
- [ ] Implement GDI object/device-context handles.
- [ ] Port measured GDI operations from compatible upstream sources.
- [ ] Implement measured common controls.
- [ ] Add input, timing, audio, and graphics host backends.
- [ ] Add deterministic scheduling/render-command recording where needed.
- [ ] Add resource copying and macOS `.app` packaging.
- [ ] Re-run representative real `.exe` files and the full test suite.
- [ ] Review and create the PR against `feature/x86-x64-arm64-mvp`.
