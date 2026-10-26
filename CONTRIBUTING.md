# Contributing to Recomp Studio

## Development setup

Use CMake, Ninja, a C++20 compiler, and Python 3. Validate every change with:

```sh
./scripts/test.sh
```

## Contribution rules

- Keep each change focused and provide regression coverage at a public CLI,
  parser, IR, generated-project, or verification seam.
- Preserve deterministic output and explicit unsupported diagnostics.
- Never add commercial executables, game assets, credentials, logs, caches, or
  generated build output to the repository.
- Do not claim compatibility without executable evidence.
- Include third-party provenance and license review before introducing external
  source or dependencies.

## Reporting changes

Use clear commit messages such as `feat:`, `fix:`, `test:`, `docs:`, or
`chore:`. Update `CHANGELOG.md` for user-visible behavior.
