# Recomp Studio

Recomp Studio is an experimental static recompilation CLI. The current MVP
develops one small, verified path: genuine Windows x86/x64 PE input to a native
macOS ARM64 host executable. It rejects unsupported input and features instead
of simulating success.

## Build

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

## Foundation commands

```sh
build/recomp-studio --help
build/recomp-studio --version --json
build/recomp-studio doctor --json
```
