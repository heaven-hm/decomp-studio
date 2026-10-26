#!/usr/bin/env bash
# Install the free Recomp Studio toolchain without modifying global Python packages.
set -euo pipefail

mode="dry-run"
prefix="${RECOMP_STUDIO_PREFIX:-$PWD/.tools}"
if [[ "${1:-}" == "--install" ]]; then mode="install"; fi
if [[ "${1:-}" == "--help" ]]; then
  echo "Usage: ./scripts/bootstrap.sh [--install]"
  echo "Default is a dry-run. Set RECOMP_STUDIO_PREFIX to choose the isolated Python-tool location."
  exit 0
fi

host_os="$(uname -s)"; host_arch="$(uname -m)"
echo "Recomp Studio bootstrap: ${host_os}/${host_arch} (${mode})"
run() { echo "+ $*"; [[ "$mode" == "install" ]] && "$@"; }
have() { command -v "$1" >/dev/null 2>&1; }

case "$host_os" in
  Darwin)
    if have brew; then run brew install cmake ninja llvm lief zydis ghidra radare2 z3; else echo "BLOCKED: install Homebrew from https://brew.sh first."; fi
    ;;
  Linux)
    if have apt-get; then run sudo apt-get update; run sudo apt-get install -y cmake ninja-build clang llvm python3 python3-venv z3 radare2
    elif have dnf; then run sudo dnf install -y cmake ninja-build clang llvm python3 z3 radare2
    elif have pacman; then run sudo pacman -Sy --noconfirm cmake ninja clang llvm python z3 radare2
    else echo "BLOCKED: supported Linux package manager not found (APT, DNF, or Pacman)."; fi
    ;;
  *) echo "BLOCKED: unsupported host OS: $host_os" ;;
esac

if have python3; then
  run python3 -m venv "$prefix/python"
  if [[ "$mode" == "install" ]]; then
    "$prefix/python/bin/python" -m pip install --upgrade pip
    "$prefix/python/bin/python" -m pip install capstone lief unicorn angr z3-solver frida-tools
  else
    echo "+ $prefix/python/bin/python -m pip install capstone lief unicorn angr z3-solver frida-tools"
  fi
else
  echo "BLOCKED: Python 3 unavailable; Python analysis tooling was not installed."
fi

echo "Manual-only proprietary adapters: Binary Ninja, IDA. They are never installed by this script."
echo "Run ./scripts/bootstrap.sh --install to perform the displayed actions."
