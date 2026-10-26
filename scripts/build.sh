#!/usr/bin/env sh
set -eu
cmake -S . -B build -G Ninja
cmake --build build
