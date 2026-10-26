#!/usr/bin/env sh
set -eu
"$(dirname "$0")/build.sh"
ctest --test-dir build --output-on-failure
