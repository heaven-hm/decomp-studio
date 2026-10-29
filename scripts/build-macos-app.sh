#!/usr/bin/env bash
# ==============================================================================
# build-macos-app.sh — Automated Static Recompiler & macOS .app Bundler
#
# Input:  Any Windows PE32 CLI or GUI executable (e.g., game.exe)
# Output: Native macOS ARM64 source code + native binary + Game.app bundle
# ==============================================================================
set -euo pipefail

# Resolve canonical path across symlinks
REAL_SCRIPT="$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}" 2>/dev/null || readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$REAL_SCRIPT")"
if [[ "$(basename "$SCRIPT_DIR")" == "scripts" ]]; then
  REPO_ROOT="$(dirname "$SCRIPT_DIR")"
else
  REPO_ROOT="$SCRIPT_DIR"
fi

# Ensure valid working directory even if invoked from a deleted/stale folder
cd "$REPO_ROOT" 2>/dev/null || true

RECOMP_STUDIO="${RECOMP_STUDIO_BIN:-${REPO_ROOT}/build/recomp-studio}"

usage() {
  cat << 'EOF'
Usage:
  ./build-macos-app.sh <input.exe> [output_dir] [--run]

Arguments:
  <input.exe>   Path to the Windows executable (.exe)
  [output_dir]  Target directory for generated source and .app (default: out/<game_name>)
  --run         Launch the compiled .app after build completes

Example:
  ./build-macos-app.sh /Users/haseeb-mir/Downloads/recomp-apps/win32/cube.exe
  ./build-macos-app.sh /Users/haseeb-mir/Downloads/recomp-apps/win32/mines.exe out/mines --run
EOF
  exit 1
}

if [[ $# -lt 1 ]] || [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
  usage
fi

INPUT_EXE="$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$1" 2>/dev/null || echo "$1")"
if [[ ! -f "$INPUT_EXE" ]]; then
  echo "Error: Input executable not found: $1"
  exit 1
fi

EXE_BASENAME="$(basename "$INPUT_EXE")"
GAME_NAME="${EXE_BASENAME%.*}"
# Capitalize first letter for nice macOS App name (e.g. cube -> Cube)
APP_TITLE="$(echo "${GAME_NAME:0:1}" | tr '[:lower:]' '[:upper:]')${GAME_NAME:1}"

SHOULD_RUN=false
OUTPUT_DIR=""

for arg in "${@:2}"; do
  if [[ "$arg" == "--run" ]]; then
    SHOULD_RUN=true
  elif [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$arg"
  fi
done

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="${REPO_ROOT}/out/${GAME_NAME}"
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$OUTPUT_DIR" 2>/dev/null || echo "$OUTPUT_DIR")"

echo "========================================================================"
echo "  Static Recompilation -> Native macOS .app Pipeline"
echo "  Input:      ${INPUT_EXE}"
echo "  Target:     macOS ARM64 (Apple Silicon)"
echo "  Output Dir: ${OUTPUT_DIR}"
echo "  App Bundle: ${OUTPUT_DIR}/${APP_TITLE}.app"
echo "========================================================================"

# Step 1: Ensure recomp-studio binary exists
if [[ ! -x "$RECOMP_STUDIO" ]]; then
  echo "[1/5] Building recomp-studio toolchain..."
  cmake -B "${REPO_ROOT}/build" -G Ninja "${REPO_ROOT}"
  ninja -C "${REPO_ROOT}/build" recomp-studio
else
  echo "[1/5] Found recompiler engine: ${RECOMP_STUDIO}"
fi

# Step 2: Translate PE32 -> C++ Source Code
echo "[2/5] Translating ${EXE_BASENAME} to native C++ source..."
"${RECOMP_STUDIO}" translate "${INPUT_EXE}" --output "${OUTPUT_DIR}"

GUEST_CPP="${OUTPUT_DIR}/guest.cpp"
RUNTIME_CPP="${OUTPUT_DIR}/recomp_runtime.cpp"

if [[ ! -f "$GUEST_CPP" ]]; then
  echo "Error: Source code generation failed. guest.cpp not found in ${OUTPUT_DIR}"
  exit 1
fi

SOURCE_LINES="$(wc -l < "${GUEST_CPP}" | tr -d ' ')"
SOURCE_SIZE="$(du -h "${GUEST_CPP}" | cut -f1)"
echo "✔ Source generated: ${GUEST_CPP} (${SOURCE_LINES} lines, ${SOURCE_SIZE})"

# Step 3: Compile with Clang for macOS ARM64
echo "[3/5] Compiling native ARM64 Mach-O executable with Clang..."
BINARY_NAME="${APP_TITLE}"
BINARY_OUT="${OUTPUT_DIR}/${BINARY_NAME}"

# Optimize: use -O1 for balanced compile-time and run-time performance
clang++ -std=c++20 -O1 -w \
  -target arm64-apple-macos11 \
  -I "${OUTPUT_DIR}" \
  -o "${BINARY_OUT}" \
  "${GUEST_CPP}" \
  "${RUNTIME_CPP}"

echo "✔ Binary compiled: ${BINARY_OUT} ($(file -b "${BINARY_OUT}"))"

# Step 4: Package into macOS .app Bundle
APP_BUNDLE="${OUTPUT_DIR}/${APP_TITLE}.app"
echo "[4/5] Packaging into ${APP_BUNDLE}..."

rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

# Copy binary
cp "${BINARY_OUT}" "${APP_BUNDLE}/Contents/MacOS/${BINARY_NAME}"
chmod +x "${APP_BUNDLE}/Contents/MacOS/${BINARY_NAME}"

# Create Info.plist
cat << PLIST_EOF > "${APP_BUNDLE}/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>${BINARY_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>com.recomp.${GAME_NAME}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>${APP_TITLE}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
</dict>
</plist>
PLIST_EOF

# Write PkgInfo
printf "APPL????" > "${APP_BUNDLE}/Contents/PkgInfo"

# Clean xattrs & ad-hoc codesign
xattr -cr "${APP_BUNDLE}"
codesign -s - --force --deep "${APP_BUNDLE}"

echo "✔ Application bundle successfully created and signed: ${APP_BUNDLE}"

# Step 5: Run / Verify
echo "[5/5] Verifying execution on macOS..."
set +e
python3 -c '
import subprocess, sys
try:
    p = subprocess.run([sys.argv[1], "--help"], stdin=subprocess.DEVNULL, timeout=3)
    sys.exit(p.returncode)
except subprocess.TimeoutExpired:
    sys.exit(0)
' "${APP_BUNDLE}/Contents/MacOS/${BINARY_NAME}" > "${OUTPUT_DIR}/app_stdout.log" 2> "${OUTPUT_DIR}/app_stderr.log"
RUN_EXIT=$?
set -e

echo "✔ Application executed with exit code: ${RUN_EXIT}"
echo "------------------------------------------------------------------------"
echo "  Build & Packaging Summary:"
echo "  Source Files: ${GUEST_CPP} (${SOURCE_LINES} lines)"
echo "  Mach-O Binary: ${BINARY_OUT}"
echo "  macOS App:     ${APP_BUNDLE}"
echo "  Logs:          ${OUTPUT_DIR}/app_stderr.log"
echo "------------------------------------------------------------------------"

if [[ "$SHOULD_RUN" == true ]]; then
  echo "Launching ${APP_TITLE}.app..."
  open "${APP_BUNDLE}" 2>/dev/null || open -a Terminal "${APP_BUNDLE}/Contents/MacOS/${BINARY_NAME}" || "${APP_BUNDLE}/Contents/MacOS/${BINARY_NAME}"
fi
