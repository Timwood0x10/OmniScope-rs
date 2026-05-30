#!/bin/bash
# build.sh — Build the SafetyExportPass LLVM plugin.
#
# Prerequisites:
#   - LLVM 18+ installed with development headers
#   - CMake 3.24+
#
# Usage:
#   ./build.sh            # build with default LLVM from llvm-config
#   LLVM_PREFIX=/opt/homebrew/opt/llvm ./build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Locate LLVM ─────────────────────────────────────────────────────
if [ -z "${LLVM_PREFIX:-}" ]; then
    if ! command -v llvm-config &>/dev/null; then
        echo "Error: llvm-config not found. Install LLVM 18+ and ensure llvm-config is on PATH." >&2
        echo "  macOS:  brew install llvm@21" >&2
        echo "  Ubuntu: sudo apt install llvm-21-dev" >&2
        exit 1
    fi
    LLVM_PREFIX="$(llvm-config --prefix)"
fi

# ── Validate LLVM version (≥ 18) ───────────────────────────────────
LLVM_VERSION="$(llvm-config --version 2>/dev/null || echo "0")"
LLVM_MAJOR="${LLVM_VERSION%%.*}"
if [ "$LLVM_MAJOR" -lt 18 ]; then
    echo "Error: LLVM ${LLVM_VERSION} is too old — version 18+ required." >&2
    exit 1
fi
echo "Using LLVM ${LLVM_VERSION} at: ${LLVM_PREFIX}"

# ── Validate CMake version (≥ 3.24) ───────────────────────────────
CMAKE_VERSION="$(cmake --version 2>/dev/null | head -1 | awk '{print $3}')"
CMAKE_MAJOR="$(echo "$CMAKE_VERSION" | cut -d. -f1)"
CMAKE_MINOR="$(echo "$CMAKE_VERSION" | cut -d. -f2)"
if [ "$CMAKE_MAJOR" -lt 3 ] || { [ "$CMAKE_MAJOR" -eq 3 ] && [ "$CMAKE_MINOR" -lt 24 ]; }; then
    echo "Error: CMake ${CMAKE_VERSION} is too old — version 3.24+ required." >&2
    exit 1
fi

# ── Configure & Build ───────────────────────────────────────────────
export LLVM_PREFIX
cmake -B "$SCRIPT_DIR/build" -S "$SCRIPT_DIR" \
    -DLLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm" \
    -DCMAKE_BUILD_TYPE=Release

cmake --build "$SCRIPT_DIR/build" --config Release -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"

echo ""
echo "Build complete. Plugin: $SCRIPT_DIR/build/libSafetyExportPass.dylib"
echo ""
echo "Usage:"
echo "  opt -load-pass-plugin ./build/libSafetyExportPass.dylib \\"
echo "      -passes='safety-export' input.ll 2>/dev/null"
