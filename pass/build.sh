#!/bin/bash
# build.sh — Build the SafetyExportPass LLVM plugin.
#
# Prerequisites:
#   - LLVM (14+) installed with development headers
#   - CMake 3.20+
#
# Usage:
#   ./build.sh            # build with default LLVM from llvm-config
#   LLVM_PREFIX=/opt/homebrew/opt/llvm ./build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Locate LLVM ─────────────────────────────────────────────────────
if [ -z "${LLVM_PREFIX:-}" ]; then
    LLVM_PREFIX="$(llvm-config --prefix)"
fi

echo "Using LLVM at: $LLVM_PREFIX"

# ── Configure & Build ───────────────────────────────────────────────
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
