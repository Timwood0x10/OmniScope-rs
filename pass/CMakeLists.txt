cmake_minimum_required(VERSION 3.20)
project(SafetyExportPass LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Locate LLVM ─────────────────────────────────────────────────────
find_package(LLVM REQUIRED CONFIG
    HINTS "${LLVM_DIR}"
)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION} at ${LLVM_DIR}")
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

# LLVM definitions and include paths
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

# ── Build the pass plugin ───────────────────────────────────────────
add_llvm_pass_plugin(SafetyExportPass
    SafetyExportPass.cpp

    LINK_COMPONENTS
    Core
    Support
)

# Export compile commands for IDE integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)