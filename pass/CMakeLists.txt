cmake_minimum_required(VERSION 3.24)
project(SafetyExportPass LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Locate LLVM (18+ required) ──────────────────────────────────────
find_package(LLVM REQUIRED CONFIG
    HINTS "${LLVM_DIR}"
)

# Enforce minimum LLVM version
if(LLVM_PACKAGE_VERSION VERSION_LESS 18.0.0)
    message(FATAL_ERROR "LLVM ${LLVM_PACKAGE_VERSION} found, but version 18+ is required")
endif()

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

# Export compile commands for IDE/clang-tidy integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)