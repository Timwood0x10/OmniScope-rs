cmake_minimum_required(VERSION 3.24)

# Export compile commands for IDE/clang-tidy integration
# NOTE: This must be set before project() to ensure it takes effect
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Force the LLVM-bundled clang when LLVM_PREFIX is set (avoids version
# mismatch between the system AppleClang and the Homebrew LLVM opt).
# NOTE: This must be set before project() to ensure compile_commands.json
# uses the correct compiler.
if(DEFINED ENV{LLVM_PREFIX} OR DEFINED LLVM_PREFIX)
    file(TO_CMAKE_PATH "$ENV{LLVM_PREFIX}" _LLVM_PREFIX)
    if(NOT _LLVM_PREFIX AND DEFINED LLVM_PREFIX)
        set(_LLVM_PREFIX "${LLVM_PREFIX}")
    endif()
    if(EXISTS "${_LLVM_PREFIX}/bin/clang++")
        set(CMAKE_C_COMPILER "${_LLVM_PREFIX}/bin/clang" CACHE FILEPATH "C compiler" FORCE)
        set(CMAKE_CXX_COMPILER "${_LLVM_PREFIX}/bin/clang++" CACHE FILEPATH "C++ compiler" FORCE)
        message(STATUS "Using LLVM-bundled compiler: ${_LLVM_PREFIX}/bin/clang++")
    endif()
endif()

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