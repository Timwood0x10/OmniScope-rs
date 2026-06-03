# OmniScope-rs Makefile
# Apache 2.0 License

# Colors for output
RED    := \033[0;31m
GREEN  := \033[0;32m
YELLOW := \033[0;33m
BLUE   := \033[0;34m
NC     := \033[0m # No Color

# Project info
PROJECT_NAME := OmniScope-rs
VERSION      := 0.1.0

# Cargo commands
CARGO        := cargo
CARGO_NEXTEST := cargo nextest run
CARGO_FMT    := cargo fmt
CARGO_CLIPPY := cargo clippy
CARGO_BUILD  := cargo build

# C++ pass configuration
PASS_DIR      := pass
PASS_BUILD    := $(PASS_DIR)/build
PASS_SRC      := $(PASS_DIR)/SafetyExportPass.cpp
# Prefer newest Homebrew LLVM (22 > 21 > ...), fall back to llvm-config on PATH
LLVM_PREFIX   ?= $(shell \
	for v in 22 21 20 19 18 17; do \
		p="/opt/homebrew/opt/llvm@$$v"; \
		if [ -d "$$p" ]; then echo "$$p"; exit 0; fi; \
	done; \
	llvm-config --prefix 2>/dev/null)
CLANG_TIDY    := $(shell if [ -x "$(LLVM_PREFIX)/bin/clang-tidy" ]; then echo "$(LLVM_PREFIX)/bin/clang-tidy"; else which clang-tidy 2>/dev/null; fi)
CLANG_FORMAT  := $(shell if [ -x "$(LLVM_PREFIX)/bin/clang-format" ]; then echo "$(LLVM_PREFIX)/bin/clang-format"; else which clang-format 2>/dev/null; fi)
NPROC         := $(shell sysctl -n hw.ncpu 2>/dev/null || nproc)

# Default target
.DEFAULT_GOAL := help

## help: Show this help message
.PHONY: help
help:
	@echo "$(BLUE)$(PROJECT_NAME) - IR-level Unsafe/FFI Static Analysis Tool$(NC)"
	@echo ""
	@echo "$(GREEN)Usage:$(NC)"
	@echo "  make [target]"
	@echo ""
	@echo "$(GREEN)Targets:$(NC)"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'

## build: Build the project and copy to ./build directory
.PHONY: build
build:
	@echo "$(BLUE)Building $(PROJECT_NAME) in release mode...$(NC)"
	$(CARGO) build --workspace --release
	@echo "$(BLUE)Copying binaries to ./build directory...$(NC)"
	@mkdir -p build
	@cp -f target/release/omniscope build/omniscope
	@chmod +x build/omniscope
	@echo "$(GREEN)✓ Binary copied to build/omniscope$(NC)"
	@echo "$(GREEN)✓ Run with: ./build/omniscope [command]$(NC)"


## test: Run all tests
.PHONY: test
test:
	@echo "$(BLUE)Running tests...$(NC)"
	$(CARGO_NEXTEST)  --workspace --all-features

## test-verbose: Run tests with verbose output
.PHONY: test-verbose
test-verbose:
	@echo "$(BLUE)Running tests with verbose output...$(NC)"
	$(CARGO_NEXTEST) run --workspace --all-features --no-fail-fast

## test-release: Run tests in release mode
.PHONY: test-release
test-release:
	@echo "$(BLUE)Running tests in release mode...$(NC)"
	$(CARGO_NEXTEST) run --workspace --release --all-features

## check: Run clippy + C++ lint checks
.PHONY: check
check:
	@echo "$(BLUE)Running clippy checks...$(NC)"
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all -W clippy::perf -W clippy::style -W clippy::complexity -W clippy::suspicious -W clippy::correctness -A clippy::too_many_arguments -A clippy::type_complexity
	@$(MAKE) --no-print-directory pass-check


## check-strict: Run clippy with all pedantic lints
.PHONY: check-strict
check-strict:
	@echo "$(BLUE)Running clippy with pedantic lints...$(NC)"
	$(CARGO) clippy --workspace --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery

## fmt: Format code using rustfmt
.PHONY: fmt
fmt:
	@echo "$(BLUE)Formatting code...$(NC)"
	$(CARGO) fmt --all

## fmt-check: Check if code is formatted correctly
.PHONY: fmt-check
fmt-check:
	@echo "$(BLUE)Checking code formatting...$(NC)"
	$(CARGO) fmt --all -- --check

# ── C++ pass targets ──────────────────────────────────────────────────

## pass-lint: Run clang-tidy on SafetyExportPass.cpp
.PHONY: pass-lint
pass-lint:
ifndef CLANG_TIDY
	@echo "$(YELLOW)clang-tidy not found — skipping C++ lint$(NC)"
else
	@echo "$(BLUE)Running clang-tidy on $(PASS_SRC)...$(NC)"
	"$(CLANG_TIDY)" -p "$(PASS_BUILD)" \
		--extra-arg-before=-I"$(LLVM_PREFIX)/include" \
		$(PASS_SRC)
	@echo "$(GREEN)✓ clang-tidy passed$(NC)"
endif

## pass-format: Format SafetyExportPass.cpp with clang-format
.PHONY: pass-format
pass-format:
ifndef CLANG_FORMAT
	@echo "$(YELLOW)clang-format not found — skipping C++ format$(NC)"
else
	@echo "$(BLUE)Formatting $(PASS_SRC)...$(NC)"
	"$(CLANG_FORMAT)" -i $(PASS_SRC)
	@echo "$(GREEN)✓ clang-format done$(NC)"
endif

## pass-format-check: Check C++ formatting without modifying files
.PHONY: pass-format-check
pass-format-check:
ifndef CLANG_FORMAT
	@echo "$(YELLOW)clang-format not found — skipping C++ format check$(NC)"
else
	@echo "$(BLUE)Checking C++ formatting...$(NC)"
	"$(CLANG_FORMAT)" --dry-run --Werror $(PASS_SRC)
	@echo "$(GREEN)✓ C++ formatting OK$(NC)"
endif

## pass-build: Build the SafetyExportPass LLVM plugin
.PHONY: pass-build
pass-build:
ifndef LLVM_PREFIX
	@echo "$(RED)Error: llvm-config not found. Install LLVM and ensure llvm-config is on PATH.$(NC)"
	@exit 1
endif
	@echo "$(BLUE)Building SafetyExportPass plugin...$(NC)"
	LLVM_PREFIX="$(LLVM_PREFIX)" cmake -B "$(PASS_BUILD)" -S "$(PASS_DIR)" \
		-DLLVM_DIR="$(LLVM_PREFIX)/lib/cmake/llvm" \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build "$(PASS_BUILD)" --config Release -j$(NPROC)
	@ln -sf "$(PASS_BUILD)/compile_commands.json" "$(PASS_DIR)/compile_commands.json"
	@echo "$(GREEN)✓ Plugin built: $(PASS_BUILD)/SafetyExportPass.dylib$(NC)"

## pass-clean: Remove C++ pass build artifacts
.PHONY: pass-clean
pass-clean:
	@echo "$(YELLOW)Cleaning C++ pass build...$(NC)"
	rm -rf "$(PASS_BUILD)"

## pass-check: Run all C++ checks (format-check + lint)
.PHONY: pass-check
pass-check: pass-format-check pass-lint

## clean: Clean all build artifacts (Rust + C++)
.PHONY: clean
clean: pass-clean
	@echo "$(YELLOW)Cleaning Rust build artifacts...$(NC)"
	$(CARGO) clean

## doc: Generate documentation
.PHONY: doc
doc:
	@echo "$(BLUE)Generating documentation...$(NC)"
	$(CARGO) doc --no-deps --open

## doc-private: Generate documentation including private items
.PHONY: doc-private
doc-private:
	@echo "$(BLUE)Generating documentation (including private items)...$(NC)"
	$(CARGO) doc --no-deps --document-private-items

## bench: Run benchmarks
.PHONY: bench
bench:
	@echo "$(BLUE)Running benchmarks...$(NC)"
	$(CARGO) bench

## miri: Run Miri for unsafe code validation
.PHONY: miri
miri:
	@echo "$(BLUE)Running Miri for unsafe code validation...$(NC)"
	$(CARGO) miri test

## audit: Run security audit on dependencies
.PHONY: audit
audit:
	@echo "$(BLUE)Running security audit...$(NC)"
	$(CARGO) audit

## outdated: Check for outdated dependencies
.PHONY: outdated
outdated:
	@echo "$(BLUE)Checking for outdated dependencies...$(NC)"
	$(CARGO) outdated

## tree: Show dependency tree
.PHONY: tree
tree:
	@echo "$(BLUE)Showing dependency tree...$(NC)"
	$(CARGO) tree

## install-tools: Install required development tools
.PHONY: install-tools
install-tools:
	@echo "$(BLUE)Installing development tools...$(NC)"
	$(CARGO) install cargo-audit cargo-outdated cargo-tree

## ci: Run all CI checks (fmt, check, test, pass-check)
.PHONY: ci
ci: fmt-check pass-format-check check test
	@echo "$(GREEN)All CI checks passed!$(NC)"

## dev: Development workflow (fmt, check, test)
.PHONY: dev
dev: fmt pass-format check test
	@echo "$(GREEN)Development workflow completed!$(NC)"

## watch: Watch for changes and rebuild
.PHONY: watch
watch:
	@echo "$(BLUE)Watching for changes...$(NC)"
	$(CARGO) watch -x "fmt" -x "check" -x "test"

## coverage: Generate test coverage report
.PHONY: coverage
coverage:
	@echo "$(BLUE)Generating test coverage report...$(NC)"
	$(CARGO) tarpaulin --out Html --output-dir target/coverage

## profile: Run profiler
.PHONY: profile
profile:
	@echo "$(BLUE)Running profiler...$(NC)"
	$(CARGO) flamegraph --root

## all: Run complete build pipeline
.PHONY: all
all: clean fmt check test release
	@echo "$(GREEN)Complete build pipeline finished!$(NC)"

## version: Show project version
.PHONY: version
version:
	@echo "$(BLUE)$(PROJECT_NAME) v$(VERSION)$(NC)"

## info: Show project information
.PHONY: info
info:
	@echo "$(BLUE)Project Information:$(NC)"
	@echo "  Name:    $(PROJECT_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Rust:    $(rustc --version)"
	@echo "  Cargo:   $(cargo --version)"

## cache-stats: Show sccache statistics
.PHONY: cache-stats
cache-stats:
	@echo "$(BLUE)Showing sccache statistics...$(NC)"
	@sccache --show-stats 2>/dev/null || echo "sccache not running"

## cache-clear: Clear sccache cache
.PHONY: cache-clear
cache-clear:
	@echo "$(YELLOW)Clearing sccache cache...$(NC)"
	@sccache --stop-server 2>/dev/null || true
	@sccache --start-server 2>/dev/null || echo "sccache not available"

## build-timed: Build with timing information
.PHONY: build-timed
build-timed:
	@echo "$(BLUE)Building with timing information...$(NC)"
	@time $(CARGO_BUILD) --timings

## check-features: Check all feature combinations
.PHONY: check-features
check-features:
	@echo "$(BLUE)Checking all feature combinations...$(NC)"
	$(CARGO) hack check --each-feature

## optimize: Apply all optimizations and rebuild
.PHONY: optimize
optimize: clean
	@echo "$(BLUE)Applying optimizations...$(NC)"
	@echo "  - Using sccache for compilation caching"
	@echo "  - Using fast linker (zld/mold)"
	@echo "  - Building with LTO and optimization level 3"
	$(CARGO_BUILD) --release --timings
	@echo "$(GREEN)Optimized build complete!$(NC)"
