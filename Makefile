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
CARGO_FMT    := cargo fmt
CARGO_CLIPPY := cargo clippy
CARGO_TEST   := cargo test
CARGO_BUILD  := cargo build

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
	@cp -f target/release/omniscope build/
	@chmod +x build/omniscope
	@echo "$(GREEN)✓ Binary copied to build/omniscope$(NC)"
	@echo "$(GREEN)✓ Run with: ./build/omniscope [command]$(NC)"

## release: Build the project in release mode with optimizations
.PHONY: release
release:
	@echo "$(BLUE)Building $(PROJECT_NAME) in release mode...$(NC)"
	$(CARGO) build --workspace --release

## test: Run all tests
.PHONY: test
test:
	@echo "$(BLUE)Running tests...$(NC)"
	$(CARGO) test --workspace --all-features

## test-verbose: Run tests with verbose output
.PHONY: test-verbose
test-verbose:
	@echo "$(BLUE)Running tests with verbose output...$(NC)"
	$(CARGO) test --workspace --all-features -- --nocapture

## test-release: Run tests in release mode
.PHONY: test-release
test-release:
	@echo "$(BLUE)Running tests in release mode...$(NC)"
	$(CARGO) test --workspace --release --all-features

## check: Run clippy checks (must show 0 errors)
.PHONY: check
check:
	@echo "$(BLUE)Running clippy checks...$(NC)"
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings -W clippy::all -W clippy::perf -W clippy::style -W clippy::complexity -W clippy::suspicious -W clippy::correctness -A clippy::too_many_arguments -A clippy::type_complexity


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

## clean: Clean build artifacts
.PHONY: clean
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
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

## ci: Run all CI checks (fmt, check, test)
.PHONY: ci
ci: fmt-check check test
	@echo "$(GREEN)All CI checks passed!$(NC)"

## dev: Development workflow (fmt, check, test)
.PHONY: dev
dev: fmt check test
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
