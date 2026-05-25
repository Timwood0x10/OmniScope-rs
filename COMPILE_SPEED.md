# Compilation Speed Optimization Guide

This document describes the compilation speed optimizations configured for OmniScope-rs.

## Optimizations Enabled

### 1. **sccache** - Compilation Cache
- **What**: Caches compiled artifacts across builds
- **Speedup**: 2-10x for incremental builds
- **Configured in**: `.cargo/config.toml`
- **Usage**:
  ```bash
  # Install sccache
  cargo install sccache

  # Add to shell profile (.bashrc or .zshrc)
  export RUSTC_WRAPPER=sccache

  # View cache statistics
  make cache-stats

  # Clear cache
  make cache-clear
  ```

### 2. **Fast Linkers**
- **macOS**: `zld` (Apple's linker replacement)
  - Install: `brew install zld`
  - Speedup: 2-3x faster linking

- **Linux**: `mold` (Modern linker)
  - Install: `sudo apt install mold` or build from source
  - Speedup: 3-5x faster linking

- **Configured in**: `.cargo/config.toml`

### 3. **Incremental Compilation**
- **What**: Only recompile changed files
- **Speedup**: 5-20x for small changes
- **Configured in**: `.cargo/config.toml` and `Cargo.toml`

### 4. **Parallel Compilation**
- **What**: Compile multiple crates in parallel
- **Default**: Uses all available CPU cores
- **Customize**: `CARGO_BUILD_JOBS=8` in `.cargo/config.toml`

### 5. **LTO (Link Time Optimization)**
- **What**: Whole-program optimization
- **Profile**: Release builds only
- **Configured in**: `Cargo.toml`
  ```toml
  [profile.release]
  lto = "fat"
  codegen-units = 1
  ```

## Build Commands

### Fast Development Builds
```bash
# Quick debug build (fastest)
make build

# Quick test run
make test

# Development workflow (fmt + check + test)
make dev
```

### Optimized Release Builds
```bash
# Full release build with all optimizations
make release

# Build with timing information
make build-timed

# Full optimization pipeline
make optimize
```

### Cache Management
```bash
# View cache statistics
make cache-stats

# Clear cache
make cache-clear
```

## Performance Tips

### 1. **Use Check Instead of Build**
```bash
# Faster than build (skips codegen and linking)
cargo check
```

### 2. **Limit Dependencies**
- Use `cargo tree` to analyze dependencies
- Remove unused dependencies with `cargo udeps`

### 3. **Use Workspace Caching**
- Workspace structure already configured
- Shared dependencies across crates

### 4. **Monitor Build Times**
```bash
# Generate build timing report
cargo build --timings

# View in browser
open target/cargo-timings/cargo-timing.html
```

### 5. **Reduce Codegen Units for Release**
- Already configured: `codegen-units = 1`
- Better optimization, slower build
- Only for release builds

## Expected Performance

### Initial Build (Cold Cache)
- **Without optimizations**: ~5-10 minutes
- **With optimizations**: ~2-5 minutes

### Incremental Build (Warm Cache)
- **Without optimizations**: ~30-60 seconds
- **With optimizations**: ~5-15 seconds

### Link Time
- **Default linker**: ~10-30 seconds
- **Fast linker (zld/mold)**: ~2-10 seconds

## Troubleshooting

### sccache Not Working
```bash
# Check if sccache is running
sccache --show-stats

# Restart sccache
sccache --stop-server
sccache --start-server
```

### Linker Not Found
```bash
# macOS: Install zld
brew install zld

# Linux: Install mold
sudo apt install mold  # Debian/Ubuntu
sudo pacman -S mold    # Arch Linux
```

### Slow Builds
1. Check cache hit rate: `make cache-stats`
2. Verify linker is being used: `cargo build -vv`
3. Check for dependency issues: `cargo tree`
4. Use `cargo check` instead of `cargo build`

## Additional Tools

### cargo-watch (Auto-rebuild on changes)
```bash
cargo install cargo-watch
cargo watch -x check
```

### cargo-hack (Feature checking)
```bash
cargo install cargo-hack
make check-features
```

### flamegraph (Profiling)
```bash
cargo install cargo-flamegraph
make profile
```

## Configuration Files

- `.cargo/config.toml` - Cargo configuration
- `rust-toolchain.toml` - Rust version pinning
- `Cargo.toml` - Build profiles and dependencies
- `Makefile` - Build commands and shortcuts
