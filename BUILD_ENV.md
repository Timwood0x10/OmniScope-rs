# Build Environment Setup

This document describes how to set up the build environment for OmniScope-rs.

## System Dependencies

OmniScope-rs requires LLVM and zstd libraries for building.

### macOS

```bash
# Install dependencies via Homebrew
brew install zstd llvm@12

# Optional: Install faster linker
brew install zld
```

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y libzstd-dev llvm-12-dev

# Optional: Install faster linker
sudo apt-get install -y mold
```

### Linux (Fedora/RHEL)

```bash
# Install dependencies
sudo dnf install -y zstd-devel llvm-devel

# Optional: Install faster linker
sudo dnf install -y mold
```

## Build Configuration

The project uses `.cargo/config.toml` to configure library search paths automatically. You should not need to manually set environment variables.

### Manual Environment Setup (Optional)

If you encounter linking issues, you can run:

```bash
# Source the environment setup script
source scripts/setup-env.sh

# Or set manually:
export LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH"  # macOS
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:$PKG_CONFIG_PATH"  # macOS
```

## CI/CD

The GitHub Actions CI pipeline automatically installs all required dependencies:

- **Linux**: `libzstd-dev`, `llvm-12-dev`
- **macOS**: `zstd`, `llvm@12` (via Homebrew)

## Troubleshooting

### "library 'zstd' not found"

This means the zstd library is not installed or not in the library search path.

**Solution:**
1. Install zstd: `brew install zstd` (macOS) or `sudo apt-get install libzstd-dev` (Linux)
2. The `.cargo/config.toml` should automatically find it
3. If still failing, run: `source scripts/setup-env.sh`

### "LLVM not found"

This means LLVM is not installed.

**Solution:**
1. Install LLVM: `brew install llvm@12` (macOS) or `sudo apt-get install llvm-12-dev` (Linux)
2. Make sure you're using LLVM 12 (matching the `inkwell` feature in Cargo.toml)

### Linking errors on macOS

If you see linking errors on macOS, try:

```bash
# Set SDK root
export SDKROOT=$(xcrun --show-sdk-path)

# Or install Xcode command line tools
xcode-select --install
```

## Verification

To verify your setup:

```bash
# Check zstd is available
pkg-config --libs libzstd  # Should output: -L/opt/homebrew/lib -lzstd

# Check LLVM is available
llvm-config --version  # Should output: 12.x.x

# Build the project
cargo build --workspace

# Run tests
cargo test --workspace
```
