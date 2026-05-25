#!/bin/bash
# Setup environment for OmniScope development
# This script sets up necessary environment variables for building and testing

# Add homebrew libraries to search path (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # Set library path for linking
    export LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH"

    # Set pkg-config path
    export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:$PKG_CONFIG_PATH"

    # Set CFLAGS and LDFLAGS for C dependencies
    export CFLAGS="-I/opt/homebrew/include $CFLAGS"
    export LDFLAGS="-L/opt/homebrew/lib $LDFLAGS"

    echo "✓ macOS environment configured"
    echo "  LIBRARY_PATH: $LIBRARY_PATH"
    echo "  PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
fi

# Linux setup
if [[ "$OSTYPE" == "linux"* ]]; then
    # Common paths for Linux
    for path in /usr/local/lib /usr/lib/x86_64-linux-gnu; do
        if [ -d "$path" ]; then
            export LIBRARY_PATH="$path:$LIBRARY_PATH"
            export PKG_CONFIG_PATH="$path/pkgconfig:$PKG_CONFIG_PATH"
        fi
    done

    echo "✓ Linux environment configured"
fi

# Verify zstd is available
if command -v pkg-config &> /dev/null; then
    if pkg-config --exists libzstd 2>/dev/null; then
        echo "✓ zstd library found via pkg-config"
    else
        echo "⚠ Warning: zstd not found via pkg-config"
        echo "  Install with: brew install zstd (macOS) or apt install libzstd-dev (Linux)"
    fi
fi
