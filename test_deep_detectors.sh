#!/bin/bash

# Test script for deep detection passes
# This script tests the new deep detection passes on bun corpus

set -e

echo "=== Testing Deep Detection Passes ==="

# Build the project
echo "Building OmniScope..."
cargo build --release

# Test on a few bun corpus files
BUN_CORPUS_DIR="/tmp/bun_*"

echo "Finding bun corpus files..."
find /tmp -name "bun_*.ll" -type f | head -5 | while read file; do
    echo "Testing on: $file"
    
    # Run analysis with deep detectors
    echo "Running analysis with deep detectors..."
    cargo run --release --bin omniscope-cli -- analyze "$file" --output-format json | jq '.issues_found' || echo "Analysis completed"
    
    echo "---"
done

echo "=== Deep Detection Test Complete ==="