#!/bin/bash
# Development environment setup
# Ensures all prerequisites are met

echo "Setting up K-Scanner development environment..."

# Check for required tools
command -v gcc >/dev/null 2>&1 || { 
    echo "❌ gcc required but not installed."
    exit 1
}

command -v make >/dev/null 2>&1 || { 
    echo "❌ make required but not installed."
    exit 1
}

# Create necessary directories
mkdir -p bin obj/core obj/utils obj/modules

echo "✅ Environment ready!"
echo "   - GCC: $(gcc --version | head -n1)"
echo "   - Make: $(make --version | head -n1)"
