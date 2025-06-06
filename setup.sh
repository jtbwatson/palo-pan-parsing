#!/bin/bash

echo "🔥 PAN Log Parser Tool Setup v2.0 (Go Edition)"
echo "================================================"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.19 or later."
    echo "   Visit: https://golang.org/dl/"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | cut -d' ' -f3 | cut -d'o' -f2)
echo "✅ Found Go version: $GO_VERSION"

# Build the Go binary
echo "🔨 Building PAN parser..."
if go build -o pan-parser main.go; then
    echo "✅ Build successful! Executable: ./pan-parser"
else
    echo "❌ Build failed!"
    exit 1
fi

# Make executable
chmod +x pan-parser

echo ""
echo "🚀 Setup complete! You can now use the PAN parser:"
echo "   • Interactive mode: ./pan-parser -i"
echo "   • Command line: ./pan-parser -a <address> -l <logfile>"
echo "   • Help: ./pan-parser -h"
echo ""

# Run the parser if requested
if [[ "$1" == "--with-parser" ]]; then
    echo "🎯 Starting interactive parser..."
    ./pan-parser -i
fi