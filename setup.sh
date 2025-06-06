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
echo "   • TUI mode: ./pan-parser --tui"
echo "   • Interactive mode: ./pan-parser -i"
echo "   • Command line: ./pan-parser -a <address> -l <logfile>"
echo "   • Help: ./pan-parser -h"
echo ""

# Check if user wants global installation
read -p "🌍 Install globally? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔧 Installing globally..."
    
    # Try different installation paths
    if [ -w "/usr/local/bin" ]; then
        sudo cp pan-parser /usr/local/bin/
        echo "✅ Installed to /usr/local/bin/pan-parser"
        echo "   You can now use: pan-parser --tui"
    elif [ -d "$HOME/.local/bin" ]; then
        mkdir -p "$HOME/.local/bin"
        cp pan-parser "$HOME/.local/bin/"
        echo "✅ Installed to $HOME/.local/bin/pan-parser"
        echo "   Make sure $HOME/.local/bin is in your PATH"
        echo "   Add to ~/.bashrc or ~/.zshrc: export PATH=\"\$HOME/.local/bin:\$PATH\""
    elif [ -d "$HOME/bin" ]; then
        cp pan-parser "$HOME/bin/"
        echo "✅ Installed to $HOME/bin/pan-parser"
        echo "   Make sure $HOME/bin is in your PATH"
    else
        echo "❌ No suitable installation directory found."
        echo "   You can manually copy 'pan-parser' to a directory in your PATH"
    fi
else
    echo "   Local installation only. Use: ./pan-parser"
fi

echo ""

# Run the parser if requested
if [[ "$1" == "--with-parser" ]]; then
    echo "🎯 Starting interactive parser..."
    ./pan-parser -i
elif [[ "$1" == "--with-tui" ]]; then
    echo "🎯 Starting TUI mode..."
    ./pan-parser --tui
fi