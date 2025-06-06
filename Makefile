# PAN Log Parser Makefile

.PHONY: build install uninstall clean help run verbose

# Default target
all: build


# Build the application only (no dependency check)
build:
	@echo "🔨 Building PAN parser..."
	@go build -o pan-parser main.go
	@chmod +x pan-parser
	@echo "✅ Build complete: ./pan-parser"

# Install globally to system PATH (includes dependency check)
install:
	@echo "🔥 PAN Log Parser Installation"
	@echo "=============================="
	@if ! command -v go >/dev/null 2>&1; then \
		echo "❌ Go is not installed. Please install Go 1.23 or later."; \
		echo "   Visit: https://golang.org/dl/"; \
		exit 1; \
	fi
	@echo "✅ Found Go: $$(go version)"
	@echo "📦 Installing dependencies..."
	@go mod tidy
	@echo "🔨 Building application..."
	@go build -o pan-parser main.go
	@chmod +x pan-parser
	@echo "🔧 Installing globally..."
	@if [ -w "/usr/local/bin" ]; then \
		sudo cp pan-parser /usr/local/bin/; \
		echo "✅ Installed to /usr/local/bin/pan-parser"; \
		echo "   You can now use: pan-parser"; \
	elif [ -d "$(HOME)/.local/bin" ]; then \
		mkdir -p "$(HOME)/.local/bin"; \
		cp pan-parser "$(HOME)/.local/bin/"; \
		echo "✅ Installed to $(HOME)/.local/bin/pan-parser"; \
		echo "   You can now use: pan-parser"; \
		echo "   (Make sure $(HOME)/.local/bin is in your PATH)"; \
	elif [ -d "$(HOME)/bin" ]; then \
		cp pan-parser "$(HOME)/bin/"; \
		echo "✅ Installed to $(HOME)/bin/pan-parser"; \
		echo "   You can now use: pan-parser"; \
	else \
		echo "❌ No suitable installation directory found"; \
		echo "   Manually copy 'pan-parser' to a directory in your PATH"; \
	fi

# Uninstall from system PATH
uninstall:
	@echo "🗑️  Uninstalling..."
	@if [ -f "/usr/local/bin/pan-parser" ]; then \
		sudo rm /usr/local/bin/pan-parser; \
		echo "✅ Removed from /usr/local/bin"; \
	elif [ -f "$(HOME)/.local/bin/pan-parser" ]; then \
		rm "$(HOME)/.local/bin/pan-parser"; \
		echo "✅ Removed from $(HOME)/.local/bin"; \
	elif [ -f "$(HOME)/bin/pan-parser" ]; then \
		rm "$(HOME)/bin/pan-parser"; \
		echo "✅ Removed from $(HOME)/bin"; \
	else \
		echo "❌ pan-parser not found in common installation paths"; \
	fi

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	@rm -f pan-parser
	@echo "✅ Clean complete"

# Run in default TUI mode
run: build
	@./pan-parser

# Run in verbose interactive mode
verbose: build
	@./pan-parser --verbose

# Show help
help:
	@echo "PAN Log Parser Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install   - One-step install: check deps, build, and install globally"
	@echo "  build     - Build the application only"
	@echo "  uninstall - Remove from system PATH"
	@echo "  clean     - Remove build artifacts"
	@echo "  run       - Build and run (default TUI mode)"
	@echo "  verbose   - Build and run verbose interactive mode"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Quick start:"
	@echo "  make install    # One command does everything!"
	@echo "  pan-parser      # Use from anywhere"
	@echo ""
	@echo "Development:"
	@echo "  make run        # Test locally in TUI mode"
	@echo "  make verbose    # Test locally in verbose mode"
	@echo "  make clean      # Clean build artifacts"