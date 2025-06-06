# PAN Log Parser Makefile

.PHONY: build install uninstall clean help run tui

# Default target
all: build

# Build the application
build:
	@echo "🔨 Building PAN parser..."
	@go build -o pan-parser main.go
	@chmod +x pan-parser
	@echo "✅ Build complete: ./pan-parser"

# Install globally to system PATH
install: build
	@echo "🔧 Installing globally..."
	@if [ -w "/usr/local/bin" ]; then \
		sudo cp pan-parser /usr/local/bin/; \
		echo "✅ Installed to /usr/local/bin/pan-parser"; \
	elif [ -d "$(HOME)/.local/bin" ]; then \
		mkdir -p "$(HOME)/.local/bin"; \
		cp pan-parser "$(HOME)/.local/bin/"; \
		echo "✅ Installed to $(HOME)/.local/bin/pan-parser"; \
		echo "   Make sure $(HOME)/.local/bin is in your PATH"; \
	elif [ -d "$(HOME)/bin" ]; then \
		cp pan-parser "$(HOME)/bin/"; \
		echo "✅ Installed to $(HOME)/bin/pan-parser"; \
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

# Run in TUI mode
tui: build
	@./pan-parser --tui

# Run in interactive mode
run: build
	@./pan-parser -i

# Show help
help:
	@echo "PAN Log Parser Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build     - Build the application"
	@echo "  install   - Build and install globally"
	@echo "  uninstall - Remove from system PATH"
	@echo "  clean     - Remove build artifacts"
	@echo "  tui       - Build and run TUI mode"
	@echo "  run       - Build and run interactive mode"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make install    # Install globally so you can use 'pan-parser' anywhere"
	@echo "  make tui        # Quick run TUI mode"
	@echo "  make clean      # Clean up"