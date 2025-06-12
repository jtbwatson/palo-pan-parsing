# PAN Configuration Parser Makefile

# Build variables
BINARY_NAME=pan-parser
VERSION=1.0.0
BUILD_DIR=build
OUTPUT_DIR=outputs

# Go build flags
GO_BUILD_FLAGS=-mod=vendor -ldflags="-X main.version=$(VERSION)"
GO_TEST_FLAGS=-mod=vendor -v
GO_CLEAN_FLAGS=-mod=vendor

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Default target
.DEFAULT_GOAL := build

# Help target
.PHONY: help
help: ## Show this help message
	@echo "PAN Configuration Parser v$(VERSION)"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

# Build target
.PHONY: build
build: ## Build the binary
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

# Install target
.PHONY: install
install: build ## Build and install to local bin directory
	@echo "Installing $(BINARY_NAME) to ./$(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) ./$(BINARY_NAME)
	chmod +x ./$(BINARY_NAME)
	@echo "Installation complete. Run with: ./$(BINARY_NAME)"

# Global install target
.PHONY: install-global
install-global: build ## Install to system PATH (requires sudo)
	@echo "Installing $(BINARY_NAME) globally..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Global installation complete. Run with: $(BINARY_NAME)"

# Run target
.PHONY: run
run: build ## Build and run in TUI mode
	./$(BUILD_DIR)/$(BINARY_NAME)

# Verbose run target  
.PHONY: verbose
verbose: build ## Build and run in interactive mode
	./$(BUILD_DIR)/$(BINARY_NAME) --verbose

# Test target
.PHONY: test
test: ## Run tests
	@echo "Running tests..."
	go test $(GO_TEST_FLAGS) ./...

# Test with coverage
.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test $(GO_TEST_FLAGS) -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Benchmark target
.PHONY: benchmark
benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	go test $(GO_TEST_FLAGS) -bench=. -benchmem ./...

# Vendor target
.PHONY: vendor
vendor: ## Download and vendor dependencies
	@echo "Vendoring dependencies..."
	go mod tidy
	go mod vendor
	@echo "Dependencies vendored to vendor/"

# Clean target
.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f ./$(BINARY_NAME)
	rm -f coverage.out coverage.html
	go clean $(GO_CLEAN_FLAGS)

# Clean all target
.PHONY: clean-all
clean-all: clean ## Clean build artifacts and output files
	@echo "Cleaning output directory..."
	rm -rf $(OUTPUT_DIR)

# Format target
.PHONY: fmt
fmt: ## Format Go code
	@echo "Formatting code..."
	go fmt ./...

# Lint target (requires golangci-lint)
.PHONY: lint
lint: ## Run linter (requires golangci-lint)
	@echo "Running linter..."
	golangci-lint run

# Security scan (requires gosec)
.PHONY: security
security: ## Run security scanner (requires gosec)
	@echo "Running security scan..."
	gosec ./...

# Dependency check
.PHONY: deps
deps: ## Check dependencies
	@echo "Checking dependencies..."
	go mod verify
	go mod download

# Build for multiple platforms
.PHONY: build-all
build-all: ## Build for multiple platforms
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Multi-platform builds complete in $(BUILD_DIR)/"

# Development server (watch mode)
.PHONY: dev
dev: ## Run in development mode with file watching (requires entr)
	@echo "Starting development mode..."
	find . -name "*.go" | entr -r make run

# Example runs
.PHONY: example
example: build ## Run example analysis on panos.xml (if present)
	@if [ -f panos.xml ]; then \
		echo "Running example analysis on panos.xml..."; \
		mkdir -p $(OUTPUT_DIR); \
		./$(BUILD_DIR)/$(BINARY_NAME) -l panos.xml -a example-server; \
	else \
		echo "No panos.xml file found for example"; \
	fi

# Performance test
.PHONY: perf-test
perf-test: build ## Run performance test (requires large XML file)
	@if [ -f large-config.xml ]; then \
		echo "Running performance test..."; \
		time ./$(BUILD_DIR)/$(BINARY_NAME) -l large-config.xml -a test-server -workers 8; \
	else \
		echo "No large-config.xml file found for performance testing"; \
	fi

# Docker build (if Dockerfile exists)
.PHONY: docker
docker: ## Build Docker image (requires Dockerfile)
	@if [ -f Dockerfile ]; then \
		echo "Building Docker image..."; \
		docker build -t $(BINARY_NAME):$(VERSION) .; \
	else \
		echo "No Dockerfile found"; \
	fi

# Release preparation
.PHONY: release
release: clean fmt test build-all ## Prepare release (clean, format, test, build all platforms)
	@echo "Release preparation complete!"
	@echo "Binaries available in $(BUILD_DIR)/"

# Version information
.PHONY: version
version: ## Show version information
	@echo "PAN Configuration Parser v$(VERSION)"
	@echo "Go version: $(shell go version)"
	@echo "Platform: $(UNAME_S)/$(UNAME_M)"

# Quick start
.PHONY: quickstart
quickstart: install ## Quick start - install and show help
	@echo ""
	@echo "Quick start complete! The parser is now installed."
	@echo ""
	@echo "To get started:"
	@echo "  1. Run in TUI mode: ./$(BINARY_NAME)"
	@echo "  2. Run with help: ./$(BINARY_NAME) -h" 
	@echo "  3. Analyze a file: ./$(BINARY_NAME) -l panos.xml -a server-name"
	@echo ""

# Setup development environment
.PHONY: setup
setup: vendor ## Setup development environment
	@echo "Setting up development environment..."
	@mkdir -p $(BUILD_DIR) $(OUTPUT_DIR)
	@echo "Development environment ready!"

# Check if we can build
.PHONY: check
check: deps fmt ## Run all checks (deps, format, build test)
	@echo "Running build check..."
	go build $(GO_BUILD_FLAGS) -o /dev/null .
	@echo "Build check passed!"