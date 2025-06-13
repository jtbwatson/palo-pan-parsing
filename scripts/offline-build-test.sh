#!/bin/bash

# Offline Build Test Script
# This script verifies that the PAN parser can be built completely offline
# without accessing external package repositories.

set -e

echo "=== PAN Parser Offline Build Test ==="
echo ""

# Check if vendor directory exists
if [ ! -d "vendor" ]; then
    echo "❌ vendor/ directory not found. Run 'make vendor' first."
    exit 1
fi

echo "✅ vendor/ directory found"

# Check if go.mod exists
if [ ! -f "go.mod" ]; then
    echo "❌ go.mod not found"
    exit 1
fi

echo "✅ go.mod found"

# Test 1: Verify vendor mode builds
echo ""
echo "Test 1: Building with vendor mode..."
if go build -mod=vendor -o /tmp/pan-parser-test main.go; then
    echo "✅ Vendor mode build successful"
else
    echo "❌ Vendor mode build failed"
    exit 1
fi

# Test 2: Verify all dependencies are vendored
echo ""
echo "Test 2: Checking dependency completeness..."
if go mod verify; then
    echo "✅ All modules verified"
else
    echo "❌ Module verification failed"
    exit 1
fi

# Test 3: Test with readonly mode (simulates offline)
echo ""
echo "Test 3: Testing with GOPROXY=off (simulates offline)..."
if GOPROXY=off go build -mod=vendor -o /tmp/pan-parser-offline main.go; then
    echo "✅ Offline build successful"
else
    echo "❌ Offline build failed"
    exit 1
fi

# Test 4: Verify binary works
echo ""
echo "Test 4: Testing binary functionality..."
if /tmp/pan-parser-offline --help > /dev/null 2>&1; then
    echo "✅ Binary works correctly"
else
    echo "❌ Binary test failed"
    exit 1
fi

# Test 5: Check for any missing vendor packages
echo ""
echo "Test 5: Scanning for missing vendor packages..."
missing_packages=$(go list -mod=vendor -deps . 2>&1 | grep -i "cannot find" || true)
if [ -z "$missing_packages" ]; then
    echo "✅ No missing packages found"
else
    echo "❌ Missing packages detected:"
    echo "$missing_packages"
    exit 1
fi

# Test 6: Verify vendor completeness with modules.txt
echo ""
echo "Test 6: Checking vendor/modules.txt completeness..."
if [ -f "vendor/modules.txt" ]; then
    echo "✅ vendor/modules.txt exists"
    module_count=$(grep -c "^# " vendor/modules.txt)
    echo "✅ $module_count modules vendored"
else
    echo "❌ vendor/modules.txt not found"
    exit 1
fi

# Cleanup
rm -f /tmp/pan-parser-test /tmp/pan-parser-offline

echo ""
echo "🎉 All offline build tests passed!"
echo ""
echo "Summary:"
echo "- All dependencies are properly vendored"
echo "- Build works with -mod=vendor"
echo "- Build works with GOPROXY=off (offline mode)"
echo "- No external package access required"
echo "- Binary is fully functional"
echo ""
echo "The project is ready for offline/air-gapped deployment!"