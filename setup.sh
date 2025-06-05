#!/bin/bash

# Check for uv installation
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh > /dev/null 2>&1
fi

# Set up virtual environment if needed
if [ ! -d ".venv/bin" ]; then
    uv venv > /dev/null 2>&1
fi

# Activate virtual environment
source .venv/bin/activate

# Install required packages silently
uv pip install -q -r requirements.txt > /dev/null 2>&1

# Run the parser if requested
if [[ "$1" == "--with-parser" ]]; then
    python parse.py --interactive
fi