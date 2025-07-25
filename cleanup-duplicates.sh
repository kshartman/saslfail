#!/bin/bash
# Wrapper for Python cleanup script

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Call the Python version
exec python3 "$SCRIPT_DIR/cleanup-duplicates.py" "$@"