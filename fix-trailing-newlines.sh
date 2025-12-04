#!/bin/bash
# Fix trailing newline violations in Swift files

set -e

FILES=(
    "Sources/WireGuardKit/UdpTlsPipeConfiguration.swift"
    "Sources/WireGuardKit/UdpTlsPipeAdapter.swift"
    "Sources/WireGuardKit/WireGuardLogLevel.swift"
    "Sources/WireGuardKit/WireGuardAdapter.swift"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        # Remove all trailing whitespace and add exactly one newline
        python3 -c "
import sys
with open('$file', 'rb') as f:
    content = f.read()
content = content.rstrip() + b'\n'
with open('$file', 'wb') as f:
    f.write(content)
"
        echo "Fixed: $file"
    else
        echo "Warning: $file not found"
    fi
done

echo "Done fixing trailing newlines"

