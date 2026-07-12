#!/bin/bash
# Install manpage for ripcalc

set -e

MANPAGE_DIR=${1:-/usr/local/share/man/man1}
OUT_DIR=${OUT_DIR:-target/release/build/ripcalc-*/out}

# Find the generated manpage
MANPAGE=$(find ${OUT_DIR} -name "ripcalc.1" 2>/dev/null | head -1)

if [ -z "$MANPAGE" ]; then
    echo "Error: ripcalc.1 manpage not found. Did you run 'cargo build --release'?"
    echo "Expected location: ${OUT_DIR}/man/ripcalc.1"
    exit 1
fi

# Create directory if it doesn't exist
sudo mkdir -p "$MANPAGE_DIR"

# Install the manpage
sudo cp "$MANPAGE" "$MANPAGE_DIR/"
sudo chmod 644 "$MANPAGE_DIR/ripcalc.1"

# Update manpage database
if command -v mandb >/dev/null 2>&1; then
    sudo mandb
elif command -v makewhatis >/dev/null 2>&1; then
    sudo makewhatis "$MANPAGE_DIR"
fi

echo "Manpage installed to $MANPAGE_DIR/ripcalc.1"
echo "Try: man ripcalc"