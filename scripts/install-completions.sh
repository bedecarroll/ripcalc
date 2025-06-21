#!/bin/bash
# Install shell completions for ripcalc

set -e

# Default installation directories
BASH_COMP_DIR=${BASH_COMP_DIR:-/usr/local/share/bash-completion/completions}
ZSH_COMP_DIR=${ZSH_COMP_DIR:-/usr/local/share/zsh/site-functions}
FISH_COMP_DIR=${FISH_COMP_DIR:-/usr/local/share/fish/vendor_completions.d}

# Find build output directory
OUT_DIR=${OUT_DIR:-target/release/build/ripcalc-*/out}
COMP_DIR=$(find ${OUT_DIR} -name "completions" -type d 2>/dev/null | head -1)

if [ -z "$COMP_DIR" ]; then
    echo "Error: Shell completions not found. Did you run 'cargo build --release'?"
    echo "Expected location: ${OUT_DIR}/completions/"
    exit 1
fi

# Function to install completion file
install_completion() {
    local src_file="$1"
    local dest_dir="$2"
    local dest_name="$3"
    
    if [ -f "$src_file" ]; then
        sudo mkdir -p "$dest_dir"
        sudo cp "$src_file" "$dest_dir/$dest_name"
        sudo chmod 644 "$dest_dir/$dest_name"
        echo "Installed: $dest_dir/$dest_name"
    else
        echo "Warning: $src_file not found"
    fi
}

# Install completions for each shell
echo "Installing shell completions..."

# Bash completion
install_completion "$COMP_DIR/ripcalc.bash" "$BASH_COMP_DIR" "ripcalc"

# Zsh completion
install_completion "$COMP_DIR/_ripcalc" "$ZSH_COMP_DIR" "_ripcalc"

# Fish completion
install_completion "$COMP_DIR/ripcalc.fish" "$FISH_COMP_DIR" "ripcalc.fish"

echo ""
echo "Shell completions installed successfully!"
echo ""
echo "To enable completions:"
echo "  Bash: Restart your shell or run 'source ~/.bashrc'"
echo "  Zsh:  Restart your shell or run 'autoload -U compinit && compinit'"
echo "  Fish: Completions are automatically available"
echo ""
echo "Custom installation directories:"
echo "  Bash: BASH_COMP_DIR=/path/to/dir $0"
echo "  Zsh:  ZSH_COMP_DIR=/path/to/dir $0"
echo "  Fish: FISH_COMP_DIR=/path/to/dir $0"