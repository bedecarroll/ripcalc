# Installation

## Prerequisites

- [Rust and Cargo](https://www.rust-lang.org/tools/install) (version 1.70+ recommended)

## Quick Start

### Install from crates.io
```bash
# Coming soon - not yet published
cargo install ripcalc
```

### Build from Source (Current Method)
```bash
git clone https://github.com/bedecarroll/ripcalc.git
cd ripcalc
cargo build --release
```

The binary will be available at `target/release/ripcalc`.

### Verify Installation
```bash
./target/release/ripcalc --version
```

### Install Manpage (Optional)
```bash
# After building, install the manpage system-wide
./scripts/install-manpage.sh

# Or to a custom directory
./scripts/install-manpage.sh ~/.local/share/man/man1
```

### Install Shell Completions (Optional)
```bash
# Install completions for all supported shells (bash, zsh, fish)
./scripts/install-completions.sh

# Custom installation directories
BASH_COMP_DIR=~/.local/share/bash-completion/completions ./scripts/install-completions.sh
```

Supported shells:
- **Bash**: Tab completion for all flags and options
- **Zsh**: Advanced completion with descriptions
- **Fish**: Interactive completion with help text
- **PowerShell**: Windows support (completion file generated but install script focuses on Unix shells)

## Future Installation Methods

### System Package Managers
```bash
# Coming soon
brew install ripcalc          # Homebrew (macOS/Linux)
yay -S ripcalc               # Arch Linux (AUR)
```

## Extending sipcalc

If you're currently using sipcalc, ripcalc works seamlessly alongside it:

1. **Build ripcalc** using the method above
2. **Preserve existing workflows**: Your sipcalc scripts continue to work unchanged
3. **Gradually extend**: Use ripcalc for new scripts or enhanced features as needed

### Working Together

```bash
# Your existing sipcalc workflows remain unchanged
sipcalc 192.168.1.0/24

# ripcalc provides the same core functionality with enhancements
ripcalc 192.168.1.0/24

# Take advantage of ripcalc's extended features when needed
ripcalc --json 192.168.1.0/24  # Structured output for automation
```
