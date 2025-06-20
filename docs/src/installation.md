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
git clone <repository-url>
cd ripcalc
cargo build --release
```

The binary will be available at `target/release/ripcalc`.

### Verify Installation
```bash
./target/release/ripcalc --version
```

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
