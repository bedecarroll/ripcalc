# ripcalc

A Rust-based subnet calculator that replicates and extends the functionality of the original `sipcalc` tool.

## Features

### IPv4 Support
- Multiple input formats (CIDR, dotted decimal netmask, hex netmask)
- Network address, broadcast address, and usable range calculations
- Binary representation of addresses and masks
- Subnet splitting with various mask formats
- Classful network information
- Network interface address retrieval

### IPv6 Support
- Flexible IPv6 input formats (compressed and expanded)
- Address type identification (Global Unicast, Link-Local, etc.)
- IPv4-in-IPv6 embedded address detection
- Reverse DNS pointer generation
- Subnet splitting for IPv6 networks
- Network range calculations

### Modern Enhancements
- **JSON output format** for easy integration with other tools
- **Enhanced IPv6 support** including interface queries
- **Cross-platform compatibility** (Linux, macOS)
- **DNS resolution** for hostnames
- **Batch processing** via stdin
- **Comprehensive error handling**

## Feature Comparison with sipcalc

The table below summarizes feature parity between **ripcalc** and the original **sipcalc** tool. A feature is marked supported only if **ripcalc** has both unit tests covering it and a captured “golden” output test comparing against `sipcalc`.

| Feature                           | ripcalc | sipcalc |
|-----------------------------------|:-------:|:-------:|
| IPv4 CIDR notation (`/`)          | ✓       | ✓       |
| IPv4 dotted decimal mask          | ✓       | ✓       |
| IPv4 hex netmask                  | ✓       | ✓       |
| IPv4 subnet splitting (`-s`)      | ✓       | ✓       |
| IPv4 extra subnets (`-n`)         | ✓       | ✓       |
| IPv4 classful info (`-c`)         | ✓       | ✓       |
| IPv4 CIDR bitmap (`-b`)           | ✓       | ✓       |
| IPv4 classful bitmap (`-x`)       | ✓       | ✓       |
| IPv6 CIDR notation (`/`)          | ✓       | ✓       |
| IPv6 reverse DNS (`-r`)           | ✓       | ✓       |
| IPv6 IPv4‐in‐IPv6 (`-e`)           | ✓       | ✓       |
| IPv6 subnet splitting (`-S`)      | ✓       | ✓       |

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/ripcalc`.

## Usage

### Basic Examples

```bash
# IPv4 CIDR notation
ripcalc 192.168.1.0/24

# IPv4 with dotted decimal netmask
ripcalc "192.168.1.5 255.255.255.0"

# IPv4 with hex netmask
ripcalc "10.0.0.1 0xFFFFFF00"

# IPv6 subnet
ripcalc 2001:db8::/48

# Multiple inputs
ripcalc 192.168.1.0/24 10.0.0.0/16 2001:db8::/32
```

### Advanced Features

```bash
# All information (sipcalc compatible)
ripcalc -a 192.168.1.0/24

# CIDR and classful bitmaps
ripcalc -b 192.168.1.0/24           # CIDR bitmap
ripcalc -x 192.168.1.0/24           # Classful bitmap

# Classful vs CIDR information
ripcalc -c 192.168.1.0/24           # Classful address info
ripcalc -i 192.168.1.0/24           # CIDR address info (default)

# Subnet splitting (sipcalc compatible)
ripcalc -s 26 192.168.1.0/24        # Split IPv4 into /26 subnets
ripcalc -S 64 2001:db8::/48          # Split IPv6 into /64 subnets
ripcalc -s 28 -u 192.168.1.0/24     # Verbose subnet splitting

# Extra subnets
ripcalc -n 3 192.168.1.0/24         # Show next 3 subnets
ripcalc -n 0 192.168.10.0/26        # Show all /24 subnets containing this network

# IPv6 specific options
ripcalc -r 2001:db8::1/64           # IPv6 reverse DNS
ripcalc -e ::ffff:192.0.2.1         # IPv4-in-IPv6 information

# Address specification flags
ripcalc -4 192.168.1.0/24 -6 2001:db8::/48  # Specify IPv4 and IPv6
ripcalc -I eth0                      # Interface addresses

# DNS resolution
ripcalc -d google.com               # Enable DNS resolution

# Modern extensions
ripcalc --json 192.168.1.0/24       # JSON output

# Batch processing from stdin
echo -e "192.168.1.0/24\\n10.0.0.0/16" | ripcalc
ripcalc -                           # Read from stdin
```

### Command Line Options

**Global Options:**
- `-a, --all`: All possible information
- `-d, --resolve`: Enable name resolution  
- `-I, --addr-int <INT>`: Add an interface
- `-n, --subnets <NUM>`: Display NUM extra subnets (starting from current subnet)
- `-u, --split-verbose`: Verbose split
- `-4, --addr-ipv4 <ADDR>`: Add an IPv4 address
- `-6, --addr-ipv6 <ADDR>`: Add an IPv6 address
- `-h, --help`: Display help
- `-V, --version`: Version information

**IPv4 Options:**
- `-b, --cidr-bitmap`: CIDR bitmap
- `-c, --classful-addr`: Classful address information
- `-i, --cidr-addr`: CIDR address information (default)
- `-s, --v4split <MASK>`: Split the current network into subnets of MASK size
- `-w, --wildcard`: Display information for a wildcard (inverse mask)
- `-x, --classful-bitmap`: Classful bitmap

**IPv6 Options:**
- `-e, --v4inv6`: IPv4 compatible IPv6 information
- `-r, --v6rev`: IPv6 reverse DNS output
- `-S, --v6split <MASK>`: Split the current network into subnets of MASK size
- `-t, --v6-standard`: Standard IPv6 (default)

**Modern Extensions:**
- `--json`: Output results in JSON format

## Output Format

### IPv4 Text Output
```
-[ipv4 : 192.168.1.0/24] - 0

[CIDR]
Host address            - 192.168.1.0
Host address (decimal)  - 3232235776
Host address (hex)      - C0A80100
Network address         - 192.168.1.0
Network mask            - 255.255.255.0
Network mask (bits)     - 24
Network mask (hex)      - FFFFFF00
Broadcast address       - 192.168.1.255
Cisco wildcard          - 0.0.0.255
Addresses in network    - 256
Network range           - 192.168.1.0 - 192.168.1.255
Usable range            - 192.168.1.1 - 192.168.1.254
-
```

### IPv6 Text Output
```
-[ipv6 : 2001:db8::/48] - 0

[IPv6]
Expanded Address        - 2001:0db8:0000:0000:0000:0000:0000:0000
Compressed Address      - 2001:db8::
Subnet prefix           - 2001:db8::/48
Address ID              - ::
Prefix address          - ffff:ffff:ffff::
Prefix length           - 48
Address type            - Documentation
Network range           - 2001:db8:: - 2001:db8:0:ffff:ffff:ffff:ffff:ffff
Reverse DNS             - 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
-
```

### JSON Output
The `--json` flag produces structured output suitable for programmatic consumption:

```json
{
  "type": "ipv4",
  "input": "192.168.1.0/24",
  "index": 0,
  "host_address": "192.168.1.0",
  "host_address_decimal": 3232235776,
  "host_address_hex": "C0A80100",
  "network_address": "192.168.1.0",
  "network_mask": "255.255.255.0",
  "network_mask_bits": 24,
  "network_mask_hex": "FFFFFF00",
  "broadcast_address": "192.168.1.255",
  "cisco_wildcard": "0.0.0.255",
  "addresses_in_network": 256,
  "usable_addresses": 254,
  "network_range": {
    "start": "192.168.1.0",
    "end": "192.168.1.255"
  },
  "usable_range": {
    "start": "192.168.1.1",
    "end": "192.168.1.254"
  }
}
```

## Compatibility with sipcalc

`ripcalc` is designed to be a drop-in replacement for `sipcalc` with the same command-line interface and output format. All original `sipcalc` functionality is supported, plus additional modern features.

### IPv6 Address Classification - Intentional Improvement

**ripcalc deliberately uses modern IPv6 address classification that diverges from sipcalc for better accuracy.**

| Address Type | sipcalc (outdated) | ripcalc (modern) |
|--------------|-------------------|------------------|
| `2001:db8::/32` | "Aggregatable Global Unicast" | "Documentation Address" ✅ |
| Global addresses | Generic classification | Regional identification (ARIN, RIPE, etc.) ✅ |
| Special-purpose | Limited detection | Comprehensive (Teredo, 6to4, etc.) ✅ |

This provides more accurate and useful information for modern IPv6 networks, following current IANA registries and RFC specifications as of 2024.

## Dependencies

- `clap`: Command-line argument parsing
- `ipnetwork`: IP network calculations
- `serde` & `serde_json`: JSON serialization
- `get_if_addrs`: Network interface enumeration
- `dns-lookup`: DNS resolution
- `anyhow`: Error handling
- `tokio`: Async runtime

## License

MIT License

## Development

This project maintains **highest quality standards** with comprehensive linting and testing.

### Quick Start

```bash
# Clone and build
git clone <repo-url>
cd ripcalc
cargo build

# Run with our comprehensive quality checks
cargo fmt --all
cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery
cargo test
```

### Code Quality Standards

This project maintains **clippy compliance at nursery level** - the highest available lint level in Rust:

- **Zero warnings** allowed in CI/CD
- **No `#[allow]` bypasses** for actual issues - fix the underlying problem
- **Comprehensive linting**: pedantic + nursery + all lint groups
- **High code quality**: const functions, proper Self usage, documented design decisions

See [AGENTS.md](./AGENTS.md) for complete development workflow and quality guidelines.

## Contributing

Contributions are welcome! Please ensure all development workflow steps pass before submitting:

1. **Follow the [development workflow](./AGENTS.md#development-workflow)**
2. **Maintain [code quality standards](./AGENTS.md#code-quality-guidelines)**
3. **Submit issues and pull requests via GitHub**

All changes must pass our comprehensive linting and testing before merge.
