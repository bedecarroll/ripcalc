# CLI Usage

```bash
ripcalc [OPTIONS] [ADDRESS|INTERFACE]...
```

## Options

### Core Options
- `-a, --all`  
  Display all possible information
- `--json`  
  Output results in JSON format (ripcalc exclusive feature)
- `-d, --resolve`  
  Enable name resolution
- `-v, --version`  
  Show version information
- `-h, --help`  
  Display help information

### IPv4 Options
- `-s, --v4split <MASK>`  
  Split the current network into subnets of MASK size
- `-n, --subnets <NUM>`  
  Display NUM extra subnets (starting from current subnet)
- `-b, --cidr-bitmap`  
  CIDR bitmap
- `-c, --classful-addr`  
  Classful address information
- `-i, --cidr-addr`  
  CIDR address information (default)
- `-w, --wildcard`  
  Display information for a wildcard (inverse mask)
- `-x, --classful-bitmap`  
  Classful bitmap

### IPv6 Options
- `-S, --v6split <MASK>`  
  Split the current network into subnets of MASK size
- `-e, --v4inv6`  
  IPv4 compatible IPv6 information
- `-r, --v6rev`  
  IPv6 reverse DNS output
- `-t, --v6-standard`  
  Standard IPv6 (default)

### Input Options
- `-I, --addr-int <INT>`  
  Add an interface
- `-4, --addr-ipv4 <ADDR>`  
  Add an IPv4 address
- `-6, --addr-ipv6 <ADDR>`  
  Add an IPv6 address

### Output Options
- `-u, --split-verbose`  
  Verbose split output

## Basic Examples

### IPv4 Subnet Calculation
```bash
ripcalc 192.168.1.0/24
```

### IPv6 Network Analysis
```bash
ripcalc 2001:db8::/48
```

### IPv4 Subnet Splitting
```bash
ripcalc -s 26 10.0.0.0/24
```

### IPv6 Subnet Splitting
```bash
ripcalc -S 50 2001:db8::/48
```

### Verbose Split Output
```bash
ripcalc -u -s 26 10.0.0.0/24
```

### JSON Output (ripcalc exclusive)
```bash
ripcalc --json 192.168.1.0/24
```

## Advanced Examples

### Multiple Inputs - Enhanced Index Clarity
```bash
# ripcalc provides clear index numbering for multiple inputs
# Building on sipcalc's multiple input support
ripcalc 192.168.1.0/24 10.0.0.0/16 172.16.0.0/12
```

### IPv6 Modern Classifications

ripcalc extends sipcalc's solid IPv6 foundation with current RFC-specific classifications:

#### Documentation Address (RFC 3849)
```bash
ripcalc 2001:db8::1
# ripcalc: "Documentation Address" (RFC 3849 specific)
# sipcalc: "Aggregatable Global Unicast Addresses" (general classification)
```

#### 6to4 Transition Address (RFC 3056)
```bash
ripcalc 2002::/16
# ripcalc: "6to4 Transition Address" (RFC 3056 specific)
# sipcalc: "Aggregatable Global Unicast Addresses" (general classification)
```

#### Loopback Address (RFC 4291)
```bash
ripcalc ::1
# ripcalc: "Loopback Address" (direct classification)
# sipcalc: "Reserved" + "Comment: Loopback" (detailed approach)
```

#### IPv4-mapped IPv6 Address
```bash
ripcalc ::ffff:192.0.2.1
# ripcalc: "IPv4-mapped IPv6 address" (specific description)
# sipcalc: "Reserved" (general classification)
```

## Enhanced Error Handling

ripcalc builds upon sipcalc's robust validation with more immediate feedback:

### Invalid Input Handling
```bash
# ripcalc: Provides immediate, clear feedback
ripcalc 999.999.999.999
# Output: Error: Unable to parse '999.999.999.999'

# sipcalc: Attempts graceful continuation with partial processing
# Output: -[int-ipv4 : 999.999.999.999] - 0
#         -[ERR : Unable to retrieve interface information]
```

### Invalid Prefix Length
```bash
# ripcalc: Direct error reporting
ripcalc 192.168.1.0/99
# Output: Error: Unable to parse '192.168.1.0/99'

# sipcalc: Continues with available information
```

## JSON Output Feature

ripcalc supports structured JSON output, making it ideal for automation and integration:

```bash
ripcalc --json 192.168.1.0/24
```

```json
{
  "input": "192.168.1.0/24",
  "type": "ipv4",
  "network": "192.168.1.0",
  "netmask": "255.255.255.0",
  "prefix_length": 24,
  "broadcast": "192.168.1.255",
  "host_count": 256,
  "usable_host_count": 254,
  "first_host": "192.168.1.1",
  "last_host": "192.168.1.254"
}
```

## Building on sipcalc's Foundation

ripcalc preserves **full compatibility** with sipcalc's trusted interface while extending its capabilities:

- **Familiar command-line interface**: All sipcalc commands work seamlessly
- **Enhanced output**: Builds on sipcalc's reliable calculations with modern RFC classifications
- **Extended functionality**: Adds JSON output and additional options while preserving core behavior
- **Proven algorithms**: Maintains sipcalc's time-tested calculation methods

## Extending sipcalc's Legacy

ripcalc is designed to work alongside sipcalc, extending its proven foundation:

1. **RFC-compliant IPv6 classifications** - Building on sipcalc's solid IPv6 support
2. **Enhanced error feedback** - Extending sipcalc's validation approach
3. **Improved multiple input handling** - Refining sipcalc's multiple input capability
4. **Modern automation support** - Adding JSON output for contemporary workflows
5. **Continued development** - Maintaining and extending sipcalc's valuable contribution to networking tools
