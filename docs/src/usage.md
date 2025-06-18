# CLI Usage

```bash
ripcalc [OPTIONS] <INPUTS>...
```

## Options

- `-s, --split <bits>`  
  Split the network into subnets of the given prefix length.
- `-a, --all`  
  Display all available information (classful, bitmaps, etc.).
- `--json`  
  Output results as JSON.
- `--help`  
  Display help information.
- `-v, --verbose`  
  Verbose output (detailed split information).
- `-V, --version`  
  Show version information.

## Examples

```bash
ripcalc 192.168.1.0/24
ripcalc --json 2001:db8::/48
ripcalc -s 26 10.0.0.0/16
```
