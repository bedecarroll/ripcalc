# ripcalc Repository Guidance

This repository is a Rust-based CLI subnet calculator (`ripcalc`) that replicates
and extends `sipcalc` functionality.

## Repository structure

- `src/main.rs`: CLI entry point (argument parsing and dispatch).
- `src/ipv4.rs`: IPv4 parsing and network calculations.
- `src/ipv6.rs`: IPv6 parsing and network calculations.
- `src/dns.rs`: DNS hostname resolution utilities.
- `src/interface.rs`: Local network interface enumeration and information.
- `src/output.rs`: Formatting and printing logic (text and JSON).
- `tests/integration_tests.rs`: End-to-end integration tests for CLI behavior.
- `tests/golden_compare.rs`: Golden tests comparing ripcalc output against captured sipcalc outputs.
- `tests/sipcalc_golden/*.txt`: Captured `sipcalc` outputs for golden comparison tests.
- Unit tests in each module under `src/` (annotated with `#[cfg(test)]`).

## Development workflow

1. **Format**: `cargo fmt --all`
2. **Lint**: `cargo clippy --all-targets -- -D warnings -W clippy::pedantic`
3. **Build**: `cargo build --all-targets`
4. **Test**: `cargo test`
5. **Golden tests**: verify output parity with `sipcalc` via `cargo test --test golden_compare`.
   To update golden fixtures, run `sipcalc <args> > tests/sipcalc_golden/<name>.txt`.
6. **Documentation**: `cargo doc --open`
7. **Markdown lint**:
   `markdownlint-cli2 "**/*.md"`
8. **Commit messages**: follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

Ensure all steps pass before pushing changes.

## CLI Usage

```bash
ripcalc [OPTIONS] <INPUTS>...
```

Common options:

- `-s, --split <bits>`: split the network into subnets of the given prefix length.
- `-a, --all`          : display all available information (classful, bitmaps, etc.).
- `--json`             : output results as JSON.
- `--help`             : display help information.
- `-v, --verbose`       : verbose output (detailed split information).
- `-V, --version`       : show version information.

Examples:

```bash
ripcalc 192.168.1.0/24
ripcalc --json 2001:db8::/48
ripcalc -s 26 10.0.0.0/16
```
