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
2. **Lint (Comprehensive)**: `cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery`
   - **Code Quality Standard**: This project maintains **clippy compliance at nursery level** (the highest available)
   - **No `#[allow]` bypasses** for actual issues - fix the underlying problem instead
   - **The only allowed bypass**: `#[allow(dead_code)]` for intentionally unused but documented code
3. **Build**: `cargo build --all-targets`
4. **Test**: `cargo test`
5. **Golden tests**: verify output parity with `sipcalc` via `cargo test --test golden_compare`.
   To update golden fixtures, run `sipcalc <args> > tests/sipcalc_golden/<name>.txt`.
6. **Documentation**: `cargo doc --open`
7. **Markdown lint**:
   `markdownlint-cli2 "**/*.md"`
8. **Commit messages**: follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

**All steps must pass with zero warnings before pushing changes.**

### ⚠️ Critical: Golden Test Files Protection

**DO NOT modify files in `tests/sipcalc_golden/` unless adding new sipcalc output!**

- The `tests/sipcalc_golden/*.txt` files contain authentic `sipcalc` command output
- These files are **reference standards** for compatibility testing
- **Never edit existing golden files** - they preserve exact sipcalc behavior
- **Only add new files** when implementing new features that need sipcalc comparison
- **To add new golden output**: run `sipcalc <args> > tests/sipcalc_golden/<name>.txt`
- If ripcalc intentionally diverges from sipcalc (like modern IPv6 classification), handle the difference in test code, not golden files
- Maintaining sipcalc compatibility is a **core project goal**

### Code Quality Guidelines

- **Clippy Level**: Maintain nursery + pedantic + all lint compliance
- **Unused Code**: Remove unused code rather than ignoring with `_` prefixes
- **Documentation**: Use proper backticks around code in doc comments
- **Function Length**: Keep functions under 100 lines (split large functions into helpers)
- **Self Usage**: Use `Self` instead of repeating type names
- **Const Functions**: Make functions `const` where possible for compile-time evaluation

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
