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

**`tests/sipcalc_golden/` contains ONLY genuine sipcalc output - NEVER ripcalc output!**

#### Strict Rules for Golden Files

1. **ONLY sipcalc output** - Never add ripcalc output to this directory
2. **NO ripcalc-specific features** - JSON, modern IPv6 classifications, etc. don't belong here
3. **Never edit existing golden files** - they preserve exact sipcalc behavior
4. **Generation command**: `sipcalc <args> > tests/sipcalc_golden/<name>.txt`

#### ❌ Common Mistakes to Avoid

```bash
# WRONG - Never use ripcalc for golden files
./target/release/ripcalc 192.168.1.0/24 > tests/sipcalc_golden/example.txt

# WRONG - sipcalc doesn't support JSON
./target/release/ripcalc --json 192.168.1.0/24 > tests/sipcalc_golden/json_example.txt

# CORRECT - Always use sipcalc
sipcalc 192.168.1.0/24 > tests/sipcalc_golden/ipv4_example.txt
```

#### Testing Strategy by Feature Type

| Feature Type | Test Location | Golden Files? | Purpose |
|--------------|---------------|---------------|---------|
| **sipcalc compatibility** | `tests/golden_compare.rs::compare_with_golden_outputs()` | ✅ Yes | Exact output matching |
| **ripcalc improvements** | `tests/golden_compare.rs::test_ripcalc_improvements()` | ❌ No | Document intentional differences |
| **ripcalc-only features** | `tests/golden_compare.rs::test_json_output()` | ❌ No | Validate ripcalc functionality |
| **Modern IPv6 classification** | `tests/golden_compare.rs::test_modern_ipv6_classification()` | ❌ No | Document modernization |

#### Features That Should NOT Have Golden Files

- **JSON output** - ripcalc-specific feature (sipcalc doesn't support JSON)
- **Modern IPv6 address types** - ripcalc uses RFC-compliant terminology vs sipcalc's 1990s terms
- **Correct multiple input indexing** - ripcalc fixes sipcalc's indexing bug
- **Wildcard mode variations** - ripcalc's implementation differs intentionally
- **Verbose split differences** - different output format by design

#### Verification Before Committing

```bash
# Check for ripcalc contamination
grep -r "Documentation Address" tests/sipcalc_golden/  # Should be empty
grep -r '"type":' tests/sipcalc_golden/              # Should be empty (JSON)
grep -r "Teredo\|6to4 Transition" tests/sipcalc_golden/ # Should be empty (modern terms)

# Check for JSON format contamination
head -1 tests/sipcalc_golden/*.txt | grep "{"        # Should be empty
```

**Remember: This directory is the source of truth for sipcalc compatibility testing**

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
