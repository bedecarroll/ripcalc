# Development Workflow

This project maintains **clippy compliance at nursery level** (the highest available) and requires **all steps to pass with zero warnings** before pushing changes.

## Standard Development Process

1. **Format**: `cargo fmt --all`

2. **Lint (Comprehensive)**: `cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::nursery`
   - **Code Quality Standard**: Maintains clippy compliance at nursery level
   - **No `#[allow]` bypasses** for actual issues - fix the underlying problem instead
   - **The only allowed bypass**: `#[allow(dead_code)]` for intentionally unused but documented code

3. **Build**: `cargo build --all-targets`

4. **Test**: `cargo test`

5. **Golden tests**: `cargo test --test golden_compare`
   - Verifies output parity with `sipcalc` while accounting for our documented improvements

6. **Documentation**: `cargo doc --open`

7. **Markdown lint**: `markdownlint-cli2 "**/*.md"`

8. **Commit messages**: Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.

**All steps must pass with zero warnings before pushing changes.**

## Testing Strategy

### Golden Test Files Protection

**`tests/sipcalc_golden/` contains ONLY genuine sipcalc output - NEVER ripcalc output!**

#### Strict Rules for Golden Files

1. **ONLY sipcalc output** - Never add ripcalc output to this directory
2. **NO ripcalc-specific features** - JSON, modern IPv6 classifications, etc. don't belong here
3. **Never edit existing golden files** - they preserve exact sipcalc behavior
4. **Generation command**: `sipcalc <args> > tests/sipcalc_golden/<name>.txt`

#### Testing Strategy by Feature Type

| Feature Type | Test Location | Golden Files? | Purpose |
|--------------|---------------|---------------|---------|
| **sipcalc compatibility** | `tests/golden_compare.rs::compare_with_golden_outputs()` | ✅ Yes | Exact output matching |
| **ripcalc improvements** | `tests/golden_compare.rs::test_ripcalc_improvements()` | ❌ No | Document intentional differences |
| **ripcalc-only features** | `tests/golden_compare.rs::test_json_output()` | ❌ No | Validate ripcalc functionality |
| **Modern IPv6 classification** | `tests/golden_compare.rs::test_modern_ipv6_classification()` | ❌ No | Document modernization |

### Features That Should NOT Have Golden Files

- **JSON output** - ripcalc-specific feature (sipcalc doesn't support JSON)
- **Modern IPv6 address types** - ripcalc uses RFC-compliant terminology vs sipcalc's 1990s terms
- **Correct multiple input indexing** - ripcalc fixes sipcalc's indexing bug
- **Wildcard mode variations** - ripcalc's implementation differs intentionally
- **Verbose split differences** - different output format by design

## Code Quality Guidelines

- **Clippy Level**: Maintain nursery + pedantic + all lint compliance
- **Unused Code**: Remove unused code rather than ignoring with `_` prefixes  
- **Documentation**: Use proper backticks around code in doc comments
- **Function Length**: Keep functions under 100 lines (split large functions into helpers)
- **Self Usage**: Use `Self` instead of repeating type names
- **Const Functions**: Make functions `const` where possible for compile-time evaluation

## Contributing

Before submitting changes:

1. Run the complete development workflow above
2. Ensure all tests pass including golden tests
3. Update documentation if adding new features
4. Follow conventional commit message format
