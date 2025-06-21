# Packaging ripcalc

This document provides guidance for package maintainers who want to create distribution packages for ripcalc.

## Package Information

- **Name**: ripcalc
- **Description**: A Rust-based subnet calculator that replicates and extends sipcalc functionality
- **License**: MIT
- **Homepage**: https://github.com/bedecarroll/ripcalc
- **Documentation**: https://ripcalc.bedecarroll.com

## Build Requirements

### Runtime Dependencies
- None (statically linked Rust binary)

### Build Dependencies
- Rust toolchain (1.70+)
- Cargo
- Standard build tools (make, gcc/clang for some dependencies)

## Build Process

### Standard Build
```bash
cargo build --release
```

### With Manpage Generation
The manpage is automatically generated during the build process using `clap_mangen`. The generated manpage will be available at:
```
target/release/build/ripcalc-*/out/man/ripcalc.1
```

### Cross-compilation Support
ripcalc supports cross-compilation for various targets:
```bash
# Example for musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Installation Layout

### Binary
- **Location**: `/usr/bin/ripcalc` (or `/usr/local/bin/ripcalc`)
- **Permissions**: 755

### Manpage
- **Location**: `/usr/share/man/man1/ripcalc.1` (or `/usr/local/share/man/man1/ripcalc.1`)
- **Permissions**: 644
- **Source**: Auto-generated during build in `target/release/build/ripcalc-*/out/man/ripcalc.1`

### Shell Completions
- **Bash**: `/usr/share/bash-completion/completions/ripcalc`
- **Zsh**: `/usr/share/zsh/site-functions/_ripcalc`
- **Fish**: `/usr/share/fish/vendor_completions.d/ripcalc.fish`
- **PowerShell**: `ripcalc.ps1` (for Windows packages)
- **Permissions**: 644
- **Source**: Auto-generated during build in `target/release/build/ripcalc-*/out/completions/`

### Documentation (Optional)
- **Location**: `/usr/share/doc/ripcalc/`
- **Files**: `README.md`, `LICENSE`, `CHANGELOG.md` (if available)

## Package-Specific Notes

### Debian/Ubuntu (.deb)
```bash
# Build dependencies
Build-Depends: cargo, rustc (>= 1.70), pkg-config

# Runtime dependencies (none - statically linked)
Depends: ${shlibs:Depends}, ${misc:Depends}

# Package description
Description: Rust-based subnet calculator extending sipcalc functionality
 ripcalc is a modern subnet calculator that builds upon the excellent
 foundation of sipcalc. It maintains full compatibility with sipcalc's
 proven interface while adding modern enhancements including JSON output,
 enhanced IPv6 support with current RFC classifications, and improved
 error handling.
```

### Red Hat/Fedora (.rpm)
```spec
Name:           ripcalc
Version:        0.1.0
Release:        1%{?dist}
Summary:        Rust-based subnet calculator extending sipcalc functionality
License:        MIT
URL:            https://github.com/bedecarroll/ripcalc
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust >= 1.70

%description
ripcalc is a modern subnet calculator that builds upon the excellent
foundation of sipcalc. It maintains full compatibility with sipcalc's
proven interface while adding modern enhancements including JSON output,
enhanced IPv6 support with current RFC classifications, and improved
error handling.

%build
cargo build --release

%install
install -D -m 755 target/release/ripcalc %{buildroot}%{_bindir}/ripcalc
install -D -m 644 target/release/build/ripcalc-*/out/man/ripcalc.1 %{buildroot}%{_mandir}/man1/ripcalc.1
install -D -m 644 target/release/build/ripcalc-*/out/completions/ripcalc.bash %{buildroot}%{_datadir}/bash-completion/completions/ripcalc
install -D -m 644 target/release/build/ripcalc-*/out/completions/_ripcalc %{buildroot}%{_datadir}/zsh/site-functions/_ripcalc
install -D -m 644 target/release/build/ripcalc-*/out/completions/ripcalc.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/ripcalc.fish

%files
%license LICENSE
%doc README.md
%{_bindir}/ripcalc
%{_mandir}/man1/ripcalc.1*
%{_datadir}/bash-completion/completions/ripcalc
%{_datadir}/zsh/site-functions/_ripcalc
%{_datadir}/fish/vendor_completions.d/ripcalc.fish
```

### Arch Linux (PKGBUILD)
```bash
# Maintainer: Package Maintainer <email@domain.com>
pkgname=ripcalc
pkgver=0.1.0
pkgrel=1
pkgdesc="Rust-based subnet calculator extending sipcalc functionality"
arch=('x86_64')
url="https://github.com/bedecarroll/ripcalc"
license=('MIT')
depends=()
makedepends=('cargo' 'rust')
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$pkgname-$pkgver"
    cargo build --release --locked
}

package() {
    cd "$pkgname-$pkgver"
    install -Dm755 target/release/ripcalc "$pkgdir/usr/bin/ripcalc"
    install -Dm644 target/release/build/ripcalc-*/out/man/ripcalc.1 "$pkgdir/usr/share/man/man1/ripcalc.1"
    install -Dm644 target/release/build/ripcalc-*/out/completions/ripcalc.bash "$pkgdir/usr/share/bash-completion/completions/ripcalc"
    install -Dm644 target/release/build/ripcalc-*/out/completions/_ripcalc "$pkgdir/usr/share/zsh/site-functions/_ripcalc"
    install -Dm644 target/release/build/ripcalc-*/out/completions/ripcalc.fish "$pkgdir/usr/share/fish/vendor_completions.d/ripcalc.fish"
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
```

### Alpine Linux (APKBUILD)
```bash
# Maintainer: Package Maintainer <email@domain.com>
pkgname=ripcalc
pkgver=0.1.0
pkgrel=0
pkgdesc="Rust-based subnet calculator extending sipcalc functionality"
url="https://github.com/bedecarroll/ripcalc"
arch="all"
license="MIT"
makedepends="cargo"
source="$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz"

build() {
    cargo build --release --locked
}

check() {
    cargo test --release --locked
}

package() {
    install -Dm755 target/release/ripcalc "$pkgdir"/usr/bin/ripcalc
    install -Dm644 target/release/build/ripcalc-*/out/man/ripcalc.1 "$pkgdir"/usr/share/man/man1/ripcalc.1
    install -Dm644 target/release/build/ripcalc-*/out/completions/ripcalc.bash "$pkgdir"/usr/share/bash-completion/completions/ripcalc
    install -Dm644 target/release/build/ripcalc-*/out/completions/_ripcalc "$pkgdir"/usr/share/zsh/site-functions/_ripcalc
    install -Dm644 target/release/build/ripcalc-*/out/completions/ripcalc.fish "$pkgdir"/usr/share/fish/vendor_completions.d/ripcalc.fish
}
```

## Testing Package Builds

### Test Installation
```bash
# After package installation, verify:
ripcalc --version
man ripcalc
ripcalc 192.168.1.0/24
ripcalc --json 192.168.1.0/24

# Test shell completions
ripcalc --<TAB>    # Should show available flags
ripcalc -<TAB>     # Should show short options
```

### Compatibility Testing
```bash
# Test sipcalc compatibility (if sipcalc is available)
ripcalc 192.168.1.0/24 > ripcalc_output.txt
sipcalc 192.168.1.0/24 > sipcalc_output.txt
# Compare outputs (accounting for known improvements)
```

## Distribution-Specific Considerations

### File Conflicts
- **ripcalc** should not conflict with **sipcalc** packages
- Both tools can be installed simultaneously
- Consider adding "Suggests: sipcalc" for compatibility testing

### Security
- ripcalc is a network analysis tool (similar to sipcalc)
- No special permissions required
- Static binary with no external runtime dependencies

### Documentation
- Include README.md and LICENSE in package documentation
- Consider including example usage in package description
- Link to full documentation at https://ripcalc.bedecarroll.com

## Support

For packaging questions or issues:
1. Check existing issues at https://github.com/bedecarroll/ripcalc/issues
2. Review the development documentation in the repository
3. Create new issues for packaging-specific problems

## Version Updates

ripcalc follows semantic versioning. Package maintainers should:
1. Monitor releases at https://github.com/bedecarroll/ripcalc/releases
2. Test compatibility with existing workflows
3. Update package descriptions for new features as appropriate