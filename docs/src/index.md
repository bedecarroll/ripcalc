# ripcalc

`ripcalc` is a Rust-based CLI subnet calculator that builds upon the excellent foundation of `sipcalc`. While maintaining full compatibility with sipcalc's proven interface and core functionality, ripcalc extends the legacy with modern enhancements and additional features.

## Standing on the Shoulders of Giants

**sipcalc** has been an invaluable tool for network engineers and system administrators for decades. Its simple, reliable interface and comprehensive subnet calculations have made it a cornerstone of network tooling. ripcalc honors this legacy by:

- **Preserving the familiar interface** that sipcalc users know and trust
- **Maintaining output compatibility** for existing scripts and workflows  
- **Building upon proven algorithms** that have served the community well

## Building Upon sipcalc's Foundation

### 🎯 **Enhanced Precision**
- **Modern IPv6 Classifications**: Implements current RFC specifications while preserving sipcalc's core functionality
- **Refined Multiple Input Handling**: Extends sipcalc's multiple input support with clearer indexing
- **Improved Error Reporting**: Provides clearer feedback while maintaining sipcalc's robustness

### ✨ **Extended Capabilities**
- **JSON Output Support**: Adds structured output format (`--json`) for modern automation needs
- **Enhanced IPv6 Support**: Builds on sipcalc's IPv6 foundation with current RFC classifications
- **Memory-Safe Implementation**: Rust foundation provides additional reliability alongside sipcalc's proven algorithms

### 🏗️ **Modern Tooling**
- **Active Maintenance**: Ongoing development to keep pace with evolving network standards
- **Comprehensive Testing**: Extensive test suite including golden tests to ensure compatibility with sipcalc
- **Community-Driven**: Built for and by the network engineering community

## Evolutionary Enhancements

| Aspect | sipcalc (Proven Foundation) | ripcalc (Building Forward) |
|--------|------------------------------|----------------------------|
| **IPv6 2001:db8::/32** | "Aggregatable Global Unicast" | "Documentation Address" (RFC 3849 specific) |
| **IPv6 2002::/16** | "Aggregatable Global Unicast" | "6to4 Transition Address" (RFC 3056 specific) |
| **IPv6 ::1** | "Reserved" + comment | "Loopback Address" (direct classification) |
| **IPv4-mapped IPv6** | "Reserved" | "IPv4-mapped IPv6 address" (descriptive) |
| **Error Handling** | Continues processing | Provides immediate, clear feedback |
| **Multiple Inputs** | Index display | Enhanced index clarity |
| **Output Formats** | Text output | Text + JSON for automation |
| **Interface** | Time-tested CLI | Preserved + extended options |

## Honoring sipcalc's Legacy

ripcalc exists not to replace sipcalc, but to extend its life and utility into modern networking environments. Every design decision respects sipcalc's proven approach while thoughtfully adding capabilities that today's network professionals need.

This documentation covers installation, usage, detailed examples, and development guidelines for contributing to sipcalc's ongoing legacy.
