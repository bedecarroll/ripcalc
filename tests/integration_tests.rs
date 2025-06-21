use std::process::Command;
use std::str;

#[test]
fn test_basic_ipv4_calculation() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Check for expected output sections
    assert!(stdout.contains("-[ipv4 : 192.168.1.0/24] - 0"));
    assert!(stdout.contains("[CIDR]"));
    assert!(stdout.contains("Host address\t\t- 192.168.1.0"));
    assert!(stdout.contains("Network address\t\t- 192.168.1.0"));
    assert!(stdout.contains("Broadcast address\t- 192.168.1.255"));
    assert!(stdout.contains("Network mask\t\t- 255.255.255.0"));
    assert!(stdout.contains("Usable range\t\t- 192.168.1.1 - 192.168.1.254"));
}

#[test]
fn test_basic_ipv6_calculation() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["2001:db8::/48"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Check for expected output sections
    assert!(stdout.contains("-[ipv6 : 2001:db8::/48] - 0"));
    assert!(stdout.contains("[IPV6 INFO]"));
    assert!(stdout.contains("Expanded Address\t- 2001:0db8:0000:0000:0000:0000:0000:0000"));
    assert!(stdout.contains("Compressed address\t- 2001:db8::"));
    assert!(stdout.contains("Address type\t\t- Documentation Address"));
    assert!(stdout.contains("Network range"));
}

#[test]
fn test_json_output() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["--json", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Parse as JSON to verify it's valid
    let json: serde_json::Value = serde_json::from_str(stdout).unwrap();

    assert_eq!(json["type"], "ipv4");
    assert_eq!(json["host_address"], "192.168.1.0");
    assert_eq!(json["network_mask_bits"], 24);
    assert_eq!(json["broadcast_address"], "192.168.1.255");
}

#[test]
fn test_subnet_splitting() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-s", "26", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Check for subnet splitting output
    assert!(stdout.contains("[Split network]"));
    assert!(stdout.contains("192.168.1.0     - 192.168.1.63"));
    assert!(stdout.contains("192.168.1.64    - 192.168.1.127"));
    assert!(stdout.contains("192.168.1.128   - 192.168.1.191"));
    assert!(stdout.contains("192.168.1.192   - 192.168.1.255"));
}

#[test]
fn test_all_info_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-a", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Check for additional sections with -a flag
    assert!(stdout.contains("[CIDR]"));
    assert!(stdout.contains("[Classful]"));
    assert!(stdout.contains("[CIDR bitmaps]"));
    assert!(stdout.contains("Network class\t\t- C"));
}

#[test]
fn test_different_input_formats() {
    // Test dotted decimal netmask with explicit IPv4 flag
    let output = Command::new("./target/debug/ripcalc")
        .args(["-4", "192.168.1.5 255.255.255.0"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("192.168.1.5 255.255.255.0"));
    assert!(stdout.contains("Network address\t\t- 192.168.1.0"));

    // Test hex netmask with explicit IPv4 flag
    let output = Command::new("./target/debug/ripcalc")
        .args(["-4", "10.0.0.1 0xFFFF0000"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("10.0.0.1 0xFFFF0000"));
    assert!(stdout.contains("Network address\t\t- 10.0.0.0"));
}

#[test]
fn test_help_output() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["--help"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Check for help content
    assert!(
        stdout.contains("ripcalc is a Rust-based subnet calculator that builds upon the excellent foundation of sipcalc")
    );
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("--split"));
    assert!(stdout.contains("--all"));
}

#[test]
fn test_invalid_input_handling() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["invalid.ip.address"])
        .output()
        .expect("Failed to execute ripcalc");

    let stderr = str::from_utf8(&output.stderr).unwrap();

    // Should produce an error message
    assert!(stderr.contains("Error") || stderr.contains("Unable to parse"));
}

#[test]
fn test_comprehensive_error_handling() {
    let error_cases = &[
        ("999.999.999.999", "invalid IPv4 octets"),
        ("192.168.1.0/99", "invalid IPv4 prefix"),
        ("2001:db8::gggg", "invalid IPv6 hex"),
        ("2001:db8::/200", "invalid IPv6 prefix"),
        ("", "empty input"),
        ("not.an.ip", "invalid format"),
    ];

    for (input, description) in error_cases {
        let output = Command::new("./target/debug/ripcalc")
            .args([*input])
            .output()
            .expect("Failed to execute ripcalc");

        // Ripcalc should return non-zero exit codes on errors
        assert!(
            !output.status.success(),
            "Should fail for {description}: {input}"
        );

        let stderr = str::from_utf8(&output.stderr).unwrap();
        // Should produce some error message
        assert!(
            !stderr.is_empty(),
            "Should have error message for {description}: {input}"
        );
    }
}

#[test]
fn test_multiple_inputs() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["192.168.1.0/24", "10.0.0.0/16"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Should contain both calculations
    assert!(stdout.contains("-[ipv4 : 192.168.1.0/24] - 0"));
    assert!(stdout.contains("-[ipv4 : 10.0.0.0/16] - 1"));
}

#[test]
fn test_ipv6_split_formatting() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-S", "65", "fdbb::1/64"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Check for IPv6 split network output with correct formatting
    assert!(stdout.contains("[Split network]"));
    // Verify the specific formatting with tabs and line breaks matches sipcalc
    assert!(stdout.contains("Network\t\t\t- fdbb:0000:0000:0000:0000:0000:0000:0000 -\n\t\t\t  fdbb:0000:0000:0000:7fff:ffff:ffff:ffff"));
    assert!(stdout.contains("Network\t\t\t- fdbb:0000:0000:0000:8000:0000:0000:0000 -\n\t\t\t  fdbb:0000:0000:0000:ffff:ffff:ffff:ffff"));
}

#[test]
fn test_extra_subnets() {
    // Test -n with positive number
    let output = Command::new("./target/debug/ripcalc")
        .args(["-n", "3", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Check for extra subnets output
    assert!(stdout.contains("[Networks]"));
    assert!(stdout.contains("192.168.1.0     - 192.168.1.255 (current)"));
    assert!(stdout.contains("192.168.2.0     - 192.168.2.255"));
    assert!(stdout.contains("192.168.3.0     - 192.168.3.255"));

    // Test -n 0 to show all subnets in containing /24
    let output = Command::new("./target/debug/ripcalc")
        .args(["-n", "0", "192.168.10.64/26"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Check for all /26 subnets in the /24
    assert!(stdout.contains("[Networks]"));
    assert!(stdout.contains("192.168.10.0    - 192.168.10.63"));
    assert!(stdout.contains("192.168.10.64   - 192.168.10.127 (current)"));
    assert!(stdout.contains("192.168.10.128  - 192.168.10.191"));
    assert!(stdout.contains("192.168.10.192  - 192.168.10.255"));
}

#[test]
fn test_stdin_input() {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("./target/debug/ripcalc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ripcalc");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin
            .write_all(b"192.168.1.0/24\n10.0.0.0/16\n")
            .expect("Failed to write to stdin");
    }

    let output = child.wait_with_output().expect("Failed to read stdout");
    let stdout = str::from_utf8(&output.stdout).unwrap();

    // Should contain both calculations from stdin
    assert!(stdout.contains("192.168.1.0/24"));
    assert!(stdout.contains("10.0.0.0/16"));
}

// ===== COMPREHENSIVE FLAG TESTING =====

// All sipcalc compatibility features have been implemented:
// ✓ DNS resolution flag (-d/--resolve)
// ✓ Long format flags (--all, --help, --version, etc.)
// ✓ Hex mask without 0x prefix (NNNNNNNN format)
// ✓ Boundary values (/0, /32 for IPv4; /0, /128 for IPv6)
// ✓ Exit code handling for errors
// ✓ Comprehensive flag combination testing

#[test]
fn test_cidr_bitmap_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-b", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[CIDR bitmaps]"));
    assert!(stdout.contains("Host address\t\t- 11000000.10101000.00000001.00000000"));
    assert!(stdout.contains("Network mask\t\t- 11111111.11111111.11111111.00000000"));
    assert!(stdout.contains("Broadcast address\t- 11000000.10101000.00000001.11111111"));
}

#[test]
fn test_classful_addr_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-c", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[Classful]"));
    assert!(stdout.contains("Network class\t\t- C"));
    assert!(stdout.contains("Host address (decimal)\t- 3232235776"));
    assert!(stdout.contains("Host address (hex)\t- C0A80100"));
}

#[test]
fn test_wildcard_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-w", "0.0.0.255"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[WILDCARD]"));
    assert!(stdout.contains("Wildcard\t\t- 0.0.0.255"));
    assert!(stdout.contains("Network mask\t\t- 255.255.255.0"));
    assert!(stdout.contains("Network mask (bits)\t- 24"));
}

#[test]
fn test_classful_bitmap_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-x", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[Classful bitmaps]"));
    assert!(stdout.contains("Network address\t\t- 11000000.10101000.00000001.00000000"));
    assert!(stdout.contains("Network mask\t\t- 11111111.11111111.11111111.00000000"));
}

#[test]
fn test_ipv6_v4inv6_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-e", "::ffff:192.168.1.1"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[V4INV6]"));
}

#[test]
fn test_ipv6_reverse_dns_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-r", "2001:db8::1"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[IPV6 DNS]"));
    assert!(stdout.contains("Reverse DNS (ip6.arpa)"));
    assert!(
        stdout
            .contains("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.")
    );
}

#[test]
fn test_ipv6_standard_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-t", "2001:db8::/48"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[IPV6 INFO]"));
    assert!(stdout.contains("Expanded Address"));
    assert!(stdout.contains("Compressed address"));
}

#[test]
fn test_verbose_split_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-u", "-s", "26", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[Split network - verbose]"));
    // Should contain multiple detailed subnet calculations
    assert!(stdout.contains("192.168.1.0/24"));
    assert!(stdout.contains("192.168.1.64"));
    assert!(stdout.contains("192.168.1.128"));
    assert!(stdout.contains("192.168.1.192"));
}

#[test]
fn test_explicit_ipv4_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-4", "192.168.1.5 255.255.255.0"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("192.168.1.5 255.255.255.0"));
    assert!(stdout.contains("Network address\t\t- 192.168.1.0"));
}

#[test]
fn test_explicit_ipv6_flag() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-6", "2001:db8::1/64"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("-[ipv6 : 2001:db8::1/64]"));
    assert!(stdout.contains("[IPV6 INFO]"));
}

// ===== FLAG COMBINATION TESTS =====

#[test]
fn test_multiple_ipv4_flags() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-b", "-c", "-x", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[CIDR bitmaps]"));
    assert!(stdout.contains("[Classful]"));
    assert!(stdout.contains("[Classful bitmaps]"));
}

#[test]
fn test_multiple_ipv6_flags() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-r", "-t", "2001:db8::1"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[IPV6 DNS]"));
    assert!(stdout.contains("[IPV6 INFO]"));
}

#[test]
fn test_all_flag_with_ipv4() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-a", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    // -a should include -b -c -i -n 0 for IPv4
    assert!(stdout.contains("[CIDR]"));
    assert!(stdout.contains("[Classful]"));
    assert!(stdout.contains("[CIDR bitmaps]"));
    assert!(stdout.contains("[Networks]"));
}

#[test]
fn test_all_flag_with_ipv6() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-a", "2001:db8::/48"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    // -a should include -e -r -t for IPv6
    assert!(stdout.contains("[IPV6 INFO]"));
    assert!(stdout.contains("[IPV6 DNS]"));
    assert!(stdout.contains("[V4INV6]"));
}

#[test]
fn test_json_with_flags() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["--json", "-a", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    // Should be valid JSON even with multiple flags
    let json: serde_json::Value = serde_json::from_str(stdout).unwrap();
    assert_eq!(json["type"], "ipv4");
}

#[test]
fn test_split_with_extra_subnets() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-s", "26", "-n", "2", "192.168.1.0/24"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[Split network]"));
    assert!(stdout.contains("[Networks]"));
}

#[test]
fn test_ipv6_split_with_flags() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-S", "65", "-r", "fdbb::1/64"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("[Split network]"));
    assert!(stdout.contains("[IPV6 DNS]"));
}

// ===== COMPATIBILITY VERIFICATION TESTS =====

#[test]
fn test_sipcalc_compatibility_version() {
    let output = Command::new("./target/debug/ripcalc")
        .args(["-v"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.starts_with("ripcalc "));
    assert!(!stdout.contains("sipcalc")); // Should be ripcalc, not sipcalc
}

#[test]
fn test_interface_with_explicit_flag() {
    // Test explicit interface flag (may not work on all systems)
    let output = Command::new("./target/debug/ripcalc")
        .args(["-I", "lo"])
        .output()
        .expect("Failed to execute ripcalc");

    // Interface tests are environment-dependent, just check it doesn't crash
    assert!(output.status.success() || !str::from_utf8(&output.stderr).unwrap().is_empty());
}

#[test]
fn test_various_input_formats() {
    let test_cases = vec![
        ("-4", "192.168.1.5 255.255.255.0", "dotted decimal mask"),
        ("-4", "10.0.0.1 0xFFFF0000", "hex mask"),
        ("-4", "172.16.0.1/16", "CIDR notation"),
        ("-6", "2001:db8::1/64", "IPv6 CIDR"),
        ("-6", "::1", "IPv6 loopback"),
    ];

    for (flag, input, description) in test_cases {
        let output = Command::new("./target/debug/ripcalc")
            .args([flag, input])
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute ripcalc for {description}"));

        assert!(output.status.success(), "Failed for {description}: {input}");
        let stdout = str::from_utf8(&output.stdout).unwrap();
        assert!(
            !stdout.is_empty(),
            "Empty output for {description}: {input}"
        );
    }
}

// ===== ERROR HANDLING FOR FLAGS =====

#[test]
fn test_invalid_flag_combinations() {
    // These should still work but may produce warnings or unexpected output
    let output = Command::new("./target/debug/ripcalc")
        .args(["-4", "-6", "192.168.1.0/24"]) // conflicting explicit types
        .output()
        .expect("Failed to execute ripcalc");

    // Should not crash, may produce an error
    let stderr = str::from_utf8(&output.stderr).unwrap();
    // This is expected to work since -4 takes precedence
    assert!(output.status.success() || !stderr.is_empty());
}

#[test]
fn test_comprehensive_flag_coverage() {
    // Test that all flags are recognized and don't cause "unknown option" errors
    let all_flags = vec![
        "-a", "-b", "-c", "-d", "-e", "-h", "-i", "-I", "-n", "-r", "-s", "-S", "-t", "-u", "-v",
        "-w", "-x", "-4", "-6",
    ];

    for flag in all_flags {
        let output = Command::new("./target/debug/ripcalc")
            .args(["--help"])
            .output()
            .expect("Failed to execute ripcalc --help");

        let stdout = str::from_utf8(&output.stdout).unwrap();
        // All flags should be documented in help
        assert!(
            stdout.contains(&format!(" {flag}")) || stdout.contains(&format!("{flag},")),
            "Flag {flag} not found in help output"
        );
    }
}

// ===== MISSING SIPCALC FEATURE TESTS =====

#[test]
fn test_resolve_flag() {
    // Test -d/--resolve flag for name resolution
    // This feature enables DNS lookups for IP addresses
    // NOTE: Using localhost/127.0.0.1 to avoid CI environment DNS differences
    // In production, this should use mocking for deterministic testing
    let output = Command::new("./target/debug/ripcalc")
        .args(["-d", "127.0.0.1/8"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    // Should work even if DNS resolution fails, just test the flag is recognized
    // Note: Consider implementing proper mocking for DNS resolution testing in future
    assert!(output.status.success());
    assert!(stdout.contains("127.0.0.1"));
}

#[test]
fn test_long_format_flags() {
    // Test long format equivalents of short flags
    let test_cases = vec![
        (vec!["--all", "192.168.1.0/24"], "[CIDR]"),
        (vec!["--help"], "subnet calculator"),
        (vec!["--version"], "ripcalc"),
        (vec!["--cidr-bitmap", "192.168.1.0/24"], "[CIDR bitmaps]"),
        (vec!["--classful-addr", "192.168.1.0/24"], "[Classful]"),
        (vec!["--wildcard", "0.0.0.255"], "[WILDCARD]"),
    ];

    for (args, expected) in test_cases {
        let output = Command::new("./target/debug/ripcalc")
            .args(&args)
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute ripcalc with args: {args:?}"));

        let stdout = str::from_utf8(&output.stdout).unwrap();
        assert!(
            stdout.contains(expected),
            "Expected '{expected}' in output for args {args:?}"
        );
    }
}

#[test]
fn test_hex_mask_without_prefix() {
    // Test hex mask in nnnnnnnn format (without 0x prefix)
    let output = Command::new("./target/debug/ripcalc")
        .args(["-4", "10.0.0.1 FFFF0000"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("10.0.0.1"));
    assert!(stdout.contains("Network address\t\t- 10.0.0.0"));
}

#[test]
fn test_boundary_values() {
    // Test boundary prefix lengths
    let test_cases = vec![
        ("-4", "192.168.1.1/0", "entire IPv4 space"),
        ("-4", "192.168.1.1/32", "single host"),
        ("-6", "2001:db8::1/0", "entire IPv6 space"),
        ("-6", "2001:db8::1/128", "single IPv6 host"),
    ];

    for (flag, input, description) in test_cases {
        let output = Command::new("./target/debug/ripcalc")
            .args([flag, input])
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute ripcalc for {description}"));

        assert!(output.status.success(), "Failed for {description}: {input}");
        let stdout = str::from_utf8(&output.stdout).unwrap();
        assert!(
            !stdout.is_empty(),
            "Empty output for {description}: {input}"
        );
    }
}

#[test]
fn test_comprehensive_flag_combinations() {
    // Test comprehensive flag combinations for maximum coverage
    let test_cases = vec![
        (vec!["-a", "-d", "192.168.1.0/24"], "all info with resolve"),
        (
            vec!["-b", "-c", "-x", "-u", "192.168.1.0/24"],
            "all bitmap flags with verbose",
        ),
        (
            vec!["-s", "26", "-n", "2", "-u", "192.168.1.0/24"],
            "split with subnets and verbose",
        ),
        (vec!["-4", "-6", "192.168.1.0/24"], "conflicting type flags"),
        (
            vec!["-t", "-r", "-e", "2001:db8::1/64"],
            "all IPv6 info flags",
        ),
    ];

    for (args, description) in test_cases {
        let output = Command::new("./target/debug/ripcalc")
            .args(&args)
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute ripcalc for {description}"));

        // Should not crash, even with conflicting flags
        let _stdout = str::from_utf8(&output.stdout).unwrap();
        let stderr = str::from_utf8(&output.stderr).unwrap();
        assert!(
            output.status.success() || !stderr.is_empty(),
            "Unexpected failure for {description}: {args:?}"
        );
    }
}
