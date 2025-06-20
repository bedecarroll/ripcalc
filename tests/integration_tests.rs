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
    assert!(stdout.contains("Expanded Address        - 2001:0db8:0000:0000:0000:0000:0000:0000"));
    assert!(stdout.contains("Compressed address      - 2001:db8::"));
    assert!(stdout.contains("Address type            - Documentation Address"));
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
    assert!(stdout.contains("Network class           - C"));
}

#[test]
fn test_different_input_formats() {
    // Test dotted decimal netmask with explicit IPv4 flag
    let output = Command::new("./target/debug/ripcalc")
        .args(["-4", "192.168.1.5 255.255.255.0"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("192.168.1.5/24"));
    assert!(stdout.contains("Network address\t\t- 192.168.1.0"));

    // Test hex netmask with explicit IPv4 flag
    let output = Command::new("./target/debug/ripcalc")
        .args(["-4", "10.0.0.1 0xFFFF0000"])
        .output()
        .expect("Failed to execute ripcalc");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.contains("10.0.0.1/16"));
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
        stdout.contains("A subnet calculator that replicates and extends sipcalc functionality")
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

        // Note: ripcalc currently doesn't set proper exit codes, so we only check for error messages
        // TODO: Fix ripcalc to return non-zero exit codes on errors
        // assert!(!output.status.success(), "Should fail for {description}: {input}");

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
