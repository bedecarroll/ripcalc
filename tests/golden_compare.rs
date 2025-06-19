use std::path::PathBuf;
use std::process::Command;

/// Normalize whitespace: collapse all whitespace sequences to single spaces.
fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Returns the path to the ripcalc binary (assumes target/debug/ripcalc).
fn ripcalc_exe() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push(if cfg!(windows) {
        "ripcalc.exe"
    } else {
        "ripcalc"
    });
    path
}

#[test]
fn compare_with_golden_outputs() {
    let exe = ripcalc_exe();
    assert!(exe.exists(), "ripcalc binary not found at {exe:?}");

    // Define test cases: (golden file stem, cli arguments)
    // NOTE: IPv6 tests that use modern address classification are handled separately
    // to document intentional divergence from sipcalc's outdated terminology
    let cases: &[(&str, &[&str])] = &[
        ("ipv4_cidr", &["192.168.1.0/24"]),
        // Single argument containing spaced address and netmask
        ("ipv4_dotted_decimal", &["10.0.0.1 255.255.255.0"]),
        ("ipv4_hex_mask", &["10.0.0.1 0xFFFFFF00"]),
        ("ipv4_split", &["-s", "26", "192.168.1.0/24"]),
        ("ipv4_extra", &["-n", "3", "192.168.1.0/24"]),
        ("ipv4_classful", &["-c", "192.168.1.0/24"]),
        ("ipv4_cidr_bitmap", &["-b", "192.168.1.0/24"]),
        ("ipv4_classful_bitmap", &["-x", "192.168.1.0/24"]),
        // IPv6 tests that don't involve address type classification
        ("ipv6_reverse", &["-r", "2001:db8::/48"]),
        ("ipv6_v4inv6", &["-e", "::ffff:192.0.2.1"]),
        ("ipv6_split", &["-S", "64", "2001:db8::/48"]),
    ];

    for (name, args) in cases {
        let golden_file = format!(
            "{}/tests/sipcalc_golden/{}.txt",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        let golden = std::fs::read_to_string(&golden_file)
            .unwrap_or_else(|_| panic!("Failed to read golden file {golden_file}"));
        let golden_norm = normalize(&golden);

        let output = Command::new(&exe)
            // args is &&[&str], deref to &[&str]
            .args(*args)
            .output()
            .expect("failed to execute ripcalc");
        assert!(output.status.success(), "ripcalc returned error for {name}");
        let rip_out = String::from_utf8_lossy(&output.stdout);
        let rip_norm = normalize(&rip_out);
        assert_eq!(golden_norm, rip_norm, "Output mismatch for {name}");
    }
}

/// Test documenting intentional divergence from sipcalc for IPv6 address classification.
///
/// ripcalc uses modern IPv6 address classification based on current IANA assignments
/// and RFC standards (as of 2024), while sipcalc uses outdated terminology from the late 1990s.
///
/// This test validates our modern behavior and documents why we diverge from sipcalc.
#[test]
fn test_modern_ipv6_classification() {
    let exe = ripcalc_exe();
    assert!(exe.exists(), "ripcalc binary not found at {exe:?}");

    // Test cases that demonstrate modern IPv6 classification vs sipcalc's outdated terms
    let modern_cases: &[(&str, &str, &str)] = &[
        (
            "2001:db8::/48",
            "Documentation Address",
            "sipcalc incorrectly classifies this as 'Aggregatable Global Unicast' but RFC 3849 defines 2001:db8::/32 as documentation",
        ),
        (
            "2001:db8::1",
            "Documentation Address",
            "All addresses in 2001:db8::/32 are reserved for documentation per RFC 3849",
        ),
        (
            "2001::/32",
            "Teredo",
            "RFC 4380 defines 2001::/32 for Teredo tunneling - more specific than sipcalc's generic classification",
        ),
        (
            "2002::/16",
            "6to4 Transition",
            "RFC 3056 defines 2002::/16 for 6to4 transition mechanism",
        ),
    ];

    for (input, expected_type, rationale) in modern_cases {
        let output = Command::new(&exe)
            .args([*input])
            .output()
            .expect("failed to execute ripcalc");

        assert!(
            output.status.success(),
            "ripcalc returned error for {input}"
        );
        let rip_out = String::from_utf8_lossy(&output.stdout);

        // Verify modern classification is present
        assert!(
            rip_out.contains(expected_type),
            "Expected '{expected_type}' for {input} but got: {rip_out}\nRationale: {rationale}"
        );

        // Verify old sipcalc terminology is NOT present
        assert!(
            !rip_out.contains("Aggregatable Global Unicast"),
            "Should not contain outdated 'Aggregatable Global Unicast' terminology for {input}\nRationale: {rationale}"
        );
    }
}
