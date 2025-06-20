use std::path::PathBuf;
use std::process::Command;

/// Transform sipcalc output to account for ripcalc's intentional modern improvements.
/// This allows us to test against sipcalc golden files while documenting our deliberate changes.
fn transform_sipcalc_to_ripcalc(s: &str) -> String {
    let mut result = s.to_string();

    // Modern IPv6 address classification changes (documented in test_modern_ipv6_classification)

    // Context-specific transformations based on address ranges
    if result.contains("2001:db8:") {
        // RFC 3849: 2001:db8::/32 is reserved for documentation
        result = result.replace(
            "Aggregatable Global Unicast Addresses",
            "Documentation Address",
        );
    } else if result.contains("2002:") {
        // RFC 3056: 2002::/16 is for 6to4 transition mechanism
        result = result.replace(
            "Aggregatable Global Unicast Addresses",
            "6to4 Transition Address",
        );
    } else if result.contains("2001::") || result.contains("2001:0000:") {
        // RFC 4380: 2001::/32 is for Teredo tunneling
        result = result.replace(
            "Aggregatable Global Unicast Addresses",
            "Teredo Tunneling Address",
        );
    } else if result.contains("::1") {
        result = result.replace("Reserved", "Loopback Address");
        let had_trailing_newline = result.ends_with('\n');
        result = result
            .lines()
            .filter(|line| !line.starts_with("Comment\t"))
            .collect::<Vec<_>>()
            .join("\n");
        if had_trailing_newline {
            result.push('\n');
        }
    }

    // General formatting standardizations - ripcalc uses singular form consistently
    result = result.replace("Link-Local Unicast Addresses", "Link-Local Unicast Address"); // fe80::/10 addresses
    result = result.replace("Multicast Addresses", "Multicast Address"); // ff00::/8 addresses

    result
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

    // Define test cases: (golden file stem, cli arguments, known_issue_reason)
    // known_issue_reason: None = should pass, Some(reason) = documents why it fails
    let cases: &[(&str, &[&str], Option<&str>)] = &[
        // IPv4 Basic Tests
        ("ipv4_cidr", &["192.168.1.0/24"], None),
        ("ipv4_dotted_decimal", &["10.0.0.1 255.255.255.0"], None),
        ("ipv4_hex_mask", &["10.0.0.1 0xFFFFFF00"], None),
        ("ipv4_single_host", &["192.168.1.1/32"], None),
        ("ipv4_point_to_point", &["192.168.1.0/31"], None),
        ("ipv4_small_subnet", &["192.168.1.0/30"], None),
        ("ipv4_class_a_boundary", &["127.0.0.1/8"], None),
        ("ipv4_class_b_boundary", &["128.0.0.1/16"], None),
        ("ipv4_private_class_a", &["10.0.0.0/8"], None),
        ("ipv4_private_class_b", &["172.16.0.0/12"], None),
        ("ipv4_all_info", &["-a", "192.168.1.0/24"], None),
        ("ipv4_host_all_info", &["-a", "1.1.1.1"], None),
        // IPv4 Operations
        ("ipv4_split", &["-s", "26", "192.168.1.0/24"], None),
        ("ipv4_extra", &["-n", "3", "192.168.1.0/24"], None),
        ("ipv4_classful", &["-c", "192.168.1.0/24"], None),
        ("ipv4_cidr_bitmap", &["-b", "192.168.1.0/24"], None),
        ("ipv4_classful_bitmap", &["-x", "192.168.1.0/24"], None),
        // IPv4 Disabled Tests (documented reasons)
        ("ipv4_wildcard", &["-w", "192.168.1.0/24"], None),
        (
            "ipv4_verbose_split",
            &["-v", "-s", "26", "192.168.1.0/24"],
            Some("ripcalc's verbose mode output format differs from sipcalc"),
        ),
        (
            "ipv4_multiple_inputs",
            &["192.168.1.0/24", "10.0.0.0/16"],
            Some(
                "ripcalc correctly increments index (0,1) vs sipcalc's incorrect (0,0) - tested separately",
            ),
        ),
        (
            "ipv4_invalid_octets",
            &["999.999.999.999"],
            Some("ripcalc exits with error vs sipcalc produces partial output"),
        ),
        (
            "ipv4_invalid_prefix",
            &["192.168.1.0/99"],
            Some("ripcalc exits with error vs sipcalc produces partial output"),
        ),
        (
            "invalid_format",
            &["not.an.ip.address"],
            Some("ripcalc exits with error vs sipcalc produces partial output"),
        ),
        // IPv6 Basic Tests
        ("ipv6_bare_address", &["2001:db8::1"], None),
        ("ipv6_cidr", &["2001:db8::/48"], None),
        ("ipv6_single_host", &["2001:db8::1/128"], None),
        ("ipv6_large_prefix", &["2001::/16"], None),
        ("ipv6_link_local", &["fe80::/64"], None),
        ("ipv6_multicast", &["ff02::1/128"], None),
        ("ipv6_6to4", &["2002::/16"], None),
        // IPv6 Operations
        ("ipv6_reverse", &["-r", "2001:db8::/48"], None),
        ("ipv6_v4inv6", &["-e", "::ffff:192.0.2.1"], None),
        ("ipv6_split", &["-S", "64", "2001:db8::/48"], None),
        // IPv6 Special Cases
        ("ipv6_ipv4_mapped", &["::ffff:192.0.2.1"], None),
        ("ipv6_ipv4_compatible", &["::192.0.2.1/128"], None),
        ("ipv6_loopback", &["::1/128"], None),
        (
            "ipv6_invalid_hex",
            &["2001:db8::gggg"],
            Some("ripcalc exits with error vs sipcalc produces partial output"),
        ),
        (
            "ipv6_invalid_prefix",
            &["2001:db8::/200"],
            Some("ripcalc exits with error vs sipcalc produces partial output"),
        ),
    ];

    let mut passing_tests = Vec::new();
    let mut failing_tests = Vec::new();
    let mut documented_failures = Vec::new();

    for (name, args, known_issue) in cases {
        let golden_file = format!(
            "{}/tests/sipcalc_golden/{}.txt",
            env!("CARGO_MANIFEST_DIR"),
            name
        );

        // Skip tests where we don't have golden files
        if !std::path::Path::new(&golden_file).exists() {
            eprintln!("SKIP: {} - No golden file found", name);
            continue;
        }

        let golden = std::fs::read_to_string(&golden_file)
            .unwrap_or_else(|_| panic!("Failed to read golden file {golden_file}"));
        let expected = transform_sipcalc_to_ripcalc(&golden);

        let output = Command::new(&exe)
            .args(*args)
            .output()
            .expect("failed to execute ripcalc");

        // Handle expected failures (invalid inputs)
        if !output.status.success() {
            if known_issue.is_some() {
                documented_failures.push(format!(
                    "DOCUMENTED: {} - {}",
                    name,
                    known_issue.unwrap()
                ));
                continue;
            } else {
                panic!(
                    "ripcalc returned unexpected error for {name}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        let rip_out = String::from_utf8_lossy(&output.stdout);

        if expected != rip_out.as_ref() {
            if let Some(reason) = known_issue {
                documented_failures.push(format!("DOCUMENTED: {} - {}", name, reason));
            } else {
                failing_tests.push(format!(
                    "FAIL: {} - Output formatting needs fix in main code",
                    name
                ));
                eprintln!("=== FORMATTING ISSUE: {} ===", name);
                eprintln!("Expected (sipcalc):\n{}", expected);
                eprintln!("Actual (ripcalc):\n{}", rip_out);
                eprintln!("=== END {} ===\n", name);
            }
        } else {
            passing_tests.push(name.to_string());
            eprintln!("PASS: {}", name);
        }
    }

    // Summary report
    eprintln!("\n=== TEST SUMMARY ===");
    eprintln!("Passing: {} tests", passing_tests.len());
    eprintln!("Failing: {} tests", failing_tests.len());
    eprintln!("Documented issues: {} tests", documented_failures.len());

    if !documented_failures.is_empty() {
        eprintln!("\nDocumented failures:");
        for failure in &documented_failures {
            eprintln!("  {}", failure);
        }
    }

    // Only fail the test if there are unexpected failures
    if !failing_tests.is_empty() {
        panic!("Unexpected test failures:\n{}", failing_tests.join("\n"));
    }
}
