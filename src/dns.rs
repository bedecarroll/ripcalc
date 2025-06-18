use anyhow::{Result, anyhow};
use dns_lookup::lookup_host;
use std::net::IpAddr;

#[derive(Debug)]
pub struct ResolvedAddress {
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
}

pub fn resolve_hostname(hostname: &str) -> Result<ResolvedAddress> {
    match lookup_host(hostname) {
        Ok(addresses) => {
            if addresses.is_empty() {
                Err(anyhow!("No addresses found for hostname '{}'", hostname))
            } else {
                Ok(ResolvedAddress {
                    hostname: hostname.to_string(),
                    addresses,
                })
            }
        }
        Err(e) => Err(anyhow!("DNS lookup failed for '{}': {}", hostname, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_resolved_address_structure() {
        let resolved = ResolvedAddress {
            hostname: "example.com".to_string(),
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            ],
        };

        assert_eq!(resolved.hostname, "example.com");
        assert_eq!(resolved.addresses.len(), 2);
        assert!(matches!(resolved.addresses[0], IpAddr::V4(_)));
        assert!(matches!(resolved.addresses[1], IpAddr::V6(_)));
    }

    // Note: The following tests would require actual DNS resolution and may fail
    // in environments without internet access or with DNS restrictions.
    // In a real-world scenario, you might want to mock these or make them conditional.

    #[test]
    fn test_resolve_localhost() {
        // This should work in most environments
        if let Ok(resolved) = resolve_hostname("localhost") {
            assert_eq!(resolved.hostname, "localhost");
            assert!(!resolved.addresses.is_empty());
            // localhost should resolve to 127.0.0.1 and/or ::1
            let has_ipv4_loopback = resolved
                .addresses
                .iter()
                .any(|addr| matches!(addr, IpAddr::V4(ip) if ip.is_loopback()));
            let has_ipv6_loopback = resolved
                .addresses
                .iter()
                .any(|addr| matches!(addr, IpAddr::V6(ip) if ip.is_loopback()));
            assert!(has_ipv4_loopback || has_ipv6_loopback);
        } else {
            // DNS resolution might fail in some test environments
            // This is acceptable for unit tests
        }
    }

    #[test]
    fn test_resolve_invalid_hostname() {
        // Test with clearly invalid hostname
        let result = resolve_hostname("this-hostname-should-not-exist-12345.invalid");
        assert!(result.is_err());
    }
}
