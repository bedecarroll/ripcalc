use anyhow::{Result, anyhow};
use get_if_addrs::{IfAddr, get_if_addrs};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4_addresses: Vec<(Ipv4Addr, u8)>,
    pub ipv6_addresses: Vec<(Ipv6Addr, u8)>,
}

pub fn get_interface_info(interface_name: &str) -> Result<InterfaceInfo> {
    let if_addrs = get_if_addrs()?;

    let mut ipv4_addresses = Vec::new();
    let mut ipv6_addresses = Vec::new();
    let mut found = false;

    for if_addr in if_addrs {
        if if_addr.name == interface_name {
            found = true;
            match if_addr.addr {
                IfAddr::V4(v4_addr) => {
                    let prefix_len = netmask_to_prefix_v4(v4_addr.netmask);
                    ipv4_addresses.push((v4_addr.ip, prefix_len));
                }
                IfAddr::V6(v6_addr) => {
                    let prefix_len = netmask_to_prefix_v6(v6_addr.netmask);
                    ipv6_addresses.push((v6_addr.ip, prefix_len));
                }
            }
        }
    }

    if !found {
        return Err(anyhow!("Interface '{}' not found", interface_name));
    }

    if ipv4_addresses.is_empty() && ipv6_addresses.is_empty() {
        return Err(anyhow!(
            "No IP addresses found on interface '{}'",
            interface_name
        ));
    }

    Ok(InterfaceInfo {
        name: interface_name.to_string(),
        ipv4_addresses,
        ipv6_addresses,
    })
}

fn netmask_to_prefix_v4(netmask: Ipv4Addr) -> u8 {
    let mask_int: u32 = netmask.into();
    // count_ones() always ≤32, safe to convert
    u8::try_from(mask_int.count_ones()).unwrap_or(0)
}

fn netmask_to_prefix_v6(netmask: Ipv6Addr) -> u8 {
    let segments = netmask.segments();
    let mut prefix_len = 0u8;

    for segment in &segments {
        if *segment == 0xffff {
            prefix_len += 16;
        } else if *segment == 0 {
            break;
        } else {
            // Count the leading 1 bits in this segment
            // Count leading one bits in this segment
            prefix_len += u8::try_from(segment.leading_ones()).unwrap_or(0);
            break;
        }
    }

    prefix_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_netmask_to_prefix_v4() {
        // Test common IPv4 netmasks
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        // Test some less common netmasks
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 255, 128)), 25);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 255, 192)), 26);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 255, 224)), 27);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 255, 240)), 28);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 255, 248)), 29);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 255, 252)), 30);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(255, 255, 255, 254)), 31);
    }

    #[test]
    fn test_netmask_to_prefix_v6() {
        // Test IPv6 prefix calculations
        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            ])),
            128
        );

        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0xffff, 0xffff, 0xffff, 0xffff, 0x0000, 0x0000, 0x0000, 0x0000
            ])),
            64
        );

        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0xffff, 0xffff, 0xffff, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
            ])),
            48
        );

        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0xffff, 0xffff, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
            ])),
            32
        );

        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
            ])),
            0
        );

        // Test partial segments
        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0xffff, 0xffff, 0xffff, 0xff00, 0x0000, 0x0000, 0x0000, 0x0000
            ])),
            56
        );

        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0xffff, 0xffff, 0xffff, 0xf000, 0x0000, 0x0000, 0x0000, 0x0000
            ])),
            52
        );
    }

    #[test]
    fn test_interface_info_structure() {
        let interface_info = InterfaceInfo {
            name: "eth0".to_string(),
            ipv4_addresses: vec![
                (Ipv4Addr::new(192, 168, 1, 100), 24),
                (Ipv4Addr::new(10, 0, 0, 1), 8),
            ],
            ipv6_addresses: vec![
                ("2001:db8::1".parse().unwrap(), 64),
                ("fe80::1".parse().unwrap(), 64),
            ],
        };

        assert_eq!(interface_info.name, "eth0");
        assert_eq!(interface_info.ipv4_addresses.len(), 2);
        assert_eq!(interface_info.ipv6_addresses.len(), 2);

        // Check specific addresses
        assert_eq!(
            interface_info.ipv4_addresses[0].0,
            Ipv4Addr::new(192, 168, 1, 100)
        );
        assert_eq!(interface_info.ipv4_addresses[0].1, 24);
        assert_eq!(
            interface_info.ipv6_addresses[0].0,
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(interface_info.ipv6_addresses[0].1, 64);
    }

    #[test]
    fn test_get_interface_info_nonexistent() {
        // Test with a non-existent interface name
        let result = get_interface_info("nonexistent-interface-12345");
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.to_string().contains("not found"));
        }
    }

    // Note: The following tests interact with the actual network interfaces
    // and may behave differently in different environments

    #[test]
    fn test_netmask_edge_cases() {
        // Test edge cases for netmask conversion

        // IPv4 edge cases
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(128, 0, 0, 0)), 1);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(192, 0, 0, 0)), 2);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(224, 0, 0, 0)), 3);
        assert_eq!(netmask_to_prefix_v4(Ipv4Addr::new(240, 0, 0, 0)), 4);

        // IPv6 edge cases with partial masks
        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0x8000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
            ])),
            1
        );

        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0xc000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
            ])),
            2
        );

        assert_eq!(
            netmask_to_prefix_v6(Ipv6Addr::from([
                0xffe0, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
            ])),
            11
        );
    }
}
