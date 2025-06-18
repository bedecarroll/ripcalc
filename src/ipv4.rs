use anyhow::{Result, anyhow};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct IPv4Calculator {
    pub address: Ipv4Addr,
    pub prefix_length: u8,
    pub netmask: Ipv4Addr,
    pub network: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub wildcard: Ipv4Addr,
    pub class: NetworkClass,
}

#[derive(Debug, Clone)]
pub enum NetworkClass {
    A,
    B,
    C,
    D, // Multicast
    E, // Reserved
}

impl IPv4Calculator {
    pub fn new(input: &str) -> Result<Self> {
        let (address, prefix_length) = Self::parse_input(input)?;

        let netmask = Self::prefix_to_netmask(prefix_length);
        let network = Self::calculate_network(address, netmask);
        let broadcast = Self::calculate_broadcast(network, netmask);
        let wildcard = Self::calculate_wildcard(netmask);
        let class = Self::determine_class(address);

        Ok(IPv4Calculator {
            address,
            prefix_length,
            netmask,
            network,
            broadcast,
            wildcard,
            class,
        })
    }

    fn parse_input(input: &str) -> Result<(Ipv4Addr, u8)> {
        if input.contains('/') {
            // CIDR notation
            let parts: Vec<&str> = input.split('/').collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid CIDR notation"));
            }

            let address = Ipv4Addr::from_str(parts[0])?;
            let prefix_length: u8 = parts[1].parse()?;

            if prefix_length > 32 {
                return Err(anyhow!("Invalid prefix length"));
            }

            Ok((address, prefix_length))
        } else if input.contains(' ') {
            // Address with separate netmask
            let parts: Vec<&str> = input.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid address/netmask format"));
            }

            let address = Ipv4Addr::from_str(parts[0])?;
            let netmask_str = parts[1];

            let prefix_length = if netmask_str.starts_with("0x") || netmask_str.starts_with("0X") {
                // Hex netmask
                let hex_val = u32::from_str_radix(&netmask_str[2..], 16)?;
                Self::netmask_to_prefix(Ipv4Addr::from(hex_val))
            } else if netmask_str.contains('.') {
                // Dotted decimal netmask
                let netmask = Ipv4Addr::from_str(netmask_str)?;
                Self::netmask_to_prefix(netmask)
            } else {
                // Assume it's a prefix length
                netmask_str.parse()?
            };

            Ok((address, prefix_length))
        } else {
            // Just an IP address, try to determine classful mask
            let address = Ipv4Addr::from_str(input)?;
            let prefix_length = Self::get_classful_prefix(address);
            Ok((address, prefix_length))
        }
    }

    fn prefix_to_netmask(prefix_length: u8) -> Ipv4Addr {
        if prefix_length == 0 {
            return Ipv4Addr::new(0, 0, 0, 0);
        }

        let mask = (!0u32) << (32 - prefix_length);
        Ipv4Addr::from(mask)
    }

    fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
        let mask_int: u32 = netmask.into();
        // count_ones() always ≤32, safe to convert
        u8::try_from(mask_int.count_ones()).unwrap_or(0)
    }

    fn calculate_network(address: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
        let addr_int: u32 = address.into();
        let mask_int: u32 = netmask.into();
        Ipv4Addr::from(addr_int & mask_int)
    }

    fn calculate_broadcast(network: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
        let net_int: u32 = network.into();
        let mask_int: u32 = netmask.into();
        let wildcard = !mask_int;
        Ipv4Addr::from(net_int | wildcard)
    }

    fn calculate_wildcard(netmask: Ipv4Addr) -> Ipv4Addr {
        let mask_int: u32 = netmask.into();
        Ipv4Addr::from(!mask_int)
    }

    fn determine_class(address: Ipv4Addr) -> NetworkClass {
        let first_octet = address.octets()[0];
        match first_octet {
            0..=127 => NetworkClass::A,
            128..=191 => NetworkClass::B,
            192..=223 => NetworkClass::C,
            224..=239 => NetworkClass::D,
            240..=255 => NetworkClass::E,
        }
    }

    fn get_classful_prefix(address: Ipv4Addr) -> u8 {
        match Self::determine_class(address) {
            NetworkClass::A => 8,
            NetworkClass::B => 16,
            NetworkClass::C => 24,
            NetworkClass::D | NetworkClass::E => 32,
        }
    }

    pub fn get_host_count(&self) -> u64 {
        2u64.pow(u32::from(32 - self.prefix_length))
    }

    pub fn get_usable_host_count(&self) -> u64 {
        if self.prefix_length >= 31 {
            if self.prefix_length == 31 {
                2 // Point-to-point link
            } else {
                1 // Single host
            }
        } else {
            self.get_host_count() - 2 // Subtract network and broadcast
        }
    }

    pub fn get_first_usable(&self) -> Ipv4Addr {
        if self.prefix_length >= 31 {
            self.network
        } else {
            let net_int: u32 = self.network.into();
            Ipv4Addr::from(net_int + 1)
        }
    }

    pub fn get_last_usable(&self) -> Ipv4Addr {
        if self.prefix_length == 32 {
            self.network
        } else if self.prefix_length == 31 {
            self.broadcast
        } else {
            let broadcast_int: u32 = self.broadcast.into();
            Ipv4Addr::from(broadcast_int - 1)
        }
    }

    pub fn to_hex(&self) -> String {
        let addr_int: u32 = self.address.into();
        format!("{addr_int:08X}")
    }

    pub fn to_decimal(&self) -> u32 {
        self.address.into()
    }

    pub fn netmask_to_hex(&self) -> String {
        let mask_int: u32 = self.netmask.into();
        format!("{mask_int:08X}")
    }

    pub fn split_network(&self, new_prefix: u8) -> Result<Vec<IPv4Calculator>> {
        if new_prefix <= self.prefix_length {
            return Err(anyhow!("New prefix must be longer than current prefix"));
        }

        if new_prefix > 32 {
            return Err(anyhow!("Invalid prefix length"));
        }

        let subnet_count = 2u32.pow(u32::from(new_prefix - self.prefix_length));
        let subnet_size = 2u32.pow(u32::from(32 - new_prefix));

        let mut subnets = Vec::new();
        let base_addr: u32 = self.network.into();

        for i in 0..subnet_count {
            let subnet_addr = base_addr + (i * subnet_size);
            let subnet_ip = Ipv4Addr::from(subnet_addr);
            let subnet_cidr = format!("{subnet_ip}/{new_prefix}");

            if let Ok(calc) = IPv4Calculator::new(&subnet_cidr) {
                subnets.push(calc);
            }
        }

        Ok(subnets)
    }

    pub fn get_extra_subnets(&self, num_subnets: u32) -> Vec<IPv4Calculator> {
        let mut subnets = Vec::new();
        let subnet_size = 2u32.pow(u32::from(32 - self.prefix_length));
        let current_network: u32 = self.network.into();

        if num_subnets == 0 {
            // Special case: show all subnets in the current /24 (if not already /24 or smaller)
            if self.prefix_length < 24 {
                // Find the containing /24 and split it
                let containing_24 = current_network & 0xFFFF_FF00; // Mask to /24 boundary
                for i in 0..256 {
                    let subnet_addr = containing_24 + (i * 256);
                    let subnet_ip = Ipv4Addr::from(subnet_addr);
                    let subnet_cidr = format!("{subnet_ip}/24");
                    if let Ok(calc) = IPv4Calculator::new(&subnet_cidr) {
                        subnets.push(calc);
                    }
                }
            } else {
                // Already /24 or smaller, just return the current subnet
                subnets.push(self.clone());
            }
        } else {
            // Show num_subnets starting from the next subnet
            for i in 1..=num_subnets {
                let next_network = current_network + (i * subnet_size);
                if next_network <= 0xFFFF_FFFF - subnet_size + 1 {
                    let subnet_ip = Ipv4Addr::from(next_network);
                    let subnet_cidr = format!("{}/{}", subnet_ip, self.prefix_length);
                    if let Ok(calc) = IPv4Calculator::new(&subnet_cidr) {
                        subnets.push(calc);
                    }
                }
            }
        }

        subnets
    }

    pub fn get_binary_representation(&self) -> String {
        let addr_int: u32 = self.address.into();
        let octets = [
            (addr_int >> 24) & 0xFF,
            (addr_int >> 16) & 0xFF,
            (addr_int >> 8) & 0xFF,
            addr_int & 0xFF,
        ];

        octets
            .iter()
            .map(|octet| format!("{octet:08b}"))
            .collect::<Vec<_>>()
            .join(".")
    }

    pub fn get_netmask_binary(&self) -> String {
        let mask_int: u32 = self.netmask.into();
        let octets = [
            (mask_int >> 24) & 0xFF,
            (mask_int >> 16) & 0xFF,
            (mask_int >> 8) & 0xFF,
            mask_int & 0xFF,
        ];

        octets
            .iter()
            .map(|octet| format!("{octet:08b}"))
            .collect::<Vec<_>>()
            .join(".")
    }
}

impl std::fmt::Display for NetworkClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkClass::A => write!(f, "A"),
            NetworkClass::B => write!(f, "B"),
            NetworkClass::C => write!(f, "C"),
            NetworkClass::D => write!(f, "D (Multicast)"),
            NetworkClass::E => write!(f, "E (Reserved)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ipv4_cidr_parsing() {
        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();
        assert_eq!(calc.address, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(calc.prefix_length, 24);
        assert_eq!(calc.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(calc.network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(calc.broadcast, Ipv4Addr::new(192, 168, 1, 255));
    }

    #[test]
    fn test_ipv4_dotted_decimal_netmask() {
        let calc = IPv4Calculator::new("10.0.0.1 255.255.0.0").unwrap();
        assert_eq!(calc.address, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(calc.prefix_length, 16);
        assert_eq!(calc.netmask, Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(calc.network, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(calc.broadcast, Ipv4Addr::new(10, 0, 255, 255));
    }

    #[test]
    fn test_ipv4_hex_netmask() {
        let calc = IPv4Calculator::new("172.16.5.4 0xFFFF0000").unwrap();
        assert_eq!(calc.address, Ipv4Addr::new(172, 16, 5, 4));
        assert_eq!(calc.prefix_length, 16);
        assert_eq!(calc.netmask, Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(calc.network, Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(calc.broadcast, Ipv4Addr::new(172, 16, 255, 255));
    }

    #[test]
    fn test_ipv4_classful_defaults() {
        // Class A
        let calc = IPv4Calculator::new("10.0.0.1").unwrap();
        assert_eq!(calc.prefix_length, 8);
        assert!(matches!(calc.class, NetworkClass::A));

        // Class B
        let calc = IPv4Calculator::new("172.16.0.1").unwrap();
        assert_eq!(calc.prefix_length, 16);
        assert!(matches!(calc.class, NetworkClass::B));

        // Class C
        let calc = IPv4Calculator::new("192.168.1.1").unwrap();
        assert_eq!(calc.prefix_length, 24);
        assert!(matches!(calc.class, NetworkClass::C));

        // Multicast
        let calc = IPv4Calculator::new("224.0.0.1").unwrap();
        assert!(matches!(calc.class, NetworkClass::D));

        // Reserved
        let calc = IPv4Calculator::new("240.0.0.1").unwrap();
        assert!(matches!(calc.class, NetworkClass::E));
    }

    #[test]
    fn test_ipv4_network_calculations() {
        let calc = IPv4Calculator::new("192.168.1.100/24").unwrap();

        // Basic network info
        assert_eq!(calc.network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(calc.broadcast, Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(calc.wildcard, Ipv4Addr::new(0, 0, 0, 255));

        // Host counts
        assert_eq!(calc.get_host_count(), 256);
        assert_eq!(calc.get_usable_host_count(), 254);

        // Usable range
        assert_eq!(calc.get_first_usable(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(calc.get_last_usable(), Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_ipv4_point_to_point() {
        let calc = IPv4Calculator::new("10.0.0.1/31").unwrap();
        assert_eq!(calc.get_usable_host_count(), 2);
        assert_eq!(calc.get_first_usable(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(calc.get_last_usable(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_ipv4_single_host() {
        let calc = IPv4Calculator::new("10.0.0.1/32").unwrap();
        assert_eq!(calc.get_usable_host_count(), 1);
        assert_eq!(calc.get_first_usable(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(calc.get_last_usable(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_ipv4_hex_conversions() {
        let calc = IPv4Calculator::new("192.168.1.100/24").unwrap();
        assert_eq!(calc.to_hex(), "C0A80164");
        assert_eq!(calc.to_decimal(), 3_232_235_876);
        assert_eq!(calc.netmask_to_hex(), "FFFFFF00");
    }

    #[test]
    fn test_ipv4_binary_representation() {
        let calc = IPv4Calculator::new("192.168.1.1/24").unwrap();
        assert_eq!(
            calc.get_binary_representation(),
            "11000000.10101000.00000001.00000001"
        );
        assert_eq!(
            calc.get_netmask_binary(),
            "11111111.11111111.11111111.00000000"
        );
    }

    #[test]
    fn test_ipv4_subnet_splitting() {
        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();
        let subnets = calc.split_network(26).unwrap();

        assert_eq!(subnets.len(), 4);
        assert_eq!(subnets[0].network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(subnets[0].prefix_length, 26);
        assert_eq!(subnets[1].network, Ipv4Addr::new(192, 168, 1, 64));
        assert_eq!(subnets[2].network, Ipv4Addr::new(192, 168, 1, 128));
        assert_eq!(subnets[3].network, Ipv4Addr::new(192, 168, 1, 192));
    }

    #[test]
    fn test_ipv4_subnet_splitting_large() {
        let calc = IPv4Calculator::new("10.0.0.0/8").unwrap();
        let subnets = calc.split_network(16).unwrap();

        assert_eq!(subnets.len(), 256);
        assert_eq!(subnets[0].network, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(subnets[1].network, Ipv4Addr::new(10, 1, 0, 0));
        assert_eq!(subnets[255].network, Ipv4Addr::new(10, 255, 0, 0));
    }

    #[test]
    fn test_ipv4_invalid_inputs() {
        assert!(IPv4Calculator::new("192.168.1.0/33").is_err());
        assert!(IPv4Calculator::new("192.168.1.300/24").is_err());
        assert!(IPv4Calculator::new("192.168.1.0/abc").is_err());
        assert!(IPv4Calculator::new("invalid").is_err());
    }

    #[test]
    fn test_ipv4_invalid_subnet_splitting() {
        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();

        // Can't split to smaller prefix
        assert!(calc.split_network(20).is_err());
        // Can't split to invalid prefix
        assert!(calc.split_network(33).is_err());
    }

    #[test]
    fn test_ipv4_edge_cases() {
        // Test /0 network
        let calc = IPv4Calculator::new("0.0.0.0/0").unwrap();
        assert_eq!(calc.network, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(calc.broadcast, Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(calc.get_host_count(), 4_294_967_296);

        // Test /30 network (common for point-to-point)
        let calc = IPv4Calculator::new("10.0.0.0/30").unwrap();
        assert_eq!(calc.get_usable_host_count(), 2);
        assert_eq!(calc.get_first_usable(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(calc.get_last_usable(), Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn test_network_class_display() {
        assert_eq!(format!("{}", NetworkClass::A), "A");
        assert_eq!(format!("{}", NetworkClass::B), "B");
        assert_eq!(format!("{}", NetworkClass::C), "C");
        assert_eq!(format!("{}", NetworkClass::D), "D (Multicast)");
        assert_eq!(format!("{}", NetworkClass::E), "E (Reserved)");
    }

    #[test]
    fn test_ipv4_various_prefixes() {
        // Test various common prefix lengths
        let test_cases = vec![
            ("10.0.0.0/8", 8, 16_777_216),
            ("172.16.0.0/12", 12, 1_048_576),
            ("192.168.0.0/16", 16, 65536),
            ("192.168.1.0/24", 24, 256),
            ("192.168.1.0/25", 25, 128),
            ("192.168.1.0/26", 26, 64),
            ("192.168.1.0/27", 27, 32),
            ("192.168.1.0/28", 28, 16),
            ("192.168.1.0/29", 29, 8),
            ("192.168.1.0/30", 30, 4),
        ];

        for (input, expected_prefix, expected_hosts) in test_cases {
            let calc = IPv4Calculator::new(input).unwrap();
            assert_eq!(calc.prefix_length, expected_prefix, "Failed for {input}");
            assert_eq!(
                calc.get_host_count(),
                expected_hosts,
                "Failed host count for {input}"
            );
        }
    }
}
