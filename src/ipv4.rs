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
    pub is_bare_address: bool, // True if input was just an IP without CIDR notation
    pub original_input: String, // Store the original input for display purposes
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
        let (address, prefix_length, is_bare_address) = Self::parse_input(input, None)?;

        let netmask = Self::prefix_to_netmask(prefix_length);
        let network = Self::calculate_network(address, netmask);
        let broadcast = Self::calculate_broadcast(network, netmask);
        let wildcard = Self::calculate_wildcard(netmask);
        let class = Self::determine_class(address);

        Ok(Self {
            address,
            prefix_length,
            netmask,
            network,
            broadcast,
            wildcard,
            class,
            is_bare_address,
            original_input: input.to_string(),
        })
    }

    pub fn new_with_flags(input: &str, ipv4_flags: Option<crate::IPv4Flags>) -> Result<Self> {
        let (address, prefix_length, is_bare_address) = Self::parse_input(input, ipv4_flags)?;

        let netmask = Self::prefix_to_netmask(prefix_length);
        let network = Self::calculate_network(address, netmask);
        let broadcast = Self::calculate_broadcast(network, netmask);
        let wildcard = Self::calculate_wildcard(netmask);
        let class = Self::determine_class(address);

        Ok(Self {
            address,
            prefix_length,
            netmask,
            network,
            broadcast,
            wildcard,
            class,
            is_bare_address,
            original_input: input.to_string(),
        })
    }

    fn parse_input(
        input: &str,
        ipv4_flags: Option<crate::IPv4Flags>,
    ) -> Result<(Ipv4Addr, u8, bool)> {
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

            Ok((address, prefix_length, false))
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

            Ok((address, prefix_length, false))
        } else {
            // Just an IP address - determine prefix based on flags
            let address = Ipv4Addr::from_str(input)?;
            let prefix_length = Self::get_prefix_for_bare_address(address, ipv4_flags);
            Ok((address, prefix_length, true))
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

    const fn determine_class(address: Ipv4Addr) -> NetworkClass {
        let first_octet = address.octets()[0];
        match first_octet {
            0..=127 => NetworkClass::A,
            128..=191 => NetworkClass::B,
            192..=223 => NetworkClass::C,
            224..=239 => NetworkClass::D,
            240..=255 => NetworkClass::E,
        }
    }

    const fn get_classful_prefix(address: Ipv4Addr) -> u8 {
        match Self::determine_class(address) {
            NetworkClass::A => 8,
            NetworkClass::B => 16,
            NetworkClass::C => 24,
            NetworkClass::D | NetworkClass::E => 32,
        }
    }

    const fn get_prefix_for_bare_address(address: Ipv4Addr, ipv4_flags: Option<crate::IPv4Flags>) -> u8 {
        // Determine if we should use /32 (sipcalc-compatible) or classful behavior
        if let Some(flags) = ipv4_flags {
            // When CLASSFUL_ADDR flag is present, always use classful prefixes (highest priority)
            if flags.contains(crate::IPv4Flags::CLASSFUL_ADDR) {
                return Self::get_classful_prefix(address);
            }

            // When CIDR_BITMAP flag is present, use /32 for bare addresses (matches sipcalc behavior)
            // This covers the case where -b flag makes sipcalc treat bare addresses as /32 hosts
            if flags.contains(crate::IPv4Flags::CIDR_BITMAP) {
                return 32;
            }
        }

        // Default behavior: use classful prefixes (maintains backward compatibility)
        Self::get_classful_prefix(address)
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
        format!("{addr_int:X}")
    }

    pub fn to_decimal(&self) -> u32 {
        self.address.into()
    }

    pub fn netmask_to_hex(&self) -> String {
        let mask_int: u32 = self.netmask.into();
        format!("{mask_int:X}")
    }

    pub fn split_network(&self, new_prefix: u8) -> Result<Vec<Self>> {
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

            if let Ok(calc) = Self::new(&subnet_cidr) {
                subnets.push(calc);
            }
        }

        Ok(subnets)
    }

    /// Create a host-specific (/32) calculator for this address
    pub fn as_host(&self) -> Result<Self> {
        let cidr = format!("{}/32", self.address);
        Self::new(&cidr)
    }

    pub fn get_extra_subnets(&self, num_subnets: u32) -> Vec<Self> {
        let mut subnets = Vec::new();
        let subnet_size = 2u32.pow(u32::from(32 - self.prefix_length));
        let current_network: u32 = self.network.into();

        if num_subnets == 0 {
            // Special case: show all subnets of the same prefix length within the containing /24
            if self.prefix_length <= 24 {
                // /24 or larger (fewer hosts), just return the current subnet
                subnets.push(self.clone());
            } else {
                // Smaller than /24 (more specific), show all subnets of this prefix length in the containing /24
                let containing_24 = current_network & 0xFFFF_FF00; // Mask to /24 boundary
                let subnets_per_24 = 2u32.pow(u32::from(self.prefix_length - 24));
                let subnet_size_in_24 = 2u32.pow(u32::from(32 - self.prefix_length));

                for i in 0..subnets_per_24 {
                    let subnet_addr = containing_24 + (i * subnet_size_in_24);
                    let subnet_ip = Ipv4Addr::from(subnet_addr);
                    let subnet_cidr = format!("{subnet_ip}/{}", self.prefix_length);
                    if let Ok(calc) = Self::new(&subnet_cidr) {
                        subnets.push(calc);
                    }
                }
            }
        } else {
            // Show num_subnets starting from the current subnet
            for i in 0..num_subnets {
                let next_network = current_network + (i * subnet_size);
                if next_network <= 0xFFFF_FFFF - subnet_size + 1 {
                    let subnet_ip = Ipv4Addr::from(next_network);
                    let subnet_cidr = format!("{}/{}", subnet_ip, self.prefix_length);
                    if let Ok(calc) = Self::new(&subnet_cidr) {
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
            Self::A => write!(f, "A"),
            Self::B => write!(f, "B"),
            Self::C => write!(f, "C"),
            Self::D => write!(f, "D (Multicast)"),
            Self::E => write!(f, "E (Reserved)"),
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

    #[test]
    fn test_ipv4_network_class_sipcalc_compatibility() {
        // Test IPv4 network class detection to match sipcalc exactly
        let test_cases = vec![
            // Class A: 0.0.0.0 to 127.255.255.255
            ("0.0.0.0/8", NetworkClass::A),
            ("1.2.3.4/8", NetworkClass::A),
            ("10.0.0.0/8", NetworkClass::A),
            ("126.255.255.255/8", NetworkClass::A),
            ("127.0.0.1/8", NetworkClass::A),
            // Class B: 128.0.0.0 to 191.255.255.255
            ("128.0.0.0/16", NetworkClass::B),
            ("172.16.0.0/16", NetworkClass::B),
            ("191.255.255.255/16", NetworkClass::B),
            // Class C: 192.0.0.0 to 223.255.255.255
            ("192.0.0.0/24", NetworkClass::C),
            ("192.168.1.0/24", NetworkClass::C),
            ("223.255.255.255/24", NetworkClass::C),
            // Class D (Multicast): 224.0.0.0 to 239.255.255.255
            ("224.0.0.0/32", NetworkClass::D),
            ("239.255.255.255/32", NetworkClass::D),
            // Class E (Reserved): 240.0.0.0 to 255.255.255.255
            ("240.0.0.0/32", NetworkClass::E),
            ("255.255.255.255/32", NetworkClass::E),
        ];

        for (addr_str, expected_class) in test_cases {
            let calc = IPv4Calculator::new(addr_str).unwrap();
            assert!(
                std::mem::discriminant(&calc.class) == std::mem::discriminant(&expected_class),
                "Network class mismatch for {}: expected {:?}, got {:?}",
                addr_str,
                expected_class,
                calc.class
            );
        }
    }

    #[test]
    fn test_ipv4_classful_default_prefixes() {
        // Test that classful default prefixes match sipcalc behavior
        let test_cases = vec![
            ("10.0.0.1", 8),     // Class A -> /8
            ("172.16.0.1", 16),  // Class B -> /16
            ("192.168.1.1", 24), // Class C -> /24
            ("224.0.0.1", 32),   // Class D -> /32 (single host)
            ("240.0.0.1", 32),   // Class E -> /32 (single host)
        ];

        for (addr_str, expected_prefix) in test_cases {
            let calc = IPv4Calculator::new(addr_str).unwrap();
            assert_eq!(
                calc.prefix_length, expected_prefix,
                "Classful prefix mismatch for {}: expected /{}, got /{}",
                addr_str, expected_prefix, calc.prefix_length
            );
        }
    }

    #[test]
    fn test_ipv4_network_class_display() {
        // Test network class display strings match sipcalc format
        assert_eq!(format!("{}", NetworkClass::A), "A");
        assert_eq!(format!("{}", NetworkClass::B), "B");
        assert_eq!(format!("{}", NetworkClass::C), "C");
        assert_eq!(format!("{}", NetworkClass::D), "D (Multicast)");
        assert_eq!(format!("{}", NetworkClass::E), "E (Reserved)");
    }

    #[test]
    fn test_ipv4_boundary_conditions() {
        // Test edge cases at class boundaries

        // Class A/B boundary (127.x.x.x vs 128.x.x.x)
        let max_a_addr = IPv4Calculator::new("127.255.255.255/8").unwrap();
        assert!(matches!(max_a_addr.class, NetworkClass::A));

        let min_b_addr = IPv4Calculator::new("128.0.0.0/16").unwrap();
        assert!(matches!(min_b_addr.class, NetworkClass::B));

        // Class B/C boundary (191.x.x.x vs 192.x.x.x)
        let max_b_range = IPv4Calculator::new("191.255.255.255/16").unwrap();
        assert!(matches!(max_b_range.class, NetworkClass::B));

        let min_c_range = IPv4Calculator::new("192.0.0.0/24").unwrap();
        assert!(matches!(min_c_range.class, NetworkClass::C));

        // Class C/D boundary (223.x.x.x vs 224.x.x.x)
        let max_c_network = IPv4Calculator::new("223.255.255.255/24").unwrap();
        assert!(matches!(max_c_network.class, NetworkClass::C));

        let min_d_network = IPv4Calculator::new("224.0.0.0/32").unwrap();
        assert!(matches!(min_d_network.class, NetworkClass::D));

        // Class D/E boundary (239.x.x.x vs 240.x.x.x)
        let max_multicast = IPv4Calculator::new("239.255.255.255/32").unwrap();
        assert!(matches!(max_multicast.class, NetworkClass::D));

        let min_reserved = IPv4Calculator::new("240.0.0.0/32").unwrap();
        assert!(matches!(min_reserved.class, NetworkClass::E));
    }

    #[test]
    fn test_ipv4_extra_subnets_n_zero() {
        // Test -n 0 behavior: show all subnets of same prefix length in containing /24

        // Test /26 subnet (should show 4 /26 subnets in the /24)
        let calc = IPv4Calculator::new("192.168.1.64/26").unwrap();
        let subnets = calc.get_extra_subnets(0);
        assert_eq!(subnets.len(), 4);
        assert_eq!(subnets[0].network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(subnets[1].network, Ipv4Addr::new(192, 168, 1, 64));
        assert_eq!(subnets[2].network, Ipv4Addr::new(192, 168, 1, 128));
        assert_eq!(subnets[3].network, Ipv4Addr::new(192, 168, 1, 192));

        // Test /25 subnet (should show 2 /25 subnets in the /24)
        let calc = IPv4Calculator::new("192.168.1.128/25").unwrap();
        let subnets = calc.get_extra_subnets(0);
        assert_eq!(subnets.len(), 2);
        assert_eq!(subnets[0].network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(subnets[1].network, Ipv4Addr::new(192, 168, 1, 128));

        // Test /28 subnet (should show 16 /28 subnets in the /24)
        let calc = IPv4Calculator::new("192.168.1.64/28").unwrap();
        let subnets = calc.get_extra_subnets(0);
        assert_eq!(subnets.len(), 16);
        assert_eq!(subnets[0].network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(subnets[4].network, Ipv4Addr::new(192, 168, 1, 64));
        assert_eq!(subnets[15].network, Ipv4Addr::new(192, 168, 1, 240));

        // Test /24 subnet (should show just the /24 itself)
        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();
        let subnets = calc.get_extra_subnets(0);
        assert_eq!(subnets.len(), 1);
        assert_eq!(subnets[0].network, Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_ipv4_extra_subnets_n_positive() {
        // Test -n N behavior: show N subnets starting from current

        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();
        let subnets = calc.get_extra_subnets(3);
        assert_eq!(subnets.len(), 3);
        assert_eq!(subnets[0].network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(subnets[1].network, Ipv4Addr::new(192, 168, 2, 0));
        assert_eq!(subnets[2].network, Ipv4Addr::new(192, 168, 3, 0));

        // Test with /26 subnet
        let calc = IPv4Calculator::new("192.168.1.64/26").unwrap();
        let subnets = calc.get_extra_subnets(2);
        assert_eq!(subnets.len(), 2);
        assert_eq!(subnets[0].network, Ipv4Addr::new(192, 168, 1, 64));
        assert_eq!(subnets[1].network, Ipv4Addr::new(192, 168, 1, 128));
    }

    #[test]
    fn test_ipv4_extra_subnets_edge_cases() {
        // Test edge cases for extra subnets

        // Test large prefix (<= /24) - should show just the current subnet
        let calc = IPv4Calculator::new("10.0.0.0/16").unwrap();
        let subnets = calc.get_extra_subnets(0);
        // Should show just the current /16 subnet
        assert_eq!(subnets.len(), 1);
        assert_eq!(subnets[0].network, Ipv4Addr::new(10, 0, 0, 0));

        // Test /32 subnet
        let calc = IPv4Calculator::new("192.168.1.100/32").unwrap();
        let subnets = calc.get_extra_subnets(0);
        // Should show all /32 subnets in the /24 (256 of them)
        assert_eq!(subnets.len(), 256);
        assert_eq!(subnets[0].network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(subnets[100].network, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(subnets[255].network, Ipv4Addr::new(192, 168, 1, 255));
    }
}
