use crate::dns::ResolvedAddress;
use crate::interface::InterfaceInfo;
use crate::{Config, IPv4Calculator, IPv6Calculator};
use anyhow::Result;
use serde_json::{Value, json};

pub struct OutputFormatter {
    json_mode: bool,
}

impl OutputFormatter {
    pub fn new(json_mode: bool) -> Self {
        Self { json_mode }
    }

    pub fn format_ipv4(&self, calc: &IPv4Calculator, index: usize, config: &Config) -> Result<()> {
        if self.json_mode {
            // JSON formatting is a static function
            OutputFormatter::format_ipv4_json(calc, index, config)
        } else {
            // Delegate to static text formatter and return OK
            OutputFormatter::format_ipv4_text(calc, index, config);
            Ok(())
        }
    }

    pub fn format_ipv6(&self, calc: &IPv6Calculator, index: usize, config: &Config) -> Result<()> {
        if self.json_mode {
            // JSON formatting as static function
            OutputFormatter::format_ipv6_json(calc, index, config)
        } else {
            // Delegate to static text formatter and return OK
            OutputFormatter::format_ipv6_text(calc, index, config);
            Ok(())
        }
    }

    pub fn format_interface(
        &self,
        interface_info: &InterfaceInfo,
        index: usize,
        config: &Config,
    ) -> Result<()> {
        // Process each IP address found on the interface
        let mut addr_index = index;

        for (ipv4_addr, prefix_len) in &interface_info.ipv4_addresses {
            let cidr = format!("{ipv4_addr}/{prefix_len}");
            if let Ok(calc) = crate::IPv4Calculator::new(&cidr) {
                if self.json_mode {
                    // JSON formatting as static function
                    OutputFormatter::format_ipv4_json(&calc, addr_index, config)?;
                } else {
                    println!(
                        "-[int-ipv4 : {} ({})] - {}",
                        cidr, interface_info.name, addr_index
                    );
                    // Text formatting as static function
                    OutputFormatter::format_ipv4_text_content(&calc, config);
                }
                addr_index += 1;
            }
        }

        for (ipv6_addr, prefix_len) in &interface_info.ipv6_addresses {
            let cidr = format!("{ipv6_addr}/{prefix_len}");
            if let Ok(calc) = crate::IPv6Calculator::new(&cidr) {
                if self.json_mode {
                    // JSON formatting as static function
                    OutputFormatter::format_ipv6_json(&calc, addr_index, config)?;
                } else {
                    println!(
                        "-[int-ipv6 : {} ({})] - {}",
                        cidr, interface_info.name, addr_index
                    );
                    // Text formatting as static function
                    OutputFormatter::format_ipv6_text_content(&calc, config);
                }
                addr_index += 1;
            }
        }

        Ok(())
    }

    pub fn format_resolved(
        &self,
        resolved: &ResolvedAddress,
        index: usize,
        config: &Config,
    ) -> Result<()> {
        let mut addr_index = index;

        for ip_addr in &resolved.addresses {
            match ip_addr {
                std::net::IpAddr::V4(ipv4) => {
                    // Use classful default for resolved addresses
                    let prefix_len = match ipv4.octets()[0] {
                        0..=127 => 8,
                        128..=191 => 16,
                        192..=223 => 24,
                        _ => 32,
                    };

                    let cidr = format!("{ipv4}/{prefix_len}");
                    if let Ok(calc) = crate::IPv4Calculator::new(&cidr) {
                        if self.json_mode {
                            OutputFormatter::format_ipv4_json(&calc, addr_index, config)?;
                        } else {
                            println!(
                                "-[dns-ipv4 : {} ({})] - {}",
                                cidr, resolved.hostname, addr_index
                            );
                            // Text formatting as static function
                            OutputFormatter::format_ipv4_text_content(&calc, config);
                        }
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    let cidr = format!("{ipv6}/128");
                    if let Ok(calc) = crate::IPv6Calculator::new(&cidr) {
                        if self.json_mode {
                            OutputFormatter::format_ipv6_json(&calc, addr_index, config)?;
                        } else {
                            println!(
                                "-[dns-ipv6 : {} ({})] - {}",
                                cidr, resolved.hostname, addr_index
                            );
                            // Text formatting as static function
                            OutputFormatter::format_ipv6_text_content(&calc, config);
                        }
                    }
                }
            }
            addr_index += 1;
        }

        Ok(())
    }

    /// Format IPv4 output in text mode.
    pub fn format_ipv4_text(calc: &IPv4Calculator, index: usize, config: &Config) {
        // Inline formatting using named arguments
        println!(
            "-[ipv4 : {address}/{prefix}] - {idx}",
            address = calc.address,
            prefix = calc.prefix_length,
            idx = index
        );
        // Delegate to text content formatter
        OutputFormatter::format_ipv4_text_content(calc, config);
    }

    fn format_ipv4_text_content(calc: &IPv4Calculator, config: &Config) {
        println!();
        Self::format_ipv4_cidr_section(calc);
        if config.output.all_info || config.ipv4.contains(crate::IPv4Flags::CLASSFUL_ADDR) {
            Self::format_ipv4_classful_section(calc, config);
        }
        Self::format_ipv4_split_section(calc, config);
        Self::format_ipv4_extra_subnets_section(calc, config);
        if config.output.all_info || config.ipv4.contains(crate::IPv4Flags::CIDR_BITMAP) {
            Self::format_ipv4_cidr_bitmap_section(calc);
        }
        if config.output.all_info || config.ipv4.contains(crate::IPv4Flags::CLASSFUL_BITMAP) {
            Self::format_ipv4_classful_bitmap_section(calc);
        }
        // End of section separator
        println!("-");
        println!();
    }

    // IPv4 formatting helper sections
    fn format_ipv4_cidr_section(calc: &IPv4Calculator) {
        println!("[CIDR]");
        println!("Host address            - {}", calc.address);
        println!("Host address (decimal)  - {}", calc.to_decimal());
        println!("Host address (hex)      - {}", calc.to_hex());
        println!("Network address         - {}", calc.network);
        println!("Network mask            - {}", calc.netmask);
        println!("Network mask (bits)     - {}", calc.prefix_length);
        println!("Network mask (hex)      - {}", calc.netmask_to_hex());
        println!("Broadcast address       - {}", calc.broadcast);
        println!("Cisco wildcard          - {}", calc.wildcard);
        println!("Addresses in network    - {}", calc.get_host_count());
        println!(
            "Network range           - {network} - {broadcast}",
            network = calc.network,
            broadcast = calc.broadcast
        );
        println!(
            "Usable range            - {first} - {last}",
            first = calc.get_first_usable(),
            last = calc.get_last_usable()
        );
    }

    fn format_ipv4_classful_section(calc: &IPv4Calculator, config: &Config) {
        println!();
        println!("[Classful]");
        println!("Host address            - {}", calc.address);
        println!("Network class           - {}", calc.class);
        if config.ipv4.contains(crate::IPv4Flags::WILDCARD) {
            println!("Cisco wildcard          - {}", calc.wildcard);
        }
    }

    fn format_ipv4_split_section(calc: &IPv4Calculator, config: &Config) {
        if let Some(ref split_mask) = config.split_ipv4 {
            if let Ok(new_prefix) = Self::parse_ipv4_mask_to_prefix(split_mask) {
                if let Ok(subnets) = calc.split_network(new_prefix) {
                    println!();
                    println!("[Networks]");
                    for (i, subnet) in subnets.iter().enumerate() {
                        if config.output.verbose {
                            println!();
                            println!(
                                "Subnet {idx} - {network}/{prefix}",
                                idx = i + 1,
                                network = subnet.network,
                                prefix = subnet.prefix_length
                            );
                            println!("Network address         - {}", subnet.network);
                            println!("Broadcast address       - {}", subnet.broadcast);
                            println!(
                                "Usable range            - {first} - {last}",
                                first = subnet.get_first_usable(),
                                last = subnet.get_last_usable()
                            );
                        } else {
                            println!(
                                "{network}/{prefix}",
                                network = subnet.network,
                                prefix = subnet.prefix_length
                            );
                        }
                    }
                }
            }
        }
    }

    fn format_ipv4_extra_subnets_section(calc: &IPv4Calculator, config: &Config) {
        if let Some(num_extra) = config.extra_subnets {
            let extra_subnets = calc.get_extra_subnets(num_extra);
            println!();
            println!("[Extra subnets]");
            for (i, subnet) in extra_subnets.iter().enumerate() {
                if config.output.verbose {
                    println!();
                    println!(
                        "Subnet {idx} - {network}/{prefix}",
                        idx = i + 1,
                        network = subnet.network,
                        prefix = subnet.prefix_length
                    );
                    println!("Network address         - {}", subnet.network);
                    println!("Broadcast address       - {}", subnet.broadcast);
                    println!(
                        "Usable range            - {first} - {last}",
                        first = subnet.get_first_usable(),
                        last = subnet.get_last_usable()
                    );
                } else {
                    println!(
                        "{network}/{prefix}",
                        network = subnet.network,
                        prefix = subnet.prefix_length
                    );
                }
            }
        }
    }

    fn format_ipv4_cidr_bitmap_section(calc: &IPv4Calculator) {
        println!();
        println!("[CIDR bitmaps]");
        println!(
            "Host address            - {bits}",
            bits = calc.get_binary_representation()
        );
        println!(
            "Network mask            - {bits}",
            bits = calc.get_netmask_binary()
        );
    }

    fn format_ipv4_classful_bitmap_section(calc: &IPv4Calculator) {
        println!();
        println!("[Classful bitmaps]");
        println!(
            "Host address            - {bits}",
            bits = calc.get_binary_representation()
        );
        let classful_prefix = match calc.class {
            crate::ipv4::NetworkClass::A => 8,
            crate::ipv4::NetworkClass::B => 16,
            crate::ipv4::NetworkClass::C => 24,
            _ => calc.prefix_length,
        };
        let classful_calc =
            crate::IPv4Calculator::new(&format!("{}/{}", calc.address, classful_prefix)).unwrap();
        println!(
            "Network mask            - {bits}",
            bits = classful_calc.get_netmask_binary()
        );
    }
    /// Format IPv6 output in text mode.
    pub fn format_ipv6_text(calc: &IPv6Calculator, index: usize, config: &Config) {
        // Inline formatting using named arguments
        println!(
            "-[ipv6 : {address}/{prefix}] - {idx}",
            address = calc.address,
            prefix = calc.prefix_length,
            idx = index
        );
        // Delegate to text content formatter
        OutputFormatter::format_ipv6_text_content(calc, config);
    }

    fn format_ipv6_text_content(calc: &IPv6Calculator, config: &Config) {
        println!();

        println!("[IPv6]");
        println!("Expanded Address        - {}", calc.get_expanded_address());
        println!(
            "Compressed Address      - {}",
            calc.get_compressed_address()
        );
        println!(
            "Subnet prefix           - {}/{}",
            calc.network, calc.prefix_length
        );
        println!("Address ID              - {}", calc.get_host_id());
        println!("Prefix address          - {}", calc.prefix_mask);
        println!("Prefix length           - {}", calc.prefix_length);
        println!("Address type            - {}", calc.address_type);

        let (start, end) = calc.get_network_range();
        println!("Network range           - {start} - {end}");

        // IPv4 embedded addresses (show if v4_in_v6 flag or if address actually has IPv4)
        if let Some((expanded_v4, compressed_v4)) = calc.get_ipv4_embedded() {
            if config.ipv6.v4_in_v6 || config.output.all_info {
                println!("Expanded v4-in-v6 address - {expanded_v4}");
                println!("Compressed v4-in-v6 address - {compressed_v4}");
            }
        }

        // Reverse DNS (show if v6_reverse flag or all info)
        if config.ipv6.v6_reverse || config.output.all_info {
            println!("Reverse DNS             - {}", calc.get_reverse_dns());
        }

        // Subnet splitting if requested
        if let Some(ref split_prefix) = config.split_ipv6 {
            if let Ok(new_prefix) = split_prefix.parse::<u8>() {
                if let Ok(subnets) = calc.split_network(new_prefix) {
                    println!();
                    println!("[Networks]");
                    for (i, subnet) in subnets.iter().enumerate() {
                        if config.output.verbose {
                            println!();
                            println!(
                                "Subnet {} - {}/{}",
                                i + 1,
                                subnet.network,
                                subnet.prefix_length
                            );
                            println!(
                                "Expanded Address        - {}",
                                subnet.get_expanded_address()
                            );
                            println!(
                                "Compressed Address      - {}",
                                subnet.get_compressed_address()
                            );
                            let (start, end) = subnet.get_network_range();
                            println!("Network range           - {start} - {end}");
                        } else {
                            println!("{}/{}", subnet.network, subnet.prefix_length);
                        }
                    }
                }
            }
        }

        println!();
    }

    fn format_ipv4_json(calc: &IPv4Calculator, index: usize, config: &Config) -> Result<()> {
        let mut result = json!({
            "type": "ipv4",
            "input": format!("{}/{}", calc.address, calc.prefix_length),
            "index": index,
            "host_address": calc.address.to_string(),
            "host_address_decimal": calc.to_decimal(),
            "host_address_hex": calc.to_hex(),
            "network_address": calc.network.to_string(),
            "network_mask": calc.netmask.to_string(),
            "network_mask_bits": calc.prefix_length,
            "network_mask_hex": calc.netmask_to_hex(),
            "broadcast_address": calc.broadcast.to_string(),
            "cisco_wildcard": calc.wildcard.to_string(),
            "addresses_in_network": calc.get_host_count(),
            "usable_addresses": calc.get_usable_host_count(),
            "network_range": {
                "start": calc.network.to_string(),
                "end": calc.broadcast.to_string()
            },
            "usable_range": {
                "start": calc.get_first_usable().to_string(),
                "end": calc.get_last_usable().to_string()
            }
        });

        if config.output.all_info {
            result["classful"] = json!({
                "network_class": calc.class.to_string(),
                "binary_representation": calc.get_binary_representation(),
                "netmask_binary": calc.get_netmask_binary()
            });
        }

        if let Some(ref split_mask) = config.split_ipv4 {
            if let Ok(new_prefix) = Self::parse_ipv4_mask_to_prefix(split_mask) {
                if let Ok(subnets) = calc.split_network(new_prefix) {
                    let subnet_data: Vec<Value> = subnets
                        .iter()
                        .map(|subnet| {
                            json!({
                                "network": subnet.network.to_string(),
                                "prefix_length": subnet.prefix_length,
                                "broadcast": subnet.broadcast.to_string(),
                                "usable_range": {
                                    "start": subnet.get_first_usable().to_string(),
                                    "end": subnet.get_last_usable().to_string()
                                }
                            })
                        })
                        .collect();
                    result["subnets"] = json!(subnet_data);
                }
            }
        }

        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }

    fn format_ipv6_json(calc: &IPv6Calculator, index: usize, config: &Config) -> Result<()> {
        let (range_start, range_end) = calc.get_network_range();

        let mut result = json!({
            "type": "ipv6",
            "input": format!("{}/{}", calc.address, calc.prefix_length),
            "index": index,
            "expanded_address": calc.get_expanded_address(),
            "compressed_address": calc.get_compressed_address(),
            "subnet_prefix": format!("{}/{}", calc.network, calc.prefix_length),
            "address_id": calc.get_host_id().to_string(),
            "prefix_address": calc.prefix_mask.to_string(),
            "prefix_length": calc.prefix_length,
            "address_type": calc.address_type.to_string(),
            "network_range": {
                "start": range_start.to_string(),
                "end": range_end.to_string()
            },
            "reverse_dns": calc.get_reverse_dns()
        });

        if let Some((expanded_v4, compressed_v4)) = calc.get_ipv4_embedded() {
            result["ipv4_embedded"] = json!({
                "expanded": expanded_v4,
                "compressed": compressed_v4
            });
        }

        if let Some(ref split_prefix) = config.split_ipv6 {
            if let Ok(new_prefix) = split_prefix.parse::<u8>() {
                if let Ok(subnets) = calc.split_network(new_prefix) {
                    let subnet_data: Vec<Value> = subnets
                        .iter()
                        .map(|subnet| {
                            let (start, end) = subnet.get_network_range();
                            json!({
                                "network": subnet.network.to_string(),
                                "prefix_length": subnet.prefix_length,
                                "expanded_address": subnet.get_expanded_address(),
                                "compressed_address": subnet.get_compressed_address(),
                                "network_range": {
                                    "start": start.to_string(),
                                    "end": end.to_string()
                                }
                            })
                        })
                        .collect();
                    result["subnets"] = json!(subnet_data);
                }
            }
        }

        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }

    fn parse_ipv4_mask_to_prefix(mask_str: &str) -> Result<u8> {
        if let Ok(prefix) = mask_str.parse::<u8>() {
            if prefix <= 32 {
                return Ok(prefix);
            }
        }

        if mask_str.starts_with("0x") || mask_str.starts_with("0X") {
            let hex_val = u32::from_str_radix(&mask_str[2..], 16)?;
            let mask_addr = std::net::Ipv4Addr::from(hex_val);
            let mask_int: u32 = mask_addr.into();
            return Ok(u8::try_from(mask_int.count_ones()).unwrap_or(0));
        }

        if mask_str.contains('.') {
            let mask_addr: std::net::Ipv4Addr = mask_str.parse()?;
            let mask_int: u32 = mask_addr.into();
            return Ok(u8::try_from(mask_int.count_ones()).unwrap_or(0));
        }

        Err(anyhow::anyhow!("Invalid netmask format"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Config, IPv4Calculator, IPv4Flags, IPv6Calculator, IPv6Flags, InputFlags, OutputFlags,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_config() -> Config {
        Config {
            inputs: vec![],
            split_ipv4: None,
            split_ipv6: None,
            extra_subnets: None,
            output: OutputFlags::default(),
            ipv4: IPv4Flags::default(),
            ipv6: IPv6Flags::default(),
            input: InputFlags::default(),
        }
    }

    #[test]
    fn test_output_formatter_creation() {
        let formatter_text = OutputFormatter::new(false);
        assert!(!formatter_text.json_mode);

        let formatter_json = OutputFormatter::new(true);
        assert!(formatter_json.json_mode);
    }

    #[test]
    fn test_parse_ipv4_mask_to_prefix() {
        // Test CIDR prefix
        assert_eq!(
            OutputFormatter::parse_ipv4_mask_to_prefix("24").unwrap(),
            24
        );
        assert_eq!(
            OutputFormatter::parse_ipv4_mask_to_prefix("16").unwrap(),
            16
        );
        assert_eq!(OutputFormatter::parse_ipv4_mask_to_prefix("8").unwrap(), 8);

        // Test dotted decimal
        assert_eq!(
            OutputFormatter::parse_ipv4_mask_to_prefix("255.255.255.0").unwrap(),
            24
        );
        assert_eq!(
            OutputFormatter::parse_ipv4_mask_to_prefix("255.255.0.0").unwrap(),
            16
        );
        assert_eq!(
            OutputFormatter::parse_ipv4_mask_to_prefix("255.0.0.0").unwrap(),
            8
        );

        // Test hex format
        assert_eq!(
            OutputFormatter::parse_ipv4_mask_to_prefix("0xFFFFFF00").unwrap(),
            24
        );
        assert_eq!(
            OutputFormatter::parse_ipv4_mask_to_prefix("0xFFFF0000").unwrap(),
            16
        );
        assert_eq!(
            OutputFormatter::parse_ipv4_mask_to_prefix("0xFF000000").unwrap(),
            8
        );

        // Test invalid formats
        assert!(OutputFormatter::parse_ipv4_mask_to_prefix("33").is_err());
        assert!(OutputFormatter::parse_ipv4_mask_to_prefix("invalid").is_err());
        assert!(OutputFormatter::parse_ipv4_mask_to_prefix("256.0.0.0").is_err());
    }

    #[test]
    fn test_interface_info_formatting() {
        let formatter = OutputFormatter::new(false);
        let config = create_test_config();

        let interface_info = InterfaceInfo {
            name: "eth0".to_string(),
            ipv4_addresses: vec![(Ipv4Addr::new(192, 168, 1, 100), 24)],
            ipv6_addresses: vec![("2001:db8::1".parse().unwrap(), 64)],
        };

        // This test mainly ensures the function doesn't panic
        // In a real scenario, you might capture output for verification
        let result = formatter.format_interface(&interface_info, 0, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolved_address_formatting() {
        let formatter = OutputFormatter::new(false);
        let config = create_test_config();

        let resolved = ResolvedAddress {
            hostname: "example.com".to_string(),
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V6("2001:db8::1".parse().unwrap()),
            ],
        };

        // This test mainly ensures the function doesn't panic
        let result = formatter.format_resolved(&resolved, 0, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipv4_formatting() {
        let formatter = OutputFormatter::new(false);
        let config = create_test_config();
        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();

        // Test text formatting
        let result = formatter.format_ipv4(&calc, 0, &config);
        assert!(result.is_ok());

        // Test JSON formatting
        let formatter_json = OutputFormatter::new(true);
        let result = formatter_json.format_ipv4(&calc, 0, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipv6_formatting() {
        let formatter = OutputFormatter::new(false);
        let config = create_test_config();
        let calc = IPv6Calculator::new("2001:db8::/48").unwrap();

        // Test text formatting
        let result = formatter.format_ipv6(&calc, 0, &config);
        assert!(result.is_ok());

        // Test JSON formatting
        let formatter_json = OutputFormatter::new(true);
        let result = formatter_json.format_ipv6(&calc, 0, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_with_all_info() {
        let mut config = create_test_config();
        config.output.all_info = true;

        let formatter = OutputFormatter::new(false);
        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();

        // This should include classful and bitmap sections
        let result = formatter.format_ipv4(&calc, 0, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_with_subnet_splitting() {
        let mut config = create_test_config();
        config.split_ipv4 = Some("26".to_string());

        let formatter = OutputFormatter::new(false);
        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();

        // This should include subnet splitting section
        let result = formatter.format_ipv4(&calc, 0, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_with_verbose_splitting() {
        let mut config = create_test_config();
        config.split_ipv4 = Some("26".to_string());
        config.output.verbose = true;

        let formatter = OutputFormatter::new(false);
        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();

        // This should include verbose subnet splitting
        let result = formatter.format_ipv4(&calc, 0, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipv6_subnet_splitting() {
        let mut config = create_test_config();
        config.split_ipv6 = Some("52".to_string());

        let formatter = OutputFormatter::new(false);
        let calc = IPv6Calculator::new("2001:db8::/48").unwrap();

        // This should include IPv6 subnet splitting
        let result = formatter.format_ipv6(&calc, 0, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_interface_info() {
        let formatter = OutputFormatter::new(false);
        let config = create_test_config();

        let interface_info = InterfaceInfo {
            name: "dummy".to_string(),
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
        };

        // Should handle empty interface gracefully
        let result = formatter.format_interface(&interface_info, 0, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_resolved_addresses() {
        let formatter = OutputFormatter::new(false);
        let config = create_test_config();

        let resolved = ResolvedAddress {
            hostname: "example.com".to_string(),
            addresses: vec![],
        };

        // Should handle empty resolution gracefully
        let result = formatter.format_resolved(&resolved, 0, &config);
        assert!(result.is_ok());
    }
}
