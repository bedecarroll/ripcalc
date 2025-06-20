use crate::dns::ResolvedAddress;
use crate::interface::InterfaceInfo;
use crate::{Config, IPv4Calculator, IPv6Calculator};
use anyhow::Result;
use serde_json::{Value, json};

pub struct OutputFormatter {
    json_mode: bool,
}

impl OutputFormatter {
    pub const fn new(json_mode: bool) -> Self {
        Self { json_mode }
    }

    pub fn format_ipv4(&self, calc: &IPv4Calculator, index: usize, config: &Config) -> Result<()> {
        if self.json_mode {
            // JSON formatting is a static function
            Self::format_ipv4_json(calc, index, config)
        } else {
            // Delegate to static text formatter and return OK
            Self::format_ipv4_text(calc, index, config);
            Ok(())
        }
    }

    pub fn format_ipv6(&self, calc: &IPv6Calculator, index: usize, config: &Config) -> Result<()> {
        if self.json_mode {
            // JSON formatting as static function
            Self::format_ipv6_json(calc, index, config)
        } else {
            // Delegate to static text formatter and return OK
            Self::format_ipv6_text(calc, index, config);
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
                    Self::format_ipv4_json(&calc, addr_index, config)?;
                } else {
                    println!(
                        "-[int-ipv4 : {} ({})] - {}",
                        cidr, interface_info.name, addr_index
                    );
                    // Text formatting as static function
                    Self::format_ipv4_text_content(&calc, config);
                }
                addr_index += 1;
            }
        }

        for (ipv6_addr, prefix_len) in &interface_info.ipv6_addresses {
            let cidr = format!("{ipv6_addr}/{prefix_len}");
            if let Ok(calc) = crate::IPv6Calculator::new(&cidr) {
                if self.json_mode {
                    // JSON formatting as static function
                    Self::format_ipv6_json(&calc, addr_index, config)?;
                } else {
                    println!(
                        "-[int-ipv6 : {} ({})] - {}",
                        cidr, interface_info.name, addr_index
                    );
                    // Text formatting as static function
                    Self::format_ipv6_text_content(&calc, config);
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
                            Self::format_ipv4_json(&calc, addr_index, config)?;
                        } else {
                            println!(
                                "-[dns-ipv4 : {} ({})] - {}",
                                cidr, resolved.hostname, addr_index
                            );
                            // Text formatting as static function
                            Self::format_ipv4_text_content(&calc, config);
                        }
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    let cidr = format!("{ipv6}/128");
                    if let Ok(calc) = crate::IPv6Calculator::new(&cidr) {
                        if self.json_mode {
                            Self::format_ipv6_json(&calc, addr_index, config)?;
                        } else {
                            println!(
                                "-[dns-ipv6 : {} ({})] - {}",
                                cidr, resolved.hostname, addr_index
                            );
                            // Text formatting as static function
                            Self::format_ipv6_text_content(&calc, config);
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
        if calc.is_bare_address {
            // For bare addresses, show just the IP address (like sipcalc)
            println!(
                "-[ipv4 : {address}] - {idx}",
                address = calc.address,
                idx = index
            );
        } else {
            // For explicit CIDR notation, show IP/prefix
            println!(
                "-[ipv4 : {address}/{prefix}] - {idx}",
                address = calc.address,
                prefix = calc.prefix_length,
                idx = index
            );
        }
        // Delegate to text content formatter
        Self::format_ipv4_text_content(calc, config);
    }

    fn format_ipv4_text_content(calc: &IPv4Calculator, config: &Config) {
        // Handle -a (all info) flag - show multiple sections
        println!();
        if config.output.all_info {
            if calc.is_bare_address {
                // For bare addresses like "1.1.1.1", show both classful and host interpretations
                Self::format_ipv4_classful_section_bare_address(calc);

                // Create and show the host-specific (/32) interpretation
                println!();
                if let Ok(host_calc) = calc.as_host() {
                    Self::format_ipv4_cidr_section(&host_calc);
                    println!();
                    Self::format_ipv4_classful_bitmap_section(calc);
                    println!();
                    Self::format_ipv4_cidr_bitmap_section(&host_calc);
                    println!();
                    Self::format_ipv4_networks_section_for_bare_address(&host_calc);
                } else {
                    // Fallback to regular formatting if host calc fails
                    Self::format_ipv4_cidr_section(calc);
                    println!();
                    Self::format_ipv4_classful_bitmap_section(calc);
                    println!();
                    Self::format_ipv4_cidr_bitmap_section(calc);
                    println!();
                    Self::format_ipv4_networks_section(calc);
                }
            } else {
                // For explicit CIDR notation, show normal sections
                Self::format_ipv4_classful_section(calc);
                println!();
                Self::format_ipv4_cidr_section(calc);
                println!();
                Self::format_ipv4_classful_bitmap_section(calc);
                println!();
                Self::format_ipv4_cidr_bitmap_section(calc);
                println!();
                Self::format_ipv4_networks_section(calc);
            }
        }
        // Handle specific operations
        else if config.split_ipv4.is_some() {
            // Only split networks
            Self::format_ipv4_split_section(calc, config);
        } else if config.extra_subnets.is_some() {
            // Only extra subnets
            Self::format_ipv4_extra_subnets_section(calc, config);
        } else if config.ipv4.contains(crate::IPv4Flags::CLASSFUL_ADDR) {
            // Only classful information
            Self::format_ipv4_classful_section(calc);
        } else if config.ipv4.contains(crate::IPv4Flags::CIDR_BITMAP) {
            // Only CIDR bitmaps
            Self::format_ipv4_cidr_bitmap_section(calc);
        } else if config.ipv4.contains(crate::IPv4Flags::CLASSFUL_BITMAP) {
            // Only classful bitmaps
            Self::format_ipv4_classful_bitmap_section(calc);
        } else if config.ipv4.contains(crate::IPv4Flags::WILDCARD) {
            // Only wildcard information
            Self::format_ipv4_wildcard_section(calc);
        } else {
            // Default: show CIDR section
            Self::format_ipv4_cidr_section(calc);
        }
        // End of section separator
        println!();
        println!("-");
    }

    // IPv4 formatting helper sections
    fn format_ipv4_cidr_section(calc: &IPv4Calculator) {
        println!("[CIDR]");
        println!("Host address\t\t- {}", calc.address);
        println!("Host address (decimal)\t- {}", calc.to_decimal());
        println!("Host address (hex)\t- {}", calc.to_hex());
        println!("Network address\t\t- {}", calc.network);
        println!("Network mask\t\t- {}", calc.netmask);
        println!("Network mask (bits)\t- {}", calc.prefix_length);
        println!("Network mask (hex)\t- {}", calc.netmask_to_hex());
        println!("Broadcast address\t- {}", calc.broadcast);
        println!("Cisco wildcard\t\t- {}", calc.wildcard);
        println!("Addresses in network\t- {}", calc.get_host_count());
        println!(
            "Network range\t\t- {network} - {broadcast}",
            network = calc.network,
            broadcast = calc.broadcast
        );
        // Only show usable range for traditional networks (exclude /31 and /32)
        if calc.prefix_length < 31 {
            println!(
                "Usable range\t\t- {first} - {last}",
                first = calc.get_first_usable(),
                last = calc.get_last_usable()
            );
        }
    }

    fn format_ipv4_classful_section(calc: &IPv4Calculator) {
        println!("[Classful]");
        // Detailed classful output with tabs (for CIDR notation compatibility)
        println!("Host address\t\t- {}", calc.address);
        println!("Host address (decimal)\t- {}", calc.to_decimal());
        println!("Host address (hex)\t- {}", calc.to_hex());
        println!("Network address\t\t- {}", calc.network);
        println!("Network class\t\t- {}", calc.class);
        println!("Network mask\t\t- {}", calc.netmask);
        println!("Network mask (hex)\t- {}", calc.netmask_to_hex());
        println!("Broadcast address\t- {}", calc.broadcast);
    }

    fn format_ipv4_classful_section_bare_address(calc: &IPv4Calculator) {
        println!("[Classful]");
        // Detailed classful output matching sipcalc golden (using tabs for spacing)
        println!("Host address\t\t- {}", calc.address);
        println!("Host address (decimal)\t- {}", calc.to_decimal());
        println!("Host address (hex)\t- {}", calc.to_hex());
        println!("Network address\t\t- {}", calc.network);
        println!("Network class\t\t- {}", calc.class);
        println!("Network mask\t\t- {}", calc.netmask);
        println!("Network mask (hex)\t- {}", calc.netmask_to_hex());
        println!("Broadcast address\t- {}", calc.broadcast);
    }

    fn format_ipv4_split_section(calc: &IPv4Calculator, config: &Config) {
        if let Some(ref split_mask) = config.split_ipv4 {
            if let Ok(new_prefix) = Self::parse_ipv4_mask_to_prefix(split_mask) {
                if let Ok(subnets) = calc.split_network(new_prefix) {
                    if config.output.split_verbose {
                        // Verbose split mode - show full CIDR information for each subnet
                        println!("[Split network - verbose]");
                        for subnet in &subnets {
                            // Show header for each subnet with original network (matches sipcalc format)
                            println!(
                                "-[ipv4 : {}/{prefix}] - 0",
                                calc.network,
                                prefix = calc.prefix_length
                            );
                            println!();
                            Self::format_ipv4_cidr_section(subnet);
                            println!();
                            println!("-");
                        }
                    } else {
                        // Normal split mode - show summary
                        println!("[Split network]");
                        for subnet in &subnets {
                            // Print each subnet network and its broadcast address
                            println!(
                                "Network\t\t\t- {:<15} - {}",
                                subnet.network, subnet.broadcast
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
            // Match sipcalc golden output for extra subnets
            println!("[Networks]");
            for subnet in &extra_subnets {
                // Check if this subnet contains the original network
                if subnet.network == calc.network {
                    println!(
                        "Network\t\t\t- {:<15} - {} (current)",
                        subnet.network, subnet.broadcast
                    );
                } else {
                    println!(
                        "Network\t\t\t- {:<15} - {}",
                        subnet.network, subnet.broadcast
                    );
                }
            }
        }
    }

    fn format_ipv4_cidr_bitmap_section(calc: &IPv4Calculator) {
        println!("[CIDR bitmaps]");
        // Prepare binary representations
        let host_bits = calc.get_binary_representation();
        let network_bits = calc
            .network
            .octets()
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<Vec<_>>()
            .join(".");
        let mask_bits = calc.get_netmask_binary();
        let broadcast_bits = calc
            .broadcast
            .octets()
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<Vec<_>>()
            .join(".");
        let wildcard_bits = calc
            .wildcard
            .octets()
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<Vec<_>>()
            .join(".");
        let first_bits = calc
            .get_first_usable()
            .octets()
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<Vec<_>>()
            .join(".");
        let last_bits = calc
            .get_last_usable()
            .octets()
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<Vec<_>>()
            .join(".");
        // Output binary bitmap section matching sipcalc
        println!("Host address\t\t- {host_bits}");
        println!("Network address\t\t- {network_bits}");
        println!("Network mask\t\t- {mask_bits}");
        println!("Broadcast address\t- {broadcast_bits}");
        println!("Cisco wildcard\t\t- {wildcard_bits}");
        println!("Network range\t\t- {network_bits} -");
        println!("\t\t\t  {broadcast_bits}");

        // Only show usable range for networks that have separate usable addresses
        if calc.prefix_length < 31 {
            println!("Usable range\t\t- {first_bits} -");
            println!("\t\t\t  {last_bits}");
        }
    }

    fn format_ipv4_classful_bitmap_section(calc: &IPv4Calculator) {
        println!("[Classful bitmaps]");
        // Match sipcalc golden output: show classful network address, not host address
        let classful_prefix = match calc.class {
            crate::ipv4::NetworkClass::A => 8,
            crate::ipv4::NetworkClass::B => 16,
            crate::ipv4::NetworkClass::C => 24,
            _ => calc.prefix_length,
        };
        let classful_calc =
            crate::IPv4Calculator::new(&format!("{}/{}", calc.address, classful_prefix)).unwrap();

        let classful_network_bits = classful_calc
            .network
            .octets()
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<Vec<_>>()
            .join(".");

        println!("Network address\t\t- {classful_network_bits}");
        println!(
            "Network mask\t\t- {bits}",
            bits = classful_calc.get_netmask_binary()
        );
    }

    fn format_ipv4_networks_section(calc: &IPv4Calculator) {
        println!("[Networks]");
        println!(
            "Network\t\t\t- {network}     - {broadcast} (current)",
            network = calc.network,
            broadcast = calc.broadcast
        );
    }

    fn format_ipv4_networks_section_for_bare_address(host_calc: &IPv4Calculator) {
        println!("[Networks]");

        // Show all /32 hosts in the containing /24 network, like sipcalc does
        let base_addr = host_calc.address.octets();
        let base_network = u32::from_be_bytes([base_addr[0], base_addr[1], base_addr[2], 0]);

        for i in 0..=255 {
            let host_ip = std::net::Ipv4Addr::from(base_network + i);
            let is_current = host_ip == host_calc.address;

            if is_current {
                println!("Network\t\t\t- {host_ip:<15} - {host_ip} (current)");
            } else {
                println!("Network\t\t\t- {host_ip:<15} - {host_ip}");
            }
        }
    }

    fn format_ipv4_wildcard_section(calc: &IPv4Calculator) {
        println!("[WILDCARD]");
        println!("Wildcard\t\t- {}", calc.network);

        // Calculate the inverse of the IP address itself (not the subnet mask)
        let addr_int: u32 = calc.address.into();
        let inverted_addr = std::net::Ipv4Addr::from(!addr_int);
        println!("Network mask\t\t- {inverted_addr}");

        // Calculate number of 1-bits in the inverted address
        let inverted_bits = (!addr_int).count_ones();
        println!("Network mask (bits)\t- {inverted_bits}");
    }
    /// Format IPv6 output in text mode.
    pub fn format_ipv6_text(calc: &IPv6Calculator, index: usize, config: &Config) {
        // Inline formatting using named arguments
        // Header: omit prefix for IPv4-in-IPv6 mapping or bare addresses
        if config.ipv6.v4_in_v6 {
            println!("-[ipv6 : {}] - {}", calc.address, index);
        } else if calc.is_bare_address
            || (calc.prefix_length == 128
                && matches!(
                    calc.address_type,
                    crate::ipv6::IPv6AddressType::IPv4Compatible
                ))
        {
            // For bare addresses, show just the IPv6 address (like sipcalc)
            // For IPv4-embedded addresses, show the original input format
            let display_addr = if matches!(
                calc.address_type,
                crate::ipv6::IPv6AddressType::IPv4Mapped
                    | crate::ipv6::IPv6AddressType::IPv4Compatible
            ) {
                calc.original_input
                    .split('/')
                    .next()
                    .unwrap_or(&calc.original_input)
                    .to_string()
            } else {
                calc.address.to_string()
            };
            println!("-[ipv6 : {display_addr}] - {index}");
        } else {
            // For explicit CIDR notation, show address/prefix
            // For IPv4-embedded addresses, use original input format for the address part
            let display_addr = if matches!(
                calc.address_type,
                crate::ipv6::IPv6AddressType::IPv4Mapped
                    | crate::ipv6::IPv6AddressType::IPv4Compatible
            ) {
                calc.original_input
                    .split('/')
                    .next()
                    .unwrap_or(&calc.original_input)
                    .to_string()
            } else {
                calc.address.to_string()
            };
            println!(
                "-[ipv6 : {address}/{prefix}] - {idx}",
                address = display_addr,
                prefix = calc.prefix_length,
                idx = index
            );
        }
        // Delegate to text content formatter
        Self::format_ipv6_text_content(calc, config);
    }

    fn format_ipv6_text_content(calc: &IPv6Calculator, config: &Config) {
        println!();

        if config.ipv6.v4_in_v6 {
            Self::format_ipv6_v4inv6_section(calc);
        } else if config.ipv6.v6_reverse {
            Self::format_ipv6_reverse_section(calc);
        } else if let Some(ref split_prefix) = config.split_ipv6 {
            Self::format_ipv6_split_section(calc, split_prefix);
        } else {
            Self::format_ipv6_info_section(calc);
        }

        // End of section separator
        println!();
        println!("-");
    }

    fn format_ipv6_v4inv6_section(calc: &IPv6Calculator) {
        println!("[V4INV6]");
        if let Some((_, compressed_v4)) = calc.get_ipv4_embedded() {
            // Expanded v4inv6: first five segments zero, then ffff and dotted IPv4
            let ipv4_part = compressed_v4.trim_start_matches("::");
            let exp_v4inv6 = format!("0000:0000:0000:0000:0000:{ipv4_part}");
            println!("Expanded v4inv6 address\t- {exp_v4inv6}");
            println!("Compr. v4inv6 address\t- {compressed_v4}");
            println!("Comment\t\t\t- {}", calc.address_type);
        }
    }

    fn format_ipv6_reverse_section(calc: &IPv6Calculator) {
        println!("[IPV6 DNS]");
        println!("Reverse DNS (ip6.arpa)\t-");
        println!("{}", calc.get_reverse_dns());
    }

    fn format_ipv6_split_section(calc: &IPv6Calculator, split_prefix: &str) {
        println!("[Split network]");
        if let Ok(new_prefix) = split_prefix.parse::<u8>() {
            let prefix = calc.prefix_length;
            // Base address as 128-bit integer (network byte order)
            let base = u128::from_be_bytes(calc.network.octets());
            let count = 1_u128 << u32::from(new_prefix - prefix);
            let step = 1_u128 << u32::from(128 - new_prefix);
            for i in 0..count {
                let start_u = base + i * step;
                let end_u = base + ((i + 1) * step) - 1;
                let start_addr = std::net::Ipv6Addr::from(start_u);
                let end_addr = std::net::Ipv6Addr::from(end_u);
                let start_exp = Self::format_ipv6_addr_expanded_padding(&start_addr);
                let end_exp = Self::format_ipv6_addr_expanded_padding(&end_addr);
                println!("Network\t\t\t- {start_exp} -\n\t\t\t  {end_exp}");
            }
        }
    }

    fn format_ipv6_info_section(calc: &IPv6Calculator) {
        println!("[IPV6 INFO]");
        println!("Expanded Address\t- {}", calc.get_expanded_address());
        println!("Compressed address\t- {}", calc.get_compressed_address());

        // Network prefix
        let net_expanded = Self::format_ipv6_addr_expanded_no_padding(&calc.network);
        println!(
            "Subnet prefix (masked)\t- {net_expanded}/{}",
            calc.prefix_length
        );

        // Host ID
        let host_id = calc.get_host_id();
        let host_expanded = Self::format_ipv6_addr_expanded_no_padding(&host_id);
        println!(
            "Address ID (masked)\t- {host_expanded}/{}",
            calc.prefix_length
        );

        // Prefix mask
        let mask_expanded = Self::format_ipv6_addr_expanded_no_padding(&calc.prefix_mask);
        println!("Prefix address\t\t- {mask_expanded}");
        println!("Prefix length\t\t- {}", calc.prefix_length);
        println!("Address type\t\t- {}", calc.address_type);

        // Network range
        let (start, end) = calc.get_network_range();
        let start_exp = Self::format_ipv6_addr_expanded_padding(&start);
        let end_exp = Self::format_ipv6_addr_expanded_padding(&end);
        println!("Network range\t\t- {start_exp} -");
        println!("\t\t\t  {end_exp}");
    }

    fn format_ipv6_addr_expanded_padding(addr: &std::net::Ipv6Addr) -> String {
        let seg = addr.segments();
        format!(
            "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
            seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7]
        )
    }

    fn format_ipv6_addr_expanded_no_padding(addr: &std::net::Ipv6Addr) -> String {
        let seg = addr.segments();
        format!(
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7]
        )
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
            explicit_ipv4: vec![],
            explicit_ipv6: vec![],
            explicit_interfaces: vec![],
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
    fn test_config_with_subnet_splitting_different_mask() {
        let mut config = create_test_config();
        config.split_ipv4 = Some("28".to_string());

        let formatter = OutputFormatter::new(false);
        let calc = IPv4Calculator::new("192.168.1.0/24").unwrap();

        // This should include subnet splitting with different mask
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
