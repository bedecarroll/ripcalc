use anyhow::Result;
use bitflags::bitflags;
use clap::{Arg, Command};
use std::io::{self, BufRead};

#[derive(Debug, Default)]
struct OutputFlags {
    json: bool,
    all_info: bool,
}
// Default for IPv4Flags: empty flags
impl Default for IPv4Flags {
    fn default() -> Self {
        Self::empty()
    }
}

bitflags! {
    #[derive(Debug)]
    /// Flags controlling IPv4 output options.
    pub struct IPv4Flags: u8 {
        /// Show CIDR bitmaps.
        const CIDR_BITMAP     = 0b0001;
        /// Show classful address information.
        const CLASSFUL_ADDR   = 0b0010;
        /// Show classful bitmaps.
        const CLASSFUL_BITMAP = 0b0100;
        /// Show wildcard (inverse mask).
        const WILDCARD        = 0b1000;
    }
}

#[derive(Debug, Default)]
struct IPv6Flags {
    v4_in_v6: bool,
    v6_reverse: bool,
}

#[derive(Debug, Default)]
struct InputFlags {
    dns_resolve: bool,
    from_stdin: bool,
}

mod dns;
mod interface;
mod ipv4;
mod ipv6;
mod output;

use ipv4::IPv4Calculator;
use ipv6::IPv6Calculator;
use output::OutputFormatter;

#[derive(Debug)]
struct Config {
    inputs: Vec<String>,
    explicit_ipv4: Vec<String>,
    explicit_ipv6: Vec<String>,
    explicit_interfaces: Vec<String>,
    split_ipv4: Option<String>,
    split_ipv6: Option<String>,
    extra_subnets: Option<u32>,
    output: OutputFlags,
    ipv4: IPv4Flags,
    ipv6: IPv6Flags,
    input: InputFlags,
}

fn build_cli() -> Command {
    let cmd = base_command();
    let cmd = add_input_args(cmd);
    let cmd = add_global_flags(cmd);
    let cmd = add_ipv4_args(cmd);
    let cmd = add_ipv6_args(cmd);
    add_json_arg(cmd)
}

fn base_command() -> Command {
    Command::new("ripcalc")
        .version(env!("CARGO_PKG_VERSION"))  // Automatically use Cargo.toml version
        .about("A subnet calculator that replicates and extends sipcalc functionality")
        .disable_version_flag(true)  // Disable default -V/--version to use custom -v
}

fn add_input_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("inputs")
            .help("IP addresses, networks, interface names, or '-' for stdin")
            .num_args(0..)
            .value_name("ADDRESS|INTERFACE"),
    )
    .arg(
        Arg::new("addr-int")
            .short('I')
            .long("addr-int")
            .help("Add an interface")
            .value_name("INT")
            .action(clap::ArgAction::Append),
    )
    .arg(
        Arg::new("addr-ipv4")
            .short('4')
            .long("addr-ipv4")
            .help("Add an IPv4 address")
            .value_name("ADDR")
            .action(clap::ArgAction::Append),
    )
    .arg(
        Arg::new("addr-ipv6")
            .short('6')
            .long("addr-ipv6")
            .help("Add an IPv6 address")
            .value_name("ADDR")
            .action(clap::ArgAction::Append),
    )
}

fn add_global_flags(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("all")
            .short('a')
            .long("all")
            .help("All possible information")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("resolve")
            .short('d')
            .long("resolve")
            .help("Enable name resolution")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("subnets")
            .short('n')
            .long("subnets")
            .help("Display NUM extra subnets (starting from current subnet)")
            .value_name("NUM"),
    )
    .arg(
        Arg::new("split-verbose")
            .short('u')
            .long("split-verbose")
            .help("Verbose split (legacy)")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("version")
            .short('v')
            .long("version")
            .help("Version information")
            .action(clap::ArgAction::SetTrue),
    )
}

fn add_ipv4_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("cidr-bitmap")
            .short('b')
            .long("cidr-bitmap")
            .help("CIDR bitmap")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("classful-addr")
            .short('c')
            .long("classful-addr")
            .help("Classful address information")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("cidr-addr")
            .short('i')
            .long("cidr-addr")
            .help("CIDR address information (default)")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("v4split")
            .short('s')
            .long("v4split")
            .help("Split the current network into subnets of MASK size")
            .value_name("MASK"),
    )
    .arg(
        Arg::new("wildcard")
            .short('w')
            .long("wildcard")
            .help("Display information for a wildcard (inverse mask)")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("classful-bitmap")
            .short('x')
            .long("classful-bitmap")
            .help("Classful bitmap")
            .action(clap::ArgAction::SetTrue),
    )
}

fn add_ipv6_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("v4inv6")
            .short('e')
            .long("v4inv6")
            .help("IPv4 compatible IPv6 information")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("v6rev")
            .short('r')
            .long("v6rev")
            .help("IPv6 reverse DNS output")
            .action(clap::ArgAction::SetTrue),
    )
    .arg(
        Arg::new("v6split")
            .short('S')
            .long("v6split")
            .help("Split the current network into subnets of MASK size")
            .value_name("MASK"),
    )
    .arg(
        Arg::new("v6-standard")
            .short('t')
            .long("v6-standard")
            .help("Standard IPv6 (default)")
            .action(clap::ArgAction::SetTrue),
    )
}

fn add_json_arg(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("json")
            .long("json")
            .help("Output results in JSON format")
            .action(clap::ArgAction::SetTrue),
    )
}

fn build_config(matches: &clap::ArgMatches) -> Config {
    let mut inputs: Vec<String> = matches
        .get_many::<String>("inputs")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();

    // Collect explicit addresses
    let explicit_ipv4: Vec<String> = matches
        .get_many::<String>("addr-ipv4")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let explicit_ipv6: Vec<String> = matches
        .get_many::<String>("addr-ipv6")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let explicit_interfaces: Vec<String> = matches
        .get_many::<String>("addr-int")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();

    // Add addresses from specific flags to inputs list
    inputs.extend(explicit_ipv4.iter().cloned());
    inputs.extend(explicit_ipv6.iter().cloned());
    inputs.extend(explicit_interfaces.iter().cloned());

    // Build IPv4 flags bitmask
    let mut ipv4_flags = IPv4Flags::empty();
    if matches.get_flag("cidr-bitmap") {
        ipv4_flags |= IPv4Flags::CIDR_BITMAP;
    }
    if matches.get_flag("classful-addr") {
        ipv4_flags |= IPv4Flags::CLASSFUL_ADDR;
    }
    if matches.get_flag("classful-bitmap") {
        ipv4_flags |= IPv4Flags::CLASSFUL_BITMAP;
    }
    if matches.get_flag("wildcard") {
        ipv4_flags |= IPv4Flags::WILDCARD;
    }

    Config {
        inputs: inputs.clone(),
        explicit_ipv4,
        explicit_ipv6,
        explicit_interfaces,
        split_ipv4: matches.get_one::<String>("v4split").cloned(),
        split_ipv6: matches.get_one::<String>("v6split").cloned(),
        extra_subnets: matches
            .get_one::<String>("subnets")
            .and_then(|s| s.parse().ok()),
        output: OutputFlags {
            json: matches.get_flag("json"),
            all_info: matches.get_flag("all"),
        },
        ipv4: ipv4_flags,
        ipv6: IPv6Flags {
            v4_in_v6: matches.get_flag("v4inv6"),
            v6_reverse: matches.get_flag("v6rev"),
        },
        input: InputFlags {
            dns_resolve: matches.get_flag("resolve"),
            from_stdin: inputs.iter().any(|v| v == "-") || inputs.is_empty(),
        },
    }
}

fn main() -> Result<()> {
    let matches = build_cli().get_matches();
    
    // Handle version flag (sipcalc compatibility: -v instead of -V)
    if matches.get_flag("version") {
        println!("ripcalc {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    
    let config = build_config(&matches);

    if config.input.from_stdin {
        process_stdin(&config)?;
    } else {
        for (index, input) in config.inputs.iter().enumerate() {
            if input != "-" {
                process_input(input, index, &config)?;
            }
        }
    }

    Ok(())
}

fn process_stdin(config: &Config) -> Result<()> {
    let stdin = io::stdin();
    let mut index = 0;

    for line in stdin.lock().lines() {
        let input = line?;
        let trimmed = input.trim();
        if !trimmed.is_empty() {
            process_input(trimmed, index, config)?;
            index += 1;
        }
    }

    Ok(())
}

fn process_input(input: &str, index: usize, config: &Config) -> Result<()> {
    let formatter = OutputFormatter::new(config.output.json);

    // Check if this input was explicitly specified with a type flag
    if config.explicit_ipv4.contains(&input.to_string()) {
        // Force IPv4 parsing even if it contains spaces
        if let Ok(ipv4_calc) = IPv4Calculator::new(input) {
            formatter.format_ipv4(&ipv4_calc, index, config)?;
        } else {
            eprintln!("Error: Unable to parse '{input}' as IPv4");
        }
        return Ok(());
    }

    if config.explicit_ipv6.contains(&input.to_string()) {
        // Force IPv6 parsing
        if let Ok(ipv6_calc) = IPv6Calculator::new(input) {
            formatter.format_ipv6(&ipv6_calc, index, config)?;
        } else {
            eprintln!("Error: Unable to parse '{input}' as IPv6");
        }
        return Ok(());
    }

    if config.explicit_interfaces.contains(&input.to_string()) {
        // Force interface parsing
        if let Ok(interface_info) = interface::get_interface_info(input) {
            formatter.format_interface(&interface_info, index, config)?;
        } else {
            eprintln!("Error: Unable to find interface '{input}'");
        }
        return Ok(());
    }

    // For inputs with spaces, try interface parsing first (to match sipcalc behavior)
    if input.contains(' ') {
        // Try as interface name first
        if let Ok(interface_info) = interface::get_interface_info(input) {
            formatter.format_interface(&interface_info, index, config)?;
            return Ok(());
        }
        // If interface parsing fails, always show interface-style error message
        // (sipcalc treats all space-containing inputs as interface names)
        println!("-[int-ipv4 : {input}] - {index}");
        println!();
        println!("-[ERR : Unable to retrieve interface information]");
        println!();
        println!("-");
        return Ok(());
    }

    // For inputs without spaces, use the original parsing order
    // Try to parse as IPv4 (CIDR notation or single address)
    if let Ok(ipv4_calc) = IPv4Calculator::new(input) {
        formatter.format_ipv4(&ipv4_calc, index, config)?;
    }
    // Try to parse as IPv6
    else if let Ok(ipv6_calc) = IPv6Calculator::new(input) {
        formatter.format_ipv6(&ipv6_calc, index, config)?;
    }
    // Try as interface name
    else if let Ok(interface_info) = interface::get_interface_info(input) {
        formatter.format_interface(&interface_info, index, config)?;
    }
    // Try DNS resolution if enabled
    else if config.input.dns_resolve {
        if let Ok(resolved) = dns::resolve_hostname(input) {
            formatter.format_resolved(&resolved, index, config)?;
        } else {
            eprintln!("Error: Unable to parse or resolve '{input}'");
        }
    } else {
        eprintln!("Error: Unable to parse '{input}'");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_from_cargo() {
        // Test that version comes from Cargo.toml automatically
        let cmd = build_cli();
        let version = cmd.get_version().unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
        assert!(!version.is_empty());
    }

    #[test]
    fn test_version_flag_available() {
        // Test that our custom -v flag is available
        let cmd = build_cli();
        let version_arg = cmd.get_arguments().find(|arg| arg.get_short() == Some('v'));
        assert!(version_arg.is_some());
        assert_eq!(version_arg.unwrap().get_id(), "version");
    }
}
