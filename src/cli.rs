use clap::{Arg, Command};

#[must_use]
pub fn build_cli() -> Command {
    let cmd = base_command();
    let cmd = add_input_args(cmd);
    let cmd = add_global_flags(cmd);
    let cmd = add_ipv4_args(cmd);
    let cmd = add_ipv6_args(cmd);
    add_json_arg(cmd)
}

fn base_command() -> Command {
    Command::new("ripcalc")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A subnet calculator that replicates and extends sipcalc functionality")
        .long_about(
            "ripcalc is a Rust-based subnet calculator that builds upon the excellent \
foundation of sipcalc. While maintaining full compatibility with sipcalc's proven interface \
and core functionality, ripcalc extends the legacy with modern enhancements including JSON \
output, enhanced IPv6 support with current RFC classifications, and improved error handling.",
        )
        .disable_version_flag(true)
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
            .help("Verbose split")
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
