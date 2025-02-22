// Copyright (c) 2025 Michael Heca <michael@heca.net>
// Licensed under the MIT License

use clap::Parser;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process;

/// Program to check if a given IP or CIDR is contained in a rule loaded from a file.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// IP or CIDR to check.
    input_str: String,
    /// Path to the file with rules.
    file_path: String,
    /// Print all matching lines instead of just indicating containment.
    #[arg(short, long)]
    print: bool,
    /// Suppress output on success.
    #[arg(short, long)]
    quiet: bool,
}

struct NetworkLine {
    line: String,
    network: Option<IpNetwork>,
}

impl NetworkLine {
    fn new(line: &str) -> Self {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let network = if !parts.is_empty() {
            parts[0].parse::<IpNetwork>().ok()
        } else {
            None
        };
        NetworkLine {
            line: line.to_string(),
            network,
        }
    }
}

fn load_networks(file_path: &str) -> io::Result<Vec<NetworkLine>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut networks = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        networks.push(NetworkLine::new(trimmed));
    }
    Ok(networks)
}

/// Checks if `input` (as a network) is fully contained in `container`.
fn subnet_of(input: &IpNetwork, container: &IpNetwork) -> bool {
    // If the IP versions are different, comparison is not possible.
    if input.ip().is_ipv4() != container.ip().is_ipv4() {
        return false;
    }
    match (input, container) {
        (IpNetwork::V4(in_net), IpNetwork::V4(cont_net)) => {
            let in_network = u32::from(in_net.network());
            let in_broadcast = u32::from(in_net.broadcast());
            let cont_network = u32::from(cont_net.network());
            let cont_broadcast = u32::from(cont_net.broadcast());
            (cont_network <= in_network) && (in_broadcast <= cont_broadcast)
        }
        (IpNetwork::V6(in_net), IpNetwork::V6(cont_net)) => {
            let in_network = u128::from(in_net.network());
            let in_prefix = in_net.prefix();
            let in_mask = if in_prefix == 0 {
                0
            } else {
                (!0u128) << (128 - in_prefix)
            };
            let in_last = in_network | (!in_mask);

            let cont_network = u128::from(cont_net.network());
            let cont_prefix = cont_net.prefix();
            let cont_mask = if cont_prefix == 0 {
                0
            } else {
                (!0u128) << (128 - cont_prefix)
            };
            let cont_last = cont_network | (!cont_mask);

            (cont_network <= in_network) && (in_last <= cont_last)
        }
        _ => false,
    }
}

/// Goes through the list of networks and checks if a given IP/CIDR is contained in any of them.
/// If the print option is enabled, all matching lines are printed.
fn is_contained(input_str: &str, networks: &[NetworkLine], print_matched: bool) -> Option<bool> {
    let input_net = input_str.parse::<IpNetwork>().ok()?;
    let mut found = false;

    for net_line in networks {
        if let Some(net) = net_line.network {
            if subnet_of(&input_net, &net) {
                if print_matched {
                    println!("{}", net_line.line);
                } else {
                    return Some(true);
                }
                found = true;
            }
        }
    }
    Some(found)
}

fn main() {
    let args = Args::parse();

    let networks = match load_networks(&args.file_path) {
        Ok(nets) => nets,
        Err(err) => {
            eprintln!("ERROR: {}", err);
            process::exit(2);
        }
    };

    let result = is_contained(&args.input_str, &networks, args.print);

    if result.is_none() {
        eprintln!("ERROR: Invalid input: {}", args.input_str);
        process::exit(2);
    }

    let contained = result.unwrap();
    if !args.quiet {
        if contained {
            println!("IP or CIDR '{}' is contained in a rule.", args.input_str);
        } else {
            println!(
                "IP or CIDR '{}' is not contained in any rule.",
                args.input_str
            );
        }
    }

    process::exit(if contained { 0 } else { 1 });
}
