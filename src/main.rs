// Copyright (c) 2025 Michael Heca <michael@heca.net>
// Licensed under the MIT License

use clap::Parser;
use ipnetwork::IpNetwork;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::process;
use thiserror::Error;

// Security and resource limits
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
const MAX_LINES: usize = 1_000_000; // 1 million lines
const MAX_LINE_LENGTH: usize = 10_000; // 10 KB per line

// Exit codes
const EXIT_SUCCESS: i32 = 0; // IP/CIDR found in rules
const EXIT_NOT_FOUND: i32 = 1; // IP/CIDR not found
const EXIT_ERROR: i32 = 2; // Error during processing

// IPv6 constants
const IPV6_BITS: u8 = 128;

// Comment character for rule files
const COMMENT_CHAR: char = '#';

/// Custom error type for check-cidr application.
#[derive(Error, Debug)]
pub enum AppError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Invalid IP or CIDR notation '{input}': {reason}")]
    InvalidInput { input: String, reason: String },

    #[error("Invalid rule at line {line_number}: '{line}' - {reason}")]
    InvalidRuleLine {
        line_number: usize,
        line: String,
        reason: String,
    },

    #[error("File too large: {size} bytes (max: {max} bytes)")]
    FileTooLarge { size: u64, max: u64 },

    #[error("Too many lines: {count} (max: {max})")]
    TooManyLines { count: usize, max: usize },

    #[error("Line too long at line {line_number}: {length} bytes (max: {max} bytes)")]
    LineTooLong {
        line_number: usize,
        length: usize,
        max: usize,
    },
}

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

/// Represents a line from the rules file with its parsed network.
///
/// Contains both the original line text and the parsed network.
struct NetworkLine {
    line: String,
    network: IpNetwork,
}

impl NetworkLine {
    /// Creates a new NetworkLine from a string.
    ///
    /// Extracts the first whitespace-delimited token and attempts to parse it
    /// as an IP network. If parsing fails, returns an error.
    ///
    /// # Arguments
    ///
    /// * `line` - The line to parse
    /// * `line_number` - The line number (for error reporting)
    ///
    /// # Examples
    ///
    /// ```
    /// let line = NetworkLine::new("192.168.1.0/24 comment", 1)?;
    /// ```
    fn new(line: &str, line_number: usize) -> Result<Self, AppError> {
        let network = line
            .split_whitespace()
            .next()
            .ok_or_else(|| AppError::InvalidRuleLine {
                line_number,
                line: line.to_string(),
                reason: "Empty line after trimming".to_string(),
            })?
            .parse::<IpNetwork>()
            .map_err(|e| AppError::InvalidRuleLine {
                line_number,
                line: line.to_string(),
                reason: format!("Invalid CIDR notation: {}", e),
            })?;

        Ok(NetworkLine {
            line: line.to_string(),
            network,
        })
    }
}

/// Calculates the IPv6 network mask from prefix length.
///
/// # Arguments
///
/// * `prefix` - The prefix length (0-128)
///
/// # Examples
///
/// ```
/// let mask = ipv6_mask(64);
/// assert_eq!(mask, (!0u128) << 64);
/// ```
fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        (!0u128) << (IPV6_BITS - prefix)
    }
}

/// Calculates the last address in an IPv6 network.
///
/// # Arguments
///
/// * `network` - The network address as u128
/// * `prefix` - The prefix length
fn ipv6_broadcast(network: u128, prefix: u8) -> u128 {
    let mask = ipv6_mask(prefix);
    network | (!mask)
}

/// Loads and parses network rules from a file.
///
/// # Arguments
///
/// * `file_path` - Path to the file containing network rules
///
/// # Returns
///
/// * `Ok(Vec<NetworkLine>)` - Successfully parsed networks
/// * `Err(AppError)` - File I/O error or parsing error
///
/// # Format
///
/// Lines starting with '#' are treated as comments and ignored.
/// Empty lines are skipped.
/// Invalid lines will cause an error to be returned.
///
/// # Security
///
/// This function enforces limits on:
/// - File size (MAX_FILE_SIZE)
/// - Number of lines (MAX_LINES)
/// - Line length (MAX_LINE_LENGTH)
fn load_networks(file_path: impl AsRef<Path>) -> Result<Vec<NetworkLine>, AppError> {
    let file = File::open(file_path.as_ref())?;

    // Check file size
    let metadata = file.metadata()?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(AppError::FileTooLarge {
            size: metadata.len(),
            max: MAX_FILE_SIZE,
        });
    }

    let mut reader = BufReader::new(file);
    let mut networks = Vec::with_capacity(1024);
    let mut line_buffer = String::new();
    let mut line_number = 0;

    loop {
        line_buffer.clear();
        let bytes_read = reader.read_line(&mut line_buffer)?;
        if bytes_read == 0 {
            break; // EOF
        }

        line_number += 1;

        // Check line length
        if line_buffer.len() > MAX_LINE_LENGTH {
            return Err(AppError::LineTooLong {
                line_number,
                length: line_buffer.len(),
                max: MAX_LINE_LENGTH,
            });
        }

        // Check max lines
        if line_number > MAX_LINES {
            return Err(AppError::TooManyLines {
                count: line_number,
                max: MAX_LINES,
            });
        }

        let trimmed = line_buffer.trim();
        if trimmed.is_empty() || trimmed.starts_with(COMMENT_CHAR) {
            continue;
        }

        networks.push(NetworkLine::new(trimmed, line_number)?);
    }

    Ok(networks)
}

/// Checks if `input` (as a network) is fully contained in `container`.
///
/// Returns true if the input network is a subnet of (or equal to) the container network.
///
/// # Examples
///
/// ```
/// use ipnetwork::IpNetwork;
///
/// let input: IpNetwork = "192.168.1.0/24".parse().unwrap();
/// let container: IpNetwork = "192.168.0.0/16".parse().unwrap();
/// assert!(subnet_of(&input, &container));
/// ```
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
            let in_broadcast = ipv6_broadcast(in_network, in_net.prefix());

            let cont_network = u128::from(cont_net.network());
            let cont_broadcast = ipv6_broadcast(cont_network, cont_net.prefix());

            (cont_network <= in_network) && (in_broadcast <= cont_broadcast)
        }
        _ => false,
    }
}

/// Result of checking if an input is contained in networks.
struct MatchResult<'a> {
    is_contained: bool,
    matching_lines: Vec<&'a NetworkLine>,
}

/// Checks if a given IP/CIDR is contained in any of the networks.
///
/// Returns a MatchResult containing whether the input was found and all matching lines.
///
/// # Arguments
///
/// * `input_str` - The IP or CIDR to check
/// * `networks` - Slice of NetworkLine to check against
///
/// # Returns
///
/// * `Ok(MatchResult)` - Successfully checked containment
/// * `Err(AppError)` - Invalid input format
fn is_contained<'a>(
    input_str: &str,
    networks: &'a [NetworkLine],
) -> Result<MatchResult<'a>, AppError> {
    let input_net = input_str.parse::<IpNetwork>().map_err(|e| {
        AppError::InvalidInput {
            input: input_str.to_string(),
            reason: e.to_string(),
        }
    })?;

    let matching_lines: Vec<_> = networks
        .iter()
        .filter(|net_line| subnet_of(&input_net, &net_line.network))
        .collect();

    Ok(MatchResult {
        is_contained: !matching_lines.is_empty(),
        matching_lines,
    })
}

/// Main application logic.
///
/// Separated from main() to allow better error handling and testing.
fn run(args: Args) -> Result<i32, AppError> {
    let networks = load_networks(&args.file_path)?;
    let match_result = is_contained(&args.input_str, &networks)?;

    if args.print {
        for net_line in &match_result.matching_lines {
            println!("{}", net_line.line);
        }
    } else if !args.quiet {
        let status = if match_result.is_contained {
            "is contained in a rule"
        } else {
            "is not contained in any rule"
        };
        println!("IP or CIDR '{}' {}.", args.input_str, status);
    }

    Ok(if match_result.is_contained {
        EXIT_SUCCESS
    } else {
        EXIT_NOT_FOUND
    })
}

fn main() {
    let args = Args::parse();

    match run(args) {
        Ok(exit_code) => process::exit(exit_code),
        Err(err) => {
            eprintln!("ERROR: {err}");
            process::exit(EXIT_ERROR);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_subnet_containment() {
        let input: IpNetwork = "192.168.1.0/24".parse().unwrap();
        let container: IpNetwork = "192.168.0.0/16".parse().unwrap();
        assert!(subnet_of(&input, &container));
    }

    #[test]
    fn test_ipv4_not_contained() {
        let input: IpNetwork = "10.0.0.0/8".parse().unwrap();
        let container: IpNetwork = "192.168.0.0/16".parse().unwrap();
        assert!(!subnet_of(&input, &container));
    }

    #[test]
    fn test_ipv6_subnet_containment() {
        let input: IpNetwork = "2001:db8:1::/64".parse().unwrap();
        let container: IpNetwork = "2001:db8::/32".parse().unwrap();
        assert!(subnet_of(&input, &container));
    }

    #[test]
    fn test_ipv6_not_contained() {
        let input: IpNetwork = "2001:db8:1::/64".parse().unwrap();
        let container: IpNetwork = "2001:db9::/32".parse().unwrap();
        assert!(!subnet_of(&input, &container));
    }

    #[test]
    fn test_mixed_ip_versions() {
        let input: IpNetwork = "192.168.1.0/24".parse().unwrap();
        let container: IpNetwork = "2001:db8::/32".parse().unwrap();
        assert!(!subnet_of(&input, &container));
    }

    #[test]
    fn test_ipv6_mask_calculation() {
        assert_eq!(ipv6_mask(0), 0);
        assert_eq!(ipv6_mask(128), !0u128);
        assert_eq!(ipv6_mask(64), (!0u128) << 64);
    }

    #[test]
    fn test_same_network() {
        let network: IpNetwork = "192.168.1.0/24".parse().unwrap();
        assert!(subnet_of(&network, &network));
    }

    #[test]
    fn test_network_line_parsing() {
        let line = NetworkLine::new("192.168.1.0/24 some comment", 1).unwrap();
        assert_eq!(line.network.to_string(), "192.168.1.0/24");
        assert!(line.line.contains("comment"));
    }

    #[test]
    fn test_network_line_invalid() {
        let result = NetworkLine::new("invalid", 1);
        assert!(result.is_err());
    }
}
