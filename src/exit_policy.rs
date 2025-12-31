//! Exit policy parsing and evaluation for Tor relays.
//!
//! This module provides types for parsing and evaluating Tor exit policies,
//! which determine what traffic a relay will allow to exit the Tor network.
//! Exit policies are a fundamental part of Tor's design, allowing relay
//! operators to control which destinations their relay will connect to.
//!
//! # Overview
//!
//! Exit policies consist of ordered rules that are evaluated in sequence.
//! Each rule either accepts or rejects traffic to specific addresses and ports.
//! The first matching rule determines whether traffic is allowed.
//!
//! # Policy Types
//!
//! This module provides three main types:
//!
//! - [`ExitPolicy`]: A complete exit policy consisting of multiple rules
//! - [`ExitPolicyRule`]: A single accept/reject rule with address and port specifications
//! - [`MicroExitPolicy`]: A compact policy format used in microdescriptors
//!
//! # Rule Format
//!
//! Exit policy rules follow the format defined in the Tor directory specification:
//!
//! ```text
//! accept|reject[6] addrspec:portspec
//! ```
//!
//! Where:
//! - `accept` or `reject` determines if matching traffic is allowed
//! - `accept6` or `reject6` are IPv6-specific variants
//! - `addrspec` is an address specification (wildcard, IPv4, or IPv6 with optional CIDR mask)
//! - `portspec` is a port specification (wildcard, single port, or port range)
//!
//! # Address Specifications
//!
//! Address specifications can be:
//! - `*` - matches any address (IPv4 or IPv6)
//! - `*4` - matches any IPv4 address
//! - `*6` - matches any IPv6 address
//! - IPv4 address: `192.168.1.1`
//! - IPv4 with CIDR: `10.0.0.0/8`
//! - IPv4 with mask: `192.168.0.0/255.255.0.0`
//! - IPv6 address: `[::1]`
//! - IPv6 with CIDR: `[2001:db8::]/32`
//!
//! # Port Specifications
//!
//! Port specifications can be:
//! - `*` - matches any port (1-65535)
//! - Single port: `80`
//! - Port range: `80-443`
//!
//! # Example
//!
//! ```rust
//! use stem_rs::exit_policy::{ExitPolicy, MicroExitPolicy};
//! use std::net::IpAddr;
//!
//! // Parse a full exit policy
//! let policy = ExitPolicy::parse("accept *:80, accept *:443, reject *:*").unwrap();
//!
//! // Check if traffic can exit to a destination
//! let addr: IpAddr = "192.168.1.1".parse().unwrap();
//! assert!(policy.can_exit_to(addr, 80));   // HTTP allowed
//! assert!(policy.can_exit_to(addr, 443));  // HTTPS allowed
//! assert!(!policy.can_exit_to(addr, 22));  // SSH blocked
//!
//! // Get a summary of the policy
//! assert_eq!(policy.summary(), "accept 80, 443");
//!
//! // Parse a microdescriptor policy (port-only)
//! let micro = MicroExitPolicy::parse("accept 80,443").unwrap();
//! assert!(micro.can_exit_to(80));
//! assert!(!micro.can_exit_to(22));
//! ```
//!
//! # Private and Default Rules
//!
//! Exit policies may contain special rule sequences:
//!
//! - **Private rules**: Rules expanded from the `private` keyword that block
//!   traffic to private/internal IP ranges (10.0.0.0/8, 192.168.0.0/16, etc.)
//! - **Default rules**: The standard suffix appended by Tor that blocks
//!   commonly abused ports (SMTP, NetBIOS, etc.)
//!
//! Use [`ExitPolicy::has_private`] and [`ExitPolicy::has_default`] to check
//! for these, and [`ExitPolicy::strip_private`] and [`ExitPolicy::strip_default`]
//! to remove them.
//!
//! # See Also
//!
//! - [`crate::descriptor::ServerDescriptor`] - Contains relay exit policies
//! - [`crate::descriptor::Microdescriptor`] - Contains micro exit policies
//! - [Tor Directory Specification](https://spec.torproject.org/dir-spec) - Formal policy format

use crate::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// The type of address in an exit policy rule.
///
/// This enum categorizes the address specification in an exit policy rule,
/// determining how address matching is performed.
///
/// # Variants
///
/// - [`Wildcard`](AddressType::Wildcard): Matches any address (IPv4 or IPv6)
/// - [`IPv4`](AddressType::IPv4): Matches only IPv4 addresses
/// - [`IPv6`](AddressType::IPv6): Matches only IPv6 addresses
///
/// # Example
///
/// ```rust
/// use stem_rs::exit_policy::{ExitPolicyRule, AddressType};
///
/// let rule = ExitPolicyRule::parse("accept *:80").unwrap();
/// assert_eq!(rule.get_address_type(), AddressType::Wildcard);
///
/// let rule = ExitPolicyRule::parse("accept 192.168.1.1:80").unwrap();
/// assert_eq!(rule.get_address_type(), AddressType::IPv4);
///
/// let rule = ExitPolicyRule::parse("accept [::1]:80").unwrap();
/// assert_eq!(rule.get_address_type(), AddressType::IPv6);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// Matches any address, both IPv4 and IPv6.
    ///
    /// This is used when the address specification is `*` without
    /// a version suffix.
    Wildcard,
    /// Matches only IPv4 addresses.
    ///
    /// This includes explicit IPv4 addresses, CIDR ranges, and the `*4` wildcard.
    IPv4,
    /// Matches only IPv6 addresses.
    ///
    /// This includes explicit IPv6 addresses (in brackets), CIDR ranges,
    /// the `*6` wildcard, and rules using `accept6`/`reject6`.
    IPv6,
}

/// A range of TCP/UDP ports.
///
/// Represents a contiguous range of ports from `min` to `max` (inclusive).
/// Used in exit policies to specify which ports a rule applies to.
///
/// # Invariants
///
/// - `min` must be less than or equal to `max`
/// - Valid port values are 0-65535, though port 0 is typically not used
///
/// # Example
///
/// ```rust
/// use stem_rs::exit_policy::PortRange;
///
/// // Create a range for common web ports
/// let web_ports = PortRange::new(80, 443).unwrap();
/// assert!(web_ports.contains(80));
/// assert!(web_ports.contains(443));
/// assert!(web_ports.contains(200));
/// assert!(!web_ports.contains(22));
///
/// // Create a single port
/// let ssh = PortRange::single(22);
/// assert!(ssh.contains(22));
/// assert!(!ssh.contains(23));
///
/// // Create a wildcard range (all ports)
/// let all = PortRange::all();
/// assert!(all.is_wildcard());
/// assert!(all.contains(1));
/// assert!(all.contains(65535));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    /// The minimum port number (inclusive).
    pub min: u16,
    /// The maximum port number (inclusive).
    pub max: u16,
}

impl PortRange {
    /// Creates a new port range from minimum to maximum port.
    ///
    /// # Arguments
    ///
    /// * `min` - The minimum port number (inclusive)
    /// * `max` - The maximum port number (inclusive)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if `min` is greater than `max`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::PortRange;
    ///
    /// let range = PortRange::new(80, 443).unwrap();
    /// assert!(range.contains(200));
    ///
    /// // Invalid range (min > max)
    /// assert!(PortRange::new(443, 80).is_err());
    /// ```
    pub fn new(min: u16, max: u16) -> Result<Self, Error> {
        if min > max {
            return Err(Error::Parse {
                location: "port range".to_string(),
                reason: format!("min port {} greater than max port {}", min, max),
            });
        }
        Ok(Self { min, max })
    }

    /// Creates a port range containing only a single port.
    ///
    /// # Arguments
    ///
    /// * `port` - The single port number
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::PortRange;
    ///
    /// let ssh = PortRange::single(22);
    /// assert!(ssh.contains(22));
    /// assert!(!ssh.contains(23));
    /// assert_eq!(ssh.to_string(), "22");
    /// ```
    pub fn single(port: u16) -> Self {
        Self {
            min: port,
            max: port,
        }
    }

    /// Creates a port range covering all valid ports (1-65535).
    ///
    /// This is equivalent to the `*` wildcard in exit policy rules.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::PortRange;
    ///
    /// let all = PortRange::all();
    /// assert!(all.is_wildcard());
    /// assert!(all.contains(1));
    /// assert!(all.contains(65535));
    /// assert_eq!(all.to_string(), "*");
    /// ```
    pub fn all() -> Self {
        Self { min: 1, max: 65535 }
    }

    /// Checks if a port is within this range.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to check
    ///
    /// # Returns
    ///
    /// `true` if `port` is between `min` and `max` (inclusive), `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::PortRange;
    ///
    /// let range = PortRange::new(80, 443).unwrap();
    /// assert!(range.contains(80));   // min boundary
    /// assert!(range.contains(443));  // max boundary
    /// assert!(range.contains(200));  // middle
    /// assert!(!range.contains(79));  // below min
    /// assert!(!range.contains(444)); // above max
    /// ```
    pub fn contains(&self, port: u16) -> bool {
        port >= self.min && port <= self.max
    }

    /// Checks if this range covers all ports (is a wildcard).
    ///
    /// A range is considered a wildcard if it covers ports 1-65535.
    /// Port 0 is excluded as it's not a valid destination port.
    ///
    /// # Returns
    ///
    /// `true` if this range matches any port, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::PortRange;
    ///
    /// assert!(PortRange::all().is_wildcard());
    /// assert!(PortRange::new(1, 65535).unwrap().is_wildcard());
    /// assert!(!PortRange::new(80, 443).unwrap().is_wildcard());
    /// ```
    pub fn is_wildcard(&self) -> bool {
        self.min <= 1 && self.max == 65535
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_wildcard() {
            write!(f, "*")
        } else if self.min == self.max {
            write!(f, "{}", self.min)
        } else {
            write!(f, "{}-{}", self.min, self.max)
        }
    }
}

/// A single rule in an exit policy.
///
/// Each rule specifies whether to accept or reject traffic to a particular
/// address and port combination. Rules are evaluated in order, and the first
/// matching rule determines whether traffic is allowed.
///
/// # Rule Format
///
/// Rules follow the Tor exit policy format:
///
/// ```text
/// accept|reject[6] addrspec:portspec
/// ```
///
/// # Matching Semantics
///
/// A rule matches a destination if:
/// 1. The destination address matches the rule's address specification
///    (considering CIDR masks and address family)
/// 2. The destination port is within the rule's port range
///
/// # Address Family Matching
///
/// - Wildcard (`*`) rules match both IPv4 and IPv6 addresses
/// - IPv4-specific rules (`*4`, explicit IPv4) only match IPv4 addresses
/// - IPv6-specific rules (`*6`, explicit IPv6, `accept6`/`reject6`) only match IPv6
///
/// # Example
///
/// ```rust
/// use stem_rs::exit_policy::ExitPolicyRule;
/// use std::net::IpAddr;
///
/// // Parse a rule that accepts HTTP traffic
/// let rule = ExitPolicyRule::parse("accept *:80").unwrap();
/// assert!(rule.is_accept);
/// assert!(rule.is_address_wildcard());
/// assert!(!rule.is_port_wildcard());
///
/// // Check if the rule matches a destination
/// let addr: IpAddr = "192.168.1.1".parse().unwrap();
/// assert!(rule.is_match(Some(addr), Some(80)));
/// assert!(!rule.is_match(Some(addr), Some(443)));
///
/// // Parse a CIDR rule
/// let rule = ExitPolicyRule::parse("reject 10.0.0.0/8:*").unwrap();
/// assert!(!rule.is_accept);
/// assert_eq!(rule.get_masked_bits(), Some(8));
/// ```
///
/// # See Also
///
/// - [`ExitPolicy`]: A collection of rules forming a complete policy
/// - [`MicroExitPolicy`]: A compact port-only policy format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitPolicyRule {
    /// Whether this rule accepts (`true`) or rejects (`false`) matching traffic.
    pub is_accept: bool,
    address: Option<IpAddr>,
    mask_bits: Option<u8>,
    address_type: AddressType,
    /// The minimum port number this rule applies to (inclusive).
    pub min_port: u16,
    /// The maximum port number this rule applies to (inclusive).
    pub max_port: u16,
    is_default: bool,
    is_private: bool,
}

impl ExitPolicyRule {
    /// Parses an exit policy rule from a string.
    ///
    /// The rule must follow the Tor exit policy format:
    ///
    /// ```text
    /// accept|reject[6] addrspec:portspec
    /// ```
    ///
    /// # Arguments
    ///
    /// * `rule` - The rule string to parse
    ///
    /// # Supported Formats
    ///
    /// ## Actions
    /// - `accept` - Allow matching traffic
    /// - `reject` - Block matching traffic
    /// - `accept6` - Allow matching IPv6 traffic only
    /// - `reject6` - Block matching IPv6 traffic only
    ///
    /// ## Address Specifications
    /// - `*` - Any address (IPv4 or IPv6)
    /// - `*4` - Any IPv4 address
    /// - `*6` - Any IPv6 address
    /// - `A.B.C.D` - Specific IPv4 address
    /// - `A.B.C.D/N` - IPv4 CIDR notation (N = 0-32)
    /// - `A.B.C.D/M.M.M.M` - IPv4 with subnet mask
    /// - `[IPv6]` - Specific IPv6 address
    /// - `[IPv6]/N` - IPv6 CIDR notation (N = 0-128)
    ///
    /// ## Port Specifications
    /// - `*` - Any port (1-65535)
    /// - `N` - Single port
    /// - `N-M` - Port range (inclusive)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The rule doesn't start with `accept` or `reject`
    /// - The address specification is invalid
    /// - The port specification is invalid
    /// - The CIDR mask is out of range
    /// - The port range is invalid (min > max)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicyRule;
    ///
    /// // Various valid rule formats
    /// let rule = ExitPolicyRule::parse("accept *:80").unwrap();
    /// let rule = ExitPolicyRule::parse("reject 10.0.0.0/8:*").unwrap();
    /// let rule = ExitPolicyRule::parse("accept 192.168.0.0/255.255.0.0:80-443").unwrap();
    /// let rule = ExitPolicyRule::parse("accept6 [::1]:22").unwrap();
    /// let rule = ExitPolicyRule::parse("reject [2001:db8::]/32:*").unwrap();
    ///
    /// // Invalid rules
    /// assert!(ExitPolicyRule::parse("allow *:80").is_err());  // Invalid action
    /// assert!(ExitPolicyRule::parse("accept *").is_err());    // Missing port
    /// assert!(ExitPolicyRule::parse("accept *:443-80").is_err()); // Invalid range
    /// ```
    pub fn parse(rule: &str) -> Result<Self, Error> {
        let rule = rule.trim();
        let (is_accept, exitpattern) = if let Some(rest) = rule.strip_prefix("accept6 ") {
            (true, rest.trim())
        } else if let Some(rest) = rule.strip_prefix("reject6 ") {
            (false, rest.trim())
        } else if let Some(rest) = rule.strip_prefix("accept ") {
            (true, rest.trim())
        } else if let Some(rest) = rule.strip_prefix("reject ") {
            (false, rest.trim())
        } else {
            return Err(Error::Parse {
                location: rule.to_string(),
                reason: "rule must start with accept/reject".to_string(),
            });
        };

        let is_ipv6_only = rule.starts_with("accept6") || rule.starts_with("reject6");
        let (addrspec, portspec) = Self::split_addr_port(exitpattern)?;
        let (address, mask_bits, address_type) = Self::parse_addrspec(addrspec, is_ipv6_only)?;
        let (min_port, max_port) = Self::parse_portspec(portspec)?;

        Ok(Self {
            is_accept,
            address,
            mask_bits,
            address_type,
            min_port,
            max_port,
            is_default: false,
            is_private: false,
        })
    }

    /// Splits an exit pattern into address and port specifications.
    ///
    /// Handles both IPv4 and IPv6 address formats. IPv6 addresses are enclosed
    /// in brackets, so the colon separator must be found after the closing bracket.
    ///
    /// # Arguments
    ///
    /// * `exitpattern` - The exit pattern string (e.g., "192.168.1.1:80" or "[::1]:80")
    ///
    /// # Returns
    ///
    /// A tuple of (addrspec, portspec) on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the pattern is malformed.
    fn split_addr_port(exitpattern: &str) -> Result<(&str, &str), Error> {
        if exitpattern.contains('[') {
            if let Some(bracket_end) = exitpattern.find(']') {
                let after_bracket = &exitpattern[bracket_end + 1..];
                if let Some(colon_pos) = after_bracket.find(':') {
                    let addrspec = &exitpattern[..bracket_end + 1 + colon_pos];
                    let portspec = &after_bracket[colon_pos + 1..];
                    return Ok((addrspec, portspec));
                }
            }
            return Err(Error::Parse {
                location: exitpattern.to_string(),
                reason: "malformed IPv6 address".to_string(),
            });
        }

        if let Some(colon_pos) = exitpattern.rfind(':') {
            let addrspec = &exitpattern[..colon_pos];
            let portspec = &exitpattern[colon_pos + 1..];
            Ok((addrspec, portspec))
        } else {
            Err(Error::Parse {
                location: exitpattern.to_string(),
                reason: "exitpattern must be addrspec:portspec".to_string(),
            })
        }
    }

    /// Parses an address specification into its components.
    ///
    /// Handles wildcards (`*`, `*4`, `*6`), IPv4 addresses with optional CIDR
    /// or subnet mask notation, and IPv6 addresses with optional CIDR notation.
    ///
    /// # Arguments
    ///
    /// * `addrspec` - The address specification string
    /// * `is_ipv6_only` - Whether this is from an `accept6`/`reject6` rule
    ///
    /// # Returns
    ///
    /// A tuple of (address, mask_bits, address_type) on success.
    /// - `address` is `None` for wildcards
    /// - `mask_bits` is `None` for wildcards, otherwise the CIDR prefix length
    /// - `address_type` indicates the type of address
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the address specification is invalid.
    fn parse_addrspec(
        addrspec: &str,
        is_ipv6_only: bool,
    ) -> Result<(Option<IpAddr>, Option<u8>, AddressType), Error> {
        let addrspec = if addrspec == "*4" {
            "0.0.0.0/0"
        } else if addrspec == "*6" || (addrspec == "*" && is_ipv6_only) {
            "[::]/0"
        } else {
            addrspec
        };

        if addrspec == "*" {
            return Ok((None, None, AddressType::Wildcard));
        }

        let (addr_part, mask_part) = if let Some(slash_pos) = addrspec.rfind('/') {
            (&addrspec[..slash_pos], Some(&addrspec[slash_pos + 1..]))
        } else {
            (addrspec, None)
        };

        if addr_part.starts_with('[') && addr_part.ends_with(']') {
            let ipv6_str = &addr_part[1..addr_part.len() - 1];
            let ipv6: Ipv6Addr = ipv6_str.parse().map_err(|_| Error::Parse {
                location: addr_part.to_string(),
                reason: "invalid IPv6 address".to_string(),
            })?;

            let mask_bits = match mask_part {
                Some(m) => {
                    let bits: u8 = m.parse().map_err(|_| Error::Parse {
                        location: m.to_string(),
                        reason: "invalid mask bits".to_string(),
                    })?;
                    if bits > 128 {
                        return Err(Error::Parse {
                            location: m.to_string(),
                            reason: "IPv6 mask must be 0-128".to_string(),
                        });
                    }
                    bits
                }
                None => 128,
            };

            return Ok((Some(IpAddr::V6(ipv6)), Some(mask_bits), AddressType::IPv6));
        }

        if let Ok(ipv4) = addr_part.parse::<Ipv4Addr>() {
            let mask_bits = match mask_part {
                Some(m) => {
                    if let Ok(bits) = m.parse::<u8>() {
                        if bits > 32 {
                            return Err(Error::Parse {
                                location: m.to_string(),
                                reason: "IPv4 mask must be 0-32".to_string(),
                            });
                        }
                        bits
                    } else if let Ok(mask_addr) = m.parse::<Ipv4Addr>() {
                        Self::ipv4_mask_to_bits(mask_addr)?
                    } else {
                        return Err(Error::Parse {
                            location: m.to_string(),
                            reason: "invalid mask".to_string(),
                        });
                    }
                }
                None => 32,
            };

            return Ok((Some(IpAddr::V4(ipv4)), Some(mask_bits), AddressType::IPv4));
        }

        Err(Error::Parse {
            location: addrspec.to_string(),
            reason: "not a valid address".to_string(),
        })
    }

    /// Converts an IPv4 subnet mask to CIDR bit count.
    ///
    /// Takes a subnet mask in dotted-quad notation (e.g., `255.255.0.0`) and
    /// converts it to the equivalent CIDR prefix length (e.g., `16`).
    ///
    /// # Arguments
    ///
    /// * `mask` - The subnet mask as an IPv4 address
    ///
    /// # Returns
    ///
    /// The number of leading 1-bits in the mask (0-32).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the mask is not a valid subnet mask
    /// (i.e., not a contiguous sequence of 1-bits followed by 0-bits).
    /// For example, `255.255.0.255` is invalid.
    fn ipv4_mask_to_bits(mask: Ipv4Addr) -> Result<u8, Error> {
        let mask_u32 = u32::from_be_bytes(mask.octets());
        if mask_u32 == 0 {
            return Ok(0);
        }
        let leading_ones = mask_u32.leading_ones();
        let expected = if leading_ones == 32 {
            u32::MAX
        } else {
            !((1u32 << (32 - leading_ones)) - 1)
        };
        if mask_u32 != expected {
            return Err(Error::Parse {
                location: mask.to_string(),
                reason: "mask cannot be represented as bit count".to_string(),
            });
        }
        Ok(leading_ones as u8)
    }

    /// Parses a port specification into min and max port values.
    ///
    /// Handles wildcards (`*`), single ports, and port ranges.
    ///
    /// # Arguments
    ///
    /// * `portspec` - The port specification string (e.g., "*", "80", "80-443")
    ///
    /// # Returns
    ///
    /// A tuple of (min_port, max_port) on success.
    /// For single ports, min and max are the same.
    /// For wildcards, returns (1, 65535).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The port number is not a valid u16
    /// - The port range has min > max
    fn parse_portspec(portspec: &str) -> Result<(u16, u16), Error> {
        if portspec == "*" {
            return Ok((1, 65535));
        }

        if let Some(dash_pos) = portspec.find('-') {
            let min_str = &portspec[..dash_pos];
            let max_str = &portspec[dash_pos + 1..];
            let min: u16 = min_str.parse().map_err(|_| Error::Parse {
                location: portspec.to_string(),
                reason: "invalid min port".to_string(),
            })?;
            let max: u16 = max_str.parse().map_err(|_| Error::Parse {
                location: portspec.to_string(),
                reason: "invalid max port".to_string(),
            })?;
            if min > max {
                return Err(Error::Parse {
                    location: portspec.to_string(),
                    reason: "min port greater than max port".to_string(),
                });
            }
            return Ok((min, max));
        }

        let port: u16 = portspec.parse().map_err(|_| Error::Parse {
            location: portspec.to_string(),
            reason: "invalid port".to_string(),
        })?;
        Ok((port, port))
    }

    /// Checks if this rule matches a given destination.
    ///
    /// A rule matches if both the address and port match the rule's specifications.
    /// If either the address or port is `None`, the rule performs a "fuzzy" match
    /// where the missing component is considered to potentially match.
    ///
    /// This is equivalent to calling [`is_match_strict`](Self::is_match_strict)
    /// with `strict = false`.
    ///
    /// # Arguments
    ///
    /// * `address` - The destination IP address, or `None` to match any address
    /// * `port` - The destination port, or `None` to match any port
    ///
    /// # Returns
    ///
    /// `true` if the rule matches the destination, `false` otherwise.
    ///
    /// # Matching Rules
    ///
    /// - If the rule has a wildcard address, any address matches
    /// - If the rule has a specific address/CIDR, only addresses in that range match
    /// - IPv4 rules don't match IPv6 addresses and vice versa
    /// - If the rule has a wildcard port, any port matches
    /// - If the rule has a specific port range, only ports in that range match
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicyRule;
    /// use std::net::IpAddr;
    ///
    /// let rule = ExitPolicyRule::parse("accept 10.0.0.0/8:80-443").unwrap();
    ///
    /// // Exact match
    /// let addr: IpAddr = "10.1.2.3".parse().unwrap();
    /// assert!(rule.is_match(Some(addr), Some(80)));
    /// assert!(rule.is_match(Some(addr), Some(443)));
    /// assert!(!rule.is_match(Some(addr), Some(22)));
    ///
    /// // Address outside CIDR range
    /// let addr: IpAddr = "192.168.1.1".parse().unwrap();
    /// assert!(!rule.is_match(Some(addr), Some(80)));
    ///
    /// // Fuzzy match (None means "any")
    /// assert!(rule.is_match(None, Some(80)));  // Any address, port 80
    /// ```
    pub fn is_match(&self, address: Option<IpAddr>, port: Option<u16>) -> bool {
        self.is_match_strict(address, port, false)
    }

    /// Checks if this rule matches a destination with strict mode option.
    ///
    /// Similar to [`is_match`](Self::is_match), but with control over how
    /// fuzzy matches (when address or port is `None`) are handled.
    ///
    /// # Arguments
    ///
    /// * `address` - The destination IP address, or `None` to match any address
    /// * `port` - The destination port, or `None` to match any port
    /// * `strict` - Controls fuzzy match behavior:
    ///   - `false`: Fuzzy matches return `true` for accept rules, `false` for reject
    ///   - `true`: Fuzzy matches return `false` for accept rules, `true` for reject
    ///
    /// # Strict Mode Semantics
    ///
    /// When `strict = true`, the question becomes "does this rule match ALL
    /// possible values for the missing component?" rather than "does this rule
    /// match ANY possible value?"
    ///
    /// This is useful for determining if traffic can definitely exit (strict=true)
    /// versus if traffic might be able to exit (strict=false).
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicyRule;
    ///
    /// let accept_rule = ExitPolicyRule::parse("accept 10.0.0.0/8:80").unwrap();
    ///
    /// // Non-strict: "can ANY address on port 80 match?"
    /// assert!(accept_rule.is_match_strict(None, Some(80), false));
    ///
    /// // Strict: "do ALL addresses on port 80 match?"
    /// assert!(!accept_rule.is_match_strict(None, Some(80), true));
    /// ```
    pub fn is_match_strict(
        &self,
        address: Option<IpAddr>,
        port: Option<u16>,
        strict: bool,
    ) -> bool {
        let mut fuzzy_match = false;

        if !self.is_address_wildcard() {
            match address {
                None => fuzzy_match = true,
                Some(addr) => {
                    if let Some(rule_addr) = &self.address {
                        if !Self::same_address_family(&addr, rule_addr) {
                            return false;
                        }
                    }
                    if !self.address_in_network(addr) {
                        return false;
                    }
                }
            }
        }

        if !self.is_port_wildcard() {
            match port {
                None => fuzzy_match = true,
                Some(p) => {
                    if p < self.min_port || p > self.max_port {
                        return false;
                    }
                }
            }
        }

        if fuzzy_match {
            strict != self.is_accept
        } else {
            true
        }
    }

    /// Checks if two IP addresses are in the same address family.
    ///
    /// Returns `true` if both addresses are IPv4 or both are IPv6.
    ///
    /// # Arguments
    ///
    /// * `a` - First IP address
    /// * `b` - Second IP address
    ///
    /// # Returns
    ///
    /// `true` if both addresses are the same family, `false` otherwise.
    fn same_address_family(a: &IpAddr, b: &IpAddr) -> bool {
        matches!(
            (a, b),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        )
    }

    /// Checks if an address falls within this rule's network range.
    ///
    /// Applies the rule's subnet mask to both the rule's address and the
    /// test address, then compares the masked values.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IP address to check
    ///
    /// # Returns
    ///
    /// `true` if the address is within the rule's network, `false` otherwise.
    /// Returns `true` if the rule has no address (wildcard) or no mask.
    fn address_in_network(&self, addr: IpAddr) -> bool {
        let Some(rule_addr) = &self.address else {
            return true;
        };
        let Some(mask_bits) = self.mask_bits else {
            return true;
        };

        match (addr, rule_addr) {
            (IpAddr::V4(a), IpAddr::V4(r)) => {
                let a_u32 = u32::from_be_bytes(a.octets());
                let r_u32 = u32::from_be_bytes(r.octets());
                let mask = if mask_bits == 0 {
                    0
                } else {
                    !((1u32 << (32 - mask_bits)) - 1)
                };
                (a_u32 & mask) == (r_u32 & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(r)) => {
                let a_u128 = u128::from_be_bytes(a.octets());
                let r_u128 = u128::from_be_bytes(r.octets());
                let mask = if mask_bits == 0 {
                    0
                } else {
                    !((1u128 << (128 - mask_bits)) - 1)
                };
                (a_u128 & mask) == (r_u128 & mask)
            }
            _ => false,
        }
    }

    /// Checks if this rule matches any address (is an address wildcard).
    ///
    /// A rule is an address wildcard if its address specification is `*`,
    /// which matches both IPv4 and IPv6 addresses.
    ///
    /// Note that `*4` and `*6` are NOT considered wildcards by this method,
    /// as they only match one address family.
    ///
    /// # Returns
    ///
    /// `true` if the rule matches any address, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicyRule;
    ///
    /// assert!(ExitPolicyRule::parse("accept *:80").unwrap().is_address_wildcard());
    /// assert!(!ExitPolicyRule::parse("accept *4:80").unwrap().is_address_wildcard());
    /// assert!(!ExitPolicyRule::parse("accept *6:80").unwrap().is_address_wildcard());
    /// assert!(!ExitPolicyRule::parse("accept 10.0.0.0/8:80").unwrap().is_address_wildcard());
    /// ```
    pub fn is_address_wildcard(&self) -> bool {
        self.address_type == AddressType::Wildcard
    }

    /// Checks if this rule matches any port (is a port wildcard).
    ///
    /// A rule is a port wildcard if its port specification covers all valid
    /// ports (1-65535), typically written as `*` in the rule string.
    ///
    /// # Returns
    ///
    /// `true` if the rule matches any port, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicyRule;
    ///
    /// assert!(ExitPolicyRule::parse("accept *:*").unwrap().is_port_wildcard());
    /// assert!(ExitPolicyRule::parse("accept *:1-65535").unwrap().is_port_wildcard());
    /// assert!(!ExitPolicyRule::parse("accept *:80").unwrap().is_port_wildcard());
    /// assert!(!ExitPolicyRule::parse("accept *:80-443").unwrap().is_port_wildcard());
    /// ```
    pub fn is_port_wildcard(&self) -> bool {
        self.min_port <= 1 && self.max_port == 65535
    }

    /// Returns the address type of this rule.
    ///
    /// # Returns
    ///
    /// The [`AddressType`] indicating whether this rule matches:
    /// - [`AddressType::Wildcard`]: Any address (IPv4 or IPv6)
    /// - [`AddressType::IPv4`]: Only IPv4 addresses
    /// - [`AddressType::IPv6`]: Only IPv6 addresses
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::{ExitPolicyRule, AddressType};
    ///
    /// let rule = ExitPolicyRule::parse("accept *:80").unwrap();
    /// assert_eq!(rule.get_address_type(), AddressType::Wildcard);
    ///
    /// let rule = ExitPolicyRule::parse("accept 192.168.1.1:80").unwrap();
    /// assert_eq!(rule.get_address_type(), AddressType::IPv4);
    ///
    /// let rule = ExitPolicyRule::parse("accept [::1]:80").unwrap();
    /// assert_eq!(rule.get_address_type(), AddressType::IPv6);
    /// ```
    pub fn get_address_type(&self) -> AddressType {
        self.address_type
    }

    /// Returns the subnet mask as an IP address.
    ///
    /// For IPv4 rules, returns the mask in dotted-quad notation (e.g., `255.255.0.0`).
    /// For IPv6 rules, returns the mask as an IPv6 address.
    /// For wildcard rules, returns `None`.
    ///
    /// # Returns
    ///
    /// The subnet mask as an [`IpAddr`], or `None` for wildcard rules.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicyRule;
    /// use std::net::IpAddr;
    ///
    /// let rule = ExitPolicyRule::parse("accept 192.168.0.0/16:*").unwrap();
    /// assert_eq!(rule.get_mask(), Some("255.255.0.0".parse::<IpAddr>().unwrap()));
    ///
    /// let rule = ExitPolicyRule::parse("accept 10.0.0.0/8:*").unwrap();
    /// assert_eq!(rule.get_mask(), Some("255.0.0.0".parse::<IpAddr>().unwrap()));
    ///
    /// let rule = ExitPolicyRule::parse("accept *:80").unwrap();
    /// assert_eq!(rule.get_mask(), None);
    /// ```
    pub fn get_mask(&self) -> Option<IpAddr> {
        let bits = self.mask_bits?;
        match self.address_type {
            AddressType::Wildcard => None,
            AddressType::IPv4 => {
                let mask = if bits == 0 {
                    0u32
                } else {
                    !((1u32 << (32 - bits)) - 1)
                };
                Some(IpAddr::V4(Ipv4Addr::from(mask)))
            }
            AddressType::IPv6 => {
                let mask = if bits == 0 {
                    0u128
                } else {
                    !((1u128 << (128 - bits)) - 1)
                };
                Some(IpAddr::V6(Ipv6Addr::from(mask)))
            }
        }
    }

    /// Returns the number of bits in the subnet mask.
    ///
    /// For CIDR notation like `10.0.0.0/8`, this returns `8`.
    /// For specific addresses without a mask, returns the full mask (32 for IPv4, 128 for IPv6).
    /// For wildcard rules, returns `None`.
    ///
    /// # Returns
    ///
    /// The number of mask bits, or `None` for wildcard rules.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicyRule;
    ///
    /// let rule = ExitPolicyRule::parse("accept 10.0.0.0/8:*").unwrap();
    /// assert_eq!(rule.get_masked_bits(), Some(8));
    ///
    /// let rule = ExitPolicyRule::parse("accept 192.168.1.1:80").unwrap();
    /// assert_eq!(rule.get_masked_bits(), Some(32));  // Full mask for specific address
    ///
    /// let rule = ExitPolicyRule::parse("accept *:80").unwrap();
    /// assert_eq!(rule.get_masked_bits(), None);
    /// ```
    pub fn get_masked_bits(&self) -> Option<u8> {
        self.mask_bits
    }

    /// Checks if this rule is part of Tor's default exit policy suffix.
    ///
    /// Tor appends a default policy suffix that blocks commonly abused ports
    /// (SMTP, NetBIOS, etc.) and then accepts all other traffic. This method
    /// returns `true` if this rule was identified as part of that suffix.
    ///
    /// # Returns
    ///
    /// `true` if this rule is part of the default policy suffix, `false` otherwise.
    ///
    /// # See Also
    ///
    /// - [`ExitPolicy::has_default`]: Check if a policy contains default rules
    /// - [`ExitPolicy::strip_default`]: Remove default rules from a policy
    pub fn is_default(&self) -> bool {
        self.is_default
    }

    /// Checks if this rule was expanded from the `private` keyword.
    ///
    /// The `private` keyword in Tor exit policies expands to rules blocking
    /// traffic to private/internal IP ranges (10.0.0.0/8, 192.168.0.0/16,
    /// 127.0.0.0/8, etc.). This method returns `true` if this rule was
    /// identified as part of that expansion.
    ///
    /// # Returns
    ///
    /// `true` if this rule was expanded from `private`, `false` otherwise.
    ///
    /// # See Also
    ///
    /// - [`ExitPolicy::has_private`]: Check if a policy contains private rules
    /// - [`ExitPolicy::strip_private`]: Remove private rules from a policy
    pub fn is_private(&self) -> bool {
        self.is_private
    }

    /// Returns the IP address this rule applies to.
    ///
    /// For rules with a specific address or CIDR range, returns the base address.
    /// For wildcard rules, returns `None`.
    ///
    /// # Returns
    ///
    /// The IP address, or `None` for wildcard rules.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicyRule;
    /// use std::net::IpAddr;
    ///
    /// let rule = ExitPolicyRule::parse("accept 192.168.1.1:80").unwrap();
    /// assert_eq!(rule.address(), Some("192.168.1.1".parse::<IpAddr>().unwrap()));
    ///
    /// let rule = ExitPolicyRule::parse("accept 10.0.0.0/8:*").unwrap();
    /// assert_eq!(rule.address(), Some("10.0.0.0".parse::<IpAddr>().unwrap()));
    ///
    /// let rule = ExitPolicyRule::parse("accept *:80").unwrap();
    /// assert_eq!(rule.address(), None);
    /// ```
    pub fn address(&self) -> Option<IpAddr> {
        self.address
    }

    /// Sets whether this rule is part of Tor's default exiffix.
    ///
    /// This is called internally during policy construction when detecting
    /// the default policy suffix.
    ///
    /// # Arguments
    ///
    /// * `is_default` - Whether this rule is part of the default suffix
    fn set_default(&mut self, is_default: bool) {
        self.is_default = is_default;
    }

    /// Sets whether this rule was expanded from the `private` keyword.
    ///
    /// This is called internally during policy construction when detecting
    /// private address rules.
    ///
    /// # Arguments
    ///
    /// * `is_private` - Whether this rule was expanded from `private`
    fn set_private(&mut self, is_private: bool) {
        self.is_private = is_private;
    }
}

impl fmt::Display for ExitPolicyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = if self.is_accept { "accept" } else { "reject" };
        write!(f, "{} ", action)?;

        match (&self.address, self.address_type) {
            (None, AddressType::Wildcard) => write!(f, "*")?,
            (Some(IpAddr::V4(addr)), _) => {
                write!(f, "{}", addr)?;
                if let Some(bits) = self.mask_bits {
                    if bits != 32 {
                        write!(f, "/{}", bits)?;
                    }
                }
            }
            (Some(IpAddr::V6(addr)), _) => {
                write!(f, "[{}]", addr)?;
                if let Some(bits) = self.mask_bits {
                    if bits != 128 {
                        write!(f, "/{}", bits)?;
                    }
                }
            }
            _ => write!(f, "*")?,
        }

        write!(f, ":")?;

        if self.is_port_wildcard() {
            write!(f, "*")
        } else if self.min_port == self.max_port {
            write!(f, "{}", self.min_port)
        } else {
            write!(f, "{}-{}", self.min_port, self.max_port)
        }
    }
}

impl FromStr for ExitPolicyRule {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

const PRIVATE_ADDRESSES: &[&str] = &[
    "0.0.0.0/8",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
];

const DEFAULT_POLICY_RULES: &[&str] = &[
    "reject *:25",
    "reject *:119",
    "reject *:135-139",
    "reject *:445",
    "reject *:563",
    "reject *:1214",
    "reject *:4661-4666",
    "reject *:6346-6429",
    "reject *:6699",
    "reject *:6881-6999",
    "accept *:*",
];

/// A complete exit policy consisting of multiple rules.
///
/// An exit policy is an ordered list of [`ExitPolicyRule`]s that determine
/// whether a Tor relay will allow traffic to exit to a given destination.
/// Rules are evaluated in order, and the first matching rule determines
/// whether traffic is allowed.
///
/// # Rule Evaluation
///
/// When checking if traffic can exit to a destination:
/// 1. Each rule is checked in order
/// 2. The first rule that matches the destination determines the result
/// 3. If no rule matches, the default is to allow traffic
///
/// # Special Rule Sequences
///
/// Exit policies may contain special rule sequences that are automatically
/// detected:
///
/// - **Private rules**: Rules blocking traffic to private/internal IP ranges
///   (expanded from the `private` keyword in torrc)
/// - **Default rules**: Tor's standard suffix blocking commonly abused ports
///
/// # Example
///
/// ```rust
/// use stem_rs::exit_policy::ExitPolicy;
/// use std::net::IpAddr;
///
/// // Parse a policy that allows only web traffic
/// let policy = ExitPolicy::parse("accept *:80, accept *:443, reject *:*").unwrap();
///
/// let addr: IpAddr = "192.168.1.1".parse().unwrap();
/// assert!(policy.can_exit_to(addr, 80));   // HTTP allowed
/// assert!(policy.can_exit_to(addr, 443));  // HTTPS allowed
/// assert!(!policy.can_exit_to(addr, 22));  // SSH blocked
///
/// // Get a summary
/// assert_eq!(policy.summary(), "accept 80, 443");
///
/// // Check if any exiting is allowed
/// assert!(policy.is_exiting_allowed());
///
/// // A reject-all policy
/// let reject_all = ExitPolicy::parse("reject *:*").unwrap();
/// assert!(!reject_all.is_exiting_allowed());
/// ```
///
/// # See Also
///
/// - [`ExitPolicyRule`]: Individual rules that make up a policy
/// - [`MicroExitPolicy`]: Compact port-only policy format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitPolicy {
    rules: Vec<ExitPolicyRule>,
    is_allowed_default: bool,
}

impl ExitPolicy {
    /// Creates a new exit policy from a vector of rules.
    ///
    /// The rules are automatically analyzed to detect private and default
    /// rule sequences.
    ///
    /// # Arguments
    ///
    /// * `rules` - The rules that make up this policy
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::{ExitPolicy, ExitPolicyRule};
    ///
    /// let rules = vec![
    ///     ExitPolicyRule::parse("accept *:80").unwrap(),
    ///     ExitPolicyRule::parse("reject *:*").unwrap(),
    /// ];
    /// let policy = ExitPolicy::new(rules);
    /// assert_eq!(policy.len(), 2);
    /// ```
    pub fn new(rules: Vec<ExitPolicyRule>) -> Self {
        let mut policy = Self {
            rules,
            is_allowed_default: true,
        };
        policy.flag_private_rules();
        policy.flag_default_rules();
        policy
    }

    /// Parses an exit policy from a string.
    ///
    /// The string can contain multiple rules separated by commas or newlines.
    /// Rules after a catch-all rule (`accept *:*` or `reject *:*`) are ignored.
    ///
    /// # Arguments
    ///
    /// * `content` - The policy string to parse
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if any rule in the policy is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// // Comma-separated rules
    /// let policy = ExitPolicy::parse("accept *:80, accept *:443, reject *:*").unwrap();
    /// assert_eq!(policy.len(), 3);
    ///
    /// // Newline-separated rules
    /// let policy = ExitPolicy::parse("accept *:80\naccept *:443\nreject *:*").unwrap();
    /// assert_eq!(policy.len(), 3);
    ///
    /// // Rules after catch-all are ignored
    /// let policy = ExitPolicy::parse("reject *:*, accept *:80").unwrap();
    /// assert_eq!(policy.len(), 1);  // Only the reject rule
    /// ```
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut rules = Vec::new();
        let delimiter = if content.contains('\n') { '\n' } else { ',' };
        for rule_str in content.split(delimiter) {
            let rule_str = rule_str.trim();
            if rule_str.is_empty() {
                continue;
            }
            let rule = ExitPolicyRule::parse(rule_str)?;
            let is_catch_all = rule.is_address_wildcard() && rule.is_port_wildcard();
            rules.push(rule);
            if is_catch_all {
                break;
            }
        }
        Ok(Self::new(rules))
    }

    /// Creates an exit policy from a slice of rule strings.
    ///
    /// Similar to [`parse`](Self::parse), but takes individual rule strings
    /// instead of a single concatenated string.
    ///
    /// # Arguments
    ///
    /// * `rules` - Slice of rule strings
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if any rule is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::from_rules(&[
    ///     "accept *:80",
    ///     "accept *:443",
    ///     "reject *:*",
    /// ]).unwrap();
    /// assert_eq!(policy.len(), 3);
    /// ```
    pub fn from_rules<S: AsRef<str>>(rules: &[S]) -> Result<Self, Error> {
        let mut parsed_rules = Vec::new();
        for rule_str in rules {
            let rule_str = rule_str.as_ref().trim();
            if rule_str.is_empty() {
                continue;
            }
            let rule = ExitPolicyRule::parse(rule_str)?;
            let is_catch_all = rule.is_address_wildcard() && rule.is_port_wildcard();
            parsed_rules.push(rule);
            if is_catch_all {
                break;
            }
        }
        Ok(Self::new(parsed_rules))
    }

    /// Detects and flags rules that were expanded from the `private` keyword.
    ///
    /// Scans the policy for sequences of rulesatch the private address
    /// ranges (0.0.0.0/8, 169.254.0.0/16, 127.0.0.0/8, 192.168.0.0/16,
    /// 10.0.0.0/8, 172.16.0.0/12) with the same port range and action.
    ///
    /// When found, marks those rules as private via [`ExitPolicyRule::set_private`].
    /// Also marks the following rule if it appears to be the relay's public IP.
    fn flag_private_rules(&mut self) {
        if self.rules.len() < PRIVATE_ADDRESSES.len() {
            return;
        }

        for start_idx in 0..=self.rules.len() - PRIVATE_ADDRESSES.len() {
            let mut is_match = true;
            let first_rule = &self.rules[start_idx];
            let min_port = first_rule.min_port;
            let max_port = first_rule.max_port;
            let is_accept = first_rule.is_accept;

            for (i, private_addr) in PRIVATE_ADDRESSES.iter().enumerate() {
                let rule = &self.rules[start_idx + i];
                if rule.min_port != min_port
                    || rule.max_port != max_port
                    || rule.is_accept != is_accept
                {
                    is_match = false;
                    break;
                }

                let expected = format!(
                    "{} {}:{}",
                    if is_accept { "accept" } else { "reject" },
                    private_addr,
                    if min_port == max_port {
                        format!("{}", min_port)
                    } else if min_port <= 1 && max_port == 65535 {
                        "*".to_string()
                    } else {
                        format!("{}-{}", min_port, max_port)
                    }
                );

                if let Ok(expected_rule) = ExitPolicyRule::parse(&expected) {
                    if rule.address != expected_rule.address
                        || rule.mask_bits != expected_rule.mask_bits
                    {
                        is_match = false;
                        break;
                    }
                } else {
                    is_match = false;
                    break;
                }
            }

            if is_match {
                for i in 0..PRIVATE_ADDRESSES.len() {
                    self.rules[start_idx + i].set_private(true);
                }

                let next_idx = start_idx + PRIVATE_ADDRESSES.len();
                if next_idx < self.rules.len() {
                    let next_rule = &self.rules[next_idx];
                    if !next_rule.is_address_wildcard()
                        && next_rule.min_port == min_port
                        && next_rule.max_port == max_port
                        && next_rule.is_accept == is_accept
                    {
                        self.rules[next_idx].set_private(true);
                    }
                }
            }
        }
    }

    /// Detects and flags rules that match Tor's default exit policy suffix.
    ///
    /// Checks if the policy ends with the standard default suffix that Tor
    /// appends to exit policies. The default suffix blocks commonly abused
    /// ports (SMTP port 25, NNTP port 119, NetBIOS ports 135-139, etc.)
    /// and then accepts all other traffic.
    ///
    /// When found, marks those rules as default via [`ExitPolicyRule::set_default`].
    fn flag_default_rules(&mut self) {
        if self.rules.len() < DEFAULT_POLICY_RULES.len() {
            return;
        }

        let start_idx = self.rules.len() - DEFAULT_POLICY_RULES.len();
        let mut is_match = true;

        for (i, default_rule_str) in DEFAULT_POLICY_RULES.iter().enumerate() {
            if let Ok(default_rule) = ExitPolicyRule::parse(default_rule_str) {
                let rule = &self.rules[start_idx + i];
                if rule.is_accept != default_rule.is_accept
                    || rule.address != default_rule.address
                    || rule.mask_bits != default_rule.mask_bits
                    || rule.min_port != default_rule.min_port
                    || rule.max_port != default_rule.max_port
                {
                    is_match = false;
                    break;
                }
            } else {
                is_match = false;
                break;
            }
        }

        if is_match {
            for i in 0..DEFAULT_POLICY_RULES.len() {
                self.rules[start_idx + i].set_default(true);
            }
        }
    }

    /// Checks if traffic can exit to a specific destination.
    ///
    /// Evaluates the policy rules in order and returns whether traffic to
    /// the given address and port is allowed.
    ///
    /// # Arguments
    ///
    /// * `address` - The destination IP address
    /// * `port` - The destination port
    ///
    /// # Returns
    ///
    /// `true` if traffic to this destination is allowed, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    /// use std::net::IpAddr;
    ///
    /// let policy = ExitPolicy::parse("accept *:80, accept *:443, reject *:*").unwrap();
    /// let addr: IpAddr = "192.168.1.1".parse().unwrap();
    ///
    /// assert!(policy.can_exit_to(addr, 80));   // HTTP allowed
    /// assert!(policy.can_exit_to(addr, 443));  // HTTPS allowed
    /// assert!(!policy.can_exit_to(addr, 22));  // SSH blocked
    /// ```
    pub fn can_exit_to(&self, address: IpAddr, port: u16) -> bool {
        self.can_exit_to_optional(Some(address), Some(port), false)
    }

    /// Checks if traffic can exit to a destination with optional parameters.
    ///
    /// Similar to [`can_exit_to`](Self::can_exit_to), but allows omitting
    /// the address or port to check if traffic to ANY matching destination
    /// is allowed.
    ///
    /// # Arguments
    ///
    /// * `address` - The destination IP address, or `None` for any address
    /// * `port` - The destination port, or `None` for any port
    /// * `strict` - If `true`, checks if ALL matching destinations are allowed;
    ///   if `false`, checks if ANY matching destination is allowed
    ///
    /// # Returns
    ///
    /// `true` if traffic is allowed according to the strict mode, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::parse("reject 10.0.0.0/8:80, accept *:*").unwrap();
    ///
    /// // Non-strict: Can ANY address exit on port 80?
    /// assert!(policy.can_exit_to_optional(None, Some(80), false));
    ///
    /// // Strict: Can ALL addresses exit on port 80?
    /// assert!(!policy.can_exit_to_optional(None, Some(80), true));
    /// ```
    pub fn can_exit_to_optional(
        &self,
        address: Option<IpAddr>,
        port: Option<u16>,
        strict: bool,
    ) -> bool {
        if !self.is_exiting_allowed() {
            return false;
        }

        for rule in &self.rules {
            if rule.is_match_strict(address, port, strict) {
                return rule.is_accept;
            }
        }

        self.is_allowed_default
    }

    /// Checks if this policy allows any exiting at all.
    ///
    /// Returns `false` if the policy effectively blocks all traffic
    /// (e.g., `reject *:*` with no prior accept rules).
    ///
    /// # Returns
    ///
    /// `true` if at least some traffic can exit, `false` if all traffic is blocked.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::parse("accept *:80, reject *:*").unwrap();
    /// assert!(policy.is_exiting_allowed());
    ///
    /// let policy = ExitPolicy::parse("reject *:*").unwrap();
    /// assert!(!policy.is_exiting_allowed());
    ///
    /// // Empty policy allows by default
    /// let policy = ExitPolicy::parse("").unwrap();
    /// assert!(policy.is_exiting_allowed());
    /// ```
    pub fn is_exiting_allowed(&self) -> bool {
        let mut rejected_ports = std::collections::HashSet::new();

        for rule in &self.rules {
            if rule.is_accept {
                for port in rule.min_port..=rule.max_port {
                    if !rejected_ports.contains(&port) {
                        return true;
                    }
                }
            } else if rule.is_address_wildcard() {
                if rule.is_port_wildcard() {
                    return false;
                }
                for port in rule.min_port..=rule.max_port {
                    rejected_ports.insert(port);
                }
            }
        }

        self.is_allowed_default
    }

    /// Returns a short summary of the policy, similar to a microdescriptor.
    ///
    /// The summary shows which ports are accepted or rejected, ignoring
    /// address-specific rules. This is useful for quickly understanding
    /// what a relay allows.
    ///
    /// # Returns
    ///
    /// A string like `"accept 80, 443"` or `"reject 1-1024"`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::parse("accept *:80, accept *:443, reject *:*").unwrap();
    /// assert_eq!(policy.summary(), "accept 80, 443");
    ///
    /// let policy = ExitPolicy::parse("accept *:443, reject *:1-1024, accept *:*").unwrap();
    /// assert_eq!(policy.summary(), "reject 1-442, 444-1024");
    /// ```
    pub fn summary(&self) -> String {
        let mut is_whitelist = !self.is_allowed_default;

        for rule in &self.rules {
            if rule.is_address_wildcard() && rule.is_port_wildcard() {
                is_whitelist = !rule.is_accept;
                break;
            }
        }

        let mut display_ports = Vec::new();
        let mut skip_ports = std::collections::HashSet::new();

        for rule in &self.rules {
            if !rule.is_address_wildcard() {
                continue;
            }
            if rule.is_port_wildcard() {
                break;
            }

            for port in rule.min_port..=rule.max_port {
                if skip_ports.contains(&port) {
                    continue;
                }
                if rule.is_accept == is_whitelist {
                    display_ports.push(port);
                }
                skip_ports.insert(port);
            }
        }

        let display_ranges = if display_ports.is_empty() {
            is_whitelist = !is_whitelist;
            vec!["1-65535".to_string()]
        } else {
            display_ports.sort();
            Self::ports_to_ranges(&display_ports)
        };

        let prefix = if is_whitelist { "accept " } else { "reject " };
        format!("{}{}", prefix, display_ranges.join(", "))
    }

    /// Converts a sorted list of ports into a list of range strings.
    ///
    /// Groups consecutive ports into ranges for compact display.
    /// For example, `[80, 81, 82, 443]` becomes `["80-82", "443"]`.
    ///
    /// # Arguments
    ///
    /// * `ports` - A sorted slice of port numbers
    ///
    /// # Returns
    ///
    /// A vector of range strings (e.g., "80", "80-443").
    fn ports_to_ranges(ports: &[u16]) -> Vec<String> {
        if ports.is_empty() {
            return vec![];
        }

        let mut ranges = Vec::new();
        let mut range_start = ports[0];
        let mut range_end = ports[0];

        for &port in &ports[1..] {
            if port == range_end + 1 {
                range_end = port;
            } else {
                if range_start == range_end {
                    ranges.push(format!("{}", range_start));
                } else {
                    ranges.push(format!("{}-{}", range_start, range_end));
                }
                range_start = port;
                range_end = port;
            }
        }

        if range_start == range_end {
            ranges.push(format!("{}", range_start));
        } else {
            ranges.push(format!("{}-{}", range_start, range_end));
        }

        ranges
    }

    /// Checks if this policy contains rules expanded from the `private` keyword.
    ///
    /// The `private` keyword in Tor exit policies expands to rules blocking
    /// traffic to private/internal IP ranges. This method detects if such
    /// rules are present.
    ///
    /// # Returns
    ///
    /// `true` if the policy contains private rules, `false` otherwise.
    ///
    /// # See Also
    ///
    /// - [`strip_private`](Self::strip_private): Remove private rules
    /// - [`ExitPolicyRule::is_private`]: Check individual rules
    pub fn has_private(&self) -> bool {
        self.rules.iter().any(|r| r.is_private())
    }

    /// Returns a copy of this policy without private rules.
    ///
    /// Creates a new policy with all rules expanded from the `private`
    /// keyword removed.
    ///
    /// # Returns
    ///
    /// A new [`ExitPolicy`] without private rules.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::parse("accept *:80, reject *:*").unwrap();
    /// let stripped = policy.strip_private();
    /// assert!(!stripped.has_private());
    /// ```
    pub fn strip_private(&self) -> Self {
        let rules: Vec<_> = self
            .rules
            .iter()
            .filter(|r| !r.is_private())
            .cloned()
            .collect();
        Self {
            rules,
            is_allowed_default: self.is_allowed_default,
        }
    }

    /// Checks if this policy contains Tor's default exit policy suffix.
    ///
    /// Tor appends a default suffix to exit policies that blocks commonly
    /// abused ports (SMTP, NetBIOS, etc.) and then accepts all other traffic.
    ///
    /// # Returns
    ///
    /// `true` if the policy ends with the default suffix, `false` otherwise.
    ///
    /// # See Also
    ///
    /// - [`strip_default`](Self::strip_default): Remove default rules
    /// - [`ExitPolicyRule::is_default`]: Check individual rules
    pub fn has_default(&self) -> bool {
        self.rules.iter().any(|r| r.is_default())
    }

    /// Returns a copy of this policy without the default suffix.
    ///
    /// Creates a new policy with Tor's default exit policy suffix removed.
    ///
    /// # Returns
    ///
    /// A new [`ExitPolicy`] without default rules.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::parse("accept *:80, reject *:*").unwrap();
    /// let stripped = policy.strip_default();
    /// assert!(!stripped.has_default());
    /// ```
    pub fn strip_default(&self) -> Self {
        let rules: Vec<_> = self
            .rules
            .iter()
            .filter(|r| !r.is_default())
            .cloned()
            .collect();
        Self {
            rules,
            is_allowed_default: self.is_allowed_default,
        }
    }

    /// Returns an iterator over the rules in this policy.
    ///
    /// Rules are yielded in evaluation order (first rule first).
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::parse("accept *:80, reject *:*").unwrap();
    /// for rule in policy.iter() {
    ///     println!("{}", rule);
    /// }
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &ExitPolicyRule> {
        self.rules.iter()
    }

    /// Returns a slice of all rules in this policy.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::parse("accept *:80, reject *:*").unwrap();
    /// let rules = policy.rules();
    /// assert_eq!(rules.len(), 2);
    /// ```
    pub fn rules(&self) -> &[ExitPolicyRule] {
        &self.rules
    }

    /// Returns the number of rules in this policy.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::parse("accept *:80, reject *:*").unwrap();
    /// assert_eq!(policy.len(), 2);
    /// ```
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Checks if this policy has no rules.
    ///
    /// An empty policy allows all traffic by default.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::ExitPolicy;
    ///
    /// let policy = ExitPolicy::parse("").unwrap();
    /// assert!(policy.is_empty());
    ///
    /// let policy = ExitPolicy::parse("accept *:80").unwrap();
    /// assert!(!policy.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl fmt::Display for ExitPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rules: Vec<String> = self.rules.iter().map(|r| r.to_string()).collect();
        write!(f, "{}", rules.join(", "))
    }
}

impl FromStr for ExitPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A compact exit policy used in microdescriptors.
///
/// Microdescriptor exit policies are a simplified form of exit policy that
/// only specify ports, not addresses. They are used in Tor's microdescriptor
/// format to provide a compact representation of a relay's exit policy.
///
/// # Format
///
/// Micro exit policies have the format:
///
/// ```text
/// accept|reject port[,port...]
/// ```
///
/// Where each port can be a single port or a range (e.g., `80-443`).
///
/// # Matching Semantics
///
/// - `accept` policies allow traffic to the listed ports
/// - `reject` policies block traffic to the listed ports (allowing all others)
///
/// Since micro policies don't include address information, clients can only
/// guess whether a relay will accept their traffic. If the guess is wrong,
/// the relay will return an end-reason-exit-policy error.
///
/// # Example
///
/// ```rust
/// use stem_rs::exit_policy::MicroExitPolicy;
///
/// // Accept only web ports
/// let policy = MicroExitPolicy::parse("accept 80,443").unwrap();
/// assert!(policy.can_exit_to(80));
/// assert!(policy.can_exit_to(443));
/// assert!(!policy.can_exit_to(22));
///
/// // Reject privileged ports
/// let policy = MicroExitPolicy::parse("reject 1-1024").unwrap();
/// assert!(!policy.can_exit_to(80));
/// assert!(policy.can_exit_to(8080));
/// ```
///
/// # See Also
///
/// - [`ExitPolicy`]: Full exit policy with address support
/// - [`crate::descriptor::Microdescriptor`]: Contains micro exit policies
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroExitPolicy {
    /// Whether this policy accepts (`true`) or rejects (`false`) the listed ports.
    pub is_accept: bool,
    /// The port ranges this policy applies to.
    pub ports: Vec<PortRange>,
}

impl MicroExitPolicy {
    /// Parses a micro exit policy from a string.
    ///
    /// The string must follow the microdescriptor policy format:
    ///
    /// ```text
    /// accept|reject port[,port...]
    /// ```
    ///
    /// # Arguments
    ///
    /// * `content` - The policy string to parse
    ///
    /// # Supported Formats
    ///
    /// - Single port: `accept 80`
    /// - Multiple ports: `accept 80,443`
    /// - Port range: `reject 1-1024`
    /// - Mixed: `accept 80,443,8080-8090`
    /// - Wildcard: `accept *` (all ports)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The policy doesn't start with `accept` or `reject`
    /// - A port number is invalid
    /// - A port range is invalid (min > max)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::MicroExitPolicy;
    ///
    /// let policy = MicroExitPolicy::parse("accept 80,443").unwrap();
    /// assert!(policy.is_accept);
    /// assert_eq!(policy.ports.len(), 2);
    ///
    /// let policy = MicroExitPolicy::parse("reject 1-1024").unwrap();
    /// assert!(!policy.is_accept);
    ///
    /// // Invalid policies
    /// assert!(MicroExitPolicy::parse("allow 80").is_err());
    /// assert!(MicroExitPolicy::parse("80,443").is_err());
    /// ```
    pub fn parse(content: &str) -> Result<Self, Error> {
        let content = content.trim();
        let (is_accept, port_list) = if let Some(rest) = content.strip_prefix("accept ") {
            (true, rest.trim())
        } else if let Some(rest) = content.strip_prefix("reject ") {
            (false, rest.trim())
        } else {
            return Err(Error::Parse {
                location: content.to_string(),
                reason: "microdescriptor policy must start with accept/reject".to_string(),
            });
        };

        let mut ports = Vec::new();
        for port_entry in port_list.split(',') {
            let port_entry = port_entry.trim();
            if port_entry.is_empty() {
                continue;
            }

            let range = if port_entry == "*" {
                PortRange::new(1, 65535)?
            } else if let Some(dash_pos) = port_entry.find('-') {
                let min_str = &port_entry[..dash_pos];
                let max_str = &port_entry[dash_pos + 1..];
                let min: u16 = min_str.parse().map_err(|_| Error::Parse {
                    location: port_entry.to_string(),
                    reason: "invalid min port".to_string(),
                })?;
                let max: u16 = max_str.parse().map_err(|_| Error::Parse {
                    location: port_entry.to_string(),
                    reason: "invalid max port".to_string(),
                })?;
                PortRange::new(min, max)?
            } else {
                let port: u16 = port_entry.parse().map_err(|_| Error::Parse {
                    location: port_entry.to_string(),
                    reason: "invalid port".to_string(),
                })?;
                PortRange::single(port)
            };
            ports.push(range);
        }

        Ok(Self { is_accept, ports })
    }

    /// Checks if traffic can exit to a specific port.
    ///
    /// For `accept` policies, returns `true` if the port is in the list.
    /// For `reject` policies, returns `true` if the port is NOT in the list.
    ///
    /// # Arguments
    ///
    /// * `port` - The destination port to check
    ///
    /// # Returns
    ///
    /// `true` if traffic to this port is allowed, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::exit_policy::MicroExitPolicy;
    ///
    /// // Accept policy: only listed ports are allowed
    /// let policy = MicroExitPolicy::parse("accept 80,443").unwrap();
    /// assert!(policy.can_exit_to(80));
    /// assert!(policy.can_exit_to(443));
    /// assert!(!policy.can_exit_to(22));
    ///
    /// // Reject policy: listed ports are blocked, others allowed
    /// let policy = MicroExitPolicy::parse("reject 1-1024").unwrap();
    /// assert!(!policy.can_exit_to(80));
    /// assert!(!policy.can_exit_to(443));
    /// assert!(policy.can_exit_to(8080));
    /// ```
    pub fn can_exit_to(&self, port: u16) -> bool {
        let matches = self.ports.iter().any(|r| r.contains(port));
        if self.is_accept {
            matches
        } else {
            !matches
        }
    }
}

impl fmt::Display for MicroExitPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = if self.is_accept { "accept" } else { "reject" };
        let ports: Vec<String> = self.ports.iter().map(|r| r.to_string()).collect();
        write!(f, "{} {}", action, ports.join(","))
    }
}

impl FromStr for MicroExitPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_accept_all() {
        let rule = ExitPolicyRule::parse("accept *:*").unwrap();
        assert!(rule.is_accept);
        assert!(rule.is_address_wildcard());
        assert!(rule.is_port_wildcard());
    }

    #[test]
    fn test_parse_reject_all() {
        let rule = ExitPolicyRule::parse("reject *:*").unwrap();
        assert!(!rule.is_accept);
        assert!(rule.is_address_wildcard());
        assert!(rule.is_port_wildcard());
    }

    #[test]
    fn test_parse_specific_port() {
        let rule = ExitPolicyRule::parse("accept *:80").unwrap();
        assert!(rule.is_accept);
        assert!(rule.is_address_wildcard());
        assert_eq!(rule.min_port, 80);
        assert_eq!(rule.max_port, 80);
    }

    #[test]
    fn test_parse_port_range() {
        let rule = ExitPolicyRule::parse("reject *:80-443").unwrap();
        assert!(!rule.is_accept);
        assert_eq!(rule.min_port, 80);
        assert_eq!(rule.max_port, 443);
    }

    #[test]
    fn test_parse_ipv4_address() {
        let rule = ExitPolicyRule::parse("accept 192.168.1.1:80").unwrap();
        assert!(rule.is_accept);
        assert_eq!(
            rule.address(),
            Some(IpAddr::V4("192.168.1.1".parse().unwrap()))
        );
        assert_eq!(rule.get_masked_bits(), Some(32));
    }

    #[test]
    fn test_parse_ipv4_cidr() {
        let rule = ExitPolicyRule::parse("reject 10.0.0.0/8:*").unwrap();
        assert!(!rule.is_accept);
        assert_eq!(
            rule.address(),
            Some(IpAddr::V4("10.0.0.0".parse().unwrap()))
        );
        assert_eq!(rule.get_masked_bits(), Some(8));
    }

    #[test]
    fn test_parse_ipv6_address() {
        let rule = ExitPolicyRule::parse("accept [::1]:80").unwrap();
        assert!(rule.is_accept);
        assert!(matches!(rule.address(), Some(IpAddr::V6(_))));
        assert_eq!(rule.get_masked_bits(), Some(128));
    }

    #[test]
    fn test_parse_ipv6_cidr() {
        let rule = ExitPolicyRule::parse("reject [2001:db8::]/32:*").unwrap();
        assert!(!rule.is_accept);
        assert_eq!(rule.get_masked_bits(), Some(32));
    }

    #[test]
    fn test_rule_match_wildcard() {
        let rule = ExitPolicyRule::parse("accept *:80").unwrap();
        assert!(rule.is_match(Some("192.168.1.1".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("10.0.0.1".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("192.168.1.1".parse().unwrap()), Some(443)));
    }

    #[test]
    fn test_rule_match_cidr() {
        let rule = ExitPolicyRule::parse("accept 10.0.0.0/8:*").unwrap();
        assert!(rule.is_match(Some("10.0.0.1".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("10.255.255.255".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("192.168.1.1".parse().unwrap()), Some(80)));
    }

    #[test]
    fn test_rule_match_port_range() {
        let rule = ExitPolicyRule::parse("accept *:80-443").unwrap();
        assert!(rule.is_match(Some("192.168.1.1".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("192.168.1.1".parse().unwrap()), Some(443)));
        assert!(rule.is_match(Some("192.168.1.1".parse().unwrap()), Some(200)));
        assert!(!rule.is_match(Some("192.168.1.1".parse().unwrap()), Some(79)));
        assert!(!rule.is_match(Some("192.168.1.1".parse().unwrap()), Some(444)));
    }

    #[test]
    fn test_policy_can_exit_to() {
        let policy = ExitPolicy::parse("accept *:80, accept *:443, reject *:*").unwrap();
        assert!(policy.can_exit_to("192.168.1.1".parse().unwrap(), 80));
        assert!(policy.can_exit_to("192.168.1.1".parse().unwrap(), 443));
        assert!(!policy.can_exit_to("192.168.1.1".parse().unwrap(), 22));
    }

    #[test]
    fn test_policy_is_exiting_allowed() {
        let policy = ExitPolicy::parse("accept *:80, reject *:*").unwrap();
        assert!(policy.is_exiting_allowed());

        let policy = ExitPolicy::parse("reject *:*").unwrap();
        assert!(!policy.is_exiting_allowed());
    }

    #[test]
    fn test_policy_summary() {
        let policy = ExitPolicy::parse("accept *:80, accept *:443, reject *:*").unwrap();
        assert_eq!(policy.summary(), "accept 80, 443");

        let policy = ExitPolicy::parse("accept *:443, reject *:1-1024, accept *:*").unwrap();
        assert_eq!(policy.summary(), "reject 1-442, 444-1024");
    }

    #[test]
    fn test_micro_exit_policy_parse() {
        let policy = MicroExitPolicy::parse("accept 80,443").unwrap();
        assert!(policy.is_accept);
        assert_eq!(policy.ports.len(), 2);
    }

    #[test]
    fn test_micro_exit_policy_can_exit_to() {
        let policy = MicroExitPolicy::parse("accept 80,443").unwrap();
        assert!(policy.can_exit_to(80));
        assert!(policy.can_exit_to(443));
        assert!(!policy.can_exit_to(22));

        let policy = MicroExitPolicy::parse("reject 1-1024").unwrap();
        assert!(!policy.can_exit_to(80));
        assert!(policy.can_exit_to(8080));
    }

    #[test]
    fn test_rule_display() {
        let rule = ExitPolicyRule::parse("accept *:80").unwrap();
        assert_eq!(rule.to_string(), "accept *:80");

        let rule = ExitPolicyRule::parse("reject 10.0.0.0/8:*").unwrap();
        assert_eq!(rule.to_string(), "reject 10.0.0.0/8:*");

        let rule = ExitPolicyRule::parse("accept *:80-443").unwrap();
        assert_eq!(rule.to_string(), "accept *:80-443");
    }

    #[test]
    fn test_policy_display() {
        let policy = ExitPolicy::parse("accept *:80, reject *:*").unwrap();
        assert_eq!(policy.to_string(), "accept *:80, reject *:*");
    }

    #[test]
    fn test_micro_policy_display() {
        let policy = MicroExitPolicy::parse("accept 80,443").unwrap();
        assert_eq!(policy.to_string(), "accept 80,443");
    }

    #[test]
    fn test_ipv4_mask_notation() {
        let rule = ExitPolicyRule::parse("accept 192.168.0.0/255.255.0.0:*").unwrap();
        assert_eq!(rule.get_masked_bits(), Some(16));
    }

    #[test]
    fn test_address_type() {
        let rule = ExitPolicyRule::parse("accept *:*").unwrap();
        assert_eq!(rule.get_address_type(), AddressType::Wildcard);

        let rule = ExitPolicyRule::parse("accept 192.168.1.1:*").unwrap();
        assert_eq!(rule.get_address_type(), AddressType::IPv4);

        let rule = ExitPolicyRule::parse("accept [::1]:*").unwrap();
        assert_eq!(rule.get_address_type(), AddressType::IPv6);
    }

    #[test]
    fn test_get_mask() {
        let rule = ExitPolicyRule::parse("accept 192.168.0.0/16:*").unwrap();
        assert_eq!(
            rule.get_mask(),
            Some(IpAddr::V4("255.255.0.0".parse().unwrap()))
        );

        let rule = ExitPolicyRule::parse("accept 10.0.0.0/8:*").unwrap();
        assert_eq!(
            rule.get_mask(),
            Some(IpAddr::V4("255.0.0.0".parse().unwrap()))
        );
    }

    #[test]
    fn test_policy_from_rules() {
        let policy = ExitPolicy::from_rules(&["accept *:80", "reject *:*"]).unwrap();
        assert_eq!(policy.len(), 2);
        assert!(policy.can_exit_to("192.168.1.1".parse().unwrap(), 80));
        assert!(!policy.can_exit_to("192.168.1.1".parse().unwrap(), 443));
    }

    #[test]
    fn test_invalid_rule_no_action() {
        assert!(ExitPolicyRule::parse("*:80").is_err());
    }

    #[test]
    fn test_invalid_rule_no_port() {
        assert!(ExitPolicyRule::parse("accept *").is_err());
    }

    #[test]
    fn test_invalid_rule_bad_port_range() {
        assert!(ExitPolicyRule::parse("accept *:443-80").is_err());
    }

    #[test]
    fn test_invalid_rule_bad_mask() {
        assert!(ExitPolicyRule::parse("accept 192.168.0.0/33:*").is_err());
    }

    #[test]
    fn test_cidr_matching_edge_cases() {
        let rule = ExitPolicyRule::parse("accept 192.168.0.0/24:*").unwrap();
        assert!(rule.is_match(Some("192.168.0.0".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("192.168.0.255".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("192.168.1.0".parse().unwrap()), Some(80)));
    }

    #[test]
    fn test_ipv6_cidr_matching() {
        let rule = ExitPolicyRule::parse("accept [2001:db8::]/32:*").unwrap();
        assert!(rule.is_match(Some("2001:db8::1".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("2001:db8:ffff::1".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("2001:db9::1".parse().unwrap()), Some(80)));
    }

    #[test]
    fn test_policy_iter() {
        let policy = ExitPolicy::parse("accept *:80, accept *:443, reject *:*").unwrap();
        let rules: Vec<_> = policy.iter().collect();
        assert_eq!(rules.len(), 3);
    }

    #[test]
    fn test_port_range_struct() {
        let range = PortRange::new(80, 443).unwrap();
        assert!(range.contains(80));
        assert!(range.contains(443));
        assert!(range.contains(200));
        assert!(!range.contains(79));
        assert!(!range.contains(444));

        let single = PortRange::single(80);
        assert!(single.contains(80));
        assert!(!single.contains(81));

        let all = PortRange::all();
        assert!(all.is_wildcard());
        assert!(all.contains(1));
        assert!(all.contains(65535));
    }

    #[test]
    fn test_port_range_invalid() {
        assert!(PortRange::new(443, 80).is_err());
    }

    #[test]
    fn test_accept6_reject6() {
        let rule = ExitPolicyRule::parse("accept6 [::]/0:*").unwrap();
        assert!(rule.is_accept);
        assert_eq!(rule.get_address_type(), AddressType::IPv6);

        let rule = ExitPolicyRule::parse("reject6 [::]/0:*").unwrap();
        assert!(!rule.is_accept);
    }

    #[test]
    fn test_star4_star6_wildcards() {
        let rule = ExitPolicyRule::parse("accept *4:*").unwrap();
        assert_eq!(rule.get_address_type(), AddressType::IPv4);
        assert_eq!(rule.get_masked_bits(), Some(0));

        let rule = ExitPolicyRule::parse("accept *6:*").unwrap();
        assert_eq!(rule.get_address_type(), AddressType::IPv6);
        assert_eq!(rule.get_masked_bits(), Some(0));
    }
}

#[cfg(test)]
mod stem_tests {
    use super::*;

    #[test]
    fn test_example() {
        let policy =
            ExitPolicy::from_rules(&["accept *:80", "accept *:443", "reject *:*"]).unwrap();
        assert_eq!(policy.to_string(), "accept *:80, accept *:443, reject *:*");
        assert_eq!(policy.summary(), "accept 80, 443");
        assert!(policy.can_exit_to("75.119.206.243".parse().unwrap(), 80));

        let policy = MicroExitPolicy::parse("accept 80,443").unwrap();
        assert!(policy.can_exit_to(80));
    }

    #[test]
    fn test_constructor_truncates_after_catch_all() {
        let policy = ExitPolicy::from_rules(&[
            "accept *:80",
            "accept *:443",
            "reject *:*",
            "accept *:20-50",
        ])
        .unwrap();
        assert_eq!(policy.len(), 3);
    }

    #[test]
    fn test_can_exit_to_various_ports() {
        let policy =
            ExitPolicy::from_rules(&["accept *:80", "accept *:443", "reject *:*"]).unwrap();

        for port in 1..100u16 {
            let ip: IpAddr = format!("{}.{}.{}.{}", port / 2, port / 2, port / 2, port / 2)
                .parse()
                .unwrap_or("0.0.0.0".parse().unwrap());
            let expected = port == 80 || port == 443;
            assert_eq!(
                expected,
                policy.can_exit_to(ip, port),
                "port {} expected {}",
                port,
                expected
            );
        }
    }

    #[test]
    fn test_can_exit_to_strictness() {
        let policy = ExitPolicy::from_rules(&["reject 1.0.0.0/8:80", "accept *:*"]).unwrap();
        assert!(!policy.can_exit_to_optional(None, Some(80), true));
        assert!(policy.can_exit_to_optional(None, Some(80), false));

        let policy = ExitPolicy::from_rules(&["accept 1.0.0.0/8:80", "reject *:*"]).unwrap();
        assert!(!policy.can_exit_to_optional(None, Some(80), true));
        assert!(policy.can_exit_to_optional(None, Some(80), false));
    }

    #[test]
    fn test_is_exiting_allowed_various() {
        let test_cases: Vec<(&[&str], bool)> = vec![
            (&[], true),
            (&["accept *:*"], true),
            (&["reject *:*"], false),
            (&["accept *:80", "reject *:*"], true),
            (&["reject *:80", "accept *:80", "reject *:*"], false),
            (&["reject *:50-90", "accept *:80", "reject *:*"], false),
            (
                &["reject *:2-65535", "accept *:80-65535", "reject *:*"],
                false,
            ),
            (
                &["reject *:2-65535", "accept 127.0.0.0:1", "reject *:*"],
                true,
            ),
            (&["reject 127.0.0.1:*", "accept *:80", "reject *:*"], true),
        ];

        for (rules, expected) in test_cases {
            let policy = ExitPolicy::from_rules(rules).unwrap();
            assert_eq!(
                expected,
                policy.is_exiting_allowed(),
                "rules {:?} expected {}",
                rules,
                expected
            );
        }
    }

    #[test]
    fn test_summary_large_ranges() {
        let policy =
            ExitPolicy::from_rules(&["reject *:80-65535", "accept *:1-65533", "reject *:*"])
                .unwrap();
        assert_eq!(policy.summary(), "accept 1-79");
    }

    #[test]
    fn test_non_private_non_default_policy() {
        let policy =
            ExitPolicy::from_rules(&["reject *:80-65535", "accept *:1-65533", "reject *:*"])
                .unwrap();

        for rule in policy.iter() {
            assert!(!rule.is_private());
            assert!(!rule.is_default());
        }

        assert!(!policy.has_private());
        assert!(!policy.has_default());
    }

    #[test]
    fn test_str_whitespace_handling() {
        let policy = ExitPolicy::from_rules(&["  accept *:80\n", "\taccept *:443"]).unwrap();
        assert_eq!(policy.to_string(), "accept *:80, accept *:443");
    }

    #[test]
    fn test_str_mask_conversion() {
        let policy =
            ExitPolicy::from_rules(&["reject 0.0.0.0/255.255.255.0:*", "accept *:*"]).unwrap();
        assert_eq!(policy.to_string(), "reject 0.0.0.0/24:*, accept *:*");
    }

    #[test]
    fn test_microdescriptor_parsing_valid() {
        assert!(MicroExitPolicy::parse("accept 80").is_ok());
        assert!(MicroExitPolicy::parse("accept 80,443").is_ok());
    }

    #[test]
    fn test_microdescriptor_parsing_invalid() {
        assert!(MicroExitPolicy::parse("").is_err());
        assert!(MicroExitPolicy::parse("accept").is_err());
        assert!(MicroExitPolicy::parse("accept ").is_err());
        assert!(MicroExitPolicy::parse("80,443").is_err());
        assert!(MicroExitPolicy::parse("bar 80,443").is_err());
    }

    #[test]
    fn test_microdescriptor_attributes() {
        let policy = MicroExitPolicy::parse("accept 443").unwrap();
        assert!(policy.is_accept);

        let policy = MicroExitPolicy::parse("accept 80,443").unwrap();
        assert!(policy.is_accept);

        let policy = MicroExitPolicy::parse("reject 1-1024").unwrap();
        assert!(!policy.is_accept);
    }

    #[test]
    fn test_microdescriptor_can_exit_to_various() {
        let test_cases: Vec<(&str, Vec<(u16, bool)>)> = vec![
            ("accept 443", vec![(442, false), (443, true), (444, false)]),
            ("reject 443", vec![(442, true), (443, false), (444, true)]),
            ("accept 80,443", vec![(80, true), (443, true), (10, false)]),
            (
                "reject 1-1024",
                vec![(1, false), (1024, false), (1025, true)],
            ),
        ];

        for (policy_str, checks) in test_cases {
            let policy = MicroExitPolicy::parse(policy_str).unwrap();
            for (port, expected) in checks {
                assert_eq!(
                    expected,
                    policy.can_exit_to(port),
                    "policy {} port {} expected {}",
                    policy_str,
                    port,
                    expected
                );
            }
        }
    }

    #[test]
    fn test_accept_or_reject() {
        assert!(ExitPolicyRule::parse("accept *:*").unwrap().is_accept);
        assert!(!ExitPolicyRule::parse("reject *:*").unwrap().is_accept);
    }

    #[test]
    fn test_invalid_rule_formats() {
        let invalid_inputs = [
            "accept",
            "reject",
            "acceptt *:*",
            "rejectt *:*",
            "blarg *:*",
            " *:*",
            "*:*",
            "",
        ];

        for input in invalid_inputs {
            assert!(
                ExitPolicyRule::parse(input).is_err(),
                "expected error for: {}",
                input
            );
        }
    }

    #[test]
    fn test_with_multiple_spaces() {
        let rule = ExitPolicyRule::parse("accept    *:80").unwrap();
        assert_eq!(rule.to_string(), "accept *:80");

        let policy = MicroExitPolicy::parse("accept      80,443").unwrap();
        assert!(policy.can_exit_to(80));
    }

    #[test]
    fn test_str_unchanged() {
        let test_inputs = [
            "accept *:*",
            "reject *:*",
            "accept *:80",
            "accept *:80-443",
            "accept 127.0.0.1:80",
            "accept 87.0.0.1/24:80",
        ];

        for input in test_inputs {
            let rule = ExitPolicyRule::parse(input).unwrap();
            assert_eq!(input, rule.to_string(), "input: {}", input);
        }
    }

    #[test]
    fn test_str_changed() {
        let test_cases = [
            ("accept 10.0.0.1/32:80", "accept 10.0.0.1:80"),
            (
                "accept 192.168.0.1/255.255.255.0:80",
                "accept 192.168.0.1/24:80",
            ),
        ];

        for (input, expected) in test_cases {
            let rule = ExitPolicyRule::parse(input).unwrap();
            assert_eq!(expected, rule.to_string(), "input: {}", input);
        }
    }

    #[test]
    fn test_valid_wildcard() {
        let test_cases: Vec<(&str, bool, bool)> = vec![
            ("reject *:*", true, true),
            ("reject *:80", true, false),
            ("accept 192.168.0.1:*", false, true),
            ("accept 192.168.0.1:80", false, false),
            ("reject *4:*", false, true),
            ("reject *6:*", false, true),
            ("reject 127.0.0.1/0:*", false, true),
            ("reject 127.0.0.1/16:*", false, true),
            ("reject 127.0.0.1/32:*", false, true),
            ("accept 192.168.0.1:0-65535", false, true),
            ("accept 192.168.0.1:1-65535", false, true),
            ("accept 192.168.0.1:2-65535", false, false),
            ("accept 192.168.0.1:1-65534", false, false),
        ];

        for (rule_str, is_addr_wildcard, is_port_wildcard) in test_cases {
            let rule = ExitPolicyRule::parse(rule_str).unwrap();
            assert_eq!(
                is_addr_wildcard,
                rule.is_address_wildcard(),
                "{} address wildcard",
                rule_str
            );
            assert_eq!(
                is_port_wildcard,
                rule.is_port_wildcard(),
                "{} port wildcard",
                rule_str
            );
        }
    }

    #[test]
    fn test_invalid_wildcard() {
        let invalid_inputs = [
            "reject */16:*",
            "reject 127.0.0.1/*:*",
            "reject *:0-*",
            "reject *:*-15",
        ];

        for input in invalid_inputs {
            assert!(
                ExitPolicyRule::parse(input).is_err(),
                "expected error for: {}",
                input
            );
        }
    }

    #[test]
    fn test_wildcard_attributes() {
        let rule = ExitPolicyRule::parse("reject *:*").unwrap();
        assert_eq!(AddressType::Wildcard, rule.get_address_type());
        assert!(rule.address().is_none());
        assert!(rule.get_mask().is_none());
        assert!(rule.get_masked_bits().is_none());
        assert_eq!(1, rule.min_port);
        assert_eq!(65535, rule.max_port);
    }

    #[test]
    fn test_valid_ipv4_addresses() {
        let test_cases: Vec<(&str, &str, &str, u8)> = vec![
            ("0.0.0.0", "0.0.0.0", "255.255.255.255", 32),
            ("127.0.0.1/32", "127.0.0.1", "255.255.255.255", 32),
            ("192.168.0.50/24", "192.168.0.50", "255.255.255.0", 24),
            ("255.255.255.255/0", "255.255.255.255", "0.0.0.0", 0),
        ];

        for (rule_addr, address, mask, masked_bits) in test_cases {
            let rule = ExitPolicyRule::parse(&format!("accept {}:*", rule_addr)).unwrap();
            assert_eq!(AddressType::IPv4, rule.get_address_type());
            assert_eq!(
                Some(address.parse::<IpAddr>().unwrap()),
                rule.address(),
                "address for {}",
                rule_addr
            );
            assert_eq!(
                Some(mask.parse::<IpAddr>().unwrap()),
                rule.get_mask(),
                "mask for {}",
                rule_addr
            );
            assert_eq!(
                Some(masked_bits),
                rule.get_masked_bits(),
                "bits for {}",
                rule_addr
            );
        }
    }

    #[test]
    fn test_invalid_ipv4_addresses() {
        let invalid_inputs = [
            "256.0.0.0",
            "0.0.0",
            "0.0.0.",
            "0.0.0.a",
            "127.0.0.1/-1",
            "127.0.0.1/33",
        ];

        for addr in invalid_inputs {
            assert!(
                ExitPolicyRule::parse(&format!("accept {}:*", addr)).is_err(),
                "expected error for: {}",
                addr
            );
        }
    }

    #[test]
    fn test_valid_ipv6_addresses() {
        let rule = ExitPolicyRule::parse("accept [fe80::0202:b3ff:fe1e:8329]:*").unwrap();
        assert_eq!(AddressType::IPv6, rule.get_address_type());
        assert_eq!(Some(128), rule.get_masked_bits());

        let rule = ExitPolicyRule::parse("accept [::]:*").unwrap();
        assert_eq!(AddressType::IPv6, rule.get_address_type());
        assert_eq!(Some(128), rule.get_masked_bits());

        let rule = ExitPolicyRule::parse("accept [::]/0:*").unwrap();
        assert_eq!(Some(0), rule.get_masked_bits());
    }

    #[test]
    fn test_invalid_ipv6_addresses() {
        let invalid_inputs = [
            "fe80::0202:b3ff:fe1e:8329",
            "[fe80::0202:b3ff:fe1e:8329",
            "fe80::0202:b3ff:fe1e:8329]",
            "[fe80::0202:b3ff:fe1e:8329]/-1",
            "[fe80::0202:b3ff:fe1e:8329]/129",
        ];

        for addr in invalid_inputs {
            assert!(
                ExitPolicyRule::parse(&format!("accept {}:*", addr)).is_err(),
                "expected error for: {}",
                addr
            );
        }
    }

    #[test]
    fn test_valid_ports() {
        let test_cases: Vec<(&str, u16, u16)> = vec![
            ("0", 0, 0),
            ("1", 1, 1),
            ("80", 80, 80),
            ("80-443", 80, 443),
        ];

        for (port_str, min_port, max_port) in test_cases {
            let rule = ExitPolicyRule::parse(&format!("accept 127.0.0.1:{}", port_str)).unwrap();
            assert_eq!(min_port, rule.min_port, "min_port for {}", port_str);
            assert_eq!(max_port, rule.max_port, "max_port for {}", port_str);
        }
    }

    #[test]
    fn test_invalid_ports() {
        let invalid_inputs = ["65536", "a", "5-3", "5-", "-3"];

        for port in invalid_inputs {
            assert!(
                ExitPolicyRule::parse(&format!("accept 127.0.0.1:{}", port)).is_err(),
                "expected error for port: {}",
                port
            );
        }
    }

    #[test]
    fn test_is_match_wildcard_rule() {
        let rule = ExitPolicyRule::parse("reject *:*").unwrap();
        assert!(rule.is_match(Some("192.168.0.1".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("0.0.0.0".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("255.255.255.255".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("fe80::0202:b3ff:fe1e:8329".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("192.168.0.1".parse().unwrap()), None));
        assert!(rule.is_match(None, Some(80)));
        assert!(rule.is_match(None, None));
    }

    #[test]
    fn test_is_match_ipv4_specific() {
        let rule = ExitPolicyRule::parse("reject 192.168.0.50:*").unwrap();
        assert!(rule.is_match(Some("192.168.0.50".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("192.168.0.51".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("192.168.0.49".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("192.168.0.50".parse().unwrap()), None));
    }

    #[test]
    fn test_is_match_ipv4_cidr() {
        let rule = ExitPolicyRule::parse("reject 0.0.0.0/24:*").unwrap();
        assert!(rule.is_match(Some("0.0.0.0".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("0.0.0.1".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("0.0.0.255".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("0.0.1.0".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("0.1.0.0".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("1.0.0.0".parse().unwrap()), Some(80)));
    }

    #[test]
    fn test_is_match_ipv6_specific() {
        let rule = ExitPolicyRule::parse("reject [fe80::0202:b3ff:fe1e:8329]:*").unwrap();
        assert!(rule.is_match(Some("fe80::0202:b3ff:fe1e:8329".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("fe80::0202:b3ff:fe1e:8330".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("fe80::0202:b3ff:fe1e:8328".parse().unwrap()), Some(80)));
    }

    #[test]
    fn test_is_match_ipv6_cidr() {
        let rule = ExitPolicyRule::parse("reject [fe80::0202:b3ff:fe1e:8329]/112:*").unwrap();
        assert!(rule.is_match(Some("fe80::0202:b3ff:fe1e:8329".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("fe80::0202:b3ff:fe1e:0000".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("fe80::0202:b3ff:fe1e:ffff".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("fe80::0202:b3ff:fe1f:8329".parse().unwrap()), Some(80)));
    }

    #[test]
    fn test_is_match_port_specific() {
        let rule = ExitPolicyRule::parse("reject *:80").unwrap();
        assert!(rule.is_match(Some("192.168.0.50".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("192.168.0.50".parse().unwrap()), Some(81)));
        assert!(!rule.is_match(Some("192.168.0.50".parse().unwrap()), Some(79)));
        assert!(rule.is_match(None, Some(80)));
    }

    #[test]
    fn test_is_match_port_range() {
        let rule = ExitPolicyRule::parse("reject *:80-85").unwrap();
        assert!(!rule.is_match(Some("192.168.0.50".parse().unwrap()), Some(79)));
        assert!(rule.is_match(Some("192.168.0.50".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("192.168.0.50".parse().unwrap()), Some(83)));
        assert!(rule.is_match(Some("192.168.0.50".parse().unwrap()), Some(85)));
        assert!(!rule.is_match(Some("192.168.0.50".parse().unwrap()), Some(86)));
        assert!(rule.is_match(None, Some(83)));
    }

    #[test]
    fn test_ipv4_ipv6_address_family_mismatch() {
        let rule = ExitPolicyRule::parse("reject *4:*").unwrap();
        assert!(rule.is_match(Some("192.168.0.1".parse().unwrap()), Some(80)));
        assert!(!rule.is_match(Some("fe80::0202:b3ff:fe1e:8329".parse().unwrap()), Some(80)));

        let rule = ExitPolicyRule::parse("reject *6:*").unwrap();
        assert!(!rule.is_match(Some("192.168.0.1".parse().unwrap()), Some(80)));
        assert!(rule.is_match(Some("fe80::0202:b3ff:fe1e:8329".parse().unwrap()), Some(80)));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn ipv4_addr() -> impl Strategy<Value = Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    fn ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
        (
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
        )
            .prop_map(|(a, b, c, d, e, f, g, h)| Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    fn valid_port() -> impl Strategy<Value = u16> {
        1..=65535u16
    }

    fn valid_port_range() -> impl Strategy<Value = (u16, u16)> {
        (1..=65535u16).prop_flat_map(|min| (Just(min), min..=65535u16))
    }

    fn cidr_mask_ipv4() -> impl Strategy<Value = u8> {
        0..=32u8
    }

    fn cidr_mask_ipv6() -> impl Strategy<Value = u8> {
        0..=128u8
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_exit_policy_evaluation_consistency(
            addr in ipv4_addr(),
            port in valid_port()
        ) {
            let policy = ExitPolicy::from_rules(&["accept *:80", "accept *:443", "reject *:*"]).unwrap();
            let result1 = policy.can_exit_to(IpAddr::V4(addr), port);
            let result2 = policy.can_exit_to(IpAddr::V4(addr), port);
            prop_assert_eq!(result1, result2, "evaluation should be consistent");

            let expected = port == 80 || port == 443;
            prop_assert_eq!(expected, result1, "port {} should be {}", port, expected);
        }

        #[test]
        fn prop_exit_policy_cidr_matching_ipv4(
            network_base in 0..=255u8,
            mask_bits in cidr_mask_ipv4(),
            test_addr in ipv4_addr(),
            port in valid_port()
        ) {
            let network = Ipv4Addr::new(network_base, 0, 0, 0);
            let rule_str = format!("accept {}/{}:*", network, mask_bits);
            let rule = ExitPolicyRule::parse(&rule_str).unwrap();

            let network_u32 = u32::from_be_bytes(network.octets());
            let test_u32 = u32::from_be_bytes(test_addr.octets());
            let mask = if mask_bits == 0 { 0 } else { !((1u32 << (32 - mask_bits)) - 1) };

            let should_match = (network_u32 & mask) == (test_u32 & mask);
            let does_match = rule.is_match(Some(IpAddr::V4(test_addr)), Some(port));

            prop_assert_eq!(should_match, does_match,
                "CIDR {}/{} test {} expected {} got {}",
                network, mask_bits, test_addr, should_match, does_match);
        }

        #[test]
        fn prop_exit_policy_cidr_matching_ipv6(
            mask_bits in cidr_mask_ipv6(),
            test_addr in ipv6_addr(),
            port in valid_port()
        ) {
            let network = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
            let rule_str = format!("accept [{}]/{}:*", network, mask_bits);
            let rule = ExitPolicyRule::parse(&rule_str).unwrap();

            let network_u128 = u128::from_be_bytes(network.octets());
            let test_u128 = u128::from_be_bytes(test_addr.octets());
            let mask = if mask_bits == 0 { 0 } else { !((1u128 << (128 - mask_bits)) - 1) };

            let should_match = (network_u128 & mask) == (test_u128 & mask);
            let does_match = rule.is_match(Some(IpAddr::V6(test_addr)), Some(port));

            prop_assert_eq!(should_match, does_match,
                "CIDR [{}]/{} test {} expected {} got {}",
                network, mask_bits, test_addr, should_match, does_match);
        }

        #[test]
        fn prop_exit_policy_port_range_matching(
            (min_port, max_port) in valid_port_range(),
            test_port in valid_port(),
            addr in ipv4_addr()
        ) {
            let rule_str = format!("accept *:{}-{}", min_port, max_port);
            let rule = ExitPolicyRule::parse(&rule_str).unwrap();

            let should_match = test_port >= min_port && test_port <= max_port;
            let does_match = rule.is_match(Some(IpAddr::V4(addr)), Some(test_port));

            prop_assert_eq!(should_match, does_match,
                "port range {}-{} test {} expected {} got {}",
                min_port, max_port, test_port, should_match, does_match);
        }

        #[test]
        fn prop_policy_first_match_semantics(
            addr in ipv4_addr(),
            port in valid_port()
        ) {
            let policy = ExitPolicy::from_rules(&[
                "reject 10.0.0.0/8:*",
                "accept *:80",
                "reject *:*"
            ]).unwrap();

            let is_10_network = addr.octets()[0] == 10;
            let result = policy.can_exit_to(IpAddr::V4(addr), port);

            if is_10_network {
                prop_assert!(!result, "10.x.x.x should be rejected");
            } else if port == 80 {
                prop_assert!(result, "port 80 should be accepted for non-10.x.x.x");
            } else {
                prop_assert!(!result, "other ports should be rejected for non-10.x.x.x");
            }
        }

        #[test]
        fn prop_micro_policy_port_matching(
            port1 in valid_port(),
            port2 in valid_port(),
            test_port in valid_port()
        ) {
            let (min, max) = if port1 <= port2 { (port1, port2) } else { (port2, port1) };
            let policy_str = format!("accept {}-{}", min, max);
            let policy = MicroExitPolicy::parse(&policy_str).unwrap();

            let should_match = test_port >= min && test_port <= max;
            let does_match = policy.can_exit_to(test_port);

            prop_assert_eq!(should_match, does_match,
                "micro policy {}-{} test {} expected {} got {}",
                min, max, test_port, should_match, does_match);
        }

        #[test]
        fn prop_port_range_contains(
            (min, max) in valid_port_range(),
            test_port in valid_port()
        ) {
            let range = PortRange::new(min, max).unwrap();
            let should_contain = test_port >= min && test_port <= max;
            prop_assert_eq!(should_contain, range.contains(test_port));
        }

        #[test]
        fn prop_address_type_ipv4(addr in ipv4_addr(), port in valid_port()) {
            let rule_str = format!("accept {}:*", addr);
            let rule = ExitPolicyRule::parse(&rule_str).unwrap();
            prop_assert_eq!(AddressType::IPv4, rule.get_address_type());
            prop_assert!(rule.is_match(Some(IpAddr::V4(addr)), Some(port)));
        }

        #[test]
        fn prop_address_type_ipv6(addr in ipv6_addr(), port in valid_port()) {
            let rule_str = format!("accept [{}]:*", addr);
            let rule = ExitPolicyRule::parse(&rule_str).unwrap();
            prop_assert_eq!(AddressType::IPv6, rule.get_address_type());
            prop_assert!(rule.is_match(Some(IpAddr::V6(addr)), Some(port)));
        }
    }
}
