//! Server descriptor parsing for Tor relay descriptors.
//!
//! This module provides parsing for server descriptors, which are the primary
//! documents that Tor relays publish to describe themselves to the network.
//! Server descriptors contain comprehensive metadata about a relay including
//! its identity, network addresses, bandwidth capabilities, exit policy,
//! and cryptographic keys.
//!
//! # Overview
//!
//! Server descriptors are published by relays to directory authorities and
//! cached by clients. They contain:
//!
//! - **Identity information**: Nickname, fingerprint, contact info
//! - **Network addresses**: IPv4/IPv6 addresses and ports (OR, SOCKS, Dir)
//! - **Bandwidth**: Advertised and observed bandwidth values
//! - **Exit policy**: Rules for what traffic the relay will exit
//! - **Cryptographic keys**: Onion keys, signing keys, Ed25519 certificates
//! - **Protocol versions**: Supported link and circuit protocol versions
//! - **Family**: Related relays operated by the same entity
//!
//! # Descriptor Format
//!
//! Server descriptors follow a text-based format defined in the
//! [Tor directory protocol specification](https://spec.torproject.org/dir-spec).
//! The format consists of keyword-value lines, with some values spanning
//! multiple lines (like PEM-encoded keys).
//!
//! ```text
//! router <nickname> <address> <ORPort> <SOCKSPort> <DirPort>
//! platform Tor <version> on <OS>
//! published <YYYY-MM-DD HH:MM:SS>
//! fingerprint <40 hex chars with spaces>
//! bandwidth <avg> <burst> <observed>
//! onion-key
//! -----BEGIN RSA PUBLIC KEY-----
//! <base64 encoded key>
//! -----END RSA PUBLIC KEY-----
//! signing-key
//! -----BEGIN RSA PUBLIC KEY-----
//! <base64 encoded key>
//! -----END RSA PUBLIC KEY-----
//! accept|reject <exit policy rule>
//! router-signature
//! -----BEGIN SIGNATURE-----
//! <base64 encoded signature>
//! -----END SIGNATURE-----
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::descriptor::{ServerDescriptor, Descriptor, DigestHash, DigestEncoding};
//!
//! let content = r#"router example 192.168.1.1 9001 0 0
//! published 2023-01-01 00:00:00
//! bandwidth 1000000 2000000 500000
//! accept *:80
//! accept *:443
//! reject *:*
//! router-signature
//! -----BEGIN SIGNATURE-----
//! dGVzdA==
//! -----END SIGNATURE-----
//! "#;
//!
//! let descriptor = ServerDescriptor::parse(content).unwrap();
//! println!("Relay: {} at {}", descriptor.nickname, descriptor.address);
//! println!("Bandwidth: {} bytes/sec observed", descriptor.bandwidth_observed);
//!
//! // Check exit policy
//! if descriptor.exit_policy.can_exit_to("10.0.0.1".parse().unwrap(), 80) {
//!     println!("Allows HTTP traffic");
//! }
//! ```
//!
//! # Digest Computation
//!
//! Server descriptor digests are computed over the content from the
//! `router` line through the `router-signature` line (inclusive of the
//! newline after `router-signature`). This is the signed portion of
//! the descriptor.
//!
//! # Bridge Descriptors
//!
//! Bridge descriptors are similar to server descriptors but have some
//! fields redacted for privacy. They use the `bridge-server-descriptor`
//! type annotation and may have different `bridge-distribution-request`
//! values.
//!
//! # See Also
//!
//! - [`Microdescriptor`](super::Microdescriptor) - Compact client-side descriptors
//! - [`ExtraInfoDescriptor`](super::ExtraInfoDescriptor) - Additional relay statistics
//! - [Python Stem ServerDescriptor](https://stem.torproject.org/api/descriptor/server_descriptor.html)

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::exit_policy::ExitPolicy;
use crate::version::Version;
use crate::{BridgeDistribution, Error};

use super::{compute_digest, Descriptor, DigestEncoding, DigestHash};

type RouterLineResult = (String, IpAddr, u16, Option<u16>, Option<u16>);

/// A server descriptor containing metadata about a Tor relay.
///
/// Server descriptors are the primary documents that relays publish to
/// describe themselves. They contain identity information, network addresses,
/// bandwidth capabilities, exit policies, and cryptographic keys needed
/// for circuit construction.
///
/// # Fields Overview
///
/// | Category | Fields |
/// |----------|--------|
/// | Identity | `nickname`, `fingerprint`, `contact` |
/// | Network | `address`, `or_port`, `dir_port`, `or_addresses` |
/// | Bandwidth | `bandwidth_avg`, `bandwidth_burst`, `bandwidth_observed` |
/// | Policy | `exit_policy`, `exit_policy_v6` |
/// | Keys | `onion_key`, `signing_key`, `ntor_onion_key`, Ed25519 keys |
/// | Protocols | `protocols`, `link_protocols`, `circuit_protocols` |
/// | Metadata | `platform`, `tor_version`, `published`, `uptime` |
///
/// # Invariants
///
/// - `nickname` is 1-19 alphanumeric characters
/// - `fingerprint` is 40 uppercase hex characters (if present)
/// - `or_port` is non-zero
/// - `published` is a valid UTC timestamp
/// - `signature` is always present and non-empty
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::descriptor::{ServerDescriptor, Descriptor};
///
/// let content = std::fs::read_to_string("server-descriptor").unwrap();
/// let desc = ServerDescriptor::parse(&content).unwrap();
///
/// println!("Nickname: {}", desc.nickname);
/// println!("Address: {}:{}", desc.address, desc.or_port);
/// println!("Published: {}", desc.published);
/// println!("Bandwidth: {} B/s avg, {} B/s observed",
///          desc.bandwidth_avg, desc.bandwidth_observed);
///
/// if let Some(ref fp) = desc.fingerprint {
///     println!("Fingerprint: {}", fp);
/// }
///
/// if let Some(ref version) = desc.tor_version {
///     println!("Tor version: {}", version);
/// }
/// ```
///
/// # Thread Safety
///
/// `ServerDescriptor` is `Send` and `Sync` as it contains only owned data.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerDescriptor {
    /// The relay's nickname (1-19 alphanumeric characters).
    pub nickname: String,
    /// The relay's fingerprint (40 hex characters), derived from identity key.
    pub fingerprint: Option<String>,
    /// The relay's primary IPv4 address.
    pub address: IpAddr,
    /// The relay's onion routing port (always non-zero).
    pub or_port: u16,
    /// The relay's SOCKS port (deprecated, usually None).
    pub socks_port: Option<u16>,
    /// The relay's directory port for serving cached descriptors.
    pub dir_port: Option<u16>,
    /// Additional addresses (IPv4 or IPv6) the relay listens on.
    /// Each tuple is (address, port, is_ipv6).
    pub or_addresses: Vec<(IpAddr, u16, bool)>,
    /// Raw platform string (e.g., "Tor 0.4.7.10 on Linux").
    pub platform: Option<Vec<u8>>,
    /// Parsed Tor version from the platform string.
    pub tor_version: Option<Version>,
    /// Operating system from the platform string.
    pub operating_system: Option<String>,
    /// When this descriptor was published (UTC).
    pub published: DateTime<Utc>,
    /// Seconds the relay has been running.
    pub uptime: Option<u64>,
    /// Contact information for the relay operator.
    pub contact: Option<Vec<u8>>,
    /// Supported link protocol versions (legacy).
    pub link_protocols: Option<Vec<String>>,
    /// Supported circuit protocol versions (legacy).
    pub circuit_protocols: Option<Vec<String>>,
    /// Average bandwidth in bytes per second the relay is willing to sustain.
    pub bandwidth_avg: u64,
    /// Maximum bandwidth in bytes per second for short bursts.
    pub bandwidth_burst: u64,
    /// Bandwidth in bytes per second the relay has actually observed.
    pub bandwidth_observed: u64,
    /// The relay's exit policy (rules for what traffic it will exit).
    pub exit_policy: ExitPolicy,
    /// IPv6 exit policy summary (e.g., "accept 80,443" or "reject 1-65535").
    pub exit_policy_v6: Option<String>,
    /// How this bridge wants to be distributed (bridges only).
    pub bridge_distribution: BridgeDistribution,
    /// Fingerprints of related relays (same operator).
    pub family: HashSet<String>,
    /// Whether the relay is currently hibernating (reduced service).
    pub hibernating: bool,
    /// Whether the relay allows single-hop exits (security risk).
    pub allow_single_hop_exits: bool,
    /// Whether the relay accepts tunneled directory requests.
    pub allow_tunneled_dir_requests: bool,
    /// Whether the relay caches extra-info descriptors.
    pub extra_info_cache: bool,
    /// SHA-1 digest of the relay's extra-info descriptor.
    pub extra_info_digest: Option<String>,
    /// SHA-256 digest of the relay's extra-info descriptor.
    pub extra_info_sha256_digest: Option<String>,
    /// Whether the relay serves as a hidden service directory.
    pub is_hidden_service_dir: bool,
    /// Supported protocol versions (modern format).
    /// Maps protocol name to list of supported versions.
    pub protocols: HashMap<String, Vec<u32>>,
    /// RSA onion key for circuit creation (PEM format).
    pub onion_key: Option<String>,
    /// Cross-certification of onion key by identity key.
    pub onion_key_crosscert: Option<String>,
    /// Curve25519 onion key for ntor handshake (base64).
    pub ntor_onion_key: Option<String>,
    /// Cross-certification of ntor key.
    pub ntor_onion_key_crosscert: Option<String>,
    /// Sign bit for ntor key cross-certification.
    pub ntor_onion_key_crosscert_sign: Option<String>,
    /// RSA signing key (PEM format).
    pub signing_key: Option<String>,
    /// Ed25519 identity certificate (PEM format).
    pub ed25519_certificate: Option<String>,
    /// Ed25519 master key (base64).
    pub ed25519_master_key: Option<String>,
    /// Ed25519 signature over the descriptor.
    pub ed25519_signature: Option<String>,
    /// RSA signature over the descriptor (PEM format).
    pub signature: String,
    /// Raw bytes of the original descriptor content.
    raw_content: Vec<u8>,
    /// Lines that were not recognized during parsing.
    unrecognized_lines: Vec<String>,
}

impl ServerDescriptor {
    /// Creates a new server descriptor with minimal required fields.
    ///
    /// This creates a descriptor with default values for optional fields.
    /// Use this for testing or when constructing descriptors programmatically.
    ///
    /// # Arguments
    ///
    /// * `nickname` - The relay's nickname (1-19 alphanumeric characters)
    /// * `address` - The relay's primary IP address
    /// * `or_port` - The relay's onion routing port
    /// * `published` - When this descriptor was published
    /// * `signature` - The RSA signature (PEM format)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::ServerDescriptor;
    /// use chrono::Utc;
    /// use std::net::IpAddr;
    ///
    /// let desc = ServerDescriptor::new(
    ///     "MyRelay".to_string(),
    ///     "192.168.1.1".parse().unwrap(),
    ///     9001,
    ///     Utc::now(),
    ///     "-----BEGIN SIGNATURE-----\ntest\n-----END SIGNATURE-----".to_string(),
    /// );
    ///
    /// assert_eq!(desc.nickname, "MyRelay");
    /// assert_eq!(desc.or_port, 9001);
    /// ```
    pub fn new(
        nickname: String,
        address: IpAddr,
        or_port: u16,
        published: DateTime<Utc>,
        signature: String,
    ) -> Self {
        Self {
            nickname,
            fingerprint: None,
            address,
            or_port,
            socks_port: None,
            dir_port: None,
            or_addresses: Vec::new(),
            platform: None,
            tor_version: None,
            operating_system: None,
            published,
            uptime: None,
            contact: None,
            link_protocols: None,
            circuit_protocols: None,
            bandwidth_avg: 0,
            bandwidth_burst: 0,
            bandwidth_observed: 0,
            exit_policy: ExitPolicy::new(Vec::new()),
            exit_policy_v6: None,
            bridge_distribution: BridgeDistribution::Any,
            family: HashSet::new(),
            hibernating: false,
            allow_single_hop_exits: false,
            allow_tunneled_dir_requests: false,
            extra_info_cache: false,
            extra_info_digest: None,
            extra_info_sha256_digest: None,
            is_hidden_service_dir: false,
            protocols: HashMap::new(),
            onion_key: None,
            onion_key_crosscert: None,
            ntor_onion_key: None,
            ntor_onion_key_crosscert: None,
            ntor_onion_key_crosscert_sign: None,
            signing_key: None,
            ed25519_certificate: None,
            ed25519_master_key: None,
            ed25519_signature: None,
            signature,
            raw_content: Vec::new(),
            unrecognized_lines: Vec::new(),
        }
    }

    /// Parses the `router` line of a server descriptor.
    ///
    /// Format: `router <nickname> <address> <ORPort> <SOCKSPort> <DirPort>`
    fn parse_router_line(line: &str) -> Result<RouterLineResult, Error> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Err(Error::Parse {
                location: "router".to_string(),
                reason: "router line requires 5 fields".to_string(),
            });
        }

        let nickname = parts[0].to_string();
        if !is_valid_nickname(&nickname) {
            return Err(Error::Parse {
                location: "router".to_string(),
                reason: format!("invalid nickname: {}", nickname),
            });
        }

        let address: IpAddr = parts[1].parse().map_err(|_| Error::Parse {
            location: "router".to_string(),
            reason: format!("invalid address: {}", parts[1]),
        })?;

        let or_port: u16 = parts[2].parse().map_err(|_| Error::Parse {
            location: "router".to_string(),
            reason: format!("invalid or_port: {}", parts[2]),
        })?;

        let socks_port: Option<u16> = {
            let port: u16 = parts[3].parse().map_err(|_| Error::Parse {
                location: "router".to_string(),
                reason: format!("invalid socks_port: {}", parts[3]),
            })?;
            if port == 0 {
                None
            } else {
                Some(port)
            }
        };

        let dir_port: Option<u16> = {
            let port: u16 = parts[4].parse().map_err(|_| Error::Parse {
                location: "router".to_string(),
                reason: format!("invalid dir_port: {}", parts[4]),
            })?;
            if port == 0 {
                None
            } else {
                Some(port)
            }
        };

        Ok((nickname, address, or_port, socks_port, dir_port))
    }

    fn parse_bandwidth_line(line: &str) -> Result<(u64, u64, u64), Error> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Error::Parse {
                location: "bandwidth".to_string(),
                reason: "bandwidth line requires 3 values".to_string(),
            });
        }

        let avg: u64 = parts[0].parse().map_err(|_| Error::Parse {
            location: "bandwidth".to_string(),
            reason: format!("invalid average bandwidth: {}", parts[0]),
        })?;

        let burst: u64 = parts[1].parse().map_err(|_| Error::Parse {
            location: "bandwidth".to_string(),
            reason: format!("invalid burst bandwidth: {}", parts[1]),
        })?;

        let observed: u64 = parts[2].parse().map_err(|_| Error::Parse {
            location: "bandwidth".to_string(),
            reason: format!("invalid observed bandwidth: {}", parts[2]),
        })?;

        Ok((avg, burst, observed))
    }

    fn parse_published_line(line: &str) -> Result<DateTime<Utc>, Error> {
        let datetime =
            NaiveDateTime::parse_from_str(line.trim(), "%Y-%m-%d %H:%M:%S").map_err(|e| {
                Error::Parse {
                    location: "published".to_string(),
                    reason: format!("invalid datetime: {} - {}", line, e),
                }
            })?;
        Ok(datetime.and_utc())
    }

    fn parse_fingerprint_line(line: &str) -> String {
        line.replace(' ', "")
    }

    fn parse_platform_line(line: &str) -> (Option<Vec<u8>>, Option<Version>, Option<String>) {
        let platform = line.as_bytes().to_vec();
        let mut tor_version = None;
        let mut operating_system = None;

        if let Some(on_pos) = line.find(" on ") {
            let version_part = &line[..on_pos];
            operating_system = Some(line[on_pos + 4..].to_string());

            if let Some(ver_start) = version_part.find(char::is_whitespace) {
                let ver_str = version_part[ver_start..].trim();
                if let Ok(v) = Version::parse(ver_str) {
                    tor_version = Some(v);
                }
            }
        }

        (Some(platform), tor_version, operating_system)
    }

    fn parse_protocols_line(line: &str) -> (Option<Vec<String>>, Option<Vec<String>>) {
        let mut link_protocols = None;
        let mut circuit_protocols = None;
        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut i = 0;
        while i < parts.len() {
            if parts[i] == "Link" {
                let mut protos = Vec::new();
                i += 1;
                while i < parts.len() && parts[i] != "Circuit" {
                    protos.push(parts[i].to_string());
                    i += 1;
                }
                link_protocols = Some(protos);
            } else if parts[i] == "Circuit" {
                let mut protos = Vec::new();
                i += 1;
                while i < parts.len() && parts[i] != "Link" {
                    protos.push(parts[i].to_string());
                    i += 1;
                }
                circuit_protocols = Some(protos);
            } else {
                i += 1;
            }
        }
        (link_protocols, circuit_protocols)
    }

    fn parse_family_line(line: &str) -> HashSet<String> {
        line.split_whitespace().map(|s| s.to_string()).collect()
    }

    fn parse_or_address(line: &str) -> Result<(IpAddr, u16, bool), Error> {
        let line = line.trim();
        if line.starts_with('[') {
            if let Some(bracket_end) = line.find(']') {
                let ipv6_str = &line[1..bracket_end];
                let port_str = &line[bracket_end + 2..];
                let addr: IpAddr = ipv6_str.parse().map_err(|_| Error::Parse {
                    location: "or-address".to_string(),
                    reason: format!("invalid IPv6 address: {}", ipv6_str),
                })?;
                let port: u16 = port_str.parse().map_err(|_| Error::Parse {
                    location: "or-address".to_string(),
                    reason: format!("invalid port: {}", port_str),
                })?;
                return Ok((addr, port, true));
            }
        }

        if let Some(colon_pos) = line.rfind(':') {
            let addr_str = &line[..colon_pos];
            let port_str = &line[colon_pos + 1..];
            let addr: IpAddr = addr_str.parse().map_err(|_| Error::Parse {
                location: "or-address".to_string(),
                reason: format!("invalid address: {}", addr_str),
            })?;
            let port: u16 = port_str.parse().map_err(|_| Error::Parse {
                location: "or-address".to_string(),
                reason: format!("invalid port: {}", port_str),
            })?;
            let is_ipv6 = addr.is_ipv6();
            return Ok((addr, port, is_ipv6));
        }

        Err(Error::Parse {
            location: "or-address".to_string(),
            reason: format!("invalid or-address format: {}", line),
        })
    }

    fn parse_extra_info_digest(line: &str) -> (Option<String>, Option<String>) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let sha1_digest = parts.first().map(|s| s.to_string());
        let sha256_digest = parts.get(1).map(|s| s.to_string());
        (sha1_digest, sha256_digest)
    }

    fn extract_pem_block(lines: &[&str], start_idx: usize) -> (String, usize) {
        let mut block = String::new();
        let mut idx = start_idx;
        while idx < lines.len() {
            let line = lines[idx];
            block.push_str(line);
            block.push('\n');
            if line.starts_with("-----END ") {
                break;
            }
            idx += 1;
        }
        (block.trim_end().to_string(), idx)
    }

    /// Finds the content range used for digest computation.
    ///
    /// The digest is computed from `router ` through `router-signature\n`.
    fn find_digest_content(content: &str) -> Option<&str> {
        let start_marker = "router ";
        let end_marker = "\nrouter-signature\n";
        let start = content.find(start_marker)?;
        let end = content.find(end_marker)?;
        Some(&content[start..end + end_marker.len()])
    }
}

/// Validates a relay nickname.
///
/// A valid nickname is 1-19 characters, all alphanumeric (a-z, A-Z, 0-9).
///
/// # Arguments
///
/// * `nickname` - The nickname to validate
///
/// # Returns
///
/// `true` if the nickname is valid, `false` otherwise.
fn is_valid_nickname(nickname: &str) -> bool {
    if nickname.is_empty() || nickname.len() > 19 {
        return false;
    }
    nickname.chars().all(|c| c.is_ascii_alphanumeric())
}

impl Descriptor for ServerDescriptor {
    fn parse(content: &str) -> Result<Self, Error> {
        let raw_content = content.as_bytes().to_vec();
        let lines: Vec<&str> = content.lines().collect();

        let mut nickname = String::new();
        let mut address: Option<IpAddr> = None;
        let mut or_port: u16 = 0;
        let mut socks_port: Option<u16> = None;
        let mut dir_port: Option<u16> = None;
        let mut fingerprint: Option<String> = None;
        let mut or_addresses: Vec<(IpAddr, u16, bool)> = Vec::new();
        let mut platform: Option<Vec<u8>> = None;
        let mut tor_version: Option<Version> = None;
        let mut operating_system: Option<String> = None;
        let mut published: Option<DateTime<Utc>> = None;
        let mut uptime: Option<u64> = None;
        let mut contact: Option<Vec<u8>> = None;
        let mut link_protocols: Option<Vec<String>> = None;
        let mut circuit_protocols: Option<Vec<String>> = None;
        let mut bandwidth_avg: u64 = 0;
        let mut bandwidth_burst: u64 = 0;
        let mut bandwidth_observed: u64 = 0;
        let mut exit_policy_rules: Vec<String> = Vec::new();
        let mut exit_policy_v6: Option<String> = None;
        let mut bridge_distribution = BridgeDistribution::Any;
        let mut family: HashSet<String> = HashSet::new();
        let mut hibernating = false;
        let mut allow_single_hop_exits = false;
        let mut allow_tunneled_dir_requests = false;
        let mut extra_info_cache = false;
        let mut extra_info_digest: Option<String> = None;
        let mut extra_info_sha256_digest: Option<String> = None;
        let mut is_hidden_service_dir = false;
        let mut protocols: HashMap<String, Vec<u32>> = HashMap::new();
        let mut onion_key: Option<String> = None;
        let mut onion_key_crosscert: Option<String> = None;
        let mut ntor_onion_key: Option<String> = None;
        let mut ntor_onion_key_crosscert: Option<String> = None;
        let mut ntor_onion_key_crosscert_sign: Option<String> = None;
        let mut signing_key: Option<String> = None;
        let mut ed25519_certificate: Option<String> = None;
        let mut ed25519_master_key: Option<String> = None;
        let mut ed25519_signature: Option<String> = None;
        let mut signature = String::new();
        let mut unrecognized_lines: Vec<String> = Vec::new();

        let mut idx = 0;
        while idx < lines.len() {
            let line = lines[idx];

            if line.starts_with("@type ") {
                idx += 1;
                continue;
            }

            let line = line.strip_prefix("opt ").unwrap_or(line);

            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "router" => {
                    let (n, a, op, sp, dp) = Self::parse_router_line(value)?;
                    nickname = n;
                    address = Some(a);
                    or_port = op;
                    socks_port = sp;
                    dir_port = dp;
                }
                "identity-ed25519" => {
                    let (block, end_idx) = Self::extract_pem_block(&lines, idx + 1);
                    ed25519_certificate = Some(block);
                    idx = end_idx;
                }
                "master-key-ed25519" => {
                    ed25519_master_key = Some(value.to_string());
                }
                "bandwidth" => {
                    let (avg, burst, obs) = Self::parse_bandwidth_line(value)?;
                    bandwidth_avg = avg;
                    bandwidth_burst = burst;
                    bandwidth_observed = obs;
                }
                "platform" => {
                    let (p, v, os) = Self::parse_platform_line(value);
                    platform = p;
                    tor_version = v;
                    operating_system = os;
                }
                "published" => {
                    published = Some(Self::parse_published_line(value)?);
                }
                "fingerprint" => {
                    fingerprint = Some(Self::parse_fingerprint_line(value));
                }
                "uptime" => {
                    uptime = value.parse().ok();
                }
                "contact" => {
                    contact = Some(value.as_bytes().to_vec());
                }
                "protocols" => {
                    let (lp, cp) = Self::parse_protocols_line(value);
                    link_protocols = lp;
                    circuit_protocols = cp;
                }
                "proto" => {
                    for entry in value.split_whitespace() {
                        if let Some(eq_pos) = entry.find('=') {
                            let proto_name = &entry[..eq_pos];
                            let versions_str = &entry[eq_pos + 1..];
                            let versions: Vec<u32> = versions_str
                                .split(',')
                                .filter_map(|v| {
                                    if let Some(dash) = v.find('-') {
                                        let start: u32 = v[..dash].parse().ok()?;
                                        let end: u32 = v[dash + 1..].parse().ok()?;
                                        Some((start..=end).collect::<Vec<_>>())
                                    } else {
                                        v.parse().ok().map(|n| vec![n])
                                    }
                                })
                                .flatten()
                                .collect();
                            protocols.insert(proto_name.to_string(), versions);
                        }
                    }
                }
                "family" => {
                    family = Self::parse_family_line(value);
                }
                "or-address" => {
                    if let Ok(addr) = Self::parse_or_address(value) {
                        or_addresses.push(addr);
                    }
                }
                "extra-info-digest" => {
                    let (sha1, sha256) = Self::parse_extra_info_digest(value);
                    extra_info_digest = sha1;
                    extra_info_sha256_digest = sha256;
                }
                "hidden-service-dir" => {
                    is_hidden_service_dir = true;
                }
                "caches-extra-info" => {
                    extra_info_cache = true;
                }
                "hibernating" => {
                    hibernating = value == "1";
                }
                "allow-single-hop-exits" => {
                    allow_single_hop_exits = true;
                }
                "tunnelled-dir-server" => {
                    allow_tunneled_dir_requests = true;
                }
                "bridge-distribution-request" => {
                    bridge_distribution = match value.to_lowercase().as_str() {
                        "https" => BridgeDistribution::Https,
                        "email" => BridgeDistribution::Email,
                        "moat" => BridgeDistribution::Moat,
                        "hyphae" => BridgeDistribution::Hyphae,
                        _ => BridgeDistribution::Any,
                    };
                }
                "accept" | "reject" => {
                    exit_policy_rules.push(line.to_string());
                }
                "ipv6-policy" => {
                    exit_policy_v6 = Some(value.to_string());
                }
                "onion-key" => {
                    let (block, end_idx) = Self::extract_pem_block(&lines, idx + 1);
                    onion_key = Some(block);
                    idx = end_idx;
                }
                "onion-key-crosscert" => {
                    let (block, end_idx) = Self::extract_pem_block(&lines, idx + 1);
                    onion_key_crosscert = Some(block);
                    idx = end_idx;
                }
                "ntor-onion-key" => {
                    ntor_onion_key = Some(value.to_string());
                }
                "ntor-onion-key-crosscert" => {
                    ntor_onion_key_crosscert_sign = Some(value.to_string());
                    let (block, end_idx) = Self::extract_pem_block(&lines, idx + 1);
                    ntor_onion_key_crosscert = Some(block);
                    idx = end_idx;
                }
                "signing-key" => {
                    let (block, end_idx) = Self::extract_pem_block(&lines, idx + 1);
                    signing_key = Some(block);
                    idx = end_idx;
                }
                "router-sig-ed25519" => {
                    ed25519_signature = Some(value.to_string());
                }
                "router-signature" => {
                    let (block, end_idx) = Self::extract_pem_block(&lines, idx + 1);
                    signature = block;
                    idx = end_idx;
                }
                _ => {
                    if !line.is_empty() && !line.starts_with("-----") {
                        unrecognized_lines.push(line.to_string());
                    }
                }
            }
            idx += 1;
        }

        let address = address.ok_or_else(|| Error::Parse {
            location: "router".to_string(),
            reason: "missing router line".to_string(),
        })?;

        let published = published.ok_or_else(|| Error::Parse {
            location: "published".to_string(),
            reason: "missing published line".to_string(),
        })?;

        let exit_policy = if exit_policy_rules.is_empty() {
            ExitPolicy::new(Vec::new())
        } else {
            ExitPolicy::from_rules(&exit_policy_rules)?
        };

        Ok(Self {
            nickname,
            fingerprint,
            address,
            or_port,
            socks_port,
            dir_port,
            or_addresses,
            platform,
            tor_version,
            operating_system,
            published,
            uptime,
            contact,
            link_protocols,
            circuit_protocols,
            bandwidth_avg,
            bandwidth_burst,
            bandwidth_observed,
            exit_policy,
            exit_policy_v6,
            bridge_distribution,
            family,
            hibernating,
            allow_single_hop_exits,
            allow_tunneled_dir_requests,
            extra_info_cache,
            extra_info_digest,
            extra_info_sha256_digest,
            is_hidden_service_dir,
            protocols,
            onion_key,
            onion_key_crosscert,
            ntor_onion_key,
            ntor_onion_key_crosscert,
            ntor_onion_key_crosscert_sign,
            signing_key,
            ed25519_certificate,
            ed25519_master_key,
            ed25519_signature,
            signature,
            raw_content,
            unrecognized_lines,
        })
    }

    fn to_descriptor_string(&self) -> String {
        let mut result = String::new();

        result.push_str(&format!(
            "router {} {} {} {} {}\n",
            self.nickname,
            self.address,
            self.or_port,
            self.socks_port.unwrap_or(0),
            self.dir_port.unwrap_or(0)
        ));

        if let Some(ref platform) = self.platform {
            if let Ok(s) = std::str::from_utf8(platform) {
                result.push_str(&format!("platform {}\n", s));
            }
        }

        if let Some(ref link) = self.link_protocols {
            if let Some(ref circuit) = self.circuit_protocols {
                result.push_str(&format!(
                    "protocols Link {} Circuit {}\n",
                    link.join(" "),
                    circuit.join(" ")
                ));
            }
        }

        result.push_str(&format!(
            "published {}\n",
            self.published.format("%Y-%m-%d %H:%M:%S")
        ));

        if let Some(ref fp) = self.fingerprint {
            let formatted: String = fp
                .chars()
                .collect::<Vec<_>>()
                .chunks(4)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(" ");
            result.push_str(&format!("fingerprint {}\n", formatted));
        }

        if let Some(uptime) = self.uptime {
            result.push_str(&format!("uptime {}\n", uptime));
        }

        result.push_str(&format!(
            "bandwidth {} {} {}\n",
            self.bandwidth_avg, self.bandwidth_burst, self.bandwidth_observed
        ));

        if let Some(ref digest) = self.extra_info_digest {
            if let Some(ref sha256) = self.extra_info_sha256_digest {
                result.push_str(&format!("extra-info-digest {} {}\n", digest, sha256));
            } else {
                result.push_str(&format!("extra-info-digest {}\n", digest));
            }
        }

        if let Some(ref key) = self.onion_key {
            result.push_str("onion-key\n");
            result.push_str(key);
            result.push('\n');
        }

        if let Some(ref key) = self.signing_key {
            result.push_str("signing-key\n");
            result.push_str(key);
            result.push('\n');
        }

        if !self.family.is_empty() {
            let family_str: Vec<&str> = self.family.iter().map(|s| s.as_str()).collect();
            result.push_str(&format!("family {}\n", family_str.join(" ")));
        }

        if self.is_hidden_service_dir {
            result.push_str("hidden-service-dir\n");
        }

        if let Some(ref contact) = self.contact {
            if let Ok(s) = std::str::from_utf8(contact) {
                result.push_str(&format!("contact {}\n", s));
            }
        }

        for rule in self.exit_policy.iter() {
            result.push_str(&format!("{}\n", rule));
        }

        result.push_str("router-signature\n");
        result.push_str(&self.signature);
        result.push('\n');

        result
    }

    fn digest(&self, hash: DigestHash, encoding: DigestEncoding) -> Result<String, Error> {
        let content_str = std::str::from_utf8(&self.raw_content).map_err(|_| Error::Parse {
            location: "digest".to_string(),
            reason: "invalid UTF-8 in raw content".to_string(),
        })?;

        let digest_content =
            Self::find_digest_content(content_str).ok_or_else(|| Error::Parse {
                location: "digest".to_string(),
                reason: "could not find digest content boundaries".to_string(),
            })?;

        Ok(compute_digest(digest_content.as_bytes(), hash, encoding))
    }

    fn raw_content(&self) -> &[u8] {
        &self.raw_content
    }

    fn unrecognized_lines(&self) -> &[String] {
        &self.unrecognized_lines
    }
}

impl FromStr for ServerDescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for ServerDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_descriptor_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};

    const EXAMPLE_DESCRIPTOR: &str = r#"@type server-descriptor 1.0
router caerSidi 71.35.133.197 9001 0 0
platform Tor 0.2.1.30 on Linux x86_64
opt protocols Link 1 2 Circuit 1
published 2012-03-01 17:15:27
opt fingerprint A756 9A83 B570 6AB1 B1A9 CB52 EFF7 D2D3 2E45 53EB
uptime 588217
bandwidth 153600 256000 104590
opt extra-info-digest D225B728768D7EA4B5587C13A7A9D22EBBEE6E66
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJv5IIWQ+WDWYUdyA/0L8qbIkEVH/cwryZWoIaPAzINfrw1WfNZGtBmg
skFtXhOHHqTRN4GPPrZsAIUOQGzQtGb66IQgT4tO/pj+P6QmSCCdTfhvGfgTCsC+
WPi4Fl2qryzTb3QO5r5x7T8OsG2IBUET1bLQzmtbC560SYR49IvVAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAKwvOXyztVKnuYvpTKt+nS3XIKeO8dVungi8qGoeS+6gkR6lDtGfBTjd
uE9UIkdAl9zi8/1Ic2wsUNHE9jiS0VgeupITGZY8YOyMJJ/xtV1cqgiWhq1dUYaq
51TOtUogtAPgXPh4J+V8HbFFIcCzIh3qCO/xXo+DSHhv7SSif1VpAgMBAAE=
-----END RSA PUBLIC KEY-----
family $0CE3CFB1E9CC47B63EA8869813BF6FAB7D4540C1 $1FD187E8F69A9B74C9202DC16A25B9E7744AB9F6 $74FB5EFA6A46DE4060431D515DC9A790E6AD9A7C $77001D8DA9BF445B0F81AA427A675F570D222E6A $B6D83EC2D9E18B0A7A33428F8CFA9C536769E209 $D2F37F46182C23AB747787FD657E680B34EAF892 $E0BD57A11F00041A9789577C53A1B784473669E4 $E5E3E9A472EAF7BE9682B86E92305DB4C71048EF
opt hidden-service-dir
contact www.atagar.com/contact
reject *:*
router-signature
-----BEGIN SIGNATURE-----
dskLSPz8beUW7bzwDjR6EVNGpyoZde83Ejvau+5F2c6cGnlu91fiZN3suE88iE6e
758b9ldq5eh5mapb8vuuV3uO+0Xsud7IEOqfxdkmk0GKnUX8ouru7DSIUzUL0zqq
Qlx9HNCqCY877ztFRC624ja2ql6A2hBcuoYMbkHjcQ4=
-----END SIGNATURE-----
"#;

    #[test]
    fn test_parse_example_descriptor() {
        let desc = ServerDescriptor::parse(EXAMPLE_DESCRIPTOR).unwrap();

        assert_eq!(desc.nickname, "caerSidi");
        assert_eq!(
            desc.fingerprint,
            Some("A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB".to_string())
        );
        assert_eq!(desc.address.to_string(), "71.35.133.197");
        assert_eq!(desc.or_port, 9001);
        assert_eq!(desc.socks_port, None);
        assert_eq!(desc.dir_port, None);
        assert_eq!(
            desc.platform,
            Some(b"Tor 0.2.1.30 on Linux x86_64".to_vec())
        );
        assert_eq!(desc.tor_version, Some(Version::parse("0.2.1.30").unwrap()));
        assert_eq!(desc.operating_system, Some("Linux x86_64".to_string()));
        assert_eq!(desc.uptime, Some(588217));
        assert_eq!(
            desc.published,
            NaiveDateTime::parse_from_str("2012-03-01 17:15:27", "%Y-%m-%d %H:%M:%S")
                .unwrap()
                .and_utc()
        );
        assert_eq!(desc.contact, Some(b"www.atagar.com/contact".to_vec()));
        assert_eq!(
            desc.link_protocols,
            Some(vec!["1".to_string(), "2".to_string()])
        );
        assert_eq!(desc.circuit_protocols, Some(vec!["1".to_string()]));
        assert!(desc.is_hidden_service_dir);
        assert!(!desc.hibernating);
        assert!(!desc.allow_single_hop_exits);
        assert!(!desc.allow_tunneled_dir_requests);
        assert!(!desc.extra_info_cache);
        assert_eq!(
            desc.extra_info_digest,
            Some("D225B728768D7EA4B5587C13A7A9D22EBBEE6E66".to_string())
        );
        assert_eq!(desc.extra_info_sha256_digest, None);
        assert_eq!(desc.bridge_distribution, BridgeDistribution::Any);
        assert_eq!(desc.family.len(), 8);
        assert!(desc
            .family
            .contains("$0CE3CFB1E9CC47B63EA8869813BF6FAB7D4540C1"));
        assert_eq!(desc.bandwidth_avg, 153600);
        assert_eq!(desc.bandwidth_burst, 256000);
        assert_eq!(desc.bandwidth_observed, 104590);
        assert!(desc.onion_key.is_some());
        assert!(desc.signing_key.is_some());
        assert!(desc.signature.contains("BEGIN SIGNATURE"));
        assert!(desc.unrecognized_lines.is_empty());
    }

    #[test]
    fn test_parse_minimal_descriptor() {
        let minimal = r#"router TestRelay 192.168.1.1 9001 0 0
published 2023-01-01 00:00:00
bandwidth 1000 2000 500
router-signature
-----BEGIN SIGNATURE-----
test
-----END SIGNATURE-----
"#;
        let desc = ServerDescriptor::parse(minimal).unwrap();
        assert_eq!(desc.nickname, "TestRelay");
        assert_eq!(desc.address.to_string(), "192.168.1.1");
        assert_eq!(desc.or_port, 9001);
        assert_eq!(desc.bandwidth_avg, 1000);
        assert_eq!(desc.bandwidth_burst, 2000);
        assert_eq!(desc.bandwidth_observed, 500);
    }

    #[test]
    fn test_parse_router_line() {
        let (nickname, address, or_port, socks_port, dir_port) =
            ServerDescriptor::parse_router_line("caerSidi 71.35.133.197 9001 0 0").unwrap();
        assert_eq!(nickname, "caerSidi");
        assert_eq!(address.to_string(), "71.35.133.197");
        assert_eq!(or_port, 9001);
        assert_eq!(socks_port, None);
        assert_eq!(dir_port, None);
    }

    #[test]
    fn test_parse_router_line_with_ports() {
        let (nickname, address, or_port, socks_port, dir_port) =
            ServerDescriptor::parse_router_line("TestRelay 10.0.0.1 9001 9050 9030").unwrap();
        assert_eq!(nickname, "TestRelay");
        assert_eq!(address.to_string(), "10.0.0.1");
        assert_eq!(or_port, 9001);
        assert_eq!(socks_port, Some(9050));
        assert_eq!(dir_port, Some(9030));
    }

    #[test]
    fn test_parse_bandwidth_line() {
        let (avg, burst, observed) =
            ServerDescriptor::parse_bandwidth_line("153600 256000 104590").unwrap();
        assert_eq!(avg, 153600);
        assert_eq!(burst, 256000);
        assert_eq!(observed, 104590);
    }

    #[test]
    fn test_parse_published_line() {
        let dt = ServerDescriptor::parse_published_line("2012-03-01 17:15:27").unwrap();
        assert_eq!(dt.year(), 2012);
        assert_eq!(dt.month(), 3);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 17);
        assert_eq!(dt.minute(), 15);
        assert_eq!(dt.second(), 27);
    }

    #[test]
    fn test_parse_fingerprint_line() {
        let fp = ServerDescriptor::parse_fingerprint_line(
            "A756 9A83 B570 6AB1 B1A9 CB52 EFF7 D2D3 2E45 53EB",
        );
        assert_eq!(fp, "A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB");
    }

    #[test]
    fn test_parse_platform_line() {
        let (platform, version, os) =
            ServerDescriptor::parse_platform_line("Tor 0.2.1.30 on Linux x86_64");
        assert_eq!(platform, Some(b"Tor 0.2.1.30 on Linux x86_64".to_vec()));
        assert_eq!(version, Some(Version::parse("0.2.1.30").unwrap()));
        assert_eq!(os, Some("Linux x86_64".to_string()));
    }

    #[test]
    fn test_parse_protocols_line() {
        let (link, circuit) = ServerDescriptor::parse_protocols_line("Link 1 2 Circuit 1");
        assert_eq!(link, Some(vec!["1".to_string(), "2".to_string()]));
        assert_eq!(circuit, Some(vec!["1".to_string()]));
    }

    #[test]
    fn test_parse_family_line() {
        let family = ServerDescriptor::parse_family_line("$ABC123 $DEF456 $GHI789");
        assert_eq!(family.len(), 3);
        assert!(family.contains("$ABC123"));
        assert!(family.contains("$DEF456"));
        assert!(family.contains("$GHI789"));
    }

    #[test]
    fn test_parse_or_address_ipv4() {
        let (addr, port, is_ipv6) = ServerDescriptor::parse_or_address("192.168.1.1:9001").unwrap();
        assert_eq!(addr.to_string(), "192.168.1.1");
        assert_eq!(port, 9001);
        assert!(!is_ipv6);
    }

    #[test]
    fn test_parse_or_address_ipv6() {
        let (addr, port, is_ipv6) =
            ServerDescriptor::parse_or_address("[2001:db8::1]:9001").unwrap();
        assert_eq!(addr.to_string(), "2001:db8::1");
        assert_eq!(port, 9001);
        assert!(is_ipv6);
    }

    #[test]
    fn test_invalid_nickname_too_long() {
        let result = ServerDescriptor::parse_router_line(
            "ThisNicknameIsWayTooLongToBeValid 192.168.1.1 9001 0 0",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nickname_special_chars() {
        let result = ServerDescriptor::parse_router_line("Invalid$Name 192.168.1.1 9001 0 0");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_address() {
        let result = ServerDescriptor::parse_router_line("TestRelay 999.999.999.999 9001 0 0");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_port() {
        let result = ServerDescriptor::parse_router_line("TestRelay 192.168.1.1 99999 0 0");
        assert!(result.is_err());
    }

    #[test]
    fn test_digest_sha1() {
        let desc = ServerDescriptor::parse(EXAMPLE_DESCRIPTOR).unwrap();
        let digest = desc.digest(DigestHash::Sha1, DigestEncoding::Hex).unwrap();
        assert_eq!(digest.len(), 40);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_digest_sha256() {
        let desc = ServerDescriptor::parse(EXAMPLE_DESCRIPTOR).unwrap();
        let digest = desc
            .digest(DigestHash::Sha256, DigestEncoding::Hex)
            .unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_to_descriptor_string() {
        let desc = ServerDescriptor::parse(EXAMPLE_DESCRIPTOR).unwrap();
        let output = desc.to_descriptor_string();
        assert!(output.contains("router caerSidi 71.35.133.197 9001 0 0"));
        assert!(output.contains("bandwidth 153600 256000 104590"));
        assert!(output.contains("router-signature"));
    }

    #[test]
    fn test_descriptor_with_exit_policy() {
        let content = r#"router TestRelay 192.168.1.1 9001 0 0
published 2023-01-01 00:00:00
bandwidth 1000 2000 500
accept *:80
accept *:443
reject *:*
router-signature
-----BEGIN SIGNATURE-----
test
-----END SIGNATURE-----
"#;
        let desc = ServerDescriptor::parse(content).unwrap();
        assert!(desc
            .exit_policy
            .can_exit_to("10.0.0.1".parse().unwrap(), 80));
        assert!(desc
            .exit_policy
            .can_exit_to("10.0.0.1".parse().unwrap(), 443));
        assert!(!desc
            .exit_policy
            .can_exit_to("10.0.0.1".parse().unwrap(), 22));
    }

    #[test]
    fn test_descriptor_with_hibernating() {
        let content = r#"router TestRelay 192.168.1.1 9001 0 0
published 2023-01-01 00:00:00
bandwidth 1000 2000 500
hibernating 1
router-signature
-----BEGIN SIGNATURE-----
test
-----END SIGNATURE-----
"#;
        let desc = ServerDescriptor::parse(content).unwrap();
        assert!(desc.hibernating);
    }

    #[test]
    fn test_descriptor_with_proto() {
        let content = r#"router TestRelay 192.168.1.1 9001 0 0
published 2023-01-01 00:00:00
bandwidth 1000 2000 500
proto Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-4 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2
router-signature
-----BEGIN SIGNATURE-----
test
-----END SIGNATURE-----
"#;
        let desc = ServerDescriptor::parse(content).unwrap();
        assert!(desc.protocols.contains_key("Cons"));
        assert!(desc.protocols.contains_key("Link"));
        assert_eq!(desc.protocols.get("Cons"), Some(&vec![1, 2]));
    }

    #[test]
    fn test_is_valid_nickname() {
        assert!(is_valid_nickname("caerSidi"));
        assert!(is_valid_nickname("TestRelay123"));
        assert!(is_valid_nickname("A"));
        assert!(is_valid_nickname("ABCDEFGHIJKLMNOPQRS"));
        assert!(!is_valid_nickname(""));
        assert!(!is_valid_nickname("ABCDEFGHIJKLMNOPQRST"));
        assert!(!is_valid_nickname("Invalid$Name"));
        assert!(!is_valid_nickname("Invalid Name"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn valid_nickname() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9]{0,18}".prop_filter("must be valid nickname", |s| {
            !s.is_empty() && s.len() <= 19 && s.chars().all(|c| c.is_ascii_alphanumeric())
        })
    }

    fn valid_ipv4() -> impl Strategy<Value = IpAddr> {
        (1u8..255, 0u8..255, 0u8..255, 1u8..255)
            .prop_map(|(a, b, c, d)| IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)))
    }

    fn valid_port() -> impl Strategy<Value = u16> {
        1u16..65535
    }

    fn valid_bandwidth() -> impl Strategy<Value = u64> {
        1u64..1_000_000_000
    }

    fn valid_datetime() -> impl Strategy<Value = DateTime<Utc>> {
        (
            2000i32..2030,
            1u32..13,
            1u32..29,
            0u32..24,
            0u32..60,
            0u32..60,
        )
            .prop_map(|(year, month, day, hour, min, sec)| {
                NaiveDateTime::new(
                    chrono::NaiveDate::from_ymd_opt(year, month, day).unwrap(),
                    chrono::NaiveTime::from_hms_opt(hour, min, sec).unwrap(),
                )
                .and_utc()
            })
    }

    fn valid_fingerprint() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            proptest::char::range('0', '9').prop_union(proptest::char::range('A', 'F')),
            40..=40,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    fn simple_server_descriptor() -> impl Strategy<Value = ServerDescriptor> {
        (
            valid_nickname(),
            valid_ipv4(),
            valid_port(),
            valid_datetime(),
            valid_bandwidth(),
            valid_bandwidth(),
            valid_bandwidth(),
            proptest::option::of(valid_fingerprint()),
        )
            .prop_map(
                |(nickname, address, or_port, published, bw_avg, bw_burst, bw_obs, fingerprint)| {
                    let mut desc = ServerDescriptor::new(
                        nickname,
                        address,
                        or_port,
                        published,
                        "-----BEGIN SIGNATURE-----\ntest\n-----END SIGNATURE-----".to_string(),
                    );
                    desc.bandwidth_avg = bw_avg;
                    desc.bandwidth_burst = bw_burst;
                    desc.bandwidth_observed = bw_obs;
                    desc.fingerprint = fingerprint;
                    desc
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_server_descriptor_roundtrip(desc in simple_server_descriptor()) {
            let serialized = desc.to_descriptor_string();
            let parsed = ServerDescriptor::parse(&serialized);

            prop_assert!(parsed.is_ok(), "Failed to parse serialized descriptor: {:?}", parsed.err());

            let parsed = parsed.unwrap();

            prop_assert_eq!(&desc.nickname, &parsed.nickname, "nickname mismatch");
            prop_assert_eq!(desc.address, parsed.address, "address mismatch");
            prop_assert_eq!(desc.or_port, parsed.or_port, "or_port mismatch");
            prop_assert_eq!(desc.socks_port, parsed.socks_port, "socks_port mismatch");
            prop_assert_eq!(desc.dir_port, parsed.dir_port, "dir_port mismatch");

            prop_assert_eq!(desc.bandwidth_avg, parsed.bandwidth_avg, "bandwidth_avg mismatch");
            prop_assert_eq!(desc.bandwidth_burst, parsed.bandwidth_burst, "bandwidth_burst mismatch");
            prop_assert_eq!(desc.bandwidth_observed, parsed.bandwidth_observed, "bandwidth_observed mismatch");

            prop_assert_eq!(desc.published, parsed.published, "published mismatch");

            prop_assert_eq!(desc.fingerprint, parsed.fingerprint, "fingerprint mismatch");
        }

        #[test]
        fn prop_valid_nickname_parsing(nickname in valid_nickname()) {
            let content = format!(
                "router {} 192.168.1.1 9001 0 0\npublished 2023-01-01 00:00:00\nbandwidth 1000 2000 500\nrouter-signature\n-----BEGIN SIGNATURE-----\ntest\n-----END SIGNATURE-----\n",
                nickname
            );
            let result = ServerDescriptor::parse(&content);
            prop_assert!(result.is_ok(), "Failed to parse descriptor with nickname '{}': {:?}", nickname, result.err());
            prop_assert_eq!(result.unwrap().nickname, nickname);
        }

        #[test]
        fn prop_bandwidth_preserved(
            avg in valid_bandwidth(),
            burst in valid_bandwidth(),
            observed in valid_bandwidth()
        ) {
            let content = format!(
                "router TestRelay 192.168.1.1 9001 0 0\npublished 2023-01-01 00:00:00\nbandwidth {} {} {}\nrouter-signature\n-----BEGIN SIGNATURE-----\ntest\n-----END SIGNATURE-----\n",
                avg, burst, observed
            );
            let result = ServerDescriptor::parse(&content);
            prop_assert!(result.is_ok());
            let desc = result.unwrap();
            prop_assert_eq!(desc.bandwidth_avg, avg);
            prop_assert_eq!(desc.bandwidth_burst, burst);
            prop_assert_eq!(desc.bandwidth_observed, observed);
        }

        #[test]
        fn prop_ports_preserved(
            or_port in valid_port(),
            socks_port in proptest::option::of(valid_port()),
            dir_port in proptest::option::of(valid_port())
        ) {
            let socks = socks_port.unwrap_or(0);
            let dir = dir_port.unwrap_or(0);
            let content = format!(
                "router TestRelay 192.168.1.1 {} {} {}\npublished 2023-01-01 00:00:00\nbandwidth 1000 2000 500\nrouter-signature\n-----BEGIN SIGNATURE-----\ntest\n-----END SIGNATURE-----\n",
                or_port, socks, dir
            );
            let result = ServerDescriptor::parse(&content);
            prop_assert!(result.is_ok());
            let desc = result.unwrap();
            prop_assert_eq!(desc.or_port, or_port);
            prop_assert_eq!(desc.socks_port, if socks == 0 { None } else { Some(socks) });
            prop_assert_eq!(desc.dir_port, if dir == 0 { None } else { Some(dir) });
        }

        #[test]
        fn prop_fingerprint_format_preserved(fp in valid_fingerprint()) {
            let formatted: String = fp
                .chars()
                .collect::<Vec<_>>()
                .chunks(4)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(" ");

            let content = format!(
                "router TestRelay 192.168.1.1 9001 0 0\npublished 2023-01-01 00:00:00\nfingerprint {}\nbandwidth 1000 2000 500\nrouter-signature\n-----BEGIN SIGNATURE-----\ntest\n-----END SIGNATURE-----\n",
                formatted
            );
            let result = ServerDescriptor::parse(&content);
            prop_assert!(result.is_ok());
            let desc = result.unwrap();
            prop_assert_eq!(desc.fingerprint, Some(fp));
        }
    }
}
