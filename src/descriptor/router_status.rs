//! Router status entry parsing for Tor network status documents.
//!
//! This module provides types for parsing router status entries, which describe
//! individual relays within a network status consensus document. Router status
//! entries are the core building blocks of consensus documents, containing
//! essential information about each relay in the Tor network.
//!
//! # Overview
//!
//! Router status entries appear in several contexts:
//!
//! - **Network status consensus documents** - The authoritative list of relays
//! - **Control port responses** - Via `GETINFO ns/*` and `GETINFO md/*` queries
//! - **Cached consensus files** - Local copies of network status documents
//!
//! Each entry contains information about a single relay including its identity,
//! network address, capabilities (flags), bandwidth, and exit policy summary.
//!
//! # Entry Types
//!
//! Different versions and flavors of network status documents use different
//! entry formats:
//!
//! | Type | Description | Digest Field |
//! |------|-------------|--------------|
//! | [`RouterStatusEntryType::V2`] | Legacy v2 network status | SHA-1 hex digest |
//! | [`RouterStatusEntryType::V3`] | Standard v3 consensus | SHA-1 hex digest |
//! | [`RouterStatusEntryType::MicroV3`] | Microdescriptor consensus | Base64 microdesc digest |
//! | [`RouterStatusEntryType::Bridge`] | Bridge network status | SHA-1 hex digest |
//!
//! # Entry Format
//!
//! Router status entries consist of several lines, each starting with a keyword:
//!
//! - `r` - Router identity (nickname, fingerprint, address, ports, publication time)
//! - `a` - Additional OR addresses (IPv6 addresses)
//! - `s` - Flags assigned by directory authorities
//! - `v` - Tor version string
//! - `w` - Bandwidth weights for path selection
//! - `p` - Exit policy summary (accept/reject port ranges)
//! - `pr` - Protocol versions supported
//! - `m` - Microdescriptor digest (for microdescriptor consensus)
//! - `id` - Ed25519 identity key (in votes)
//!
//! # Example
//!
//! ```rust
//! use stem_rs::descriptor::router_status::RouterStatusEntry;
//!
//! let entry_content = r#"r example ARIJF2zbqirB9IwsW0mQznccWww oQZFLYe9e4A7bOkWKR7TaNxb0JE 2024-01-15 12:00:00 192.0.2.1 9001 0
//! s Fast Guard Running Stable Valid
//! v Tor 0.4.8.10
//! w Bandwidth=5000
//! p reject 1-65535"#;
//!
//! let entry = RouterStatusEntry::parse(entry_content).unwrap();
//! assert_eq!(entry.nickname, "example");
//! assert!(entry.flags.contains(&"Guard".to_string()));
//! ```
//!
//! # Flags
//!
//! Directory authorities assign flags to relays based on their behavior and
//! capabilities. Common flags include:
//!
//! - `Authority` - A directory authority
//! - `BadExit` - Believed to be useless as an exit node
//! - `Exit` - Suitable for exit traffic
//! - `Fast` - Suitable for high-bandwidth circuits
//! - `Guard` - Suitable as an entry guard
//! - `HSDir` - Hidden service directory
//! - `Running` - Currently usable
//! - `Stable` - Suitable for long-lived circuits
//! - `Valid` - Has been validated
//! - `V2Dir` - Supports v2 directory protocol
//!
//! # Bandwidth Weights
//!
//! The `w` line contains bandwidth information used for path selection:
//!
//! - `Bandwidth` - Consensus bandwidth weight (arbitrary units, typically KB/s)
//! - `Measured` - Bandwidth measured by bandwidth authorities
//! - `Unmeasured` - Set to 1 if bandwidth is not based on measurements
//!
//! # See Also
//!
//! - [`crate::descriptor::consensus`] - Network status consensus documents
//! - [`crate::descriptor::micro`] - Microdescriptor parsing
//! - [`crate::descriptor::server`] - Full server descriptors
//! - [`crate::exit_policy`] - Exit policy evaluation
//!
//! # See Also
//!
//! - [Tor Directory Protocol Specification](https://spec.torproject.org/dir-spec)
//! - Python Stem's `RouterStatusEntry` class

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::exit_policy::MicroExitPolicy;
use crate::version::Version;
use crate::Error;

/// The type of router status entry, determining its format and available fields.
///
/// Different versions and flavors of network status documents use different
/// entry formats. The entry type affects which fields are present and how
/// certain lines (like the `r` line) are parsed.
///
/// # Variants
///
/// Each variant corresponds to a specific document type:
///
/// - [`V2`](Self::V2) - Legacy network status v2 documents
/// - [`V3`](Self::V3) - Standard network status v3 consensus
/// - [`MicroV3`](Self::MicroV3) - Microdescriptor-flavored v3 consensus
/// - [`Bridge`](Self::Bridge) - Bridge network status documents
///
/// # Format Differences
///
/// The main difference between entry types is the `r` line format:
///
/// - **V2/V3/Bridge**: `r nickname identity digest published address or_port dir_port`
/// - **MicroV3**: `r nickname identity published address or_port dir_port` (no digest)
///
/// MicroV3 entries use the `m` line for the microdescriptor digest instead.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::router_status::RouterStatusEntryType;
///
/// let entry_type = RouterStatusEntryType::V3;
/// assert_eq!(entry_type, RouterStatusEntryType::V3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterStatusEntryType {
    /// Legacy network status v2 entry format.
    ///
    /// Used in older network status documents. Contains a SHA-1 digest
    /// of the relay's server descriptor.
    V2,

    /// Standard network status v3 entry format.
    ///
    /// The most common format, used in regular consensus documents.
    /// Contains a SHA-1 digest of the relay's server descriptor.
    V3,

    /// Microdescriptor-flavored v3 entry format.
    ///
    /// Used in microdescriptor consensus documents. Does not contain
    /// a server descriptor digest in the `r` line; instead uses the
    /// `m` line for the microdescriptor digest.
    MicroV3,

    /// Bridge network status entry format.
    ///
    /// Used for bridge relay status entries. Similar to V2 format
    /// but specific to bridge authority documents.
    Bridge,
}

/// Microdescriptor hash information from vote documents.
///
/// In directory authority votes, the `m` line contains microdescriptor
/// digests computed using different consensus methods. This allows
/// authorities to vote on which microdescriptor digest should be used
/// for each relay.
///
/// # Fields
///
/// - `methods` - Consensus method numbers that produce this digest
/// - `hashes` - Mapping of hash algorithm names to digest values
///
/// # Format
///
/// The `m` line format in votes is:
/// ```text
/// m methods algorithm=digest [algorithm=digest ...]
/// ```
///
/// For example:
/// ```text
/// m 13,14,15 sha256=uaAYTOVuYRqUwJpNfP2WizjzO0FiNQB4U97xSQu+vMc
/// ```
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::router_status::MicrodescriptorHash;
/// use std::collections::HashMap;
///
/// let hash = MicrodescriptorHash {
///     methods: vec![13, 14, 15],
///     hashes: {
///         let mut h = HashMap::new();
///         h.insert("sha256".to_string(), "uaAYTOVuYRqUwJpNfP2WizjzO0FiNQB4U97xSQu+vMc".to_string());
///         h
///     },
/// };
///
/// assert_eq!(hash.methods, vec![13, 14, 15]);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct MicrodescriptorHash {
    /// Consensus method numbers that produce this microdescriptor digest.
    ///
    /// Different consensus methods may produce different microdescriptor
    /// digests for the same relay. This field lists which methods
    /// correspond to the digests in the `hashes` field.
    pub methods: Vec<u32>,

    /// Mapping of hash algorithm names to digest values.
    ///
    /// The key is the algorithm name (e.g., "sha256") and the value
    /// is the base64-encoded digest.
    pub hashes: HashMap<String, String>,
}

/// Information about an individual relay in a network status document.
///
/// A `RouterStatusEntry` contains the essential information about a single
/// relay as recorded in a network status consensus or vote. This includes
/// the relay's identity, network location, capabilities, and performance
/// characteristics.
///
/// # Overview
///
/// Router status entries are the building blocks of consensus documents.
/// Each entry describes one relay and contains:
///
/// - **Identity**: Nickname, fingerprint, and optional Ed25519 identity
/// - **Network**: IP address, OR port, directory port, additional addresses
/// - **Capabilities**: Flags assigned by directory authorities
/// - **Performance**: Bandwidth weights for path selection
/// - **Policy**: Exit policy summary
/// - **Version**: Tor software version
///
/// # Entry Types
///
/// The [`entry_type`](Self::entry_type) field determines the format:
///
/// | Type | Digest Field | Microdescriptor |
/// |------|--------------|-----------------|
/// | V2 | `digest` (hex) | N/A |
/// | V3 | `digest` (hex) | Via `m` line in votes |
/// | MicroV3 | N/A | `microdescriptor_digest` |
/// | Bridge | `digest` (hex) | N/A |
///
/// # Parsing
///
/// Use the appropriate parsing method for your entry type:
///
/// - [`parse()`](Self::parse) - Standard V3 consensus entries
/// - [`parse_micro()`](Self::parse_micro) - Microdescriptor consensus entries
/// - [`parse_v2()`](Self::parse_v2) - Legacy V2 entries
/// - [`parse_vote()`](Self::parse_vote) - Vote document entries
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::router_status::RouterStatusEntry;
///
/// let content = r#"r example ARIJF2zbqirB9IwsW0mQznccWww oQZFLYe9e4A7bOkWKR7TaNxb0JE 2024-01-15 12:00:00 192.0.2.1 9001 9030
/// s Fast Guard Running Stable Valid
/// v Tor 0.4.8.10
/// w Bandwidth=5000 Measured=4800
/// p accept 80,443"#;
///
/// let entry = RouterStatusEntry::parse(content).unwrap();
///
/// // Access relay identity
/// assert_eq!(entry.nickname, "example");
/// assert!(!entry.fingerprint.is_empty());
///
/// // Check flags
/// assert!(entry.flags.contains(&"Guard".to_string()));
/// assert!(entry.flags.contains(&"Running".to_string()));
///
/// // Check bandwidth
/// assert_eq!(entry.bandwidth, Some(5000));
/// assert_eq!(entry.measured, Some(4800));
/// ```
///
/// # Flags
///
/// The `flags` field contains strings assigned by directory authorities.
/// Common flags include:
///
/// - `Authority` - A directory authority
/// - `BadExit` - Believed to be useless as an exit
/// - `Exit` - Suitable for exit traffic
/// - `Fast` - Suitable for high-bandwidth circuits
/// - `Guard` - Suitable as an entry guard
/// - `HSDir` - Hidden service directory
/// - `Running` - Currently usable
/// - `Stable` - Suitable for long-lived circuits
/// - `Valid` - Has been validated
///
/// # Thread Safety
///
/// `RouterStatusEntry` is `Send` and `Sync`, making it safe to share
/// across threads.
///
/// # See Also
///
/// - [`crate::descriptor::consensus::NetworkStatusDocument`] - Contains router status entries
/// - [`crate::Flag`] - Enum of standard relay flags
#[derive(Debug, Clone, PartialEq)]
pub struct RouterStatusEntry {
    /// The type of this router status entry.
    ///
    /// Determines the format and which fields are available.
    pub entry_type: RouterStatusEntryType,

    /// The relay's nickname (1-19 alphanumeric characters).
    ///
    /// Nicknames are not unique identifiers; use `fingerprint` for
    /// reliable relay identification.
    pub nickname: String,

    /// The relay's identity fingerprint as uppercase hexadecimal.
    ///
    /// This is a 40-character hex string representing the SHA-1 hash
    /// of the relay's identity key. This is the authoritative identifier
    /// for a relay.
    pub fingerprint: String,

    /// SHA-1 digest of the relay's server descriptor (hex, uppercase).
    ///
    /// Present in V2, V3, and Bridge entries. Not present in MicroV3
    /// entries (use `microdescriptor_digest` instead).
    pub digest: Option<String>,

    /// When the relay's descriptor was published (UTC).
    pub published: DateTime<Utc>,

    /// The relay's primary IP address.
    pub address: IpAddr,

    /// The relay's OR (onion router) port for relay traffic.
    pub or_port: u16,

    /// The relay's directory port, if it serves directory information.
    ///
    /// `None` if the relay doesn't serve directory information (port 0).
    pub dir_port: Option<u16>,

    /// Additional OR addresses (typically IPv6).
    ///
    /// Each tuple contains (address, port, is_ipv6). The primary address
    /// is in the `address` field; this contains additional addresses
    /// from `a` lines.
    pub or_addresses: Vec<(IpAddr, u16, bool)>,

    /// Flags assigned to this relay by directory authorities.
    ///
    /// Common flags: "Authority", "BadExit", "Exit", "Fast", "Guard",
    /// "HSDir", "Running", "Stable", "Valid", "V2Dir".
    pub flags: Vec<String>,

    /// The raw version line from the entry.
    ///
    /// Typically starts with "Tor " followed by the version number.
    pub version_line: Option<String>,

    /// Parsed Tor version, if the version line was parseable.
    ///
    /// `None` if the relay uses a non-standard version format.
    pub version: Option<Version>,

    /// Consensus bandwidth weight (arbitrary units, typically KB/s).
    ///
    /// Used for path selection weighting. Higher values indicate
    /// more bandwidth capacity.
    pub bandwidth: Option<u64>,

    /// Bandwidth measured by bandwidth authorities.
    ///
    /// More accurate than self-reported bandwidth. Used when available.
    pub measured: Option<u64>,

    /// Whether the bandwidth value is unmeasured.
    ///
    /// `true` if the bandwidth is not based on actual measurements
    /// (fewer than 3 measurements available).
    pub is_unmeasured: bool,

    /// Unrecognized entries from the `w` (bandwidth) line.
    ///
    /// Contains any bandwidth-related key=value pairs that weren't
    /// recognized during parsing.
    pub unrecognized_bandwidth_entries: Vec<String>,

    /// Exit policy summary from the `p` line.
    ///
    /// A compact representation of the relay's exit policy.
    pub exit_policy: Option<MicroExitPolicy>,

    /// Protocol versions supported by this relay.
    ///
    /// Maps protocol names (e.g., "Link", "Relay") to lists of
    /// supported version numbers.
    pub protocols: HashMap<String, Vec<u32>>,

    /// Microdescriptor digest (base64) for MicroV3 entries.
    ///
    /// Used to fetch the corresponding microdescriptor.
    pub microdescriptor_digest: Option<String>,

    /// Microdescriptor hashes from vote documents.
    ///
    /// Contains digests computed using different consensus methods.
    /// Only present in vote documents, not consensus documents.
    pub microdescriptor_hashes: Vec<MicrodescriptorHash>,

    /// Ed25519 identity key type (typically "ed25519").
    ///
    /// Present in vote documents when the relay has an Ed25519 key.
    pub identifier_type: Option<String>,

    /// Ed25519 identity key value (base64).
    ///
    /// The value "none" indicates the relay doesn't have an Ed25519 key.
    pub identifier: Option<String>,

    /// Lines that weren't recognized during parsing.
    ///
    /// Useful for forward compatibility with new entry fields.
    unrecognized_lines: Vec<String>,
}

impl RouterStatusEntry {
    /// Creates a new router status entry with minimal required fields.
    ///
    /// This constructor creates an entry with only the essential fields
    /// populated. Optional fields are set to their default values.
    ///
    /// # Arguments
    ///
    /// * `entry_type` - The type of entry (V2, V3, MicroV3, or Bridge)
    /// * `nickname` - The relay's nickname (1-19 alphanumeric characters)
    /// * `fingerprint` - The relay's identity fingerprint (40 hex characters)
    /// * `published` - When the relay's descriptor was published
    /// * `address` - The relay's primary IP address
    /// * `or_port` - The relay's OR port
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::router_status::{RouterStatusEntry, RouterStatusEntryType};
    /// use chrono::Utc;
    /// use std::net::IpAddr;
    ///
    /// let entry = RouterStatusEntry::new(
    ///     RouterStatusEntryType::V3,
    ///     "example".to_string(),
    ///     "AABBCCDD".repeat(5),
    ///     Utc::now(),
    ///     "192.0.2.1".parse().unwrap(),
    ///     9001,
    /// );
    ///
    /// assert_eq!(entry.nickname, "example");
    /// assert_eq!(entry.or_port, 9001);
    /// ```
    pub fn new(
        entry_type: RouterStatusEntryType,
        nickname: String,
        fingerprint: String,
        published: DateTime<Utc>,
        address: IpAddr,
        or_port: u16,
    ) -> Self {
        Self {
            entry_type,
            nickname,
            fingerprint,
            digest: None,
            published,
            address,
            or_port,
            dir_port: None,
            or_addresses: Vec::new(),
            flags: Vec::new(),
            version_line: None,
            version: None,
            bandwidth: None,
            measured: None,
            is_unmeasured: false,
            unrecognized_bandwidth_entries: Vec::new(),
            exit_policy: None,
            protocols: HashMap::new(),
            microdescriptor_digest: None,
            microdescriptor_hashes: Vec::new(),
            identifier_type: None,
            identifier: None,
            unrecognized_lines: Vec::new(),
        }
    }

    /// Parses a V3 router status entry from a string.
    ///
    /// This is the standard parsing method for entries from network status
    /// v3 consensus documents.
    ///
    /// # Arguments
    ///
    /// * `content` - The entry content as a multi-line string
    ///
    /// # Returns
    ///
    /// A parsed `RouterStatusEntry` on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The `r` line is missing or malformed
    /// - Required fields cannot be parsed
    /// - The fingerprint cannot be decoded from base64
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::router_status::RouterStatusEntry;
    ///
    /// let content = r#"r example ARIJF2zbqirB9IwsW0mQznccWww oQZFLYe9e4A7bOkWKR7TaNxb0JE 2024-01-15 12:00:00 192.0.2.1 9001 0
    /// s Fast Running Valid"#;
    ///
    /// let entry = RouterStatusEntry::parse(content).unwrap();
    /// assert_eq!(entry.nickname, "example");
    /// ```
    pub fn parse(content: &str) -> Result<Self, Error> {
        Self::parse_with_type(content, RouterStatusEntryType::V3, false)
    }

    /// Parses a microdescriptor-flavored V3 router status entry.
    ///
    /// Use this method for entries from microdescriptor consensus documents.
    /// The main difference from [`parse()`](Self::parse) is that the `r` line
    /// does not contain a server descriptor digest.
    ///
    /// # Arguments
    ///
    /// * `content` - The entry content as a multi-line string
    ///
    /// # Returns
    ///
    /// A parsed `RouterStatusEntry` with `entry_type` set to `MicroV3`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the entry is malformed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::router_status::RouterStatusEntry;
    ///
    /// let content = r#"r example ARIJF2zbqirB9IwsW0mQznccWww 2024-01-15 12:00:00 192.0.2.1 9001 0
    /// m aiUklwBrua82obG5AsTX+iEpkjQA2+AQHxZ7GwMfY70
    /// s Fast Running Valid"#;
    ///
    /// let entry = RouterStatusEntry::parse_micro(content).unwrap();
    /// assert!(entry.digest.is_none());
    /// assert!(entry.microdescriptor_digest.is_some());
    /// ```
    pub fn parse_micro(content: &str) -> Result<Self, Error> {
        Self::parse_with_type(content, RouterStatusEntryType::MicroV3, false)
    }

    /// Parses a legacy V2 router status entry.
    ///
    /// Use this method for entries from older network status v2 documents.
    ///
    /// # Arguments
    ///
    /// * `content` - The entry content as a multi-line string
    ///
    /// # Returns
    ///
    /// A parsed `RouterStatusEntry` with `entry_type` set to `V2`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the entry is malformed.
    pub fn parse_v2(content: &str) -> Result<Self, Error> {
        Self::parse_with_type(content, RouterStatusEntryType::V2, false)
    }

    /// Parses a router status entry from a vote document.
    ///
    /// Vote documents may contain additional fields not present in
    /// consensus documents, such as Ed25519 identity keys (`id` line)
    /// and microdescriptor hashes (`m` lines with method numbers).
    ///
    /// # Arguments
    ///
    /// * `content` - The entry content as a multi-line string
    ///
    /// # Returns
    ///
    /// A parsed `RouterStatusEntry` with vote-specific fields populated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the entry is malformed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::router_status::RouterStatusEntry;
    ///
    /// let content = r#"r example ARIJF2zbqirB9IwsW0mQznccWww oQZFLYe9e4A7bOkWKR7TaNxb0JE 2024-01-15 12:00:00 192.0.2.1 9001 0
    /// s Fast Running Valid
    /// id ed25519 8RH34kO07Pp+XYwzdoATVyCibIvmbslUjRkAm7J4IA8
    /// m 13,14,15 sha256=uaAYTOVuYRqUwJpNfP2WizjzO0FiNQB4U97xSQu+vMc"#;
    ///
    /// let entry = RouterStatusEntry::parse_vote(content).unwrap();
    /// assert_eq!(entry.identifier_type, Some("ed25519".to_string()));
    /// assert!(!entry.microdescriptor_hashes.is_empty());
    /// ```
    pub fn parse_vote(content: &str) -> Result<Self, Error> {
        Self::parse_with_type(content, RouterStatusEntryType::V3, true)
    }

    /// Parses a router status entry with explicit type and vote flag.
    ///
    /// This is the general-purpose parsing method that other parse methods
    /// delegate to. Use this when you need explicit control over the entry
    /// type and whether vote-specific parsing should be enabled.
    ///
    /// # Arguments
    ///
    /// * `content` - The entry content as a multi-line string
    /// * `entry_type` - The type of entry to parse as
    /// * `is_vote` - Whether to enable vote-specific parsing (for `m` and `id` lines)
    ///
    /// # Returns
    ///
    /// A parsed `RouterStatusEntry` on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The `r` line is missing or has insufficient fields
    /// - The fingerprint or digest cannot be decoded from base64
    /// - The IP address is invalid
    /// - The ports are invalid
    /// - The publication timestamp is malformed
    ///
    /// # Line Parsing
    ///
    /// The following lines are recognized:
    ///
    /// | Keyword | Description |
    /// |---------|-------------|
    /// | `r` | Router identity (required) |
    /// | `a` | Additional OR addresses |
    /// | `s` | Flags |
    /// | `v` | Version |
    /// | `w` | Bandwidth weights |
    /// | `p` | Exit policy summary |
    /// | `pr` | Protocol versions |
    /// | `m` | Microdescriptor digest/hashes |
    /// | `id` | Ed25519 identity (votes only) |
    pub fn parse_with_type(
        content: &str,
        entry_type: RouterStatusEntryType,
        is_vote: bool,
    ) -> Result<Self, Error> {
        let lines: Vec<&str> = content.lines().collect();
        let is_micro = entry_type == RouterStatusEntryType::MicroV3;

        let mut nickname = String::new();
        let mut fingerprint = String::new();
        let mut digest: Option<String> = None;
        let mut published: Option<DateTime<Utc>> = None;
        let mut address: Option<IpAddr> = None;
        let mut or_port: u16 = 0;
        let mut dir_port: Option<u16> = None;
        let mut or_addresses: Vec<(IpAddr, u16, bool)> = Vec::new();
        let mut flags: Vec<String> = Vec::new();
        let mut version_line: Option<String> = None;
        let mut version: Option<Version> = None;
        let mut bandwidth: Option<u64> = None;
        let mut measured: Option<u64> = None;
        let mut is_unmeasured = false;
        let mut unrecognized_bandwidth_entries: Vec<String> = Vec::new();
        let mut exit_policy: Option<MicroExitPolicy> = None;
        let mut protocols: HashMap<String, Vec<u32>> = HashMap::new();
        let mut microdescriptor_digest: Option<String> = None;
        let mut microdescriptor_hashes: Vec<MicrodescriptorHash> = Vec::new();
        let mut identifier_type: Option<String> = None;
        let mut identifier: Option<String> = None;
        let mut unrecognized_lines: Vec<String> = Vec::new();

        for line in lines {
            if line.is_empty() {
                continue;
            }

            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "r" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    let min_parts = if is_micro { 7 } else { 8 };
                    if parts.len() < min_parts {
                        return Err(Error::Parse {
                            location: "r".to_string(),
                            reason: format!("r line requires {} fields", min_parts),
                        });
                    }
                    nickname = parts[0].to_string();
                    fingerprint = Self::base64_to_hex(parts[1])?;
                    let (date_idx, time_idx, addr_idx, or_idx, dir_idx) = if is_micro {
                        (2, 3, 4, 5, 6)
                    } else {
                        digest = Some(Self::base64_to_hex(parts[2])?);
                        (3, 4, 5, 6, 7)
                    };
                    let datetime_str = format!("{} {}", parts[date_idx], parts[time_idx]);
                    published = Some(Self::parse_timestamp(&datetime_str)?);
                    address = Some(parts[addr_idx].parse().map_err(|_| Error::Parse {
                        location: "r".to_string(),
                        reason: format!("invalid address: {}", parts[addr_idx]),
                    })?);
                    or_port = parts[or_idx].parse().map_err(|_| Error::Parse {
                        location: "r".to_string(),
                        reason: format!("invalid or_port: {}", parts[or_idx]),
                    })?;
                    let dp: u16 = parts[dir_idx].parse().map_err(|_| Error::Parse {
                        location: "r".to_string(),
                        reason: format!("invalid dir_port: {}", parts[dir_idx]),
                    })?;
                    dir_port = if dp == 0 { None } else { Some(dp) };
                }
                "a" => {
                    if let Ok(addr) = Self::parse_or_address(value) {
                        or_addresses.push(addr);
                    }
                }
                "s" => {
                    flags = value.split_whitespace().map(|s| s.to_string()).collect();
                }
                "v" => {
                    version_line = Some(value.to_string());
                    if let Some(stripped) = value.strip_prefix("Tor ") {
                        version = Version::parse(stripped).ok();
                    }
                }
                "w" => {
                    for entry in value.split_whitespace() {
                        if let Some(eq_pos) = entry.find('=') {
                            let key = &entry[..eq_pos];
                            let val = &entry[eq_pos + 1..];
                            match key {
                                "Bandwidth" => bandwidth = val.parse().ok(),
                                "Measured" => measured = val.parse().ok(),
                                "Unmeasured" => is_unmeasured = val == "1",
                                _ => unrecognized_bandwidth_entries.push(entry.to_string()),
                            }
                        } else {
                            unrecognized_bandwidth_entries.push(entry.to_string());
                        }
                    }
                }
                "p" => {
                    exit_policy = MicroExitPolicy::parse(value).ok();
                }
                "pr" => {
                    protocols = Self::parse_protocols(value);
                }
                "m" => {
                    if is_micro {
                        microdescriptor_digest = Some(value.to_string());
                    } else if is_vote {
                        if let Ok(hash) = Self::parse_microdescriptor_hash(value) {
                            microdescriptor_hashes.push(hash);
                        }
                    } else {
                        microdescriptor_digest = Some(value.to_string());
                    }
                }
                "id" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.len() >= 2 {
                        identifier_type = Some(parts[0].to_string());
                        identifier = Some(parts[1].to_string());
                    }
                }
                _ => {
                    if !line.is_empty() {
                        unrecognized_lines.push(line.to_string());
                    }
                }
            }
        }

        let address = address.ok_or_else(|| Error::Parse {
            location: "r".to_string(),
            reason: "missing r line".to_string(),
        })?;
        let published = published.ok_or_else(|| Error::Parse {
            location: "r".to_string(),
            reason: "missing published time".to_string(),
        })?;

        Ok(Self {
            entry_type,
            nickname,
            fingerprint,
            digest,
            published,
            address,
            or_port,
            dir_port,
            or_addresses,
            flags,
            version_line,
            version,
            bandwidth,
            measured,
            is_unmeasured,
            unrecognized_bandwidth_entries,
            exit_policy,
            protocols,
            microdescriptor_digest,
            microdescriptor_hashes,
            identifier_type,
            identifier,
            unrecognized_lines,
        })
    }

    /// Parses a microdescriptor hash line from a vote document.
    ///
    /// The `m` line in votes has the format:
    /// ```text
    /// m methods algorithm=digest [algorithm=digest ...]
    /// ```
    ///
    /// # Arguments
    ///
    /// * `value` - The value portion of the `m` line (after "m ")
    ///
    /// # Returns
    ///
    /// A [`MicrodescriptorHash`] containing the parsed methods and digests.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the line is empty.
    fn parse_microdescriptor_hash(value: &str) -> Result<MicrodescriptorHash, Error> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.is_empty() {
            return Err(Error::Parse {
                location: "m".to_string(),
                reason: "empty m line".to_string(),
            });
        }

        let methods: Vec<u32> = parts[0].split(',').filter_map(|s| s.parse().ok()).collect();

        let mut hashes = HashMap::new();
        for entry in parts.iter().skip(1) {
            if let Some(eq_pos) = entry.find('=') {
                let algo = &entry[..eq_pos];
                let digest = &entry[eq_pos + 1..];
                hashes.insert(algo.to_string(), digest.to_string());
            }
        }

        Ok(MicrodescriptorHash { methods, hashes })
    }

    /// Parses a timestamp string in "YYYY-MM-DD HH:MM:SS" format.
    ///
    /// # Arguments
    ///
    /// * `value` - The timestamp string to parse
    ///
    /// # Returns
    ///
    /// A UTC `DateTime` on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the timestamp format is invalid.
    fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, Error> {
        let datetime =
            NaiveDateTime::parse_from_str(value.trim(), "%Y-%m-%d %H:%M:%S").map_err(|e| {
                Error::Parse {
                    location: "timestamp".to_string(),
                    reason: format!("invalid datetime: {} - {}", value, e),
                }
            })?;
        Ok(datetime.and_utc())
    }

    /// Converts a base64-encoded identity to uppercase hexadecimal.
    ///
    /// Used to decode relay fingerprints and digests from the compact
    /// base64 format used in router status entries.
    ///
    /// # Arguments
    ///
    /// * `input` - Base64-encoded string (without padding)
    ///
    /// # Returns
    ///
    /// Uppercase hexadecimal string representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the base64 decoding fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let hex = RouterStatusEntry::base64_to_hex("p1aag7VwarGxqctS7/fS0y5FU+s").unwrap();
    /// assert_eq!(hex, "A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB");
    /// ```
    fn base64_to_hex(input: &str) -> Result<String, Error> {
        let decoded = Self::base64_decode(input)?;
        Ok(decoded.iter().map(|b| format!("{:02X}", b)).collect())
    }

    /// Decodes a base64 string to bytes.
    ///
    /// Handles base64 strings with or without padding.
    ///
    /// # Arguments
    ///
    /// * `input` - Base64-encoded string
    ///
    /// # Returns
    ///
    /// Decoded bytes on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the input contains invalid base64 characters.
    fn base64_decode(input: &str) -> Result<Vec<u8>, Error> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let input = input.trim_end_matches('=');
        let mut result = Vec::new();
        let chars: Vec<u8> = input
            .chars()
            .filter_map(|c| ALPHABET.iter().position(|&x| x == c as u8).map(|p| p as u8))
            .collect();

        let mut i = 0;
        while i < chars.len() {
            let n = chars.len() - i;
            if n >= 4 {
                let a = chars[i] as u32;
                let b = chars[i + 1] as u32;
                let c = chars[i + 2] as u32;
                let d = chars[i + 3] as u32;
                let triple = (a << 18) | (b << 12) | (c << 6) | d;
                result.push((triple >> 16) as u8);
                result.push((triple >> 8) as u8);
                result.push(triple as u8);
                i += 4;
            } else if n == 3 {
                let a = chars[i] as u32;
                let b = chars[i + 1] as u32;
                let c = chars[i + 2] as u32;
                let triple = (a << 18) | (b << 12) | (c << 6);
                result.push((triple >> 16) as u8);
                result.push((triple >> 8) as u8);
                i += 3;
            } else if n == 2 {
                let a = chars[i] as u32;
                let b = chars[i + 1] as u32;
                let triple = (a << 18) | (b << 12);
                result.push((triple >> 16) as u8);
                i += 2;
            } else {
                break;
            }
        }
        Ok(result)
    }

    /// Parses an OR address from an `a` line.
    ///
    /// Handles both IPv4 and IPv6 addresses. IPv6 addresses are expected
    /// to be enclosed in brackets: `[address]:port`.
    ///
    /// # Arguments
    ///
    /// * `line` - The address:port string (e.g., "192.0.2.1:9001" or "[::1]:9001")
    ///
    /// # Returns
    ///
    /// A tuple of (address, port, is_ipv6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the address or port is invalid.
    fn parse_or_address(line: &str) -> Result<(IpAddr, u16, bool), Error> {
        let line = line.trim();
        if line.starts_with('[') {
            if let Some(bracket_end) = line.find(']') {
                let ipv6_str = &line[1..bracket_end];
                let port_str = &line[bracket_end + 2..];
                let addr: IpAddr = ipv6_str.parse().map_err(|_| Error::Parse {
                    location: "a".to_string(),
                    reason: format!("invalid IPv6 address: {}", ipv6_str),
                })?;
                let port: u16 = port_str.parse().map_err(|_| Error::Parse {
                    location: "a".to_string(),
                    reason: format!("invalid port: {}", port_str),
                })?;
                return Ok((addr, port, true));
            }
        }
        if let Some(colon_pos) = line.rfind(':') {
            let addr_str = &line[..colon_pos];
            let port_str = &line[colon_pos + 1..];
            let addr: IpAddr = addr_str.parse().map_err(|_| Error::Parse {
                location: "a".to_string(),
                reason: format!("invalid address: {}", addr_str),
            })?;
            let port: u16 = port_str.parse().map_err(|_| Error::Parse {
                location: "a".to_string(),
                reason: format!("invalid port: {}", port_str),
            })?;
            let is_ipv6 = addr.is_ipv6();
            return Ok((addr, port, is_ipv6));
        }
        Err(Error::Parse {
            location: "a".to_string(),
            reason: format!("invalid or-address format: {}", line),
        })
    }

    /// Parses protocol versions from a `pr` line.
    ///
    /// The `pr` line format is:
    /// ```text
    /// pr Protocol=versions [Protocol=versions ...]
    /// ```
    ///
    /// Versions can be individual numbers or ranges (e.g., "1-4").
    ///
    /// # Arguments
    ///
    /// * `value` - The value portion of the `pr` line
    ///
    /// # Returns
    ///
    /// A map of protocol names to lists of supported version numbers.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let protocols = RouterStatusEntry::parse_protocols("Link=1-4 Relay=1-2");
    /// assert_eq!(protocols.get("Link"), Some(&vec![1, 2, 3, 4]));
    /// ```
    fn parse_protocols(value: &str) -> HashMap<String, Vec<u32>> {
        let mut protocols = HashMap::new();
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
        protocols
    }

    /// Returns lines that weren't recognized during parsing.
    ///
    /// This is useful for forward compatibility when new fields are added
    /// to the router status entry format.
    ///
    /// # Returns
    ///
    /// A slice of unrecognized line strings.
    pub fn unrecognized_lines(&self) -> &[String] {
        &self.unrecognized_lines
    }
}

/// Formats the router status entry back to its string representation.
///
/// The output follows the standard router status entry format and can
/// be parsed back using the appropriate `parse_*` method.
impl fmt::Display for RouterStatusEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let is_micro = self.entry_type == RouterStatusEntryType::MicroV3;
        if is_micro {
            writeln!(
                f,
                "r {} {} {} {} {} {}",
                self.nickname,
                Self::hex_to_base64(&self.fingerprint),
                self.published.format("%Y-%m-%d %H:%M:%S"),
                self.address,
                self.or_port,
                self.dir_port.unwrap_or(0)
            )?;
        } else {
            writeln!(
                f,
                "r {} {} {} {} {} {} {}",
                self.nickname,
                Self::hex_to_base64(&self.fingerprint),
                self.digest
                    .as_ref()
                    .map(|d| Self::hex_to_base64(d))
                    .unwrap_or_default(),
                self.published.format("%Y-%m-%d %H:%M:%S"),
                self.address,
                self.or_port,
                self.dir_port.unwrap_or(0)
            )?;
        }
        for (addr, port, is_ipv6) in &self.or_addresses {
            if *is_ipv6 {
                writeln!(f, "a [{}]:{}", addr, port)?;
            } else {
                writeln!(f, "a {}:{}", addr, port)?;
            }
        }
        if !self.flags.is_empty() {
            writeln!(f, "s {}", self.flags.join(" "))?;
        }
        if let Some(ref v) = self.version_line {
            writeln!(f, "v {}", v)?;
        }
        if let Some(bw) = self.bandwidth {
            let mut w_parts = vec![format!("Bandwidth={}", bw)];
            if let Some(m) = self.measured {
                w_parts.push(format!("Measured={}", m));
            }
            if self.is_unmeasured {
                w_parts.push("Unmeasured=1".to_string());
            }
            for entry in &self.unrecognized_bandwidth_entries {
                w_parts.push(entry.clone());
            }
            writeln!(f, "w {}", w_parts.join(" "))?;
        }
        if let Some(ref policy) = self.exit_policy {
            writeln!(f, "p {}", policy)?;
        }
        if !self.protocols.is_empty() {
            let proto_str: Vec<String> = self
                .protocols
                .iter()
                .map(|(k, v)| {
                    let versions: Vec<String> = v.iter().map(|n| n.to_string()).collect();
                    format!("{}={}", k, versions.join(","))
                })
                .collect();
            writeln!(f, "pr {}", proto_str.join(" "))?;
        }
        if let (Some(ref id_type), Some(ref id)) = (&self.identifier_type, &self.identifier) {
            writeln!(f, "id {} {}", id_type, id)?;
        }
        for hash in &self.microdescriptor_hashes {
            let methods: Vec<String> = hash.methods.iter().map(|m| m.to_string()).collect();
            let hashes: Vec<String> = hash
                .hashes
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            if hashes.is_empty() {
                writeln!(f, "m {}", methods.join(","))?;
            } else {
                writeln!(f, "m {} {}", methods.join(","), hashes.join(" "))?;
            }
        }
        if let Some(ref m) = self.microdescriptor_digest {
            if self.microdescriptor_hashes.is_empty() {
                writeln!(f, "m {}", m)?;
            }
        }
        Ok(())
    }
}

impl RouterStatusEntry {
    /// Converts a hexadecimal string to base64 encoding.
    ///
    /// Used when formatting router status entries back to their string
    /// representation, as fingerprints and digests are stored in hex
    /// but displayed in base64.
    ///
    /// # Arguments
    ///
    /// * `hex` - Uppercase hexadecimal string
    ///
    /// # Returns
    ///
    /// Base64-encoded string (without padding).
    fn hex_to_base64(hex: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();
        let mut result = String::new();
        let mut i = 0;
        while i < bytes.len() {
            let b0 = bytes[i] as u32;
            let b1 = bytes.get(i + 1).map(|&b| b as u32).unwrap_or(0);
            let b2 = bytes.get(i + 2).map(|&b| b as u32).unwrap_or(0);
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
            result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
            if i + 1 < bytes.len() {
                result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
            }
            if i + 2 < bytes.len() {
                result.push(ALPHABET[(triple & 0x3F) as usize] as char);
            }
            i += 3;
        }
        result
    }
}

/// Parses a router status entry from a string.
///
/// This implementation delegates to [`RouterStatusEntry::parse()`],
/// parsing the content as a V3 consensus entry.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::router_status::RouterStatusEntry;
/// use std::str::FromStr;
///
/// let content = r#"r example ARIJF2zbqirB9IwsW0mQznccWww oQZFLYe9e4A7bOkWKR7TaNxb0JE 2024-01-15 12:00:00 192.0.2.1 9001 0
/// s Running Valid"#;
///
/// let entry = RouterStatusEntry::from_str(content).unwrap();
/// assert_eq!(entry.nickname, "example");
/// ```
impl FromStr for RouterStatusEntry {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_V3_ENTRY: &str = r#"r test002r NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
s Exit Fast Guard HSDir Running Stable V2Dir Valid
v Tor 0.3.0.7
pr Cons=1-2 Desc=1-2 DirCache=1 HSDir=1-2 HSIntro=3-4 HSRend=1-2 Link=1-4 LinkAuth=1,3 Microdesc=1-2 Relay=1-2
w Bandwidth=0 Unmeasured=1
p accept 1-65535"#;

    const EXAMPLE_MICRO_ENTRY: &str = r#"r test002r NIIl+DyFR5ay3WNk5lyxibM71pY 2017-05-25 04:46:11 127.0.0.1 5002 7002
s Exit Fast Guard HSDir Running Stable V2Dir Valid
v Tor 0.3.0.7
w Bandwidth=0 Unmeasured=1
p accept 1-65535
m uhCGfIM6RbeD1Z/C6e9ct41+NIl9EbpgP8wG7uZT2Rw"#;

    const ENTRY_WITHOUT_ED25519: &str = r#"r seele AAoQ1DAR6kkoo19hBAX5K0QztNw m0ynPuwzSextzsiXYJYA0Hce+Cs 2015-08-23 00:26:35 73.15.150.172 9001 0
s Running Stable Valid
v Tor 0.2.6.10
w Bandwidth=102 Measured=31
p reject 1-65535
id ed25519 none
m 13,14,15 sha256=uaAYTOVuYRqUwJpNfP2WizjzO0FiNQB4U97xSQu+vMc
m 16,17 sha256=G6FmPe/ehgfb6tsRzFKDCwvvae+RICeP1MaP0vWDGyI
m 18,19,20,21 sha256=/XhIMOnhElo2UiKjL2S10uRka/fhg1CFfNd+9wgUwEE"#;

    const ENTRY_WITH_ED25519: &str = r#"r PDrelay1 AAFJ5u9xAqrKlpDW6N0pMhJLlKs yrJ6b/73pmHBiwsREgw+inf8WFw 2015-08-23 16:52:37 95.215.44.189 8080 0
s Fast Running Stable Valid
v Tor 0.2.7.2-alpha-dev
w Bandwidth=608 Measured=472
p reject 1-65535
id ed25519 8RH34kO07Pp+XYwzdoATVyCibIvmbslUjRkAm7J4IA8
m 13 sha256=PTSHzE7RKnRGZMRmBddSzDiZio254FUhv9+V4F5zq8s
m 14,15 sha256=0wsEwBbxJ8RtPmGYwilHQTVEw2pWzUBEVlSgEO77OyU
m 16,17 sha256=JK2xhYr/VsCF60px+LsT990BCpfKfQTeMxRbD63o2vE
m 18,19,20 sha256=AkZH3gIvz3wunsroqh5izBJizdYuR7kn2oVbsvqgML8
m 21 sha256=AVp41YVxKEJCaoEf0+77Cdvyw5YgpyDXdob0+LSv/pE"#;

    const ENTRY_WITH_IPV6: &str = r#"r MYLEX AQt3KEVEEfSFzinUx5oUU0FRwsQ 2018-07-15 16:38:10 77.123.42.148 444 800
a [2001:470:71:9b9:f66d:4ff:fee7:954c]:444
m GWb+xjav0fsuwPwPNnUvW9Q1Ivk5nz8m1McECM4KY8A
s Fast Guard HSDir Running Stable V2Dir Valid
v Tor 0.2.5.16
pr Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=1-4 LinkAuth=1 Microdesc=1 Relay=1-2
w Bandwidth=4950"#;

    #[test]
    fn test_parse_v3_entry() {
        let entry = RouterStatusEntry::parse(EXAMPLE_V3_ENTRY).unwrap();
        assert_eq!(entry.nickname, "test002r");
        assert_eq!(
            entry.fingerprint,
            "348225F83C854796B2DD6364E65CB189B33BD696"
        );
        assert!(entry.digest.is_some());
        assert_eq!(entry.address.to_string(), "127.0.0.1");
        assert_eq!(entry.or_port, 5002);
        assert_eq!(entry.dir_port, Some(7002));
    }

    #[test]
    fn test_parse_flags() {
        let entry = RouterStatusEntry::parse(EXAMPLE_V3_ENTRY).unwrap();
        assert!(entry.flags.contains(&"Exit".to_string()));
        assert!(entry.flags.contains(&"Fast".to_string()));
        assert!(entry.flags.contains(&"Guard".to_string()));
        assert!(entry.flags.contains(&"Running".to_string()));
        assert!(entry.flags.contains(&"Stable".to_string()));
        assert!(entry.flags.contains(&"Valid".to_string()));
    }

    #[test]
    fn test_parse_version() {
        let entry = RouterStatusEntry::parse(EXAMPLE_V3_ENTRY).unwrap();
        assert_eq!(entry.version_line, Some("Tor 0.3.0.7".to_string()));
        assert!(entry.version.is_some());
    }

    #[test]
    fn test_parse_bandwidth() {
        let entry = RouterStatusEntry::parse(EXAMPLE_V3_ENTRY).unwrap();
        assert_eq!(entry.bandwidth, Some(0));
        assert!(entry.is_unmeasured);
    }

    #[test]
    fn test_parse_exit_policy() {
        let entry = RouterStatusEntry::parse(EXAMPLE_V3_ENTRY).unwrap();
        assert!(entry.exit_policy.is_some());
        let policy = entry.exit_policy.unwrap();
        assert!(policy.is_accept);
    }

    #[test]
    fn test_parse_protocols() {
        let entry = RouterStatusEntry::parse(EXAMPLE_V3_ENTRY).unwrap();
        assert_eq!(entry.protocols.get("Cons"), Some(&vec![1, 2]));
        assert_eq!(entry.protocols.get("Link"), Some(&vec![1, 2, 3, 4]));
    }

    #[test]
    fn test_parse_micro_entry() {
        let entry = RouterStatusEntry::parse_micro(EXAMPLE_MICRO_ENTRY).unwrap();
        assert_eq!(entry.nickname, "test002r");
        assert_eq!(
            entry.fingerprint,
            "348225F83C854796B2DD6364E65CB189B33BD696"
        );
        assert!(entry.digest.is_none());
        assert_eq!(
            entry.microdescriptor_digest,
            Some("uhCGfIM6RbeD1Z/C6e9ct41+NIl9EbpgP8wG7uZT2Rw".to_string())
        );
    }

    #[test]
    fn test_parse_or_addresses() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
a [2001:6b0:7:125::242]:9001
a 10.0.0.1:9002"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(entry.or_addresses.len(), 2);
        let (addr1, port1, is_ipv6_1) = &entry.or_addresses[0];
        assert_eq!(addr1.to_string(), "2001:6b0:7:125::242");
        assert_eq!(*port1, 9001);
        assert!(*is_ipv6_1);
        let (addr2, port2, is_ipv6_2) = &entry.or_addresses[1];
        assert_eq!(addr2.to_string(), "10.0.0.1");
        assert_eq!(*port2, 9002);
        assert!(!*is_ipv6_2);
    }

    #[test]
    fn test_base64_to_hex() {
        let hex = RouterStatusEntry::base64_to_hex("NIIl+DyFR5ay3WNk5lyxibM71pY").unwrap();
        assert_eq!(hex, "348225F83C854796B2DD6364E65CB189B33BD696");
    }

    #[test]
    fn test_fingerprint_decoding() {
        let test_values = [
            (
                "p1aag7VwarGxqctS7/fS0y5FU+s",
                "A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB",
            ),
            (
                "IbhGa8T+8tyy/MhxCk/qI+EI2LU",
                "21B8466BC4FEF2DCB2FCC8710A4FEA23E108D8B5",
            ),
            (
                "20wYcbFGwFfMktmuffYj6Z1RM9k",
                "DB4C1871B146C057CC92D9AE7DF623E99D5133D9",
            ),
            (
                "nTv9AG1cZeFW2hXiSIEAF6JLRJ4",
                "9D3BFD006D5C65E156DA15E248810017A24B449E",
            ),
            (
                "/UKsQiOSGPi/6es0/ha1prNTeDI",
                "FD42AC42239218F8BFE9EB34FE16B5A6B3537832",
            ),
            (
                "/nHdqoKZ6bKZixxAPzYt9Qen+Is",
                "FE71DDAA8299E9B2998B1C403F362DF507A7F88B",
            ),
        ];
        for (input, expected) in test_values {
            let result = RouterStatusEntry::base64_to_hex(input).unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_without_ed25519() {
        let entry = RouterStatusEntry::parse_vote(ENTRY_WITHOUT_ED25519).unwrap();
        assert_eq!(entry.nickname, "seele");
        assert_eq!(
            entry.fingerprint,
            "000A10D43011EA4928A35F610405F92B4433B4DC"
        );
        assert_eq!(entry.address.to_string(), "73.15.150.172");
        assert_eq!(entry.or_port, 9001);
        assert_eq!(entry.dir_port, None);
        assert!(entry.flags.contains(&"Running".to_string()));
        assert!(entry.flags.contains(&"Stable".to_string()));
        assert!(entry.flags.contains(&"Valid".to_string()));
        assert_eq!(entry.version_line, Some("Tor 0.2.6.10".to_string()));
        assert_eq!(entry.bandwidth, Some(102));
        assert_eq!(entry.measured, Some(31));
        assert!(!entry.is_unmeasured);
        assert_eq!(entry.identifier_type, Some("ed25519".to_string()));
        assert_eq!(entry.identifier, Some("none".to_string()));
        assert_eq!(
            entry.digest,
            Some("9B4CA73EEC3349EC6DCEC897609600D0771EF82B".to_string())
        );
        assert_eq!(entry.microdescriptor_hashes.len(), 3);
        assert_eq!(entry.microdescriptor_hashes[0].methods, vec![13, 14, 15]);
        assert_eq!(
            entry.microdescriptor_hashes[0].hashes.get("sha256"),
            Some(&"uaAYTOVuYRqUwJpNfP2WizjzO0FiNQB4U97xSQu+vMc".to_string())
        );
    }

    #[test]
    fn test_with_ed25519() {
        let entry = RouterStatusEntry::parse_vote(ENTRY_WITH_ED25519).unwrap();
        assert_eq!(entry.nickname, "PDrelay1");
        assert_eq!(
            entry.fingerprint,
            "000149E6EF7102AACA9690D6E8DD2932124B94AB"
        );
        assert_eq!(entry.address.to_string(), "95.215.44.189");
        assert_eq!(entry.or_port, 8080);
        assert_eq!(entry.dir_port, None);
        assert!(entry.flags.contains(&"Fast".to_string()));
        assert!(entry.flags.contains(&"Running".to_string()));
        assert!(entry.flags.contains(&"Stable".to_string()));
        assert!(entry.flags.contains(&"Valid".to_string()));
        assert_eq!(
            entry.version_line,
            Some("Tor 0.2.7.2-alpha-dev".to_string())
        );
        assert_eq!(entry.bandwidth, Some(608));
        assert_eq!(entry.measured, Some(472));
        assert!(!entry.is_unmeasured);
        assert_eq!(entry.identifier_type, Some("ed25519".to_string()));
        assert_eq!(
            entry.identifier,
            Some("8RH34kO07Pp+XYwzdoATVyCibIvmbslUjRkAm7J4IA8".to_string())
        );
        assert_eq!(
            entry.digest,
            Some("CAB27A6FFEF7A661C18B0B11120C3E8A77FC585C".to_string())
        );
        assert_eq!(entry.microdescriptor_hashes.len(), 5);
        assert_eq!(entry.microdescriptor_hashes[0].methods, vec![13]);
        assert_eq!(entry.microdescriptor_hashes[1].methods, vec![14, 15]);
    }

    #[test]
    fn test_with_ipv6() {
        let entry = RouterStatusEntry::parse_micro(ENTRY_WITH_IPV6).unwrap();
        assert_eq!(entry.nickname, "MYLEX");
        assert_eq!(
            entry.fingerprint,
            "010B7728454411F485CE29D4C79A14534151C2C4"
        );
        assert_eq!(entry.address.to_string(), "77.123.42.148");
        assert_eq!(entry.or_port, 444);
        assert_eq!(entry.dir_port, Some(800));
        assert!(entry.flags.contains(&"Fast".to_string()));
        assert!(entry.flags.contains(&"Guard".to_string()));
        assert!(entry.flags.contains(&"HSDir".to_string()));
        assert!(entry.flags.contains(&"Running".to_string()));
        assert!(entry.flags.contains(&"Stable".to_string()));
        assert!(entry.flags.contains(&"V2Dir".to_string()));
        assert!(entry.flags.contains(&"Valid".to_string()));
        assert_eq!(entry.version_line, Some("Tor 0.2.5.16".to_string()));
        assert_eq!(entry.or_addresses.len(), 1);
        let (addr, port, is_ipv6) = &entry.or_addresses[0];
        assert_eq!(addr.to_string(), "2001:470:71:9b9:f66d:4ff:fee7:954c");
        assert_eq!(*port, 444);
        assert!(*is_ipv6);
        assert_eq!(entry.bandwidth, Some(4950));
        assert_eq!(entry.measured, None);
        assert!(!entry.is_unmeasured);
        assert_eq!(entry.protocols.len(), 10);
        assert_eq!(
            entry.microdescriptor_digest,
            Some("GWb+xjav0fsuwPwPNnUvW9Q1Ivk5nz8m1McECM4KY8A".to_string())
        );
    }

    #[test]
    fn test_unrecognized_bandwidth_entries() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
s Running Valid
w Bandwidth=11111 Measured=482 Blarg!"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(entry.bandwidth, Some(11111));
        assert_eq!(entry.measured, Some(482));
        assert_eq!(entry.unrecognized_bandwidth_entries, vec!["Blarg!"]);
    }

    #[test]
    fn test_blank_lines() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002

s Running Valid

v Tor 0.2.2.35

"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(entry.version_line, Some("Tor 0.2.2.35".to_string()));
    }

    #[test]
    fn test_unrecognized_lines() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
s Running Valid
z New tor feature: sparkly unicorns!"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(
            entry.unrecognized_lines(),
            &["z New tor feature: sparkly unicorns!"]
        );
    }

    #[test]
    fn test_ipv6_addresses_multiple() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
a [2607:fcd0:daaa:101::602c:bd62]:443
a [1148:fcd0:daaa:101::602c:bd62]:80"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(entry.or_addresses.len(), 2);
        let (addr1, port1, is_ipv6_1) = &entry.or_addresses[0];
        assert_eq!(addr1.to_string(), "2607:fcd0:daaa:101::602c:bd62");
        assert_eq!(*port1, 443);
        assert!(*is_ipv6_1);
        let (addr2, port2, is_ipv6_2) = &entry.or_addresses[1];
        assert_eq!(addr2.to_string(), "1148:fcd0:daaa:101::602c:bd62");
        assert_eq!(*port2, 80);
        assert!(*is_ipv6_2);
    }

    #[test]
    fn test_versions() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
v Tor 0.2.2.35"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(entry.version_line, Some("Tor 0.2.2.35".to_string()));
        assert!(entry.version.is_some());

        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
v Torr new_stuff"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(entry.version_line, Some("Torr new_stuff".to_string()));
        assert!(entry.version.is_none());
    }

    #[test]
    fn test_bandwidth_variations() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
w Bandwidth=63138"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(entry.bandwidth, Some(63138));
        assert_eq!(entry.measured, None);
        assert!(!entry.is_unmeasured);

        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
w Bandwidth=11111 Measured=482"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(entry.bandwidth, Some(11111));
        assert_eq!(entry.measured, Some(482));
        assert!(!entry.is_unmeasured);

        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
w Bandwidth=11111 Measured=482 Unmeasured=1"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert_eq!(entry.bandwidth, Some(11111));
        assert_eq!(entry.measured, Some(482));
        assert!(entry.is_unmeasured);
    }

    #[test]
    fn test_exit_policy_variations() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
p reject 1-65535"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert!(entry.exit_policy.is_some());
        let policy = entry.exit_policy.unwrap();
        assert!(!policy.is_accept);

        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
p accept 80,110,143,443"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert!(entry.exit_policy.is_some());
        let policy = entry.exit_policy.unwrap();
        assert!(policy.is_accept);
    }

    #[test]
    fn test_flags_variations() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
s "#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert!(entry.flags.is_empty() || entry.flags.iter().all(|f| f.is_empty()));

        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
s Fast"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert!(entry.flags.contains(&"Fast".to_string()));

        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
s Fast Valid"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert!(entry.flags.contains(&"Fast".to_string()));
        assert!(entry.flags.contains(&"Valid".to_string()));

        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
s Ugabuga"#;
        let entry = RouterStatusEntry::parse(content).unwrap();
        assert!(entry.flags.contains(&"Ugabuga".to_string()));
    }

    #[test]
    fn test_microdescriptor_hashes_variations() {
        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
m 8,9,10,11,12 sha256=g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs"#;
        let entry = RouterStatusEntry::parse_vote(content).unwrap();
        assert_eq!(entry.microdescriptor_hashes.len(), 1);
        assert_eq!(
            entry.microdescriptor_hashes[0].methods,
            vec![8, 9, 10, 11, 12]
        );
        assert_eq!(
            entry.microdescriptor_hashes[0].hashes.get("sha256"),
            Some(&"g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs".to_string())
        );

        let content = r#"r test NIIl+DyFR5ay3WNk5lyxibM71pY UzQp+EE8G0YCKtNlZVy+3h5tv0Q 2017-05-25 04:46:11 127.0.0.1 5002 7002
m 11,12 sha256=g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs
m 31,32 sha512=g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs"#;
        let entry = RouterStatusEntry::parse_vote(content).unwrap();
        assert_eq!(entry.microdescriptor_hashes.len(), 2);
        assert_eq!(entry.microdescriptor_hashes[0].methods, vec![11, 12]);
        assert_eq!(entry.microdescriptor_hashes[1].methods, vec![31, 32]);
    }
}
