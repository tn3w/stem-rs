//! Microdescriptor parsing for Tor relay microdescriptors.
//!
//! Microdescriptors are compact relay descriptors used by Tor clients
//! to reduce bandwidth usage. They contain a subset of server descriptor
//! information and are referenced by their SHA-256 digest.
//!
//! # Overview
//!
//! Microdescriptors were introduced to reduce the bandwidth required for
//! clients to learn about the Tor network. Instead of downloading full
//! server descriptors, clients download:
//!
//! 1. A consensus document containing microdescriptor hashes
//! 2. The microdescriptors themselves (much smaller than server descriptors)
//!
//! Microdescriptors contain only the information clients need for circuit
//! building:
//!
//! - **Onion keys**: For circuit creation handshakes
//! - **Exit policy summary**: Compact representation of allowed ports
//! - **Protocol versions**: Supported protocol versions
//! - **Family**: Related relays
//!
//! # Descriptor Format
//!
//! Microdescriptors use a compact text format:
//!
//! ```text
//! onion-key
//! -----BEGIN RSA PUBLIC KEY-----
//! <base64 encoded key>
//! -----END RSA PUBLIC KEY-----
//! ntor-onion-key <base64 curve25519 key>
//! a [<ipv6>]:<port>
//! family <fingerprint> <fingerprint> ...
//! p accept|reject <port-list>
//! p6 accept|reject <port-list>
//! pr <protocol>=<versions> ...
//! id <type> <digest>
//! ```
//!
//! # Annotations
//!
//! Microdescriptors from CollecTor archives may include annotations
//! (lines starting with `@`) that provide metadata like when the
//! descriptor was last seen:
//!
//! ```text
//! @last-listed 2023-01-01 00:00:00
//! onion-key
//! ...
//! ```
//!
//! # Example
//!
//! ```rust
//! use stem_rs::descriptor::{Microdescriptor, Descriptor, DigestHash, DigestEncoding};
//!
//! let content = r#"onion-key
//! -----BEGIN RSA PUBLIC KEY-----
//! MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
//! H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
//! CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
//! -----END RSA PUBLIC KEY-----
//! ntor-onion-key r5572HzD+PMPBbXlZwBhsm6YEbxnYgis8vhZ1jmdI2k=
//! p accept 80,443
//! "#;
//!
//! let desc = Microdescriptor::parse(content).unwrap();
//! println!("Has ntor key: {}", desc.ntor_onion_key.is_some());
//! println!("Exit policy: {}", desc.exit_policy);
//!
//! // Compute SHA-256 digest (used for identification)
//! let digest = desc.digest(DigestHash::Sha256, DigestEncoding::Base64).unwrap();
//! println!("Digest: {}", digest);
//! ```
//!
//! # Digest Computation
//!
//! Unlike server descriptors which use SHA-1, microdescriptors are
//! identified by their SHA-256 digest. The digest is computed over
//! the entire microdescriptor content (excluding annotations).
//!
//! # See Also
//!
//! - [`ServerDescriptor`](super::ServerDescriptor) - Full relay descriptors
//! - [`NetworkStatusDocument`](super::NetworkStatusDocument) - Contains microdescriptor hashes
//! - [Python Stem Microdescriptor](https://stem.torproject.org/api/descriptor/microdescriptor.html)

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::exit_policy::MicroExitPolicy;
use crate::Error;

use super::{compute_digest, Descriptor, DigestEncoding, DigestHash};

/// A microdescriptor containing compact relay information for clients.
///
/// Microdescriptors are designed to minimize bandwidth for Tor clients.
/// They contain only the information needed for circuit building, omitting
/// details like contact info, platform, and full exit policies.
///
/// # Fields Overview
///
/// | Field | Description |
/// |-------|-------------|
/// | `onion_key` | RSA key for TAP handshake (legacy) |
/// | `ntor_onion_key` | Curve25519 key for ntor handshake |
/// | `exit_policy` | Compact exit policy (ports only) |
/// | `family` | Related relay fingerprints |
/// | `protocols` | Supported protocol versions |
///
/// # Invariants
///
/// - `onion_key` is always present (required field)
/// - `exit_policy` defaults to "reject 1-65535" if not specified
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::{Microdescriptor, Descriptor};
///
/// let content = r#"onion-key
/// -----BEGIN RSA PUBLIC KEY-----
/// MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
/// H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
/// CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
/// -----END RSA PUBLIC KEY-----
/// p accept 80,443
/// "#;
///
/// let desc = Microdescriptor::parse(content).unwrap();
/// assert!(desc.exit_policy.is_accept);
/// ```
///
/// # Thread Safety
///
/// `Microdescriptor` is `Send` and `Sync` as it contains only owned data.
#[derive(Debug, Clone, PartialEq)]
pub struct Microdescriptor {
    /// RSA onion key for TAP circuit handshake (PEM format).
    ///
    /// This is the legacy key used for the original Tor handshake.
    /// Modern clients prefer the ntor handshake using `ntor_onion_key`.
    pub onion_key: String,
    /// Curve25519 onion key for ntor circuit handshake (base64).
    ///
    /// This is the modern key used for the ntor handshake, which provides
    /// better security properties than the TAP handshake.
    pub ntor_onion_key: Option<String>,
    /// Additional addresses (IPv4 or IPv6) the relay listens on.
    ///
    /// Each tuple is (address, port, is_ipv6). The `a` lines in the
    /// microdescriptor provide these additional addresses.
    pub or_addresses: Vec<(IpAddr, u16, bool)>,
    /// Fingerprints of related relays (same operator).
    ///
    /// These are typically prefixed with `$` and contain the full
    /// 40-character hex fingerprint.
    pub family: Vec<String>,
    /// Compact IPv4 exit policy.
    ///
    /// Unlike full exit policies, microdescriptor policies only specify
    /// which ports are accepted or rejected, not addresses.
    pub exit_policy: MicroExitPolicy,
    /// Compact IPv6 exit policy.
    ///
    /// Separate policy for IPv6 traffic, if different from IPv4.
    pub exit_policy_v6: Option<MicroExitPolicy>,
    /// Identity key digests by type.
    ///
    /// Maps key type (e.g., "rsa1024", "ed25519") to the base64-encoded
    /// digest of that key.
    pub identifiers: HashMap<String, String>,
    /// Supported protocol versions.
    ///
    /// Maps protocol name to list of supported versions.
    /// Common protocols include "Link", "Relay", "HSDir", etc.
    pub protocols: HashMap<String, Vec<u32>>,
    /// Raw bytes of the original descriptor content.
    raw_content: Vec<u8>,
    /// Annotations from CollecTor archives.
    ///
    /// Each annotation is a (key, optional_value) pair from lines
    /// starting with `@`.
    annotations: Vec<(String, Option<String>)>,
    /// Lines that were not recognized during parsing.
    unrecognized_lines: Vec<String>,
}

impl Microdescriptor {
    /// Creates a new microdescriptor with the given onion key.
    ///
    /// This creates a descriptor with default values for optional fields.
    /// The exit policy defaults to rejecting all ports.
    ///
    /// # Arguments
    ///
    /// * `onion_key` - The RSA onion key in PEM format
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::Microdescriptor;
    ///
    /// let key = "-----BEGIN RSA PUBLIC KEY-----\n...\n-----END RSA PUBLIC KEY-----";
    /// let desc = Microdescriptor::new(key.to_string());
    /// assert!(desc.ntor_onion_key.is_none());
    /// assert!(desc.family.is_empty());
    /// ```
    pub fn new(onion_key: String) -> Self {
        Self {
            onion_key,
            ntor_onion_key: None,
            or_addresses: Vec::new(),
            family: Vec::new(),
            exit_policy: MicroExitPolicy::parse("reject 1-65535").unwrap(),
            exit_policy_v6: None,
            identifiers: HashMap::new(),
            protocols: HashMap::new(),
            raw_content: Vec::new(),
            annotations: Vec::new(),
            unrecognized_lines: Vec::new(),
        }
    }

    /// Parses a microdescriptor with additional annotations.
    ///
    /// This is useful when annotations are provided separately from
    /// the descriptor content (e.g., when reading from a cache file
    /// where annotations precede the descriptor).
    ///
    /// # Arguments
    ///
    /// * `content` - The microdescriptor content
    /// * `annotations` - Additional annotation lines (with or without `@` prefix)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the content is malformed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::Microdescriptor;
    ///
    /// let content = r#"onion-key
    /// -----BEGIN RSA PUBLIC KEY-----
    /// MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
    /// H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
    /// CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
    /// -----END RSA PUBLIC KEY-----
    /// "#;
    ///
    /// let annotations = &["@last-listed 2023-01-01 00:00:00"];
    /// let desc = Microdescriptor::parse_with_annotations(content, annotations).unwrap();
    ///
    /// let anns = desc.get_annotations();
    /// assert!(anns.contains_key("last-listed"));
    /// ```
    pub fn parse_with_annotations(content: &str, annotations: &[&str]) -> Result<Self, Error> {
        let mut desc = Self::parse(content)?;
        for ann in annotations {
            let ann = ann.trim();
            if ann.is_empty() {
                continue;
            }
            let ann = ann.strip_prefix('@').unwrap_or(ann);
            if let Some(space_pos) = ann.find(' ') {
                let key = ann[..space_pos].to_string();
                let value = ann[space_pos + 1..].trim().to_string();
                desc.annotations.push((key, Some(value)));
            } else {
                desc.annotations.push((ann.to_string(), None));
            }
        }
        Ok(desc)
    }

    /// Returns all annotations as a map.
    ///
    /// Annotations are metadata lines starting with `@` that may be
    /// present in CollecTor archives.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::{Microdescriptor, Descriptor};
    ///
    /// let content = r#"@last-listed 2023-01-01 00:00:00
    /// onion-key
    /// -----BEGIN RSA PUBLIC KEY-----
    /// MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
    /// H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
    /// CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
    /// -----END RSA PUBLIC KEY-----
    /// "#;
    ///
    /// let desc = Microdescriptor::parse(content).unwrap();
    /// let annotations = desc.get_annotations();
    ///
    /// if let Some(Some(date)) = annotations.get("last-listed") {
    ///     println!("Last listed: {}", date);
    /// }
    /// ```
    pub fn get_annotations(&self) -> HashMap<String, Option<String>> {
        self.annotations.iter().cloned().collect()
    }

    /// Returns annotations formatted as lines with `@` prefix.
    ///
    /// This is useful for serializing annotations back to their
    /// original format.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::{Microdescriptor, Descriptor};
    ///
    /// let content = r#"@last-listed 2023-01-01 00:00:00
    /// onion-key
    /// -----BEGIN RSA PUBLIC KEY-----
    /// MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
    /// H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
    /// CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
    /// -----END RSA PUBLIC KEY-----
    /// "#;
    ///
    /// let desc = Microdescriptor::parse(content).unwrap();
    /// for line in desc.get_annotation_lines() {
    ///     println!("{}", line);
    /// }
    /// ```
    pub fn get_annotation_lines(&self) -> Vec<String> {
        self.annotations
            .iter()
            .map(|(k, v)| match v {
                Some(val) => format!("@{} {}", k, val),
                None => format!("@{}", k),
            })
            .collect()
    }

    /// Extracts a PEM block from lines starting at the given index.
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

    /// Parses an `a` (or-address) line.
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

    fn parse_identifiers(
        value: &str,
        identifiers: &mut HashMap<String, String>,
        validate: bool,
    ) -> Result<(), Error> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(Error::Parse {
                location: "id".to_string(),
                reason: format!(
                    "'id' lines should contain both key type and digest: {}",
                    value
                ),
            });
        }
        let key_type = parts[0].to_string();
        let key_value = parts[1].to_string();
        if validate && identifiers.contains_key(&key_type) {
            return Err(Error::Parse {
                location: "id".to_string(),
                reason: format!(
                    "There can only be one 'id' line per key type, but '{}' appeared multiple times",
                    key_type
                ),
            });
        }
        identifiers.insert(key_type, key_value);
        Ok(())
    }
}

impl Descriptor for Microdescriptor {
    fn parse(content: &str) -> Result<Self, Error> {
        let raw_content = content.as_bytes().to_vec();
        let lines: Vec<&str> = content.lines().collect();

        let mut onion_key: Option<String> = None;
        let mut ntor_onion_key: Option<String> = None;
        let mut or_addresses: Vec<(IpAddr, u16, bool)> = Vec::new();
        let mut family: Vec<String> = Vec::new();
        let mut exit_policy = MicroExitPolicy::parse("reject 1-65535")?;
        let mut exit_policy_v6: Option<MicroExitPolicy> = None;
        let mut identifiers: HashMap<String, String> = HashMap::new();
        let mut protocols: HashMap<String, Vec<u32>> = HashMap::new();
        let mut unrecognized_lines: Vec<String> = Vec::new();
        let mut annotations: Vec<(String, Option<String>)> = Vec::new();

        let mut idx = 0;
        while idx < lines.len() {
            let line = lines[idx];

            if line.starts_with('@') {
                let ann = line.strip_prefix('@').unwrap_or(line);
                if let Some(space_pos) = ann.find(' ') {
                    let key = ann[..space_pos].to_string();
                    let value = ann[space_pos + 1..].trim().to_string();
                    annotations.push((key, Some(value)));
                } else {
                    annotations.push((ann.to_string(), None));
                }
                idx += 1;
                continue;
            }

            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "onion-key" => {
                    let (block, end_idx) = Self::extract_pem_block(&lines, idx + 1);
                    onion_key = Some(block);
                    idx = end_idx;
                }
                "ntor-onion-key" => {
                    ntor_onion_key = Some(value.to_string());
                }
                "a" => {
                    if let Ok(addr) = Self::parse_or_address(value) {
                        or_addresses.push(addr);
                    }
                }
                "family" => {
                    family = value.split_whitespace().map(|s| s.to_string()).collect();
                }
                "p" => {
                    exit_policy = MicroExitPolicy::parse(value)?;
                }
                "p6" => {
                    exit_policy_v6 = Some(MicroExitPolicy::parse(value)?);
                }
                "pr" => {
                    protocols = Self::parse_protocols(value);
                }
                "id" => {
                    let _ = Self::parse_identifiers(value, &mut identifiers, false);
                }
                _ => {
                    if !line.is_empty() && !line.starts_with("-----") {
                        unrecognized_lines.push(line.to_string());
                    }
                }
            }
            idx += 1;
        }

        let onion_key = onion_key.ok_or_else(|| Error::Parse {
            location: "onion-key".to_string(),
            reason: "Microdescriptor must have a 'onion-key' entry".to_string(),
        })?;

        Ok(Self {
            onion_key,
            ntor_onion_key,
            or_addresses,
            family,
            exit_policy,
            exit_policy_v6,
            identifiers,
            protocols,
            raw_content,
            annotations,
            unrecognized_lines,
        })
    }

    fn to_descriptor_string(&self) -> String {
        let mut result = String::new();

        result.push_str("onion-key\n");
        result.push_str(&self.onion_key);
        result.push('\n');

        if let Some(ref ntor_key) = self.ntor_onion_key {
            result.push_str(&format!("ntor-onion-key {}\n", ntor_key));
        }

        for (addr, port, is_ipv6) in &self.or_addresses {
            if *is_ipv6 {
                result.push_str(&format!("a [{}]:{}\n", addr, port));
            } else {
                result.push_str(&format!("a {}:{}\n", addr, port));
            }
        }

        if !self.family.is_empty() {
            result.push_str(&format!("family {}\n", self.family.join(" ")));
        }

        result.push_str(&format!("p {}\n", self.exit_policy));

        if let Some(ref policy_v6) = self.exit_policy_v6 {
            result.push_str(&format!("p6 {}\n", policy_v6));
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
            result.push_str(&format!("pr {}\n", proto_str.join(" ")));
        }

        for (key_type, key_value) in &self.identifiers {
            result.push_str(&format!("id {} {}\n", key_type, key_value));
        }

        result
    }

    fn digest(&self, hash: DigestHash, encoding: DigestEncoding) -> Result<String, Error> {
        Ok(compute_digest(&self.raw_content, hash, encoding))
    }

    fn raw_content(&self) -> &[u8] {
        &self.raw_content
    }

    fn unrecognized_lines(&self) -> &[String] {
        &self.unrecognized_lines
    }
}

impl FromStr for Microdescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Microdescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_descriptor_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_ONION_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----";

    const SECOND_ONION_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALCOxZdpMI2WO496njSQ2M7b4IgAGATqpJmH3So7lXOa25sK6o7JipgP
qQE83K/t/xsMIpxQ/hHkft3G78HkeXXFc9lVUzH0HmHwYEu0M+PMVULSkG36MfEl
7WeSZzaG+Tlnh9OySAzVyTsv1ZJsTQFHH9V8wuM0GOMo9X8DFC+NAgMBAAE=
-----END RSA PUBLIC KEY-----";

    const THIRD_ONION_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOWFQHxO+5kGuhwPUX5jB7wJCrTbSU0fZwolNV1t9UaDdjGDvIjIhdit
y2sMbyd9K8lbQO7x9rQjNst5ZicuaSOs854XQddSjm++vMdjYbOcVMqnKGSztvpd
w/1LVWFfhcBnsGi4JMGbmP+KUZG9A8kI9deSyJhfi35jA7UepiHHAgMBAAE=
-----END RSA PUBLIC KEY-----";

    fn first_microdesc() -> &'static str {
        "@last-listed 2013-02-24 00:18:36
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----"
    }

    fn second_microdesc() -> &'static str {
        "@last-listed 2013-02-24 00:18:37
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALCOxZdpMI2WO496njSQ2M7b4IgAGATqpJmH3So7lXOa25sK6o7JipgP
qQE83K/t/xsMIpxQ/hHkft3G78HkeXXFc9lVUzH0HmHwYEu0M+PMVULSkG36MfEl
7WeSZzaG+Tlnh9OySAzVyTsv1ZJsTQFHH9V8wuM0GOMo9X8DFC+NAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key r5572HzD+PMPBbXlZwBhsm6YEbxnYgis8vhZ1jmdI2k=
family $6141629FA0D15A6AEAEF3A1BEB76E64C767B3174"
    }

    fn third_microdesc() -> &'static str {
        "@last-listed 2013-02-24 00:18:36
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOWFQHxO+5kGuhwPUX5jB7wJCrTbSU0fZwolNV1t9UaDdjGDvIjIhdit
y2sMbyd9K8lbQO7x9rQjNst5ZicuaSOs854XQddSjm++vMdjYbOcVMqnKGSztvpd
w/1LVWFfhcBnsGi4JMGbmP+KUZG9A8kI9deSyJhfi35jA7UepiHHAgMBAAE=
-----END RSA PUBLIC KEY-----
a [2001:6b0:7:125::242]:9001
p accept 80,443"
    }

    #[test]
    fn test_parse_first_microdesc() {
        let desc = Microdescriptor::parse(first_microdesc()).unwrap();
        assert_eq!(desc.onion_key, FIRST_ONION_KEY);
        assert_eq!(desc.ntor_onion_key, None);
        assert!(desc.or_addresses.is_empty());
        assert!(desc.family.is_empty());
        assert!(!desc.exit_policy.is_accept);
        assert!(desc.exit_policy.ports.iter().any(|p| p.is_wildcard()));
        let annotations = desc.get_annotations();
        assert_eq!(
            annotations.get("last-listed"),
            Some(&Some("2013-02-24 00:18:36".to_string()))
        );
    }

    #[test]
    fn test_parse_second_microdesc() {
        let desc = Microdescriptor::parse(second_microdesc()).unwrap();
        assert_eq!(desc.onion_key, SECOND_ONION_KEY);
        assert_eq!(
            desc.ntor_onion_key,
            Some("r5572HzD+PMPBbXlZwBhsm6YEbxnYgis8vhZ1jmdI2k=".to_string())
        );
        assert!(desc.or_addresses.is_empty());
        assert_eq!(
            desc.family,
            vec!["$6141629FA0D15A6AEAEF3A1BEB76E64C767B3174"]
        );
        assert!(!desc.exit_policy.is_accept);
        assert!(desc.exit_policy.ports.iter().any(|p| p.is_wildcard()));
    }

    #[test]
    fn test_parse_third_microdesc() {
        let desc = Microdescriptor::parse(third_microdesc()).unwrap();
        assert_eq!(desc.onion_key, THIRD_ONION_KEY);
        assert_eq!(desc.ntor_onion_key, None);
        assert_eq!(desc.or_addresses.len(), 1);
        let (addr, port, is_ipv6) = &desc.or_addresses[0];
        assert_eq!(addr.to_string(), "2001:6b0:7:125::242");
        assert_eq!(*port, 9001);
        assert!(*is_ipv6);
        assert!(desc.family.is_empty());
        assert_eq!(desc.exit_policy.to_string(), "accept 80,443");
    }

    #[test]
    fn test_minimal_microdescriptor() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(desc.ntor_onion_key, None);
        assert!(desc.or_addresses.is_empty());
        assert!(desc.family.is_empty());
        assert!(!desc.exit_policy.is_accept);
        assert!(desc.exit_policy.ports.iter().any(|p| p.is_wildcard()));
        assert_eq!(desc.exit_policy_v6, None);
        assert!(desc.identifiers.is_empty());
        assert!(desc.protocols.is_empty());
        assert!(desc.unrecognized_lines.is_empty());
    }

    #[test]
    fn test_unrecognized_line() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
pepperjack is oh so tasty!";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(desc.unrecognized_lines, vec!["pepperjack is oh so tasty!"]);
    }

    #[test]
    fn test_a_line() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
a 10.45.227.253:9001
a [fd9f:2e19:3bcf::02:9970]:9001";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(desc.or_addresses.len(), 2);
        let (addr1, port1, is_ipv6_1) = &desc.or_addresses[0];
        assert_eq!(addr1.to_string(), "10.45.227.253");
        assert_eq!(*port1, 9001);
        assert!(!*is_ipv6_1);
        let (addr2, port2, is_ipv6_2) = &desc.or_addresses[1];
        assert_eq!(addr2.to_string(), "fd9f:2e19:3bcf::2:9970");
        assert_eq!(*port2, 9001);
        assert!(*is_ipv6_2);
    }

    #[test]
    fn test_family() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
family Amunet1 Amunet2 Amunet3";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(desc.family, vec!["Amunet1", "Amunet2", "Amunet3"]);
    }

    #[test]
    fn test_exit_policy() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
p accept 80,110,143,443";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(desc.exit_policy.to_string(), "accept 80,110,143,443");
    }

    #[test]
    fn test_protocols() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
pr Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=1-4 LinkAuth=1 Microdesc=1 Relay=1-2";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(desc.protocols.len(), 10);
        assert_eq!(desc.protocols.get("Link"), Some(&vec![1, 2, 3, 4]));
        assert_eq!(desc.protocols.get("Relay"), Some(&vec![1, 2]));
    }

    #[test]
    fn test_identifier() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
id rsa1024 Cd47okjCHD83YGzThGBDptXs9Z4";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(
            desc.identifiers.get("rsa1024"),
            Some(&"Cd47okjCHD83YGzThGBDptXs9Z4".to_string())
        );
    }

    #[test]
    fn test_multiple_identifiers() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
id rsa1024 Cd47okjCHD83YGzThGBDptXs9Z4
id ed25519 50f6ddbecdc848dcc6b818b14d1";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(
            desc.identifiers.get("rsa1024"),
            Some(&"Cd47okjCHD83YGzThGBDptXs9Z4".to_string())
        );
        assert_eq!(
            desc.identifiers.get("ed25519"),
            Some(&"50f6ddbecdc848dcc6b818b14d1".to_string())
        );
    }

    #[test]
    fn test_digest() {
        let desc = Microdescriptor::parse(third_microdesc()).unwrap();
        let digest = desc
            .digest(DigestHash::Sha256, DigestEncoding::Base64)
            .unwrap();
        assert!(!digest.is_empty());
    }

    #[test]
    fn test_missing_onion_key() {
        let content = "ntor-onion-key r5572HzD+PMPBbXlZwBhsm6YEbxnYgis8vhZ1jmdI2k=";
        let result = Microdescriptor::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_proceeding_line() {
        let content = "family Amunet1
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(desc.family, vec!["Amunet1"]);
    }

    #[test]
    fn test_conflicting_identifiers() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
id rsa1024 Cd47okjCHD83YGzThGBDptXs9Z4
id rsa1024 50f6ddbecdc848dcc6b818b14d1";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(
            desc.identifiers.get("rsa1024"),
            Some(&"50f6ddbecdc848dcc6b818b14d1".to_string())
        );
    }

    #[test]
    fn test_exit_policy_v6() {
        let content = "onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
p accept 80,443
p6 accept 80,443";
        let desc = Microdescriptor::parse(content).unwrap();
        assert_eq!(desc.exit_policy.to_string(), "accept 80,443");
        assert!(desc.exit_policy_v6.is_some());
        assert_eq!(desc.exit_policy_v6.unwrap().to_string(), "accept 80,443");
    }

    use proptest::prelude::*;

    fn valid_base64_key() -> impl Strategy<Value = String> {
        Just("MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM\nH2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF\nCxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=".to_string())
    }

    fn valid_ntor_key() -> impl Strategy<Value = String> {
        Just("r5572HzD+PMPBbXlZwBhsm6YEbxnYgis8vhZ1jmdI2k=".to_string())
    }

    fn simple_microdescriptor() -> impl Strategy<Value = Microdescriptor> {
        (
            valid_base64_key(),
            proptest::option::of(valid_ntor_key()),
            proptest::collection::vec("[A-Za-z0-9]{1,19}", 0..3),
        )
            .prop_map(|(onion_key, ntor_key, family)| {
                let mut desc = Microdescriptor::new(format!(
                    "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----",
                    onion_key
                ));
                desc.ntor_onion_key = ntor_key;
                desc.family = family;
                desc
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_microdescriptor_roundtrip(desc in simple_microdescriptor()) {
            let serialized = desc.to_descriptor_string();
            let parsed = Microdescriptor::parse(&serialized);

            prop_assert!(parsed.is_ok(), "Failed to parse serialized microdescriptor: {:?}", parsed.err());

            let parsed = parsed.unwrap();

            prop_assert_eq!(&desc.onion_key, &parsed.onion_key, "onion_key mismatch");
            prop_assert_eq!(&desc.ntor_onion_key, &parsed.ntor_onion_key, "ntor_onion_key mismatch");
            prop_assert_eq!(&desc.family, &parsed.family, "family mismatch");
            prop_assert_eq!(desc.exit_policy.to_string(), parsed.exit_policy.to_string(), "exit_policy mismatch");
        }
    }
}
