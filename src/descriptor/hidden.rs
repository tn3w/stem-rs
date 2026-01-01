//! Hidden service descriptor parsing for Tor onion services.
//!
//! This module provides parsing for hidden service descriptors (v2 and v3)
//! which describe onion services accessible through the Tor network. Unlike
//! other descriptor types, these describe a hidden service rather than a relay.
//! They're created by the service itself and can only be fetched via relays
//! with the HSDir flag.
//!
//! # Overview
//!
//! Hidden services (also known as onion services) allow servers to receive
//! incoming connections through the Tor network without revealing their IP
//! address. Each hidden service publishes descriptors that contain the
//! information clients need to connect.
//!
//! # Descriptor Versions
//!
//! ## Version 2 (Deprecated)
//!
//! Version 2 hidden service descriptors use RSA cryptography and have `.onion`
//! addresses that are 16 characters long. These are being phased out in favor
//! of v3 descriptors.
//!
//! Key components:
//! - `descriptor_id`: Base32 hash identifying this descriptor
//! - `permanent_key`: RSA public key of the hidden service
//! - `introduction_points`: List of relays that can introduce clients
//!
//! ## Version 3 (Current)
//!
//! Version 3 hidden service descriptors use Ed25519/Curve25519 cryptography
//! and have `.onion` addresses that are 56 characters long. They provide
//! improved security through multiple encryption layers.
//!
//! Key components:
//! - `signing_cert`: Ed25519 certificate for the descriptor
//! - `superencrypted`: Outer encryption layer containing client authorization
//! - Introduction points are in the inner encrypted layer
//!
//! # Encryption Layers (V3)
//!
//! V3 descriptors have two encryption layers:
//!
//! 1. **Outer Layer** ([`OuterLayer`]): Contains client authorization data
//!    and the encrypted inner layer. Decrypted using the blinded public key
//!    and subcredential.
//!
//! 2. **Inner Layer** ([`InnerLayer`]): Contains the actual introduction
//!    points and service configuration. Requires the descriptor cookie for
//!    client-authorized services.
//!
//! # Security Considerations
//!
//! - V2 descriptors are deprecated and should not be used for new services
//! - V3 descriptor decryption requires cryptographic keys not stored in the
//!   descriptor itself
//! - Introduction point information is sensitive and encrypted
//! - The `.onion` address encodes a checksum to prevent typos
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::descriptor::hidden::{HiddenServiceDescriptorV2, HiddenServiceDescriptorV3};
//! use stem_rs::descriptor::Descriptor;
//!
//! // Parse a v2 descriptor
//! let v2_content = "rendezvous-service-descriptor ...";
//! // let desc_v2 = HiddenServiceDescriptorV2::parse(v2_content)?;
//!
//! // Parse a v3 descriptor
//! let v3_content = "hs-descriptor 3\n...";
//! // let desc_v3 = HiddenServiceDescriptorV3::parse(v3_content)?;
//!
//! // Convert between v3 address and identity key
//! let key = [0u8; 32];
//! let address = HiddenServiceDescriptorV3::address_from_identity_key(&key);
//! assert!(address.ends_with(".onion"));
//! ```
//!
//! # See Also
//!
//! - [`crate::descriptor`]: Base descriptor traits and utilities
//! - [`crate::descriptor::certificate`]: Ed25519 certificates used in v3 descriptors
//!
//! # See also
//!
//! - [Tor Rendezvous Specification v2](https://gitweb.torproject.org/torspec.git/tree/rend-spec-v2.txt) (deprecated)
//! - [Tor Rendezvous Specification v3](https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt)

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::Error;

use super::{compute_digest, Descriptor, DigestEncoding, DigestHash};

/// Introduction point for a version 2 hidden service.
///
/// An introduction point is a Tor relay that acts as an intermediary between
/// clients and the hidden service. Clients connect to introduction points to
/// establish a rendezvous with the service.
///
/// # Fields
///
/// - `identifier`: Base32-encoded hash of the introduction point's identity key
/// - `address`: IPv4 address where the introduction point is reachable
/// - `port`: Port number for the introduction point
/// - `onion_key`: RSA public key for encrypting the introduction
/// - `service_key`: RSA public key for the hidden service at this point
/// - `intro_authentication`: Optional authentication data as (type, data) pairs
///
/// # Security
///
/// Introduction points do not know the hidden service's actual location.
/// They only relay encrypted introduction requests.
///
/// # Example
///
/// ```rust,ignore
/// // Introduction points are typically parsed from a descriptor
/// let desc = HiddenServiceDescriptorV2::parse(content)?;
/// let intro_points = desc.introduction_points()?;
///
/// for point in intro_points {
///     println!("Introduction point: {} at {}:{}",
///              point.identifier, point.address, point.port);
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct IntroductionPointV2 {
    /// Base32-encoded hash of the introduction point's identity key.
    pub identifier: String,
    /// IPv4 address of the introduction point relay.
    pub address: String,
    /// Port number where the introduction point is listening.
    pub port: u16,
    /// RSA public key for encrypting introduction requests (PEM format).
    pub onion_key: Option<String>,
    /// RSA public key for the hidden service at this introduction point (PEM format).
    pub service_key: Option<String>,
    /// Authentication data as (auth_type, auth_data) pairs for establishing connections.
    pub intro_authentication: Vec<(String, String)>,
}

impl IntroductionPointV2 {
    /// Parses an introduction point from its descriptor content.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw text content of a single introduction point block
    ///
    /// # Returns
    ///
    /// A parsed `IntroductionPointV2` on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The port number is not a valid u16
    /// - Required fields are missing or malformed
    fn parse(content: &str) -> Result<Self, Error> {
        let mut identifier = String::new();
        let mut address = String::new();
        let mut port: u16 = 0;
        let mut onion_key: Option<String> = None;
        let mut service_key: Option<String> = None;
        let intro_authentication: Vec<(String, String)> = Vec::new();

        let lines: Vec<&str> = content.lines().collect();
        let mut idx = 0;

        while idx < lines.len() {
            let line = lines[idx];
            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "introduction-point" => identifier = value.to_string(),
                "ip-address" => address = value.to_string(),
                "onion-port" => {
                    port = value.parse().map_err(|_| Error::Parse {
                        location: "introduction-point".to_string(),
                        reason: format!("invalid port: {}", value),
                    })?;
                }
                "onion-key" => {
                    let (block, end_idx) = extract_pem_block(&lines, idx + 1);
                    onion_key = Some(block);
                    idx = end_idx;
                }
                "service-key" => {
                    let (block, end_idx) = extract_pem_block(&lines, idx + 1);
                    service_key = Some(block);
                    idx = end_idx;
                }
                _ => {}
            }
            idx += 1;
        }

        Ok(Self {
            identifier,
            address,
            port,
            onion_key,
            service_key,
            intro_authentication,
        })
    }
}

/// Version 2 hidden service descriptor.
///
/// A v2 hidden service descriptor contains all the information needed for
/// clients to connect to a hidden service using the v2 protocol. This includes
/// the service's public key, publication time, supported protocol versions,
/// and encrypted introduction points.
///
/// # Deprecation Notice
///
/// Version 2 hidden services are deprecated and being phased out by the Tor
/// Project. New services should use version 3 descriptors
/// ([`HiddenServiceDescriptorV3`]) which provide stronger cryptography.
///
/// # Structure
///
/// The descriptor contains:
/// - `descriptor_id`: Unique identifier (base32 hash of service key and time)
/// - `permanent_key`: RSA-1024 public key of the hidden service
/// - `secret_id_part`: Hash component for descriptor ID validation
/// - `published`: When this descriptor was created
/// - `protocol_versions`: Supported rendezvous protocol versions (typically 2,3)
/// - `introduction_points_*`: Encrypted or encoded introduction point data
/// - `signature`: RSA signature over the descriptor
///
/// # Introduction Points
///
/// Introduction points may be encrypted if the service uses client
/// authorization. Use [`introduction_points()`](Self::introduction_points)
/// to decode them when unencrypted.
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::descriptor::hidden::HiddenServiceDescriptorV2;
/// use stem_rs::descriptor::Descriptor;
///
/// let content = std::fs::read_to_string("descriptor.txt")?;
/// let desc = HiddenServiceDescriptorV2::parse(&content)?;
///
/// println!("Descriptor ID: {}", desc.descriptor_id);
/// println!("Published: {}", desc.published);
/// println!("Protocol versions: {:?}", desc.protocol_versions);
///
/// // Get introduction points (if not encrypted)
/// if let Ok(points) = desc.introduction_points() {
///     for point in points {
///         println!("Intro point: {} at {}:{}",
///                  point.identifier, point.address, point.port);
///     }
/// }
/// ```
///
/// # Security
///
/// - The `permanent_key` is the long-term identity of the service
/// - The `signature` should be verified against `permanent_key`
/// - Introduction points may be encrypted for client authorization
#[derive(Debug, Clone, PartialEq)]
pub struct HiddenServiceDescriptorV2 {
    /// Unique identifier for this descriptor (base32-encoded hash).
    pub descriptor_id: String,
    /// Hidden service descriptor version (always 2 for this type).
    pub version: u32,
    /// RSA-1024 public key of the hidden service (PEM format).
    pub permanent_key: Option<String>,
    /// Hash of time period, cookie, and replica for descriptor ID validation.
    pub secret_id_part: String,
    /// UTC timestamp when this descriptor was published.
    pub published: DateTime<Utc>,
    /// List of supported rendezvous protocol versions (typically [2, 3]).
    pub protocol_versions: Vec<u32>,
    /// Raw base64-encoded introduction points blob (MESSAGE block).
    pub introduction_points_encoded: Option<String>,
    /// Decoded introduction points content (may be encrypted).
    pub introduction_points_content: Option<Vec<u8>>,
    /// RSA signature over the descriptor content (PEM format).
    pub signature: String,
    /// Raw bytes of the original descriptor content.
    raw_content: Vec<u8>,
    /// Lines from the descriptor that were not recognized.
    unrecognized_lines: Vec<String>,
}

impl HiddenServiceDescriptorV2 {
    /// Decodes and parses the introduction points from this descriptor.
    ///
    /// Introduction points are act as intermediaries between
    /// clients and the hidden service. This method decodes the base64-encoded
    /// introduction points blob and parses each introduction point.
    ///
    /// # Returns
    ///
    /// A vector of [`IntroductionPointV2`] on success, or an empty vector
    /// if no introduction points are present.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The introduction points content is not valid UTF-8
    /// - The content is encrypted (starts with something other than
    ///   "introduction-point ")
    /// - Individual introduction points fail to parse
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let desc = HiddenServiceDescriptorV2::parse(content)?;
    /// leo_points = desc.introduction_points()?;
    ///
    /// for point in intro_points {
    ///     println!("Relay: {} at {}:{}",
    ///              point.identifier, point.address, point.port);
    /// }
    /// ```
    ///
    /// # Security
    ///
    /// If the hidden service uses client authorization, the introduction
    /// points will be encrypted and this method will return an error.
    /// Decryption requires the client's authorization cookie.
    pub fn introduction_points(&self) -> Result<Vec<IntroductionPointV2>, Error> {
        let content = match &self.introduction_points_content {
            Some(c) if !c.is_empty() => c,
            _ => return Ok(Vec::new()),
        };

        let content_str = std::str::from_utf8(content).map_err(|_| Error::Parse {
            location: "introduction-points".to_string(),
            reason: "invalid UTF-8 in introduction points".to_string(),
        })?;

        if !content_str.starts_with("introduction-point ") {
            return Err(Error::Parse {
                location: "introduction-points".to_string(),
                reason: "content is encrypted or malformed".to_string(),
            });
        }

        let mut points = Vec::new();
        let mut current_block = String::new();

        for line in content_str.lines() {
            if line.starts_with("introduction-point ") && !current_block.is_empty() {
                points.push(IntroductionPointV2::parse(&current_block)?);
                current_block.clear();
            }
            current_block.push_str(line);
            current_block.push('\n');
        }

        if !current_block.is_empty() {
            points.push(IntroductionPointV2::parse(&current_block)?);
        }

        Ok(points)
    }

    /// Parses a comma-separated list of protocol versions.
    ///
    /// # Arguments
    ///
    /// * `value` - Comma-separated version numbers (e.g., "2,3")
    ///
    /// # Returns
    ///
    /// A vector of version numbers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if any version is not a valid u32.
    fn parse_protocol_versions(value: &str) -> Result<Vec<u32>, Error> {
        if value.is_empty() {
            return Ok(Vec::new());
        }

        value
            .split(',')
            .map(|v| {
                let v = v.trim();
                v.parse::<u32>().map_err(|_| Error::Parse {
                    location: "protocol-versions".to_string(),
                    reason: format!("invalid version: {}", v),
                })
            })
            .collect()
    }

    /// Decodes base64-encoded introduction points content.
    ///
    /// Strips PEM headers and decodes the base64 content.
    ///
    /// # Arguments
    ///
    /// * `encoded` - The MESSAGE block content including headers
    ///
    /// # Returns
    ///
    /// The decoded bytes, or `None` if decoding fails.
    fn decode_introduction_points(encoded: &str) -> Option<Vec<u8>> {
        let content = encoded
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");

        if content.is_empty() {
            return Some(Vec::new());
        }

        base64_decode(&content)
    }
}

impl Descriptor for HiddenServiceDescriptorV2 {
    fn parse(content: &str) -> Result<Self, Error> {
        let raw_content = content.as_bytes().to_vec();
        let lines: Vec<&str> = content.lines().collect();

        let mut descriptor_id = String::new();
        let mut version: u32 = 0;
        let mut permanent_key: Option<String> = None;
        let mut secret_id_part = String::new();
        let mut published: Option<DateTime<Utc>> = None;
        let mut protocol_versions: Vec<u32> = Vec::new();
        let mut introduction_points_encoded: Option<String> = None;
        let mut introduction_points_content: Option<Vec<u8>> = None;
        let mut signature = String::new();
        let mut unrecognized_lines: Vec<String> = Vec::new();

        let mut idx = 0;
        while idx < lines.len() {
            let line = lines[idx];

            if line.starts_with("@type ") {
                idx += 1;
                continue;
            }

            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "rendezvous-service-descriptor" => {
                    descriptor_id = value.to_string();
                }
                "version" => {
                    version = value.parse().map_err(|_| Error::Parse {
                        location: "version".to_string(),
                        reason: format!("invalid version: {}", value),
                    })?;
                }
                "permanent-key" => {
                    let (block, end_idx) = extract_pem_block(&lines, idx + 1);
                    permanent_key = Some(block);
                    idx = end_idx;
                }
                "secret-id-part" => {
                    secret_id_part = value.to_string();
                }
                "publication-time" => {
                    let datetime = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
                        .map_err(|e| Error::Parse {
                            location: "publication-time".to_string(),
                            reason: format!("invalid datetime: {} - {}", value, e),
                        })?;
                    published = Some(datetime.and_utc());
                }
                "protocol-versions" => {
                    protocol_versions = Self::parse_protocol_versions(value)?;
                }
                "introduction-points" => {
                    let (block, end_idx) = extract_message_block(&lines, idx + 1);
                    introduction_points_encoded = Some(block.clone());
                    introduction_points_content = Self::decode_introduction_points(&block);
                    idx = end_idx;
                }
                "signature" => {
                    let (block, end_idx) = extract_pem_block(&lines, idx + 1);
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

        let published = published.ok_or_else(|| Error::Parse {
            location: "publication-time".to_string(),
            reason: "missing publication-time".to_string(),
        })?;

        Ok(Self {
            descriptor_id,
            version,
            permanent_key,
            secret_id_part,
            published,
            protocol_versions,
            introduction_points_encoded,
            introduction_points_content,
            signature,
            raw_content,
            unrecognized_lines,
        })
    }

    fn to_descriptor_string(&self) -> String {
        let mut result = String::new();

        result.push_str(&format!(
            "rendezvous-service-descriptor {}\n",
            self.descriptor_id
        ));
        result.push_str(&format!("version {}\n", self.version));

        if let Some(ref key) = self.permanent_key {
            result.push_str("permanent-key\n");
            result.push_str(key);
            result.push('\n');
        }

        result.push_str(&format!("secret-id-part {}\n", self.secret_id_part));
        result.push_str(&format!(
            "publication-time {}\n",
            self.published.format("%Y-%m-%d %H:%M:%S")
        ));

        let versions: Vec<String> = self
            .protocol_versions
            .iter()
            .map(|v| v.to_string())
            .collect();
        result.push_str(&format!("protocol-versions {}\n", versions.join(",")));

        if let Some(ref encoded) = self.introduction_points_encoded {
            result.push_str("introduction-points\n");
            result.push_str(encoded);
            result.push('\n');
        }

        result.push_str("signature\n");
        result.push_str(&self.signature);
        result.push('\n');

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

impl FromStr for HiddenServiceDescriptorV2 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for HiddenServiceDescriptorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_descriptor_string())
    }
}

/// Link specifier for v3 introduction points.
///
/// Link specifiers describe how to connect to an introduction point relay.
/// They can specify IPv4/IPv6 addresses, relay fingerprints, or Ed25519
/// identity keys.
///
/// # Variants
///
/// - `IPv4`: IPv4 address and port
/// - `IPv6`: IPv6 address and port  
/// - `Fingerprint`: 40-character hex relay fingerprint
/// - `Ed25519`: Base64-encoded Ed25519 public key
/// - `Unknown`: Unrecognized link specifier type
///
/// # Wire Format
///
/// Link specifiers are encoded as:
/// - 1 byte: type
/// - 1 byte: length
/// - N bytes: data (format depends on type)
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::hidden::LinkSpecifier;
///
/// let ipv4 = LinkSpecifier::IPv4 {
///     address: "192.168.1.1".to_string(),
///     port: 9001,
/// };
///
/// let packed = ipv4.pack();
/// assert_eq!(packed[0], 0); // Type 0 = IPv4
/// assert_eq!(packed[1], 6); // Length = 6 bytes (4 addr + 2 port)
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum LinkSpecifier {
    /// IPv4 address and port (type 0).
    IPv4 {
        /// Dotted-decimal IPv4 address.
        address: String,
        /// TCP port number.
        port: u16,
    },
    /// IPv6 address and port (type 1).
    IPv6 {
        /// Colon-separated IPv6 address.
        address: String,
        /// TCP port number.
        port: u16,
    },
    /// Relay fingerprint (type 2).
    ///
    /// 40-character uppercase hex string representing the relay's
    /// SHA-1 identity hash.
    Fingerprint(String),
    /// Ed25519 identity key (type 3).
    ///
    /// Base64-encoded 32-byte Ed25519 public key.
    Ed25519(String),
    /// Unknown or unrecognized link specifier type.
    Unknown {
        /// The type byte from the wire format.
        link_type: u8,
        /// Raw data bytes.
        data: Vec<u8>,
    },
}

impl LinkSpecifier {
    /// Packs this link specifier into its wire format.
    ///
    /// The wire format is:
    /// - 1 byte: type (0=IPv4, 1=IPv6, 2=fingerprint, 3=Ed25519)
    /// - 1 byte: length of data
    /// - N bytes: type-specific data
    ///
    /// # Returns
    ///
    /// A byte vector containing the packed link specifier.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::hidden::LinkSpecifier;
    ///
    /// let spec = LinkSpecifier::IPv4 {
    ///     address: "1.2.3.4".to_string(),
    ///     port: 9001,
    /// };
    /// let packed = spec.pack();
    /// assert_eq!(packed.len(), 8); // 1 type + 1 len + 4 addr + 2 port
    /// ```
    pub fn pack(&self) -> Vec<u8> {
        match self {
            LinkSpecifier::IPv4 { address, port } => {
                let mut data = vec![0u8];
                let parts: Vec<u8> = address.split('.').filter_map(|p| p.parse().ok()).collect();
                let len = 6u8;
                data.push(len);
                data.extend_from_slice(&parts);
                data.extend_from_slice(&port.to_be_bytes());
                data
            }
            LinkSpecifier::IPv6 { address, port } => {
                let mut data = vec![1u8];
                let len = 18u8;
                data.push(len);
                let parts: Vec<u16> = address
                    .split(':')
                    .filter_map(|p| u16::from_str_radix(p, 16).ok())
                    .collect();
                for part in parts {
                    data.extend_from_slice(&part.to_be_bytes());
                }
                data.extend_from_slice(&port.to_be_bytes());
                data
            }
            LinkSpecifier::Fingerprint(fp) => {
                let mut data = vec![2u8];
                let len = 20u8;
                data.push(len);
                let bytes: Vec<u8> = (0..fp.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&fp[i..i + 2], 16).ok())
                    .collect();
                data.extend_from_slice(&bytes);
                data
            }
            LinkSpecifier::Ed25519(key) => {
                let mut data = vec![3u8];
                let len = 32u8;
                data.push(len);
                if let Some(decoded) = base64_decode(key) {
                    data.extend_from_slice(&decoded);
                }
                data
            }
            LinkSpecifier::Unknown { link_type, data: d } => {
                let mut data = vec![*link_type];
                data.push(d.len() as u8);
                data.extend_from_slice(d);
                data
            }
        }
    }
}

/// Introduction point for a version 3 hidden service.
///
/// V3 introduction points use modern cryptography (Ed25519/X25519) and
/// support multiple ways to specify the relay's location via link specifiers.
///
/// # Fields
///
/// - `link_specifiers`: How to connect to this introduction point
/// - `onion_key_raw`: Base64 ntor key for the introduction handshake
/// - `auth_key_cert`: Ed25519 certificate cross-certifying the signing key
/// - `enc_key_raw`: Base64 encryption key for introduction requests
/// - `enc_key_cert`: Ed25519 certificate for the encryption key
/// - `legacy_key_raw`: Optional RSA key for backward compatibility
/// - `legacy_key_cert`: Optional certificate for the legacy key
///
/// # Cryptographic Keys
///
/// Each introduction point has several keys:
///
/// 1. **Onion Key**: X25519 key for the ntor handshake with the intro point
/// 2. **Auth Key**: Ed25519 key that authenticates the introduction point
/// 3. **Enc Key**: X25519 key for encrypting the introduction request
/// 4. **Legacy Key**: Optional RSA key for older clients
///
/// # Example
///
/// ```rust,ignore
/// let inner_layer = InnerLayer::parse(decrypted_content)?;
///
/// for intro_point in inner_layer.introduction_points {
///     for spec in &intro_point.link_specifiers {
///         match spec {
///             LinkSpecifier::IPv4 { address, port } => {
///                 println!("Connect to {}:{}", address, port);
///             }
///             _ => {}
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct IntroductionPointV3 {
    /// Link specifiers describing how to connect to this introduction point.
    pub link_specifiers: Vec<LinkSpecifier>,
    /// Base64-encoded X25519 public key for ntor handshake.
    pub onion_key_raw: Option<String>,
    /// Ed25519 certificate cross-certifying the signing key with the auth key.
    pub auth_key_cert: Option<String>,
    /// Base64-encoded X25519 public key for encrypting introduction requests.
    pub enc_key_raw: Option<String>,
    /// Ed25519 certificate cross-certifying the signing key by the encryption key.
    pub enc_key_cert: Option<String>,
    /// Optional base64-encoded RSA public key for legacy clients.
    pub legacy_key_raw: Option<String>,
    /// Optional certificate for the legacy RSA key.
    pub legacy_key_cert: Option<String>,
}

impl IntroductionPointV3 {
    /// Encodes this introduction point to its descriptor format.
    ///
    /// Produces the text representation suitable for inclusion in a
    /// hidden service descriptor's inner layer.
    ///
    /// # Returns
    ///
    /// A string containing the encoded introduction point.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::hidden::{IntroductionPointV3, LinkSpecifier};
    ///
    /// let intro = IntroductionPointV3 {
    ///     link_specifiers: vec![LinkSpecifier::IPv4 {
    ///         address: "1.2.3.4".to_string(),
    ///         port: 9001,
    ///     }],
    ///     onion_key_raw: Some("AAAA...".to_string()),
    ///     auth_key_cert: None,
    ///     enc_key_raw: Some("BBBB...".to_string()),
    ///     enc_key_cert: None,
    ///     legacy_key_raw: None,
    ///     legacy_key_cert: None,
    /// };
    ///
    /// let encoded = intro.encode();
    /// assert!(encoded.contains("introduction-point"));
    /// ```
    pub fn encode(&self) -> String {
        let mut lines = Vec::new();

        let mut link_data = vec![self.link_specifiers.len() as u8];
        for spec in &self.link_specifiers {
            link_data.extend(spec.pack());
        }
        lines.push(format!("introduction-point {}", base64_encode(&link_data)));

        if let Some(ref key) = self.onion_key_raw {
            lines.push(format!("onion-key ntor {}", key));
        }

        if let Some(ref cert) = self.auth_key_cert {
            lines.push("auth-key".to_string());
            lines.push(cert.clone());
        }

        if let Some(ref key) = self.enc_key_raw {
            lines.push(format!("enc-key ntor {}", key));
        }

        if let Some(ref cert) = self.enc_key_cert {
            lines.push("enc-key-cert".to_string());
            lines.push(cert.clone());
        }

        if let Some(ref key) = self.legacy_key_raw {
            lines.push("legacy-key".to_string());
            lines.push(key.clone());
        }

        if let Some(ref cert) = self.legacy_key_cert {
            lines.push("legacy-key-cert".to_string());
            lines.push(cert.clone());
        }

        lines.join("\n")
    }

    /// Parses an introduction point from its descriptor content.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw text content of a single introduction point block
    ///
    /// # Returns
    ///
    /// A parsed `IntroductionPointV3` on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the content is malformed.
    fn parse(content: &str) -> Result<Self, Error> {
        let mut link_specifiers = Vec::new();
        let mut onion_key_raw: Option<String> = None;
        let mut auth_key_cert: Option<String> = None;
        let mut enc_key_raw: Option<String> = None;
        let mut enc_key_cert: Option<String> = None;
        let mut legacy_key_raw: Option<String> = None;
        let mut legacy_key_cert: Option<String> = None;

        let lines: Vec<&str> = content.lines().collect();
        let mut idx = 0;

        while idx < lines.len() {
            let line = lines[idx];
            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "introduction-point" => {
                    if let Some(specs) = Self::parse_link_specifiers(value) {
                        link_specifiers = specs;
                    }
                }
                "onion-key" => {
                    if let Some(stripped) = value.strip_prefix("ntor ") {
                        onion_key_raw = Some(stripped.to_string());
                    }
                }
                "auth-key" => {
                    let (block, end_idx) = extract_pem_block(&lines, idx + 1);
                    auth_key_cert = Some(block);
                    idx = end_idx;
                }
                "enc-key" => {
                    if let Some(stripped) = value.strip_prefix("ntor ") {
                        enc_key_raw = Some(stripped.to_string());
                    }
                }
                "enc-key-cert" => {
                    let (block, end_idx) = extract_pem_block(&lines, idx + 1);
                    enc_key_cert = Some(block);
                    idx = end_idx;
                }
                "legacy-key" => {
                    let (block, end_idx) = extract_pem_block(&lines, idx + 1);
                    legacy_key_raw = Some(block);
                    idx = end_idx;
                }
                "legacy-key-cert" => {
                    let (block, end_idx) = extract_pem_block(&lines, idx + 1);
                    legacy_key_cert = Some(block);
                    idx = end_idx;
                }
                _ => {}
            }
            idx += 1;
        }

        Ok(Self {
            link_specifiers,
            onion_key_raw,
            auth_key_cert,
            enc_key_raw,
            enc_key_cert,
            legacy_key_raw,
            legacy_key_cert,
        })
    }

    /// Parses link specifiers from a base64-encoded string.
    ///
    /// The format is:
    /// - 1 byte: count of link specifiers
    /// - For each specifier:
    ///   - 1 byte: type
    ///   - 1 byte: length
    ///   - N bytes: data
    ///
    /// # Arguments
    ///
    /// * `encoded` - Base64-encoded link specifiers
    ///
    /// # Returns
    ///
    /// A vector of parsed link specifiers, or `None` if decoding fails.
    fn parse_link_specifiers(encoded: &str) -> Option<Vec<LinkSpecifier>> {
        let decoded = base64_decode(encoded)?;
        if decoded.is_empty() {
            return Some(Vec::new());
        }

        let count = decoded[0] as usize;
        let mut specifiers = Vec::new();
        let mut offset = 1;

        for _ in 0..count {
            if offset + 2 > decoded.len() {
                break;
            }

            let link_type = decoded[offset];
            let length = decoded[offset + 1] as usize;
            offset += 2;

            if offset + length > decoded.len() {
                break;
            }

            let data = &decoded[offset..offset + length];
            offset += length;

            let specifier = match link_type {
                0 if length == 6 => {
                    let addr = format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]);
                    let port = u16::from_be_bytes([data[4], data[5]]);
                    LinkSpecifier::IPv4 {
                        address: addr,
                        port,
                    }
                }
                1 if length == 18 => {
                    let addr_parts: Vec<String> = (0..8)
                        .map(|i| {
                            format!("{:04x}", u16::from_be_bytes([data[i * 2], data[i * 2 + 1]]))
                        })
                        .collect();
                    let addr = addr_parts.join(":");
                    let port = u16::from_be_bytes([data[16], data[17]]);
                    LinkSpecifier::IPv6 {
                        address: addr,
                        port,
                    }
                }
                2 if length == 20 => {
                    let fingerprint = data.iter().map(|b| format!("{:02X}", b)).collect();
                    LinkSpecifier::Fingerprint(fingerprint)
                }
                3 if length == 32 => {
                    let ed25519 = base64_encode(data);
                    LinkSpecifier::Ed25519(ed25519)
                }
                _ => LinkSpecifier::Unknown {
                    link_type,
                    data: data.to_vec(),
                },
            };

            specifiers.push(specifier);
        }

        Some(specifiers)
    }
}

/// Client authorized to access a v3 hidden service.
///
/// When a v3 hidden service uses client authorization, each authorized
/// client has an entry in the descriptor's outer layer containing
/// encrypted credentials.
///
/// # Fields
///
/// - `id`: Base64-encoded 8-byte client identifier
/// - `iv`: Base64-encoded 16-byte initialization vector
/// - `cookie`: Base64-encoded 16-byte encrypted authentication cookie
///
/// # Security
///
/// The cookie is encrypted with the client's private key. Only the
/// authorized client can decrypt it to access the inner layer.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizedClient {
    /// Base64-encoded client identifier (8 bytes).
    pub id: String,
    /// Base64-encoded initialization vector (16 bytes).
    pub iv: String,
    /// Base64-encoded encrypted authentication cookie (16 bytes).
    pub cookie: String,
}

/// Outer encryption layer of a v3 hidden service descriptor.
///
/// The outer layer is the first layer of encryption in a v3 descriptor.
/// It contains client authorization data and the encrypted inner layer.
///
/// # Structure
///
/// - `auth_type`: Type of client authorization (e.g., "x25519")
/// - `ephemeral_key`: Ephemeral X25519 public key for decryption
/// - `clients`: Map of client IDs to their authorization data
/// - `encrypted`: The encrypted inner layer (MESSAGE block)
///
/// # Decryption
///
/// To decrypt the outer layer, you need:
/// 1. The blinded public key derived from the service's identity key
/// 2. The subcredential derived from the identity key and time period
///
/// The decryption uses AES-256-CTR with keys derived via SHAKE-256.
///
/// # Client Authorization
///
/// If `auth_type` is set, only clients listed in `clients` can decrypt
/// the inner layer. Each client's cookie is encrypted with their public key.
///
/// # Example
///
/// ```rust,ignore
/// let outer = OuterLayer::parse(decrypted_superencrypted)?;
///
/// if let Some(auth_type) = &outer.auth_type {
///     println!("Authorization required: {}", auth_type);
///     println!("Authorized clients: {}", outer.clients.len());
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct OuterLayer {
    /// Type of client authorization (e.g., "x25519"), or None if public.
    pub auth_type: Option<String>,
    /// Ephemeral X25519 public key for descriptor encryption.
    pub ephemeral_key: Option<String>,
    /// Map of client IDs to their authorization credentials.
    pub clients: HashMap<String, AuthorizedClient>,
    /// Encrypted inner layer content (MESSAGE block).
    pub encrypted: Option<String>,
}

impl OuterLayer {
    /// Parses the outer layer from decrypted content.
    ///
    /// # Arguments
    ///
    /// * `content` - Decrypted outer layer content
    ///
    /// # Returns
    ///
    /// A parsed `OuterLayer` on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the content is malformed.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // After decrypting the superencrypted blob
    /// let outer = OuterLayer::parse(&decrypted_content)?;
    /// ```
    pub fn parse(content: &str) -> Result<Self, Error> {
        let content = content.trim_end_matches('\0');
        let lines: Vec<&str> = content.lines().collect();

        let mut auth_type: Option<String> = None;
        let mut ephemeral_key: Option<String> = None;
        let mut clients: HashMap<String, AuthorizedClient> = HashMap::new();
        let mut encrypted: Option<String> = None;

        let mut idx = 0;
        while idx < lines.len() {
            let line = lines[idx];
            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "desc-auth-type" => auth_type = Some(value.to_string()),
                "desc-auth-ephemeral-key" => ephemeral_key = Some(value.to_string()),
                "auth-client" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let client = AuthorizedClient {
                            id: parts[0].to_string(),
                            iv: parts[1].to_string(),
                            cookie: parts[2].to_string(),
                        };
                        clients.insert(parts[0].to_string(), client);
                    }
                }
                "encrypted" => {
                    let (block, end_idx) = extract_message_block(&lines, idx + 1);
                    encrypted = Some(block);
                    idx = end_idx;
                }
                _ => {}
            }
            idx += 1;
        }

        Ok(Self {
            auth_type,
            ephemeral_key,
            clients,
            encrypted,
        })
    }
}

/// Inner encryption layer of a v3 hidden service descriptor.
///
/// The inner layer contains the actual service configuration and
/// introduction points. It is encrypted within the outer layer.
///
/// # Structure
///
/// - `formats`: Supported CREATE2 cell formats (typically \[2\] for ntor)
/// - `intro_auth`: Required authentication methods for introduction
/// - `is_single_service`: Whether this is a single-onion service
/// - `introduction_points`: List of introduction point relays
///
/// # Decryption Requirements
///
/// To access the inner layer, you must first decrypt:
/// 1. The outer `superencrypted` blob using the blinded key and subcredential
/// 2. The inner `encrypted` blob using the descriptor cookie (if client auth)
///
/// # Single-Onion Services
///
/// If `is_single_service` is true, the service is running in single-onion
/// mode, which provides lower latency but reduced anonymity for the service.
///
/// # Example
///
/// ```rust,ignore
/// let inner = InnerLayer::parse(&decrypted_inner)?;
///
/// println!("CREATE2 formats: {:?}", inner.formats);
/// println!("Single-onion: {}", inner.is_single_service);
/// println!("Introduction points: {}", inner.introduction_points.len());
///
/// for intro in &inner.introduction_points {
///     println!("  - {:?}", intro.link_specifiers);
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct InnerLayer {
    /// Supported CREATE2 cell formats (typically \[2\] for ntor handshake).
    pub formats: Vec<u32>,
    /// Required authentication methods for introduction (e.g., ["ed25519"]).
    pub intro_auth: Vec<String>,
    /// Whether this is a single-onion (non-anonymous) service.
    pub is_single_service: bool,
    /// List of introduction points for connecting to the service.
    pub introduction_points: Vec<IntroductionPointV3>,
}

impl InnerLayer {
    /// Parses the inner layer from decrypted content.
    ///
    /// # Arguments
    ///
    /// * `content` - Decrypted inner layer content
    ///
    /// # Returns
    ///
    /// A parsed `InnerLayer` on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the content is malformed or
    /// introduction points fail to parse.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // After decrypting both layers
    /// let inner = InnerLayer::parse(&decrypted_content)?;
    ///
    /// for intro in inner.introduction_points {
    ///     // Connect to introduction points
    /// }
    /// ```
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut formats: Vec<u32> = Vec::new();
        let mut intro_auth: Vec<String> = Vec::new();
        let mut is_single_service = false;
        let mut introduction_points: Vec<IntroductionPointV3> = Vec::new();

        let intro_div = content.find("\nintroduction-point ");
        let (header_content, intro_content) = if let Some(div) = intro_div {
            (&content[..div], Some(&content[div + 1..]))
        } else {
            (content, None)
        };

        for line in header_content.lines() {
            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "create2-formats" => {
                    formats = value
                        .split_whitespace()
                        .filter_map(|v| v.parse().ok())
                        .collect();
                }
                "intro-auth-required" => {
                    intro_auth = value.split_whitespace().map(|s| s.to_string()).collect();
                }
                "single-onion-service" => {
                    is_single_service = true;
                }
                _ => {}
            }
        }

        if let Some(intro_str) = intro_content {
            let mut current_block = String::new();
            for line in intro_str.lines() {
                if line.starts_with("introduction-point ") && !current_block.is_empty() {
                    introduction_points.push(IntroductionPointV3::parse(&current_block)?);
                    current_block.clear();
                }
                current_block.push_str(line);
                current_block.push('\n');
            }
            if !current_block.is_empty() {
                introduction_points.push(IntroductionPointV3::parse(&current_block)?);
            }
        }

        Ok(Self {
            formats,
            intro_auth,
            is_single_service,
            introduction_points,
        })
    }
}

/// Version 3 hidden service descriptor.
///
/// A v3 hidden service descriptor uses modern Ed25519/X25519 cryptography
/// and provides stronger security than v2 descriptors. The `.onion` address
/// is 56 characters long (vs 16 for v2).
///
/// # Structure
///
/// The descriptor contains:
/// - `version`: Always 3 for this type
/// - `lifetime`: How long the descriptor is valid (in minutes)
/// - `signing_cert`: Ed25519 certificate for the descriptor signing key
/// - `revision_counter`: Monotonically increasing counter to prevent replay
/// - `superencrypted`: Encrypted outer layer (contains inner layer)
/// - `signature`: Ed25519 signature over the descriptor
///
/// # Encryption Layers
///
/// V3 descriptors have two encryption layers:
///
/// 1. **Superencrypted** (outer): Decrypted with blinded key + subcredential
/// 2. **Encrypted** (inner): May require client authorization cookie
///
/// The decryption process requires:
/// - The service's blinded public key (derived from identity key + time)
/// - The subcredential (derived from identity key)
/// - Optionally, the client's authorization cookie
///
/// # Address Format
///
/// V3 `.onion` addresses are 56 characters and encode:
/// - 32 bytes: Ed25519 public key
/// - 2 bytes: Checksum
/// - 1 byte: Version (0x03)
///
/// Use [`address_from_identity_key`](Self::address_from_identity_key) and
/// [`identity_key_from_address`](Self::identity_key_from_address) to convert.
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::descriptor::hidden::HiddenServiceDescriptorV3;
/// use stem_rs::descriptor::Descriptor;
///
/// let content = std::fs::read_to_string("v3_descriptor.txt")?;
/// let desc = HiddenServiceDescriptorV3::parse(&content)?;
///
/// println!("Version: {}", desc.version);
/// println!("Lifetime: {} minutes", desc.lifetime);
/// println!("Revision: {}", desc.revision_counter);
///
/// // Convert identity key to .onion address
/// let key = [0u8; 32]; // Your 32-byte Ed25519 public key
/// let address = HiddenServiceDescriptorV3::address_from_identity_key(&key);
/// println!("Address: {}", address);
/// ```
///
/// # Security
///
/// - The `revision_counter` prevents replay attacks
/// - The `signature` authenticates the descriptor
/// - Introduction points are encrypted and require decryption
/// - Client authorization adds an additional encryption layer
#[derive(Debug, Clone, PartialEq)]
pub struct HiddenServiceDescriptorV3 {
    /// Hidden service descriptor version (always 3 for this type).
    pub version: u32,
    /// Descriptor validity period in minutes (typically 180).
    pub lifetime: u32,
    /// Ed25519 certificate for the descriptor signing key (PEM format).
    pub signing_cert: Option<String>,
    /// Monotonically increasing counter to prevent replay attacks.
    pub revision_counter: u64,
    /// Encrypted outer layer containing client auth and inner layer.
    pub superencrypted: Option<String>,
    /// Ed25519 signature over the descriptor content.
    pub signature: String,
    /// Raw bytes of the original descriptor content.
    raw_content: Vec<u8>,
    /// Lines from the descriptor that were not recognized.
    unrecognized_lines: Vec<String>,
}

impl HiddenServiceDescriptorV3 {
    /// Converts an Ed25519 identity key to a v3 `.onion` address.
    ///
    /// The address is computed as:
    /// 1. Compute checksum: SHA3-256(".onion checksum" || pubkey || version)\[0:2\]
    /// 2. Concatenate: pubkey || checksum || version
    /// 3. Base32-encode and append ".onion"
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte Ed25519 public key
    ///
    /// # Returns
    ///
    /// A 62-character string ending in ".onion" (56 chars + ".onion").
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::hidden::HiddenServiceDescriptorV3;
    ///
    /// let key = [0u8; 32];
    /// let address = HiddenServiceDescriptorV3::address_from_identity_key(&key);
    /// assert!(address.ends_with(".onion"));
    /// assert_eq!(address.len(), 62); // 56 + ".onion"
    /// ```
    pub fn address_from_identity_key(key: &[u8]) -> String {
        use sha3::{Digest, Sha3_256};

        let version = [3u8];
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(key);
        hasher.update(version);
        let checksum = &hasher.finalize()[..2];

        let mut address_bytes = Vec::with_capacity(35);
        address_bytes.extend_from_slice(key);
        address_bytes.extend_from_slice(checksum);
        address_bytes.push(3);

        base32_encode(&address_bytes).to_lowercase() + ".onion"
    }

    /// Extracts the Ed25519 identity key from a v3 `.onion` address.
    ///
    /// Validates the address format, checksum, and version byte.
    ///
    /// # Arguments
    ///
    /// * `onion_address` - A v3 `.onion` address (with or without ".onion" suffix)
    ///
    /// # Returns
    ///
    /// The 32-byte Ed25519 public key on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The address is not valid base32
    /// - The decoded length is not 35 bytes
    /// - The version byte is not 3
    /// - The checksum does not match
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::hidden::HiddenServiceDescriptorV3;
    ///
    /// let key = [0u8; 32];
    /// let address = HiddenServiceDescriptorV3::address_from_identity_key(&key);
    /// let recovered = HiddenServiceDescriptorV3::identity_key_from_address(&address).unwrap();
    /// assert_eq!(recovered, key.to_vec());
    /// ```
    ///
    /// # Security
    ///
    /// The checksum prevents typos in addresses from connecting to the wrong
    /// service. Always validate addresses before use.
    pub fn identity_key_from_address(onion_address: &str) -> Result<Vec<u8>, Error> {
        use sha3::{Digest, Sha3_256};

        let address = onion_address.trim_end_matches(".onion").to_uppercase();

        let decoded = base32_decode(&address).ok_or_else(|| Error::Parse {
            location: "onion_address".to_string(),
            reason: "invalid base32 encoding".to_string(),
        })?;

        if decoded.len() != 35 {
            return Err(Error::Parse {
                location: "onion_address".to_string(),
                reason: format!("invalid address length: {}", decoded.len()),
            });
        }

        let pubkey = &decoded[..32];
        let expected_checksum = &decoded[32..34];
        let version = decoded[34];

        if version != 3 {
            return Err(Error::Parse {
                location: "onion_address".to_string(),
                reason: format!("unsupported version: {}", version),
            });
        }

        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(pubkey);
        hasher.update([version]);
        let checksum = &hasher.finalize()[..2];

        if checksum != expected_checksum {
            return Err(Error::Parse {
                location: "onion_address".to_string(),
                reason: "invalid checksum".to_string(),
            });
        }

        Ok(pubkey.to_vec())
    }
}

impl Descriptor for HiddenServiceDescriptorV3 {
    fn parse(content: &str) -> Result<Self, Error> {
        let raw_content = content.as_bytes().to_vec();
        let lines: Vec<&str> = content.lines().collect();

        let mut version: u32 = 0;
        let mut lifetime: u32 = 0;
        let mut signing_cert: Option<String> = None;
        let mut revision_counter: u64 = 0;
        let mut superencrypted: Option<String> = None;
        let mut signature = String::new();
        let mut unrecognized_lines: Vec<String> = Vec::new();

        let mut idx = 0;
        while idx < lines.len() {
            let line = lines[idx];

            if line.starts_with("@type ") {
                idx += 1;
                continue;
            }

            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "hs-descriptor" => {
                    version = value.parse().map_err(|_| Error::Parse {
                        location: "hs-descriptor".to_string(),
                        reason: format!("invalid version: {}", value),
                    })?;
                }
                "descriptor-lifetime" => {
                    lifetime = value.parse().map_err(|_| Error::Parse {
                        location: "descriptor-lifetime".to_string(),
                        reason: format!("invalid lifetime: {}", value),
                    })?;
                }
                "descriptor-signing-key-cert" => {
                    let (block, end_idx) = extract_pem_block(&lines, idx + 1);
                    signing_cert = Some(block);
                    idx = end_idx;
                }
                "revision-counter" => {
                    revision_counter = value.parse().map_err(|_| Error::Parse {
                        location: "revision-counter".to_string(),
                        reason: format!("invalid revision counter: {}", value),
                    })?;
                }
                "superencrypted" => {
                    let (block, end_idx) = extract_message_block(&lines, idx + 1);
                    superencrypted = Some(block);
                    idx = end_idx;
                }
                "signature" => {
                    signature = value.to_string();
                }
                _ => {
                    if !line.is_empty() && !line.starts_with("-----") {
                        unrecognized_lines.push(line.to_string());
                    }
                }
            }
            idx += 1;
        }

        Ok(Self {
            version,
            lifetime,
            signing_cert,
            revision_counter,
            superencrypted,
            signature,
            raw_content,
            unrecognized_lines,
        })
    }

    fn to_descriptor_string(&self) -> String {
        let mut result = String::new();

        result.push_str(&format!("hs-descriptor {}\n", self.version));
        result.push_str(&format!("descriptor-lifetime {}\n", self.lifetime));

        if let Some(ref cert) = self.signing_cert {
            result.push_str("descriptor-signing-key-cert\n");
            result.push_str(cert);
            result.push('\n');
        }

        result.push_str(&format!("revision-counter {}\n", self.revision_counter));

        if let Some(ref encrypted) = self.superencrypted {
            result.push_str("superencrypted\n");
            result.push_str(encrypted);
            result.push('\n');
        }

        result.push_str(&format!("signature {}\n", self.signature));

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

impl FromStr for HiddenServiceDescriptorV3 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for HiddenServiceDescriptorV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_descriptor_string())
    }
}

/// Extracts a PEM-formatted block from descriptor lines.
///
/// Reads lines starting from `start_idx` until finding a line that
/// starts with "-----END ".
///
/// # Arguments
///
/// * `lines` - Slice of descriptor lines
/// * `start_idx` - Index to start reading from
///
/// # Returns
///
/// A tuple of (block_content, end_index) where end_index is the line
/// containing the END marker.
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

/// Extracts a MESSAGE block from descriptor lines.
///
/// Reads lines starting from `start_idx`, looking for content between
/// "-----BEGIN MESSAGE-----" and "-----END MESSAGE-----" markers.
///
/// # Arguments
///
/// * `lines` - Slice of descriptor lines
/// * `start_idx` - Index to start reading from
///
/// # Returns
///
/// A tuple of (block_content, end_index) where end_index is the line
/// containing the END marker.
fn extract_message_block(lines: &[&str], start_idx: usize) -> (String, usize) {
    let mut block = String::new();
    let mut idx = start_idx;
    let mut in_block = false;

    while idx < lines.len() {
        let line = lines[idx];

        if line.starts_with("-----BEGIN MESSAGE-----") {
            in_block = true;
        }

        if in_block {
            block.push_str(line);
            block.push('\n');
        }

        if line.starts_with("-----END MESSAGE-----") {
            break;
        }
        idx += 1;
    }

    (block.trim_end().to_string(), idx)
}

/// Decodes a base64-encoded string.
///
/// Handles standard base64 alphabet (A-Z, a-z, 0-9, +, /) and ignores
/// whitespace and padding characters.
///
/// # Arguments
///
/// * `input` - Base64-encoded string
///
/// # Returns
///
/// Decoded bytes, or `None` if the input contains invalid characters.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.replace(['\n', '\r', ' '], "");
    let input = input.trim_end_matches('=');

    let mut result = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for c in input.chars() {
        let value = ALPHABET.iter().position(|&x| x == c as u8)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(result)
}

/// Encodes bytes to a base64 string.
///
/// Uses standard base64 alphabet (A-Z, a-z, 0-9, +, /) without padding.
///
/// # Arguments
///
/// * `bytes` - Bytes to encode
///
/// # Returns
///
/// Base64-encoded string.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

/// Encodes bytes to a base32 string.
///
/// Uses RFC 4648 base32 alphabet (A-Z, 2-7) without padding.
/// This is the encoding used for `.onion` addresses.
///
/// # Arguments
///
/// * `bytes` - Bytes to encode
///
/// # Returns
///
/// Uppercase base32-encoded string.
fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }

    if bits > 0 {
        buffer <<= 5 - bits;
        result.push(ALPHABET[(buffer & 0x1F) as usize] as char);
    }

    result
}

/// Decodes a base32-encoded string.
///
/// Uses RFC 4648 base32 alphabet (A-Z, 2-7), case-insensitive.
/// Ignores padding characters.
///
/// # Arguments
///
/// * `input` - Base32-encoded string
///
/// # Returns
///
/// Decoded bytes, or `None` if the input contains invalid characters.
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let input = input.trim_end_matches('=');
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for c in input.chars() {
        let value = ALPHABET
            .iter()
            .position(|&x| x == c.to_ascii_uppercase() as u8)? as u64;
        buffer = (buffer << 5) | value;
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUCKDUCKGO_DESCRIPTOR: &str = r#"@type hidden-service-descriptor 1.0
rendezvous-service-descriptor y3olqqblqw2gbh6phimfuiroechjjafa
version 2
permanent-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJ/SzzgrXPxTlFrKVhXh3buCWv2QfcNgncUpDpKouLn3AtPH5Ocys0jE
aZSKdvaiQ62md2gOwj4x61cFNdi05tdQjS+2thHKEm/KsB9BGLSLBNJYY356bupg
I5gQozM65ENelfxYlysBjJ52xSDBd8C4f/p9umdzaaaCmzXG/nhzAgMBAAE=
-----END RSA PUBLIC KEY-----
secret-id-part e24kgecavwsznj7gpbktqsiwgvngsf4e
publication-time 2015-02-23 20:00:00
protocol-versions 2,3
introduction-points
-----BEGIN MESSAGE-----
aW50cm9kdWN0aW9uLXBvaW50IGl3a2k3N3h0YnZwNnF2ZWRmcndkem5jeHMzY2th
eWV1CmlwLWFkZHJlc3MgMTc4LjYyLjIyMi4xMjkKb25pb24tcG9ydCA0NDMKb25p
b24ta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFL
OTRCRVlJSFo0S2RFa2V5UGhiTENwUlc1RVNnKzJXUFFock00eXVLWUd1cTh3Rldn
dW1aWVI5CmsvV0EvL0ZZWE1CejBiQitja3Vacy9ZdTluSytITHpwR2FwVjBjbHN0
NEdVTWNCSW5VQ3pDY3BqSlRRc1FEZ20KMy9ZM2NxaDBXNTVnT0NGaG9tUTQvMVdP
WWc3WUNqazRYWUhKRTIwT2RHMkxsNXpvdEs2ZkFnTUJBQUU9Ci0tLS0tRU5EIFJT
QSBQVUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVC
TElDIEtFWS0tLS0tCk1JR0pBb0dCQUpYbUpiOGxTeWRNTXFDZ0NnZmd2bEIyRTVy
cGQ1N2t6L0FxZzcvZDFIS2MzK2w1UW9Vdkh5dXkKWnNBbHlrYThFdTUzNGhsNDFv
cUVLcEFLWWNNbjFUTTB2cEpFR05WT2MrMDVCSW54STloOWYwTWcwMVBEMHRZdQpH
Y0xIWWdCemNyZkVtS3dNdE04V0VtY01KZDduMnVmZmFBdko4NDZXdWJiZVY3TVcx
WWVoQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1
Y3Rpb24tcG9pbnQgZW00Z2prNmVpaXVhbGhtbHlpaWZyemM3bGJ0cnNiaXAKaXAt
YWRkcmVzcyA0Ni40LjE3NC41Mgpvbmlvbi1wb3J0IDQ0Mwpvbmlvbi1rZXkKLS0t
LS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUxCbWhkRjV3SHhI
cnBMU21qQVpvdHR4MjIwKzk5NUZkTU9PdFpOalJ3MURCU3ByVVpacXR4V2EKUDhU
S3BIS3p3R0pLQ1ZZSUlqN2xvaGJ2OVQ5dXJtbGZURTA1VVJHZW5ab2lmT0ZOejNZ
d01KVFhTY1FFQkoxMAo5aVdOTERUc2tMekRLQ0FiR2hibi9NS3dPZllHQmhOVGxq
ZHlUbU5ZNUVDUmJSempldjl2QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBL
RVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0t
LS0KTUlHSkFvR0JBTXhNSG9BbXJiVU1zeGlJQ3AzaVRQWWdobjBZdWVLSHgyMTl3
dThPL1E1MVF5Y1ZWTHBYMjdkMQpoSlhrUEIzM1hRQlhzQlM3U3hzU3NTQ1EzR0V1
clFKN0d1QkxwWUlSL3Zxc2FrRS9sOHdjMkNKQzVXVWh5RkZrCisxVFdJVUk1dHhu
WEx5V0NSY0tEVXJqcWRvc0RhRG9zZ0hGZzIzTW54K3hYY2FRL2ZyQi9BZ01CQUFF
PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2lu
dCBqcWhmbDM2NHgzdXBlNmxxbnhpem9sZXdsZnJzdzJ6eQppcC1hZGRyZXNzIDYy
LjIxMC44Mi4xNjkKb25pb24tcG9ydCA0NDMKb25pb24ta2V5Ci0tLS0tQkVHSU4g
UlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFQVWtxeGdmWWR3MFBtL2c2TWJo
bVZzR0tsdWppZm1raGRmb0VldXpnbyt3bkVzR3Z3VWVienJ6CmZaSlJ0MGNhWEZo
bkNHZ1FEMklnbWFyVWFVdlAyNGZYby80bVl6TGNQZUk3Z1puZXVBUUpZdm05OFl2
OXZPSGwKTmFNL1d2RGtDc0ozR1ZOSjFIM3dMUFFSSTN2N0tiTnVjOXRDT1lsL3Iw
OU9oVmFXa3phakFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
c2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pB
b0dCQUxieDhMZXFSb1Avcjl3OWhqd0Q0MVlVbTdQbzY5N3hSdHl0RjBNY3lMQ1M3
R1JpVVluamk3S1kKZmVwWGR2Ti9KbDVxUUtISUJiNjAya3VPVGwwcE44UStZZUZV
U0lJRGNtUEJMcEJEaEgzUHZyUU1jR1ZhaU9XSAo4dzBITVpDeGd3QWNDQzUxdzVW
d2l1bXhFSk5CVmNac094MG16TjFDbG95KzkwcTBsRlhMQWdNQkFBRT0KLS0tLS1F
TkQgUlNBIFBVQkxJQyBLRVktLS0tLQoK
-----END MESSAGE-----
signature
-----BEGIN SIGNATURE-----
VKMmsDIUUFOrpqvcQroIZjDZTKxqNs88a4M9Te8cR/ZvS7H2nffv6iQs0tom5X4D
4Dy4iZiy+pwYxdHfaOxmdpgMCRvgPb34MExWr5YemH0QuGtnlp5Wxr8GYaAQVuZX
cZjQLW0juUYCbgIGdxVEBnlEt2rgBSM9+1oR7EAfV1U=
-----END SIGNATURE-----
"#;

    const V3_DESCRIPTOR: &str = r#"hs-descriptor 3
descriptor-lifetime 180
descriptor-signing-key-cert
-----BEGIN ED25519 CERT-----
AQgABl5/AZLmgPpXVS59SEydKj7bRvvAduVOqQt3u4Tj5tVlfVKhAQAgBABUhpfe
/Wd3p/M74DphsGcIMee/npQ9BTzkzCyTyVmDbykek2EciWaOTCVZJVyiKPErngfW
BDwQZ8rhp05oCqhhY3oFHqG9KS7HGzv9g2v1/PrVJMbkfpwu1YK4b3zIZAk=
-----END ED25519 CERT-----
revision-counter 42
superencrypted
-----BEGIN MESSAGE-----
Jmu66WXn0+CDLXVM02n85rj84Fv4ynLcjFFWPoLNm6Op+S14CAm0H2qfMj8OO/jw
NJiNxY/L/8SeY5ZlvqPHzI8jBqKW7nT5CN7xLUEvzdFhG3AnWC48r8fp2E+TQ8gb
-----END MESSAGE-----
signature aglChCQF+lbzKgyxJJTpYGVShV/GMDRJ4+cRGCp+a2y/yX/tLSh7hzqI7rVZrUoGj74Xr1CLMYO3fXYCS+DPDQ
"#;

    #[test]
    fn test_parse_v2_duckduckgo() {
        let desc = HiddenServiceDescriptorV2::parse(DUCKDUCKGO_DESCRIPTOR).unwrap();

        assert_eq!(desc.descriptor_id, "y3olqqblqw2gbh6phimfuiroechjjafa");
        assert_eq!(desc.version, 2);
        assert_eq!(desc.secret_id_part, "e24kgecavwsznj7gpbktqsiwgvngsf4e");
        assert_eq!(desc.protocol_versions, vec![2, 3]);
        assert!(desc.permanent_key.is_some());
        assert!(desc.introduction_points_encoded.is_some());

        let intro_points = desc.introduction_points().unwrap();
        assert_eq!(intro_points.len(), 3);

        assert_eq!(
            intro_points[0].identifier,
            "iwki77xtbvp6qvedfrwdzncxs3ckayeu"
        );
        assert_eq!(intro_points[0].address, "178.62.222.129");
        assert_eq!(intro_points[0].port, 443);
        assert!(intro_points[0].onion_key.is_some());
        assert!(intro_points[0].service_key.is_some());

        assert_eq!(
            intro_points[1].identifier,
            "em4gjk6eiiualhmlyiifrzc7lbtrsbip"
        );
        assert_eq!(intro_points[1].address, "46.4.174.52");
        assert_eq!(intro_points[1].port, 443);

        assert_eq!(
            intro_points[2].identifier,
            "jqhfl364x3upe6lqnxizolewlfrsw2zy"
        );
        assert_eq!(intro_points[2].address, "62.210.82.169");
        assert_eq!(intro_points[2].port, 443);
    }

    #[test]
    fn test_parse_v3_descriptor() {
        let desc = HiddenServiceDescriptorV3::parse(V3_DESCRIPTOR).unwrap();

        assert_eq!(desc.version, 3);
        assert_eq!(desc.lifetime, 180);
        assert_eq!(desc.revision_counter, 42);
        assert!(desc.signing_cert.is_some());
        assert!(desc.superencrypted.is_some());
        assert!(!desc.signature.is_empty());
    }

    #[test]
    fn test_v3_address_conversion() {
        let key = [0u8; 32];
        let address = HiddenServiceDescriptorV3::address_from_identity_key(&key);
        assert!(address.ends_with(".onion"));
        assert_eq!(address.len(), 62);

        let recovered_key = HiddenServiceDescriptorV3::identity_key_from_address(&address).unwrap();
        assert_eq!(recovered_key, key.to_vec());
    }

    #[test]
    fn test_v3_invalid_address() {
        let result = HiddenServiceDescriptorV3::identity_key_from_address("invalid.onion");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, World!";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_base32_roundtrip() {
        let original = b"Hello, World!";
        let encoded = base32_encode(original);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_outer_layer_parse() {
        let content = r#"desc-auth-type x25519
desc-auth-ephemeral-key AAAA
auth-client client1 iv1 cookie1
auth-client client2 iv2 cookie2
encrypted
-----BEGIN MESSAGE-----
dGVzdA==
-----END MESSAGE-----
"#;
        let layer = OuterLayer::parse(content).unwrap();
        assert_eq!(layer.auth_type, Some("x25519".to_string()));
        assert_eq!(layer.ephemeral_key, Some("AAAA".to_string()));
        assert_eq!(layer.clients.len(), 2);
        assert!(layer.encrypted.is_some());
    }

    #[test]
    fn test_inner_layer_parse() {
        let content = "create2-formats 2\n";
        let layer = InnerLayer::parse(content).unwrap();
        assert_eq!(layer.formats, vec![2]);
        assert!(!layer.is_single_service);
        assert!(layer.introduction_points.is_empty());
    }

    #[test]
    fn test_v2_to_string() {
        let desc = HiddenServiceDescriptorV2::parse(DUCKDUCKGO_DESCRIPTOR).unwrap();
        let output = desc.to_descriptor_string();
        assert!(output.contains("rendezvous-service-descriptor y3olqqblqw2gbh6phimfuiroechjjafa"));
        assert!(output.contains("version 2"));
        assert!(output.contains("protocol-versions 2,3"));
    }

    #[test]
    fn test_v3_to_string() {
        let desc = HiddenServiceDescriptorV3::parse(V3_DESCRIPTOR).unwrap();
        let output = desc.to_descriptor_string();
        assert!(output.contains("hs-descriptor 3"));
        assert!(output.contains("descriptor-lifetime 180"));
        assert!(output.contains("revision-counter 42"));
    }

    #[test]
    fn test_link_specifier_pack_ipv4() {
        let spec = LinkSpecifier::IPv4 {
            address: "1.2.3.4".to_string(),
            port: 9001,
        };
        let packed = spec.pack();
        assert_eq!(packed[0], 0);
        assert_eq!(packed[1], 6);
        assert_eq!(&packed[2..6], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([packed[6], packed[7]]), 9001);
    }

    #[test]
    fn test_link_specifier_pack_fingerprint() {
        let spec =
            LinkSpecifier::Fingerprint("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string());
        let packed = spec.pack();
        assert_eq!(packed[0], 2);
        assert_eq!(packed[1], 20);
        assert_eq!(packed.len(), 22);
    }

    #[test]
    fn test_introduction_point_v3_encode() {
        let intro_point = IntroductionPointV3 {
            link_specifiers: vec![LinkSpecifier::IPv4 {
                address: "1.2.3.4".to_string(),
                port: 9001,
            }],
            onion_key_raw: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
            auth_key_cert: None,
            enc_key_raw: Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string()),
            enc_key_cert: None,
            legacy_key_raw: None,
            legacy_key_cert: None,
        };

        let encoded = intro_point.encode();
        assert!(encoded.contains("introduction-point"));
        assert!(encoded.contains("onion-key ntor AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(encoded.contains("enc-key ntor BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="));
    }

    #[test]
    fn test_inner_layer_with_intro_points() {
        let content = r#"create2-formats 2
intro-auth-required ed25519
single-onion-service
introduction-point AQAGAQIDBCMp
onion-key ntor AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
enc-key ntor BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
"#;
        let layer = InnerLayer::parse(content).unwrap();
        assert_eq!(layer.formats, vec![2]);
        assert_eq!(layer.intro_auth, vec!["ed25519"]);
        assert!(layer.is_single_service);
        assert_eq!(layer.introduction_points.len(), 1);

        let intro = &layer.introduction_points[0];
        assert_eq!(
            intro.onion_key_raw,
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string())
        );
        assert_eq!(
            intro.enc_key_raw,
            Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string())
        );
    }

    #[test]
    fn test_v3_known_address() {
        let hs_address = "sltib6sxkuxh2scmtuvd5w2g7pahnzkovefxpo4e4ptnkzl5kkq5h2ad.onion";
        let hs_pubkey: [u8; 32] = [
            0x92, 0xe6, 0x80, 0xfa, 0x57, 0x55, 0x2e, 0x7d, 0x48, 0x4c, 0x9d, 0x2a, 0x3e, 0xdb,
            0x46, 0xfb, 0xc0, 0x76, 0xe5, 0x4e, 0xa9, 0x0b, 0x77, 0xbb, 0x84, 0xe3, 0xe6, 0xd5,
            0x65, 0x7d, 0x52, 0xa1,
        ];

        let address = HiddenServiceDescriptorV3::address_from_identity_key(&hs_pubkey);
        assert_eq!(address, hs_address);

        let recovered_key =
            HiddenServiceDescriptorV3::identity_key_from_address(hs_address).unwrap();
        assert_eq!(recovered_key, hs_pubkey.to_vec());
    }

    use proptest::prelude::*;

    fn valid_descriptor_id() -> impl Strategy<Value = String> {
        "[a-z2-7]{32}".prop_map(|s| s.to_string())
    }

    fn valid_secret_id_part() -> impl Strategy<Value = String> {
        "[a-z2-7]{32}".prop_map(|s| s.to_string())
    }

    fn valid_timestamp() -> impl Strategy<Value = DateTime<Utc>> {
        (
            2015u32..2025,
            1u32..13,
            1u32..29,
            0u32..24,
            0u32..60,
            0u32..60,
        )
            .prop_map(|(year, month, day, hour, min, sec)| {
                let naive = chrono::NaiveDate::from_ymd_opt(year as i32, month, day)
                    .unwrap()
                    .and_hms_opt(hour, min, sec)
                    .unwrap();
                naive.and_utc()
            })
    }

    fn simple_v2_descriptor() -> impl Strategy<Value = HiddenServiceDescriptorV2> {
        (
            valid_descriptor_id(),
            valid_secret_id_part(),
            valid_timestamp(),
            proptest::collection::vec(2u32..4, 1..3),
        )
            .prop_map(|(descriptor_id, secret_id_part, published, protocol_versions)| {
                HiddenServiceDescriptorV2 {
                    descriptor_id,
                    version: 2,
                    permanent_key: Some("-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAJ/SzzgrXPxTlFrKVhXh3buCWv2QfcNgncUpDpKouLn3AtPH5Ocys0jE\naZSKdvaiQ62md2gOwj4x61cFNdi05tdQjS+2thHKEm/KsB9BGLSLBNJYY356bupg\nI5gQozM65ENelfxYlysBjJ52xSDBd8C4f/p9umdzaaaCmzXG/nhzAgMBAAE=\n-----END RSA PUBLIC KEY-----".to_string()),
                    secret_id_part,
                    published,
                    protocol_versions,
                    introduction_points_encoded: None,
                    introduction_points_content: None,
                    signature: "-----BEGIN SIGNATURE-----\ntest\n-----END SIGNATURE-----".to_string(),
                    raw_content: Vec::new(),
                    unrecognized_lines: Vec::new(),
                }
            })
    }

    fn simple_v3_descriptor() -> impl Strategy<Value = HiddenServiceDescriptorV3> {
        (60u32..180, 1u64..1000).prop_map(|(lifetime, revision_counter)| {
            HiddenServiceDescriptorV3 {
                version: 3,
                lifetime,
                signing_cert: Some(
                    "-----BEGIN ED25519 CERT-----\ntest\n-----END ED25519 CERT-----".to_string(),
                ),
                revision_counter,
                superencrypted: Some(
                    "-----BEGIN MESSAGE-----\ndGVzdA==\n-----END MESSAGE-----".to_string(),
                ),
                signature: "testsignature".to_string(),
                raw_content: Vec::new(),
                unrecognized_lines: Vec::new(),
            }
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_hidden_service_v2_roundtrip(desc in simple_v2_descriptor()) {
            let serialized = desc.to_descriptor_string();
            let parsed = HiddenServiceDescriptorV2::parse(&serialized);

            prop_assert!(parsed.is_ok(), "Failed to parse serialized v2 descriptor: {:?}", parsed.err());

            let parsed = parsed.unwrap();

            prop_assert_eq!(&desc.descriptor_id, &parsed.descriptor_id, "descriptor_id mismatch");
            prop_assert_eq!(desc.version, parsed.version, "version mismatch");
            prop_assert_eq!(&desc.secret_id_part, &parsed.secret_id_part, "secret_id_part mismatch");
            prop_assert_eq!(&desc.protocol_versions, &parsed.protocol_versions, "protocol_versions mismatch");
        }

        #[test]
        fn prop_hidden_service_v3_roundtrip(desc in simple_v3_descriptor()) {
            let serialized = desc.to_descriptor_string();
            let parsed = HiddenServiceDescriptorV3::parse(&serialized);

            prop_assert!(parsed.is_ok(), "Failed to parse serialized v3 descriptor: {:?}", parsed.err());

            let parsed = parsed.unwrap();

            prop_assert_eq!(desc.version, parsed.version, "version mismatch");
            prop_assert_eq!(desc.lifetime, parsed.lifetime, "lifetime mismatch");
            prop_assert_eq!(desc.revision_counter, parsed.revision_counter, "revision_counter mismatch");
        }

        #[test]
        fn prop_v3_address_roundtrip(key in proptest::collection::vec(any::<u8>(), 32..=32)) {
            let key_array: [u8; 32] = key.clone().try_into().unwrap();
            let address = HiddenServiceDescriptorV3::address_from_identity_key(&key_array);
            let recovered = HiddenServiceDescriptorV3::identity_key_from_address(&address);

            prop_assert!(recovered.is_ok(), "Failed to recover key from address");
            prop_assert_eq!(recovered.unwrap(), key, "Key round-trip failed");
        }
    }
}
