//! Network status consensus document parsing.
//!
//! This module provides types for parsing Tor network status consensus documents
//! which describe the current state of the Tor network including all known relays.
//!
//! # Overview
//!
//! Network status documents are the authoritative source of information about
//! the Tor network. They come in two forms:
//!
//! - **Votes**: Individual directory authority opinions about the network
//! - **Consensus**: The agreed-upon view signed by multiple authorities
//!
//! Clients download the consensus to learn about available relays, their
//! capabilities, and which relays are recommended for different purposes.
//!
//! # Document Types
//!
//! | Type | Description |
//! |------|-------------|
//! | Consensus | Agreed network status signed by authorities |
//! | Vote | Individual authority's view before consensus |
//! | Microdesc Consensus | Consensus using microdescriptor hashes |
//!
//! # Validity Times
//!
//! Consensus documents have three important timestamps:
//!
//! - **valid-after**: When the consensus becomes valid
//! - **fresh-until**: When clients should fetch a new consensus
//! - **valid-until**: When the consensus expires completely
//!
//! Clients should fetch a new consensus between `fresh-until` and `valid-until`.
//!
//! # Document Format
//!
//! ```text
//! network-status-version 3 [microdesc]
//! vote-status consensus|vote
//! consensus-method <N>
//! valid-after <YYYY-MM-DD HH:MM:SS>
//! fresh-until <YYYY-MM-DD HH:MM:SS>
//! valid-until <YYYY-MM-DD HH:MM:SS>
//! voting-delay <vote-seconds> <dist-seconds>
//! known-flags <flag> <flag> ...
//! recommended-client-protocols <proto>=<versions> ...
//! required-client-protocols <proto>=<versions> ...
//! params <key>=<value> ...
//! dir-source <nickname> <identity> <hostname> <address> <dirport> <orport>
//! ...
//! directory-footer
//! bandwidth-weights <key>=<value> ...
//! directory-signature <identity> <signing-key-digest>
//! -----BEGIN SIGNATURE-----
//! <base64 signature>
//! -----END SIGNATURE-----
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::descriptor::{NetworkStatusDocument, Descriptor};
//!
//! let content = std::fs::read_to_string("cached-consensus").unwrap();
//! let consensus = NetworkStatusDocument::parse(&content).unwrap();
//!
//! println!("Consensus method: {:?}", consensus.consensus_method);
//! println!("Valid after: {}", consensus.valid_after);
//! println!("Valid until: {}", consensus.valid_until);
//! println!("Known flags: {:?}", consensus.known_flags);
//! println!("Authorities: {}", consensus.authorities.len());
//! println!("Signatures: {}", consensus.signatures.len());
//!
//! // Check protocol requirements
//! if let Some(versions) = consensus.required_client_protocols.get("Link") {
//!     println!("Required Link protocol versions: {:?}", versions);
//! }
//! ```
//!
//! # Shared Randomness
//!
//! Modern consensus documents include shared randomness values used for
//! hidden service directory assignment. These are computed collaboratively
//! by the directory authorities.
//!
//! # See Also
//!
//! - [`RouterStatusEntry`](super::RouterStatusEntry) - Individual relay entries in consensus
//! - [`DirectoryAuthority`] - Authority information
//! - [Python Stem NetworkStatusDocument](https://stem.torproject.org/api/descriptor/networkstatus.html)

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, Utc};
use derive_builder::Builder;

use crate::version::Version;
use crate::Error;

use super::authority::DirectoryAuthority;
use super::{compute_digest, Descriptor, DigestEncoding, DigestHash};

/// Validates a relay fingerprint.
///
/// A valid fingerprint is exactly 40 hexadecimal characters (case-insensitive).
fn is_valid_fingerprint(fingerprint: &str) -> bool {
    fingerprint.len() == 40 && fingerprint.chars().all(|c| c.is_ascii_hexdigit())
}

/// Shared randomness value from directory authority collaboration.
///
/// Directory authorities collaboratively generate random values that are
/// used for hidden service directory assignment. Each consensus includes
/// the current and previous shared randomness values.
///
/// # Fields
///
/// - `num_reveals`: Number of authorities that revealed their commitment
/// - `value`: The base64-encoded random value
#[derive(Debug, Clone, PartialEq)]
pub struct SharedRandomness {
    /// Number of authorities that participated in the reveal phase.
    pub num_reveals: u32,
    /// The shared random value (base64-encoded).
    pub value: String,
}

/// A signature on a network status document.
///
/// Each directory authority signs the consensus with their signing key.
/// The signature covers the document from the beginning through the
/// `directory-signature` line.
///
/// # Fields
///
/// - `identity`: The authority's identity key fingerprint
/// - `signing_key_digest`: Digest of the signing key used
/// - `signature`: The PEM-encoded signature
/// - `algorithm`: Optional algorithm identifier (e.g., "sha256")
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentSignature {
    /// The signing authority's identity key fingerprint (40 hex chars).
    pub identity: String,
    /// Digest of the signing key used for this signature.
    pub signing_key_digest: String,
    /// The PEM-encoded signature block.
    pub signature: String,
    /// Algorithm used (e.g., "sha256"), if specified.
    pub algorithm: Option<String>,
}

/// A network status consensus or vote document.
///
/// This is the primary document that describes the state of the Tor network.
/// Clients download the consensus to learn about available relays and their
/// capabilities.
///
/// # Document Types
///
/// - **Consensus** (`is_consensus = true`): The agreed-upon network view
/// - **Vote** (`is_vote = true`): An individual authority's opinion
/// - **Microdesc** (`is_microdescriptor = true`): Uses microdescriptor hashes
///
/// # Validity Times
///
/// The document has three important timestamps that control its lifecycle:
///
/// ```text
/// valid-after -----> fresh-until -----> valid-until
///     |                  |                  |
///     |   Document is    |   Should fetch   |   Document
///     |   fresh/current  |   new consensus  |   expired
/// ```
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::descriptor::{NetworkStatusDocument, Descriptor};
///
/// let content = std::fs::read_to_string("cached-consensus").unwrap();
/// let doc = NetworkStatusDocument::parse(&content).unwrap();
///
/// // Check document type
/// if doc.is_consensus {
///     println!("This is a consensus document");
/// }
///
/// // Check validity
/// let now = chrono::Utc::now();
/// if now > doc.valid_until {
///     println!("Consensus has expired!");
/// } else if now > doc.fresh_until {
///     println!("Should fetch a new consensus");
/// }
///
/// // Check required protocols
/// for (proto, versions) in &doc.required_client_protocols {
///     println!("Required {}: {:?}", proto, versions);
/// }
/// ```
///
/// # Thread Safety
///
/// `NetworkStatusDocument` is `Send` and `Sync` as it contains only owned data.
#[derive(Debug, Clone, PartialEq, Builder)]
#[builder(setter(into, strip_option))]
pub struct NetworkStatusDocument {
    /// Network status version (typically 3).
    pub version: u32,
    /// Version flavor (empty string or "microdesc").
    pub version_flavor: String,
    /// Whether this is a consensus document.
    pub is_consensus: bool,
    /// Whether this is a vote document.
    pub is_vote: bool,
    /// Whether this uses microdescriptor format.
    pub is_microdescriptor: bool,
    /// Consensus method used (consensus only).
    #[builder(default)]
    pub consensus_method: Option<u32>,
    /// Supported consensus methods (vote only).
    #[builder(default)]
    pub consensus_methods: Option<Vec<u32>>,
    /// When this vote was published (vote only).
    #[builder(default)]
    pub published: Option<DateTime<Utc>>,
    /// When this document becomes valid.
    pub valid_after: DateTime<Utc>,
    /// When clients should fetch a new document.
    pub fresh_until: DateTime<Utc>,
    /// When this document expires.
    pub valid_until: DateTime<Utc>,
    /// Seconds authorities wait for votes.
    #[builder(default)]
    pub vote_delay: Option<u32>,
    /// Seconds authorities wait for signatures.
    #[builder(default)]
    pub dist_delay: Option<u32>,
    /// Recommended Tor versions for clients.
    #[builder(default)]
    pub client_versions: Vec<Version>,
    /// Recommended Tor versions for relays.
    #[builder(default)]
    pub server_versions: Vec<Version>,
    /// Flags that may appear on relay entries.
    #[builder(default)]
    pub known_flags: Vec<String>,
    /// Recommended protocol versions for clients.
    #[builder(default)]
    pub recommended_client_protocols: HashMap<String, Vec<u32>>,
    /// Recommended protocol versions for relays.
    #[builder(default)]
    pub recommended_relay_protocols: HashMap<String, Vec<u32>>,
    /// Required protocol versions for clients.
    #[builder(default)]
    pub required_client_protocols: HashMap<String, Vec<u32>>,
    /// Required protocol versions for relays.
    #[builder(default)]
    pub required_relay_protocols: HashMap<String, Vec<u32>>,
    /// Consensus parameters (key=value pairs).
    #[builder(default)]
    pub params: HashMap<String, i32>,
    /// Previous shared randomness value.
    #[builder(default)]
    pub shared_randomness_previous: Option<SharedRandomness>,
    /// Current shared randomness value.
    #[builder(default)]
    pub shared_randomness_current: Option<SharedRandomness>,
    /// Bandwidth weights for path selection.
    #[builder(default)]
    pub bandwidth_weights: HashMap<String, i32>,
    /// Directory authorities that contributed to this document.
    #[builder(default)]
    pub authorities: Vec<DirectoryAuthority>,
    /// Signatures from directory authorities.
    #[builder(default)]
    pub signatures: Vec<DocumentSignature>,
    /// Raw bytes of the original document.
    #[builder(default)]
    raw_content: Vec<u8>,
    /// Lines that were not recognized during parsing.
    #[builder(default)]
    unrecognized_lines: Vec<String>,
}

impl NetworkStatusDocument {
    /// Validates the consensus document for correctness and consistency.
    ///
    /// Performs comprehensive validation including:
    /// - Timestamp ordering (valid_after < fresh_until < valid_until)
    /// - Authority fingerprint format (40 hex characters)
    /// - Signature presence and format
    /// - Version number validity
    ///
    /// # Returns
    ///
    /// `Ok(())` if validation passes, otherwise returns a descriptive error.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::descriptor::{NetworkStatusDocument, Descriptor};
    ///
    /// let content = std::fs::read_to_string("consensus").unwrap();
    /// let consensus = NetworkStatusDocument::parse(&content).unwrap();
    ///
    /// match consensus.validate() {
    ///     Ok(()) => println!("Consensus is valid"),
    ///     Err(e) => eprintln!("Validation failed: {}", e),
    /// }
    /// ```
    pub fn validate(&self) -> Result<(), Error> {
        use crate::descriptor::ConsensusError;

        if self.valid_after >= self.fresh_until {
            return Err(Error::Descriptor(
                crate::descriptor::DescriptorError::Consensus(
                    ConsensusError::TimestampOrderingViolation(format!(
                        "valid-after ({}) must be before fresh-until ({})",
                        self.valid_after.to_rfc3339(),
                        self.fresh_until.to_rfc3339()
                    )),
                ),
            ));
        }

        if self.fresh_until >= self.valid_until {
            return Err(Error::Descriptor(
                crate::descriptor::DescriptorError::Consensus(
                    ConsensusError::TimestampOrderingViolation(format!(
                        "fresh-until ({}) must be before valid-until ({})",
                        self.fresh_until.to_rfc3339(),
                        self.valid_until.to_rfc3339()
                    )),
                ),
            ));
        }

        if self.version != 3 {
            return Err(Error::Descriptor(
                crate::descriptor::DescriptorError::Consensus(
                    ConsensusError::InvalidNetworkStatusVersion(self.version.to_string()),
                ),
            ));
        }

        for authority in &self.authorities {
            if !is_valid_fingerprint(&authority.v3ident) {
                return Err(Error::Descriptor(
                    crate::descriptor::DescriptorError::Consensus(
                        ConsensusError::InvalidFingerprint(authority.v3ident.clone()),
                    ),
                ));
            }
        }

        if self.signatures.is_empty() {
            return Err(Error::Descriptor(
                crate::descriptor::DescriptorError::Consensus(
                    ConsensusError::MissingRequiredField("signatures".to_string()),
                ),
            ));
        }

        for signature in &self.signatures {
            if !is_valid_fingerprint(&signature.identity) {
                return Err(Error::Descriptor(
                    crate::descriptor::DescriptorError::Consensus(
                        ConsensusError::InvalidFingerprint(signature.identity.clone()),
                    ),
                ));
            }

            if !is_valid_fingerprint(&signature.signing_key_digest) {
                return Err(Error::Descriptor(
                    crate::descriptor::DescriptorError::Consensus(
                        ConsensusError::InvalidFingerprint(signature.signing_key_digest.clone()),
                    ),
                ));
            }

            if signature.signature.is_empty() {
                return Err(Error::Descriptor(
                    crate::descriptor::DescriptorError::Consensus(
                        ConsensusError::InvalidSignature("signature is empty".to_string()),
                    ),
                ));
            }
        }

        Ok(())
    }

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

    fn parse_network_status_version(
        value: &str,
        builder: &mut NetworkStatusDocumentBuilder,
    ) -> Result<(), Error> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        let version: u32 = parts.first().and_then(|v| v.parse().ok()).unwrap_or(3);
        builder.version(version);

        if let Some(flavor) = parts.get(1) {
            builder.version_flavor(flavor.to_string());
            builder.is_microdescriptor(*flavor == "microdesc");
        } else {
            builder.version_flavor("ns".to_string());
            builder.is_microdescriptor(false);
        }
        Ok(())
    }

    fn parse_vote_status(
        value: &str,
        builder: &mut NetworkStatusDocumentBuilder,
    ) -> Result<(), Error> {
        builder.is_consensus(value == "consensus");
        builder.is_vote(value == "vote");
        Ok(())
    }

    fn parse_voting_delay(
        value: &str,
        builder: &mut NetworkStatusDocumentBuilder,
    ) -> Result<(), Error> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(vote) = parts[0].parse::<u32>() {
                builder.vote_delay(vote);
            }
            if let Ok(dist) = parts[1].parse::<u32>() {
                builder.dist_delay(dist);
            }
        }
        Ok(())
    }

    fn parse_directory_signature(
        value: &str,
        lines: &[&str],
        idx: usize,
        _builder: &mut NetworkStatusDocumentBuilder,
    ) -> Result<(DocumentSignature, usize), Error> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        let (algorithm, identity, signing_key_digest) = if parts.len() >= 3 {
            (
                Some(parts[0].to_string()),
                parts[1].to_string(),
                parts[2].to_string(),
            )
        } else if parts.len() >= 2 {
            (None, parts[0].to_string(), parts[1].to_string())
        } else {
            (None, String::new(), String::new())
        };
        let (signature, end_idx) = Self::extract_pem_block(lines, idx + 1);
        Ok((
            DocumentSignature {
                identity,
                signing_key_digest,
                signature,
                algorithm,
            },
            end_idx,
        ))
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

    fn parse_params(value: &str) -> HashMap<String, i32> {
        let mut params = HashMap::new();
        for entry in value.split_whitespace() {
            if let Some(eq_pos) = entry.find('=') {
                let key = &entry[..eq_pos];
                let val_str = &entry[eq_pos + 1..];
                if let Ok(val) = val_str.parse::<i32>() {
                    params.insert(key.to_string(), val);
                }
            }
        }
        params
    }

    fn parse_shared_randomness(value: &str) -> Option<SharedRandomness> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() >= 2 {
            let num_reveals = parts[0].parse().ok()?;
            let value = parts[1].to_string();
            Some(SharedRandomness { num_reveals, value })
        } else {
            None
        }
    }

    fn parse_versions(value: &str) -> Vec<Version> {
        value
            .split(',')
            .filter_map(|v| {
                let v = v.trim();
                if v.is_empty() {
                    None
                } else {
                    Version::parse(v).ok()
                }
            })
            .collect()
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

    fn parse_dir_source(value: &str) -> Result<DirectoryAuthority, Error> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 6 {
            return Err(Error::Parse {
                location: "dir-source".to_string(),
                reason: "dir-source requires 6 fields".to_string(),
            });
        }
        let nickname = parts[0].to_string();
        let v3ident = parts[1].to_string();
        let hostname = parts[2].to_string();
        let address: IpAddr = parts[3].parse().map_err(|_| Error::Parse {
            location: "dir-source".to_string(),
            reason: format!("invalid address: {}", parts[3]),
        })?;
        let dir_port: Option<u16> = {
            let port: u16 = parts[4].parse().map_err(|_| Error::Parse {
                location: "dir-source".to_string(),
                reason: format!("invalid dir_port: {}", parts[4]),
            })?;
            if port == 0 {
                None
            } else {
                Some(port)
            }
        };
        let or_port: u16 = parts[5].parse().map_err(|_| Error::Parse {
            location: "dir-source".to_string(),
            reason: format!("invalid or_port: {}", parts[5]),
        })?;
        let is_legacy = nickname.ends_with("-legacy");
        Ok(DirectoryAuthority {
            nickname,
            v3ident,
            hostname,
            address,
            dir_port,
            or_port,
            is_legacy,
            contact: None,
            vote_digest: None,
            legacy_dir_key: None,
            key_certificate: None,
            is_shared_randomness_participate: false,
            shared_randomness_commitments: Vec::new(),
            shared_randomness_previous_reveal_count: None,
            shared_randomness_previous_value: None,
            shared_randomness_current_reveal_count: None,
            shared_randomness_current_value: None,
            raw_content: Vec::new(),
            unrecognized_lines: Vec::new(),
        })
    }
}

impl Descriptor for NetworkStatusDocument {
    fn parse(content: &str) -> Result<Self, Error> {
        let raw_content = content.as_bytes().to_vec();
        let lines: Vec<&str> = content.lines().collect();

        let mut builder = NetworkStatusDocumentBuilder::default();
        let mut unrecognized_lines: Vec<String> = Vec::new();
        let mut current_authority: Option<DirectoryAuthority> = None;

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
                "network-status-version" => {
                    Self::parse_network_status_version(value, &mut builder)?;
                }
                "vote-status" => {
                    Self::parse_vote_status(value, &mut builder)?;
                }
                "consensus-method" => {
                    if let Ok(method) = value.parse::<u32>() {
                        builder.consensus_method(method);
                    }
                }
                "consensus-methods" => {
                    let methods: Vec<u32> = value
                        .split_whitespace()
                        .filter_map(|v| v.parse().ok())
                        .collect();
                    builder.consensus_methods(methods);
                }
                "published" => {
                    builder.published(Self::parse_timestamp(value)?);
                }
                "valid-after" => {
                    builder.valid_after(Self::parse_timestamp(value)?);
                }
                "fresh-until" => {
                    builder.fresh_until(Self::parse_timestamp(value)?);
                }
                "valid-until" => {
                    builder.valid_until(Self::parse_timestamp(value)?);
                }
                "voting-delay" => {
                    Self::parse_voting_delay(value, &mut builder)?;
                }
                "client-versions" => {
                    builder.client_versions(Self::parse_versions(value));
                }
                "server-versions" => {
                    builder.server_versions(Self::parse_versions(value));
                }
                "known-flags" => {
                    let flags: Vec<String> =
                        value.split_whitespace().map(|s| s.to_string()).collect();
                    builder.known_flags(flags);
                }
                "recommended-client-protocols" => {
                    builder.recommended_client_protocols(Self::parse_protocols(value));
                }
                "recommended-relay-protocols" => {
                    builder.recommended_relay_protocols(Self::parse_protocols(value));
                }
                "required-client-protocols" => {
                    builder.required_client_protocols(Self::parse_protocols(value));
                }
                "required-relay-protocols" => {
                    builder.required_relay_protocols(Self::parse_protocols(value));
                }
                "params" => {
                    builder.params(Self::parse_params(value));
                }
                "shared-rand-previous-value" => {
                    if let Some(sr) = Self::parse_shared_randomness(value) {
                        builder.shared_randomness_previous(sr);
                    }
                }
                "shared-rand-current-value" => {
                    if let Some(sr) = Self::parse_shared_randomness(value) {
                        builder.shared_randomness_current(sr);
                    }
                }
                "bandwidth-weights" => {
                    builder.bandwidth_weights(Self::parse_params(value));
                }
                "dir-source" => {
                    if let Some(auth) = current_authority.take() {
                        let mut auths = builder.authorities.take().unwrap_or_default();
                        auths.push(auth);
                        builder.authorities(auths);
                    }
                    current_authority = Some(Self::parse_dir_source(value)?);
                }
                "contact" => {
                    if let Some(ref mut auth) = current_authority {
                        auth.contact = Some(value.to_string());
                    }
                }
                "vote-digest" => {
                    if let Some(ref mut auth) = current_authority {
                        auth.vote_digest = Some(value.to_string());
                    }
                }
                "legacy-dir-key" => {
                    if let Some(ref mut auth) = current_authority {
                        auth.legacy_dir_key = Some(value.to_string());
                    }
                }
                "directory-signature" => {
                    if let Some(auth) = current_authority.take() {
                        let mut auths = builder.authorities.take().unwrap_or_default();
                        auths.push(auth);
                        builder.authorities(auths);
                    }
                    let (signature, end_idx) =
                        Self::parse_directory_signature(value, &lines, idx, &mut builder)?;
                    let mut sigs = builder.signatures.take().unwrap_or_default();
                    sigs.push(signature);
                    builder.signatures(sigs);
                    idx = end_idx;
                }
                "r" | "s" | "v" | "pr" | "w" | "p" | "m" | "a" => {
                    if let Some(auth) = current_authority.take() {
                        let mut auths = builder.authorities.take().unwrap_or_default();
                        auths.push(auth);
                        builder.authorities(auths);
                    }
                }
                "directory-footer" => {}
                _ => {
                    if !line.is_empty() && !line.starts_with("-----") {
                        unrecognized_lines.push(line.to_string());
                    }
                }
            }
            idx += 1;
        }

        if let Some(auth) = current_authority.take() {
            let mut auths = builder.authorities.take().unwrap_or_default();
            auths.push(auth);
            builder.authorities(auths);
        }

        builder.raw_content(raw_content);
        builder.unrecognized_lines(unrecognized_lines);

        builder.build().map_err(|e| Error::Parse {
            location: "NetworkStatusDocument".to_string(),
            reason: format!("builder error: {}", e),
        })
    }

    fn to_descriptor_string(&self) -> String {
        let mut result = String::new();

        if self.is_microdescriptor {
            result.push_str(&format!(
                "network-status-version {} microdesc\n",
                self.version
            ));
        } else {
            result.push_str(&format!("network-status-version {}\n", self.version));
        }

        if self.is_consensus {
            result.push_str("vote-status consensus\n");
        } else {
            result.push_str("vote-status vote\n");
        }

        if let Some(method) = self.consensus_method {
            result.push_str(&format!("consensus-method {}\n", method));
        }

        if let Some(ref methods) = self.consensus_methods {
            let methods_str: Vec<String> = methods.iter().map(|m| m.to_string()).collect();
            result.push_str(&format!("consensus-methods {}\n", methods_str.join(" ")));
        }

        if let Some(published) = self.published {
            result.push_str(&format!(
                "published {}\n",
                published.format("%Y-%m-%d %H:%M:%S")
            ));
        }

        result.push_str(&format!(
            "valid-after {}\n",
            self.valid_after.format("%Y-%m-%d %H:%M:%S")
        ));
        result.push_str(&format!(
            "fresh-until {}\n",
            self.fresh_until.format("%Y-%m-%d %H:%M:%S")
        ));
        result.push_str(&format!(
            "valid-until {}\n",
            self.valid_until.format("%Y-%m-%d %H:%M:%S")
        ));

        if let (Some(vote), Some(dist)) = (self.vote_delay, self.dist_delay) {
            result.push_str(&format!("voting-delay {} {}\n", vote, dist));
        }

        if !self.client_versions.is_empty() {
            let versions: Vec<String> =
                self.client_versions.iter().map(|v| v.to_string()).collect();
            result.push_str(&format!("client-versions {}\n", versions.join(",")));
        }

        if !self.server_versions.is_empty() {
            let versions: Vec<String> =
                self.server_versions.iter().map(|v| v.to_string()).collect();
            result.push_str(&format!("server-versions {}\n", versions.join(",")));
        }

        if !self.known_flags.is_empty() {
            result.push_str(&format!("known-flags {}\n", self.known_flags.join(" ")));
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

impl FromStr for NetworkStatusDocument {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for NetworkStatusDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_descriptor_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_CONSENSUS: &str = r#"network-status-version 3
vote-status consensus
consensus-method 26
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
voting-delay 2 2
client-versions 
server-versions 
known-flags Authority Exit Fast Guard HSDir NoEdConsensus Running Stable V2Dir Valid
recommended-client-protocols Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=4 LinkAuth=1 Microdesc=1-2 Relay=2
recommended-relay-protocols Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=4 LinkAuth=1 Microdesc=1-2 Relay=2
required-client-protocols Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=4 LinkAuth=1 Microdesc=1-2 Relay=2
required-relay-protocols Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 Link=3-4 LinkAuth=1 Microdesc=1 Relay=1-2
dir-source test001a 596CD48D61FDA4E868F4AA10FF559917BE3B1A35 127.0.0.1 127.0.0.1 7001 5001
contact auth1@test.test
vote-digest 2E7177224BBA39B505F7608FF376C07884CF926F
dir-source test000a BCB380A633592C218757BEE11E630511A485658A 127.0.0.1 127.0.0.1 7000 5000
contact auth0@test.test
vote-digest 5DD41617166FFB82882A117EEFDA0353A2794DC5
directory-footer
bandwidth-weights Wbd=3333 Wbe=0 Wbg=0 Wbm=10000
directory-signature 596CD48D61FDA4E868F4AA10FF559917BE3B1A35 9FBF54D6A62364320308A615BF4CF6B27B254FAD
-----BEGIN SIGNATURE-----
Ho0rLojfLHs9cSPFxe6znuGuFU8BvRr6gnH1gULTjUZO0NSQvo5N628KFeAsq+pT
-----END SIGNATURE-----
"#;

    #[test]
    fn test_parse_consensus() {
        let doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
        assert_eq!(doc.version, 3);
        assert!(doc.is_consensus);
        assert!(!doc.is_vote);
        assert!(!doc.is_microdescriptor);
        assert_eq!(doc.consensus_method, Some(26));
        assert_eq!(doc.vote_delay, Some(2));
        assert_eq!(doc.dist_delay, Some(2));
    }

    #[test]
    fn test_parse_known_flags() {
        let doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
        assert!(doc.known_flags.contains(&"Authority".to_string()));
        assert!(doc.known_flags.contains(&"Exit".to_string()));
        assert!(doc.known_flags.contains(&"Fast".to_string()));
        assert!(doc.known_flags.contains(&"Guard".to_string()));
        assert!(doc.known_flags.contains(&"HSDir".to_string()));
        assert!(doc.known_flags.contains(&"Running".to_string()));
        assert!(doc.known_flags.contains(&"Stable".to_string()));
        assert!(doc.known_flags.contains(&"Valid".to_string()));
    }

    #[test]
    fn test_parse_protocols() {
        let doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
        assert_eq!(
            doc.recommended_client_protocols.get("Cons"),
            Some(&vec![1, 2])
        );
        assert_eq!(doc.recommended_client_protocols.get("Link"), Some(&vec![4]));
        assert_eq!(doc.required_relay_protocols.get("Link"), Some(&vec![3, 4]));
    }

    #[test]
    fn test_parse_authorities() {
        let doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
        assert_eq!(doc.authorities.len(), 2);
        let auth1 = &doc.authorities[0];
        assert_eq!(auth1.nickname, "test001a");
        assert_eq!(auth1.v3ident, "596CD48D61FDA4E868F4AA10FF559917BE3B1A35");
        assert_eq!(auth1.contact, Some("auth1@test.test".to_string()));
        assert_eq!(
            auth1.vote_digest,
            Some("2E7177224BBA39B505F7608FF376C07884CF926F".to_string())
        );
    }

    #[test]
    fn test_parse_bandwidth_weights() {
        let doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
        assert_eq!(doc.bandwidth_weights.get("Wbd"), Some(&3333));
        assert_eq!(doc.bandwidth_weights.get("Wbe"), Some(&0));
        assert_eq!(doc.bandwidth_weights.get("Wbm"), Some(&10000));
    }

    #[test]
    fn test_parse_signatures() {
        let doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
        assert_eq!(doc.signatures.len(), 1);
        let sig = &doc.signatures[0];
        assert_eq!(sig.identity, "596CD48D61FDA4E868F4AA10FF559917BE3B1A35");
        assert_eq!(
            sig.signing_key_digest,
            "9FBF54D6A62364320308A615BF4CF6B27B254FAD"
        );
        assert!(sig.signature.contains("BEGIN SIGNATURE"));
    }

    #[test]
    fn test_parse_timestamps() {
        let doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
        assert_eq!(
            doc.valid_after.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2017-05-25 04:46:30"
        );
        assert_eq!(
            doc.fresh_until.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2017-05-25 04:46:40"
        );
        assert_eq!(
            doc.valid_until.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2017-05-25 04:46:50"
        );
    }

    #[test]
    fn test_microdescriptor_consensus() {
        let content = "network-status-version 3 microdesc
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
";
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert!(doc.is_microdescriptor);
        assert_eq!(doc.version_flavor, "microdesc");
    }

    use proptest::prelude::*;

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

    fn valid_flag() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("Authority".to_string()),
            Just("Exit".to_string()),
            Just("Fast".to_string()),
            Just("Guard".to_string()),
            Just("HSDir".to_string()),
            Just("Running".to_string()),
            Just("Stable".to_string()),
            Just("Valid".to_string()),
        ]
    }

    fn simple_consensus() -> impl Strategy<Value = NetworkStatusDocument> {
        (
            valid_timestamp(),
            valid_timestamp(),
            valid_timestamp(),
            proptest::collection::vec(valid_flag(), 1..5),
            1u32..30,
        )
            .prop_map(|(valid_after, fresh_until, valid_until, flags, method)| {
                let mut doc = NetworkStatusDocument {
                    version: 3,
                    version_flavor: String::new(),
                    is_consensus: true,
                    is_vote: false,
                    is_microdescriptor: false,
                    consensus_method: Some(method),
                    consensus_methods: None,
                    published: None,
                    valid_after,
                    fresh_until,
                    valid_until,
                    vote_delay: Some(2),
                    dist_delay: Some(2),
                    client_versions: Vec::new(),
                    server_versions: Vec::new(),
                    known_flags: flags,
                    recommended_client_protocols: HashMap::new(),
                    recommended_relay_protocols: HashMap::new(),
                    required_client_protocols: HashMap::new(),
                    required_relay_protocols: HashMap::new(),
                    params: HashMap::new(),
                    shared_randomness_previous: None,
                    shared_randomness_current: None,
                    bandwidth_weights: HashMap::new(),
                    authorities: Vec::new(),
                    signatures: Vec::new(),
                    raw_content: Vec::new(),
                    unrecognized_lines: Vec::new(),
                };
                doc.known_flags.sort();
                doc.known_flags.dedup();
                doc
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_consensus_roundtrip(doc in simple_consensus()) {
            let serialized = doc.to_descriptor_string();
            let parsed = NetworkStatusDocument::parse(&serialized);

            prop_assert!(parsed.is_ok(), "Failed to parse serialized consensus: {:?}", parsed.err());

            let parsed = parsed.unwrap();

            prop_assert_eq!(doc.version, parsed.version, "version mismatch");
            prop_assert_eq!(doc.is_consensus, parsed.is_consensus, "is_consensus mismatch");
        }
    }
}

#[cfg(test)]
mod comprehensive_tests {
    use super::*;

    #[test]
    fn test_edge_case_empty_client_versions() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
client-versions 
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.client_versions.len(), 0);
    }

    #[test]
    fn test_edge_case_empty_server_versions() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
server-versions 
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.server_versions.len(), 0);
    }

    #[test]
    fn test_edge_case_empty_known_flags() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
known-flags 
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.known_flags.len(), 0);
    }

    #[test]
    fn test_edge_case_empty_params() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
params 
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.params.len(), 0);
    }

    #[test]
    fn test_edge_case_empty_bandwidth_weights() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
directory-footer
bandwidth-weights 
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.bandwidth_weights.len(), 0);
    }

    #[test]
    fn test_edge_case_multiple_authorities() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
dir-source auth1 596CD48D61FDA4E868F4AA10FF559917BE3B1A35 127.0.0.1 127.0.0.1 7001 5001
dir-source auth2 BCB380A633592C218757BEE11E630511A485658A 127.0.0.1 127.0.0.1 7002 5002
dir-source auth3 ABC380A633592C218757BEE11E630511A485658B 127.0.0.1 127.0.0.1 7003 5003
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.authorities.len(), 3);
        assert_eq!(doc.authorities[0].nickname, "auth1");
        assert_eq!(doc.authorities[1].nickname, "auth2");
        assert_eq!(doc.authorities[2].nickname, "auth3");
    }

    #[test]
    fn test_edge_case_multiple_signatures() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
directory-signature 596CD48D61FDA4E868F4AA10FF559917BE3B1A35 9FBF54D6A62364320308A615BF4CF6B27B254FAD
-----BEGIN SIGNATURE-----
sig1
-----END SIGNATURE-----
directory-signature BCB380A633592C218757BEE11E630511A485658A 8FBF54D6A62364320308A615BF4CF6B27B254FAE
-----BEGIN SIGNATURE-----
sig2
-----END SIGNATURE-----
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.signatures.len(), 2);
        assert_eq!(
            doc.signatures[0].identity,
            "596CD48D61FDA4E868F4AA10FF559917BE3B1A35"
        );
        assert_eq!(
            doc.signatures[1].identity,
            "BCB380A633592C218757BEE11E630511A485658A"
        );
    }

    #[test]
    fn test_edge_case_shared_randomness_both() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
shared-rand-previous-value 9 abcdef1234567890
shared-rand-current-value 10 1234567890abcdef
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert!(doc.shared_randomness_previous.is_some());
        assert!(doc.shared_randomness_current.is_some());
        let prev = doc.shared_randomness_previous.unwrap();
        assert_eq!(prev.num_reveals, 9);
        assert_eq!(prev.value, "abcdef1234567890");
        let curr = doc.shared_randomness_current.unwrap();
        assert_eq!(curr.num_reveals, 10);
        assert_eq!(curr.value, "1234567890abcdef");
    }

    #[test]
    fn test_edge_case_vote_document() {
        let content = r#"network-status-version 3
vote-status vote
consensus-methods 25 26 27
published 2017-05-25 04:46:20
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert!(!doc.is_consensus);
        assert!(doc.is_vote);
        assert!(doc.consensus_methods.is_some());
        assert_eq!(doc.consensus_methods.unwrap(), vec![25, 26, 27]);
        assert!(doc.published.is_some());
    }

    #[test]
    fn test_edge_case_protocol_ranges() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
recommended-client-protocols Cons=1-2 Link=1-5 Relay=1-3
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(
            doc.recommended_client_protocols.get("Cons"),
            Some(&vec![1, 2])
        );
        assert_eq!(
            doc.recommended_client_protocols.get("Link"),
            Some(&vec![1, 2, 3, 4, 5])
        );
        assert_eq!(
            doc.recommended_client_protocols.get("Relay"),
            Some(&vec![1, 2, 3])
        );
    }

    #[test]
    fn test_edge_case_protocol_mixed_ranges() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
required-relay-protocols Link=1-3,5,7-9
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        let link_protos = doc.required_relay_protocols.get("Link").unwrap();
        assert!(link_protos.contains(&1));
        assert!(link_protos.contains(&2));
        assert!(link_protos.contains(&3));
        assert!(link_protos.contains(&5));
        assert!(link_protos.contains(&7));
        assert!(link_protos.contains(&8));
        assert!(link_protos.contains(&9));
        assert!(!link_protos.contains(&4));
        assert!(!link_protos.contains(&6));
    }

    #[test]
    fn test_edge_case_params_negative_values() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
params param1=100 param2=-50 param3=0
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.params.get("param1"), Some(&100));
        assert_eq!(doc.params.get("param2"), Some(&-50));
        assert_eq!(doc.params.get("param3"), Some(&0));
    }

    #[test]
    fn test_edge_case_bandwidth_weights_negative() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
directory-footer
bandwidth-weights Wbd=3333 Wbe=-100 Wbg=0
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.bandwidth_weights.get("Wbd"), Some(&3333));
        assert_eq!(doc.bandwidth_weights.get("Wbe"), Some(&-100));
        assert_eq!(doc.bandwidth_weights.get("Wbg"), Some(&0));
    }

    #[test]
    fn test_edge_case_unrecognized_lines() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
unknown-field some value
another-unknown another value
"#;
        let doc = NetworkStatusDocument::parse(content).unwrap();
        assert_eq!(doc.unrecognized_lines.len(), 2);
        assert!(doc
            .unrecognized_lines
            .contains(&"unknown-field some value".to_string()));
        assert!(doc
            .unrecognized_lines
            .contains(&"another-unknown another value".to_string()));
    }

    #[test]
    fn test_validation_invalid_timestamp_ordering() {
        let doc = NetworkStatusDocument {
            version: 3,
            version_flavor: String::new(),
            is_consensus: true,
            is_vote: false,
            is_microdescriptor: false,
            consensus_method: Some(26),
            consensus_methods: None,
            published: None,
            valid_after: Utc::now(),
            fresh_until: Utc::now() - chrono::Duration::hours(1),
            valid_until: Utc::now() + chrono::Duration::hours(1),
            vote_delay: Some(2),
            dist_delay: Some(2),
            client_versions: Vec::new(),
            server_versions: Vec::new(),
            known_flags: Vec::new(),
            recommended_client_protocols: HashMap::new(),
            recommended_relay_protocols: HashMap::new(),
            required_client_protocols: HashMap::new(),
            required_relay_protocols: HashMap::new(),
            params: HashMap::new(),
            shared_randomness_previous: None,
            shared_randomness_current: None,
            bandwidth_weights: HashMap::new(),
            authorities: Vec::new(),
            signatures: Vec::new(),
            raw_content: Vec::new(),
            unrecognized_lines: Vec::new(),
        };
        let result = doc.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Descriptor(crate::descriptor::DescriptorError::Consensus(
                crate::descriptor::ConsensusError::TimestampOrderingViolation(_),
            )) => {}
            _ => panic!("Expected TimestampOrderingViolation error"),
        }
    }

    #[test]
    fn test_validation_invalid_version() {
        let doc = NetworkStatusDocument {
            version: 2,
            version_flavor: String::new(),
            is_consensus: true,
            is_vote: false,
            is_microdescriptor: false,
            consensus_method: Some(26),
            consensus_methods: None,
            published: None,
            valid_after: Utc::now(),
            fresh_until: Utc::now() + chrono::Duration::hours(1),
            valid_until: Utc::now() + chrono::Duration::hours(2),
            vote_delay: Some(2),
            dist_delay: Some(2),
            client_versions: Vec::new(),
            server_versions: Vec::new(),
            known_flags: Vec::new(),
            recommended_client_protocols: HashMap::new(),
            recommended_relay_protocols: HashMap::new(),
            required_client_protocols: HashMap::new(),
            required_relay_protocols: HashMap::new(),
            params: HashMap::new(),
            shared_randomness_previous: None,
            shared_randomness_current: None,
            bandwidth_weights: HashMap::new(),
            authorities: Vec::new(),
            signatures: Vec::new(),
            raw_content: Vec::new(),
            unrecognized_lines: Vec::new(),
        };
        let result = doc.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Descriptor(crate::descriptor::DescriptorError::Consensus(
                crate::descriptor::ConsensusError::InvalidNetworkStatusVersion(_),
            )) => {}
            _ => panic!("Expected InvalidNetworkStatusVersion error"),
        }
    }

    #[test]
    fn test_validation_invalid_authority_fingerprint() {
        let doc = NetworkStatusDocument {
            version: 3,
            version_flavor: String::new(),
            is_consensus: true,
            is_vote: false,
            is_microdescriptor: false,
            consensus_method: Some(26),
            consensus_methods: None,
            published: None,
            valid_after: Utc::now(),
            fresh_until: Utc::now() + chrono::Duration::hours(1),
            valid_until: Utc::now() + chrono::Duration::hours(2),
            vote_delay: Some(2),
            dist_delay: Some(2),
            client_versions: Vec::new(),
            server_versions: Vec::new(),
            known_flags: Vec::new(),
            recommended_client_protocols: HashMap::new(),
            recommended_relay_protocols: HashMap::new(),
            required_client_protocols: HashMap::new(),
            required_relay_protocols: HashMap::new(),
            params: HashMap::new(),
            shared_randomness_previous: None,
            shared_randomness_current: None,
            bandwidth_weights: HashMap::new(),
            authorities: vec![DirectoryAuthority {
                nickname: "test".to_string(),
                v3ident: "INVALID".to_string(),
                hostname: "test.test".to_string(),
                address: "127.0.0.1".parse().unwrap(),
                dir_port: Some(7000),
                or_port: 5000,
                is_legacy: false,
                contact: None,
                vote_digest: None,
                legacy_dir_key: None,
                key_certificate: None,
                is_shared_randomness_participate: false,
                shared_randomness_commitments: Vec::new(),
                shared_randomness_previous_reveal_count: None,
                shared_randomness_previous_value: None,
                shared_randomness_current_reveal_count: None,
                shared_randomness_current_value: None,
                raw_content: Vec::new(),
                unrecognized_lines: Vec::new(),
            }],
            signatures: Vec::new(),
            raw_content: Vec::new(),
            unrecognized_lines: Vec::new(),
        };
        let result = doc.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Descriptor(crate::descriptor::DescriptorError::Consensus(
                crate::descriptor::ConsensusError::InvalidFingerprint(_),
            )) => {}
            _ => panic!("Expected InvalidFingerprint error"),
        }
    }

    #[test]
    fn test_validation_missing_signatures() {
        let doc = NetworkStatusDocument {
            version: 3,
            version_flavor: String::new(),
            is_consensus: true,
            is_vote: false,
            is_microdescriptor: false,
            consensus_method: Some(26),
            consensus_methods: None,
            published: None,
            valid_after: Utc::now(),
            fresh_until: Utc::now() + chrono::Duration::hours(1),
            valid_until: Utc::now() + chrono::Duration::hours(2),
            vote_delay: Some(2),
            dist_delay: Some(2),
            client_versions: Vec::new(),
            server_versions: Vec::new(),
            known_flags: Vec::new(),
            recommended_client_protocols: HashMap::new(),
            recommended_relay_protocols: HashMap::new(),
            required_client_protocols: HashMap::new(),
            required_relay_protocols: HashMap::new(),
            params: HashMap::new(),
            shared_randomness_previous: None,
            shared_randomness_current: None,
            bandwidth_weights: HashMap::new(),
            authorities: Vec::new(),
            signatures: Vec::new(),
            raw_content: Vec::new(),
            unrecognized_lines: Vec::new(),
        };
        let result = doc.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Descriptor(crate::descriptor::DescriptorError::Consensus(
                crate::descriptor::ConsensusError::MissingRequiredField(_),
            )) => {}
            _ => panic!("Expected MissingRequiredField error"),
        }
    }

    #[test]
    fn test_validation_valid_consensus() {
        let doc = NetworkStatusDocument {
            version: 3,
            version_flavor: String::new(),
            is_consensus: true,
            is_vote: false,
            is_microdescriptor: false,
            consensus_method: Some(26),
            consensus_methods: None,
            published: None,
            valid_after: Utc::now(),
            fresh_until: Utc::now() + chrono::Duration::hours(1),
            valid_until: Utc::now() + chrono::Duration::hours(2),
            vote_delay: Some(2),
            dist_delay: Some(2),
            client_versions: Vec::new(),
            server_versions: Vec::new(),
            known_flags: Vec::new(),
            recommended_client_protocols: HashMap::new(),
            recommended_relay_protocols: HashMap::new(),
            required_client_protocols: HashMap::new(),
            required_relay_protocols: HashMap::new(),
            params: HashMap::new(),
            shared_randomness_previous: None,
            shared_randomness_current: None,
            bandwidth_weights: HashMap::new(),
            authorities: vec![DirectoryAuthority {
                nickname: "test".to_string(),
                v3ident: "596CD48D61FDA4E868F4AA10FF559917BE3B1A35".to_string(),
                hostname: "test.test".to_string(),
                address: "127.0.0.1".parse().unwrap(),
                dir_port: Some(7000),
                or_port: 5000,
                is_legacy: false,
                contact: None,
                vote_digest: None,
                legacy_dir_key: None,
                key_certificate: None,
                is_shared_randomness_participate: false,
                shared_randomness_commitments: Vec::new(),
                shared_randomness_previous_reveal_count: None,
                shared_randomness_previous_value: None,
                shared_randomness_current_reveal_count: None,
                shared_randomness_current_value: None,
                raw_content: Vec::new(),
                unrecognized_lines: Vec::new(),
            }],
            signatures: vec![DocumentSignature {
                identity: "596CD48D61FDA4E868F4AA10FF559917BE3B1A35".to_string(),
                signing_key_digest: "9FBF54D6A62364320308A615BF4CF6B27B254FAD".to_string(),
                signature: "test".to_string(),
                algorithm: None,
            }],
            raw_content: Vec::new(),
            unrecognized_lines: Vec::new(),
        };
        let result = doc.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_basic() {
        let now = Utc::now();
        let doc = NetworkStatusDocumentBuilder::default()
            .version(3_u32)
            .version_flavor("")
            .is_consensus(true)
            .is_vote(false)
            .is_microdescriptor(false)
            .valid_after(now)
            .fresh_until(now + chrono::Duration::hours(1))
            .valid_until(now + chrono::Duration::hours(2))
            .build()
            .expect("Failed to build");

        assert_eq!(doc.version, 3);
        assert!(doc.is_consensus);
        assert!(!doc.is_vote);
    }

    #[test]
    fn test_builder_with_optional_fields() {
        let now = Utc::now();
        let doc = NetworkStatusDocumentBuilder::default()
            .version(3_u32)
            .version_flavor("microdesc")
            .is_consensus(true)
            .is_vote(false)
            .is_microdescriptor(true)
            .consensus_method(26_u32)
            .valid_after(now)
            .fresh_until(now + chrono::Duration::hours(1))
            .valid_until(now + chrono::Duration::hours(2))
            .vote_delay(2_u32)
            .dist_delay(2_u32)
            .build()
            .expect("Failed to build");

        assert_eq!(doc.version_flavor, "microdesc");
        assert!(doc.is_microdescriptor);
        assert_eq!(doc.consensus_method, Some(26));
        assert_eq!(doc.vote_delay, Some(2));
        assert_eq!(doc.dist_delay, Some(2));
    }

    #[test]
    fn test_round_trip_serialization() {
        let content = r#"network-status-version 3
vote-status consensus
consensus-method 26
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
voting-delay 2 2
known-flags Authority Exit Fast Guard
"#;
        let doc1 = NetworkStatusDocument::parse(content).unwrap();
        let serialized = doc1.to_descriptor_string();
        let doc2 = NetworkStatusDocument::parse(&serialized).unwrap();

        assert_eq!(doc1.version, doc2.version);
        assert_eq!(doc1.is_consensus, doc2.is_consensus);
        assert_eq!(doc1.consensus_method, doc2.consensus_method);
        assert_eq!(doc1.vote_delay, doc2.vote_delay);
        assert_eq!(doc1.dist_delay, doc2.dist_delay);
        assert_eq!(doc1.known_flags, doc2.known_flags);
    }

    #[test]
    fn test_display_implementation() {
        let now = Utc::now();
        let doc = NetworkStatusDocument {
            version: 3,
            version_flavor: String::new(),
            is_consensus: true,
            is_vote: false,
            is_microdescriptor: false,
            consensus_method: Some(26),
            consensus_methods: None,
            published: None,
            valid_after: now,
            fresh_until: now + chrono::Duration::hours(1),
            valid_until: now + chrono::Duration::hours(2),
            vote_delay: Some(2),
            dist_delay: Some(2),
            client_versions: Vec::new(),
            server_versions: Vec::new(),
            known_flags: Vec::new(),
            recommended_client_protocols: HashMap::new(),
            recommended_relay_protocols: HashMap::new(),
            required_client_protocols: HashMap::new(),
            required_relay_protocols: HashMap::new(),
            params: HashMap::new(),
            shared_randomness_previous: None,
            shared_randomness_current: None,
            bandwidth_weights: HashMap::new(),
            authorities: Vec::new(),
            signatures: Vec::new(),
            raw_content: Vec::new(),
            unrecognized_lines: Vec::new(),
        };
        let display_str = format!("{}", doc);
        assert!(display_str.contains("network-status-version"));
        assert!(display_str.contains("vote-status"));
    }

    #[test]
    fn test_from_str_implementation() {
        let content = r#"network-status-version 3
vote-status consensus
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
"#;
        let doc: NetworkStatusDocument = content.parse().unwrap();
        assert_eq!(doc.version, 3);
        assert!(doc.is_consensus);
    }
}
