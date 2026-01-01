//! Directory authority parsing for Tor network status documents.
//!
//! This module provides parsing for directory authority entries found in
//! v3 network status documents (votes and consensus). Directory authorities
//! are special relays that are hardcoded into Tor and are responsible for
//! voting on the state of the network and producing the consensus document.
//!
//! # Overview
//!
//! Directory authorities perform several critical functions in the Tor network:
//!
//! - **Voting**: Each authority periodically publishes a vote describing which
//!   relays it believes are in the network and their properties (flags, bandwidth, etc.)
//! - **Consensus Generation**: Authorities exchange votes and produce a consensus
//!   document that represents the agreed-upon state of the network
//! - **Shared Randomness**: Authorities participate in a distributed random number
//!   generation protocol used for hidden service directory assignment
//!
//! # Document Types
//!
//! Authority entries appear differently in votes versus consensus documents:
//!
//! - **In Votes**: Include the authority's key certificate for signature verification
//! - **In Consensus**: Include a vote-digest referencing the authority's vote
//!
//! # Example
//!
//! ```rust
//! use stem_rs::descriptor::authority::DirectoryAuthority;
//!
//! let content = r#"dir-source moria1 D586D18309DED4CD6D57C18FDB97EFA96D330566 128.31.0.39 128.31.0.39 9131 9101
//! contact 1024D/28988BF5 arma mit edu
//! vote-digest 49015F787433103580E3B66A1707A00E60F2D15B
//! "#;
//!
//! let authority = DirectoryAuthority::parse(content, false).unwrap();
//! assert_eq!(authority.nickname, "moria1");
//! assert_eq!(authority.or_port, 9101);
//! ```
//!
//! # See Also
//!
//! - [`consensus`](super::consensus): Network status documents containing authority entries
//! - [`key_cert`](super::key_cert): Key certificates used by authorities in votes
//! - [Tor Directory Protocol Specification](https://spec.torproject.org/dir-spec)
//! - Python Stem's [`stem.directory`](https://stem.torproject.org/api/directory.html)

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::Error;

use super::key_cert::KeyCertificate;

/// A commitment to a shared random value from a directory authority.
///
/// As part of the shared randomness protocol, each participating authority
/// commits to a random value before revealing it. This prevents authorities
/// from choosing their random contribution based on others' values.
///
/// # Protocol
///
/// 1. Each authority generates a random value and publishes a commitment (hash)
/// 2. After all commitments are collected, authorities reveal their values
/// 3. The revealed values are combined to produce the shared random value
///
/// # Fields
///
/// - `version`: Protocol version (currently 1)
/// - `algorithm`: Hash algorithm used (e.g., "sha3-256")
/// - `identity`: The authority's identity fingerprint
/// - `commit`: The commitment value (hash of the random value)
/// - `reveal`: The revealed random value (only present after reveal phase)
#[derive(Debug, Clone, PartialEq)]
pub struct SharedRandomnessCommitment {
    /// Protocol version number for the shared randomness protocol.
    pub version: u32,
    /// Hash algorithm used for the commitment (e.g., "sha3-256").
    pub algorithm: String,
    /// Identity fingerprint of the committing authority.
    pub identity: String,
    /// The commitment value (hash of the random value being committed to).
    pub commit: String,
    /// The revealed random value, present only after the reveal phase.
    pub reveal: Option<String>,
}

/// A directory authority entry from a network status document.
///
/// Directory authorities are trusted relays that vote on the state of the
/// Tor network. This struct represents an authority's entry as it appears
/// in vote or consensus documents.
///
/// # Conceptual Role
///
/// Directory authorities are the backbone of Tor's distributed trust model.
/// They:
/// - Collect and validate relay server descriptors
/// - Vote on relay flags (Guard, Exit, Stable, etc.)
/// - Produce the network consensus that clients use
/// - Participate in shared randomness generation
///
/// # Vote vs Consensus Entries
///
/// Authority entries differ based on document type:
///
/// | Field | Vote | Consensus |
/// |-------|------|-----------|
/// | `key_certificate` | Required | Not present |
/// | `vote_digest` | Not present | Required |
/// | `legacy_dir_key` | May be present | Not present |
///
/// # Legacy Authorities
///
/// Some authority entries have a `-legacy` suffix on their nickname,
/// indicating they are legacy entries for backward compatibility.
/// Legacy entries have relaxed validation requirements.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::authority::DirectoryAuthority;
///
/// // Parse a consensus authority entry
/// let content = r#"dir-source gabelmoo F2044413DAC2E02E3D6BCF4735A19BCA1DE97281 131.188.40.189 131.188.40.189 80 443
/// contact 4096R/261C5FBE77285F88FB0C343266C8C2D7C5AA446D Sebastian Hahn <tor@sebastianhahn.net>
/// vote-digest 49015F787433103580E3B66A1707A00E60F2D15B
/// "#;
///
/// let authority = DirectoryAuthority::parse(content, false)?;
/// assert_eq!(authority.nickname, "gabelmoo");
/// assert!(!authority.is_legacy);
/// # Ok::<(), stem_rs::Error>(())
/// ```
///
/// # See Also
///
/// - [`KeyCertificate`]: Authority signing keys
/// - [`NetworkStatusDocument`](super::consensus::NetworkStatusDocument): Contains authority entries
#[derive(Debug, Clone, PartialEq)]
pub struct DirectoryAuthority {
    /// The authority's nickname (1-19 alphanumeric characters).
    /// May have a `-legacy` suffix for legacy entries.
    pub nickname: String,
    /// The authority's v3 identity key fingerprint (40 hex characters).
    /// Used to identify the authority and verify signatures.
    pub v3ident: String,
    /// The authority's hostname.
    pub hostname: String,
    /// The authority's IP address (IPv4 or IPv6).
    pub address: IpAddr,
    /// The directory port for HTTP directory requests, or `None` if not available.
    pub dir_port: Option<u16>,
    /// The OR (onion router) port for relay traffic.
    pub or_port: u16,
    /// Whether this is a legacy authority entry (nickname ends with `-legacy`).
    pub is_legacy: bool,
    /// Contact information for the authority operator.
    pub contact: Option<String>,
    /// Digest of the authority's vote (only in consensus documents).
    pub vote_digest: Option<String>,
    /// Legacy directory key fingerprint (only in votes, for backward compatibility).
    pub legacy_dir_key: Option<String>,
    /// The authority's key certificate (only in vote documents).
    pub key_certificate: Option<KeyCertificate>,
    /// Whether this authority participates in the shared randomness protocol.
    pub is_shared_randomness_participate: bool,
    /// Commitments to shared random values from this authority.
    pub shared_randomness_commitments: Vec<SharedRandomnessCommitment>,
    /// Number of authorities that revealed for the previous shared random value.
    pub shared_randomness_previous_reveal_count: Option<u32>,
    /// The previous shared random value (base64 encoded).
    pub shared_randomness_previous_value: Option<String>,
    /// Number of authorities that revealed for the current shared random value.
    pub shared_randomness_current_reveal_count: Option<u32>,
    /// The current shared random value (base64 encoded).
    pub shared_randomness_current_value: Option<String>,
    /// Raw bytes of the authority entry as it appeared in the document.
    pub(crate) raw_content: Vec<u8>,
    /// Lines that were not recognized during parsing.
    pub(crate) unrecognized_lines: Vec<String>,
}

impl Default for DirectoryAuthority {
    fn default() -> Self {
        Self {
            nickname: String::new(),
            v3ident: String::new(),
            hostname: String::new(),
            address: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            dir_port: None,
            or_port: 0,
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
        }
    }
}

impl DirectoryAuthority {
    /// Parses a directory authority entry from its string representation.
    ///
    /// This method parses authority entries with full validation enabled.
    /// Use [`parse_with_validation`](Self::parse_with_validation) for control
    /// over validation behavior.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw authority entry text
    /// * `is_vote` - `true` if parsing from a vote document, `false` for consensus
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The entry doesn't start with a `dir-source` line
    /// - Required fields are missing or malformed
    /// - Fingerprints are not valid 40-character hex strings
    /// - IP addresses or ports are invalid
    /// - Vote entries lack a key certificate
    /// - Consensus entries have fields that should only appear in votes
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::authority::DirectoryAuthority;
    ///
    /// // Parse a consensus entry
    /// let consensus_entry = r#"dir-source moria1 D586D18309DED4CD6D57C18FDB97EFA96D330566 128.31.0.39 128.31.0.39 9131 9101
    /// contact arma
    /// vote-digest 49015F787433103580E3B66A1707A00E60F2D15B
    /// "#;
    /// let authority = DirectoryAuthority::parse(consensus_entry, false)?;
    /// # Ok::<(), stem_rs::Error>(())
    /// ```
    pub fn parse(content: &str, is_vote: bool) -> Result<Self, Error> {
        Self::parse_with_validation(content, true, is_vote)
    }

    /// Parses a directory authority entry with configurable validation.
    ///
    /// When validation is disabled, the parser is more lenient and will
    /// attempt to extract as much information as possible even from
    /// malformed entries.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw authority entry text
    /// * `validate` - Whether to perform strict validation
    /// * `is_vote` - `true` if parsing from a vote document, `false` for consensus
    ///
    /// # Errors
    ///
    /// When `validate` is `true`, returns [`Error::Parse`] for validation failures.
    /// When `validate` is `false`, parsing errors are silently ignored where possible.
    pub fn parse_with_validation(
        content: &str,
        validate: bool,
        is_vote: bool,
    ) -> Result<Self, Error> {
        let raw_content = content.as_bytes().to_vec();

        let (authority_content, key_cert) =
            if let Some(key_div) = content.find("\ndir-key-certificate-version") {
                let cert_content = &content[key_div + 1..];
                let cert = if validate {
                    Some(KeyCertificate::parse(cert_content)?)
                } else {
                    KeyCertificate::parse_with_validation(cert_content, false).ok()
                };
                (&content[..key_div + 1], cert)
            } else {
                (content, None)
            };

        let lines: Vec<&str> = authority_content.lines().collect();

        let mut nickname: Option<String> = None;
        let mut v3ident: Option<String> = None;
        let mut hostname: Option<String> = None;
        let mut address: Option<IpAddr> = None;
        let mut dir_port: Option<u16> = None;
        let mut or_port: Option<u16> = None;
        let mut is_legacy = false;
        let mut contact: Option<String> = None;
        let mut vote_digest: Option<String> = None;
        let mut legacy_dir_key: Option<String> = None;
        let mut is_shared_randomness_participate = false;
        let mut shared_randomness_commitments: Vec<SharedRandomnessCommitment> = Vec::new();
        let mut shared_randomness_previous_reveal_count: Option<u32> = None;
        let mut shared_randomness_previous_value: Option<String> = None;
        let mut shared_randomness_current_reveal_count: Option<u32> = None;
        let mut shared_randomness_current_value: Option<String> = None;
        let mut unrecognized_lines: Vec<String> = Vec::new();
        let mut first_keyword: Option<&str> = None;

        for line in &lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            if first_keyword.is_none() {
                first_keyword = Some(keyword);
            }

            match keyword {
                "dir-source" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let nick = parts[0].to_string();
                        is_legacy = nick.ends_with("-legacy");

                        let nick_to_validate = nick.trim_end_matches("-legacy");
                        if validate && !is_valid_nickname(nick_to_validate) {
                            return Err(Error::Parse {
                                location: "dir-source".to_string(),
                                reason: format!("Authority's nickname is invalid: {}", nick),
                            });
                        }

                        if validate && !is_valid_fingerprint(parts[1]) {
                            return Err(Error::Parse {
                                location: "dir-source".to_string(),
                                reason: format!("Authority's v3ident is invalid: {}", parts[1]),
                            });
                        }

                        if validate && parts[2].is_empty() {
                            return Err(Error::Parse {
                                location: "dir-source".to_string(),
                                reason: "Authority's hostname can't be blank".to_string(),
                            });
                        }

                        let addr: Result<IpAddr, _> = parts[3].parse();
                        if validate && addr.is_err() {
                            return Err(Error::Parse {
                                location: "dir-source".to_string(),
                                reason: format!(
                                    "Authority's address isn't a valid IPv4 address: {}",
                                    parts[3]
                                ),
                            });
                        }

                        let dport: Result<u16, _> = parts[4].parse();
                        if validate && dport.is_err() {
                            return Err(Error::Parse {
                                location: "dir-source".to_string(),
                                reason: format!("Authority's DirPort is invalid: {}", parts[4]),
                            });
                        }

                        let oport: Result<u16, _> = parts[5].parse();
                        if validate && oport.is_err() {
                            return Err(Error::Parse {
                                location: "dir-source".to_string(),
                                reason: format!("Authority's ORPort is invalid: {}", parts[5]),
                            });
                        }

                        nickname = Some(nick);
                        v3ident = Some(parts[1].to_string());
                        hostname = Some(parts[2].to_string());
                        address = addr.ok();
                        dir_port = dport.ok().and_then(|p| if p == 0 { None } else { Some(p) });
                        or_port = oport.ok();
                    } else if validate {
                        return Err(Error::Parse {
                            location: "dir-source".to_string(),
                            reason: format!(
                                "Authority entry's 'dir-source' line must have six values: dir-source {}",
                                value
                            ),
                        });
                    }
                }
                "contact" => {
                    contact = Some(value.to_string());
                }
                "vote-digest" => {
                    if validate && !is_valid_fingerprint(value) {
                        return Err(Error::Parse {
                            location: "vote-digest".to_string(),
                            reason: format!("Invalid vote-digest: {}", value),
                        });
                    }
                    vote_digest = if is_valid_fingerprint(value) {
                        Some(value.to_string())
                    } else {
                        None
                    };
                }
                "legacy-dir-key" => {
                    if validate && !is_valid_fingerprint(value) {
                        return Err(Error::Parse {
                            location: "legacy-dir-key".to_string(),
                            reason: format!("Invalid legacy-dir-key: {}", value),
                        });
                    }
                    legacy_dir_key = if is_valid_fingerprint(value) {
                        Some(value.to_string())
                    } else {
                        None
                    };
                }
                "shared-rand-participate" => {
                    is_shared_randomness_participate = true;
                }
                "shared-rand-commit" => {
                    if let Some(commitment) = parse_shared_rand_commit(value) {
                        shared_randomness_commitments.push(commitment);
                    }
                }
                "shared-rand-previous-value" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.len() >= 2 {
                        shared_randomness_previous_reveal_count = parts[0].parse().ok();
                        shared_randomness_previous_value = Some(parts[1].to_string());
                    }
                }
                "shared-rand-current-value" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.len() >= 2 {
                        shared_randomness_current_reveal_count = parts[0].parse().ok();
                        shared_randomness_current_value = Some(parts[1].to_string());
                    }
                }
                _ => {
                    if !line.is_empty() && !line.starts_with("-----") {
                        unrecognized_lines.push(line.to_string());
                    }
                }
            }
        }

        if validate {
            if first_keyword != Some("dir-source") {
                return Err(Error::Parse {
                    location: "DirectoryAuthority".to_string(),
                    reason: "Authority entries are expected to start with a 'dir-source' line"
                        .to_string(),
                });
            }

            if nickname.is_none() {
                return Err(Error::Parse {
                    location: "DirectoryAuthority".to_string(),
                    reason: "Authority entries must have a 'dir-source' line".to_string(),
                });
            }

            if !is_legacy && contact.is_none() {
                return Err(Error::Parse {
                    location: "DirectoryAuthority".to_string(),
                    reason: "Authority entries must have a 'contact' line".to_string(),
                });
            }

            if is_vote {
                if key_cert.is_none() {
                    return Err(Error::Parse {
                        location: "DirectoryAuthority".to_string(),
                        reason: "Authority votes must have a key certificate".to_string(),
                    });
                }
                if vote_digest.is_some() {
                    return Err(Error::Parse {
                        location: "DirectoryAuthority".to_string(),
                        reason: "Authority votes shouldn't have a 'vote-digest' line".to_string(),
                    });
                }
            } else {
                if key_cert.is_some() {
                    return Err(Error::Parse {
                        location: "DirectoryAuthority".to_string(),
                        reason: "Authority consensus entries shouldn't have a key certificate"
                            .to_string(),
                    });
                }
                if !is_legacy && vote_digest.is_none() {
                    return Err(Error::Parse {
                        location: "DirectoryAuthority".to_string(),
                        reason: "Authority entries must have a 'vote-digest' line".to_string(),
                    });
                }
                if legacy_dir_key.is_some() {
                    return Err(Error::Parse {
                        location: "DirectoryAuthority".to_string(),
                        reason:
                            "Authority consensus entries shouldn't have a 'legacy-dir-key' line"
                                .to_string(),
                    });
                }
            }
        }

        Ok(DirectoryAuthority {
            nickname: nickname.unwrap_or_default(),
            v3ident: v3ident.unwrap_or_default(),
            hostname: hostname.unwrap_or_default(),
            address: address.unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
            dir_port,
            or_port: or_port.unwrap_or(0),
            is_legacy,
            contact,
            vote_digest,
            legacy_dir_key,
            key_certificate: key_cert,
            is_shared_randomness_participate,
            shared_randomness_commitments,
            shared_randomness_previous_reveal_count,
            shared_randomness_previous_value,
            shared_randomness_current_reveal_count,
            shared_randomness_current_value,
            raw_content,
            unrecognized_lines,
        })
    }

    /// Returns the raw bytes of the authority entry as it appeared in the document.
    ///
    /// This preserves the original formatting and can be used for
    /// signature verification or re-serialization.
    pub fn raw_content(&self) -> &[u8] {
        &self.raw_content
    }

    /// Returns lines that were not recognized during parsing.
    ///
    /// Unrecognized lines may indicate:
    /// - New fields added in newer Tor versions
    /// - Malformed or corrupted data
    /// - Custom extensions
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::authority::DirectoryAuthority;
    ///
    /// let content = r#"dir-source test AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA example.com 1.2.3.4 80 443
    /// contact test
    /// unknown-field some-value
    /// vote-digest AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    /// "#;
    /// let authority = DirectoryAuthority::parse(content, false)?;
    /// assert!(authority.unrecognized_lines().iter().any(|l| l.contains("unknown-field")));
    /// # Ok::<(), stem_rs::Error>(())
    /// ```
    pub fn unrecognized_lines(&self) -> &[String] {
        &self.unrecognized_lines
    }

    /// Converts the authority entry back to its descriptor string format.
    ///
    /// The output follows the Tor directory protocol format and can be
    /// used for serialization or debugging.
    ///
    /// # Note
    ///
    /// The output may not be byte-for-byte identical to the original
    /// input due to normalization of whitespace and field ordering.
    pub fn to_descriptor_string(&self) -> String {
        let mut result = String::new();

        let dir_port_str = self
            .dir_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "0".to_string());
        result.push_str(&format!(
            "dir-source {} {} {} {} {} {}\n",
            self.nickname, self.v3ident, self.hostname, self.address, dir_port_str, self.or_port
        ));

        if let Some(ref contact) = self.contact {
            result.push_str(&format!("contact {}\n", contact));
        }

        if let Some(ref legacy_key) = self.legacy_dir_key {
            result.push_str(&format!("legacy-dir-key {}\n", legacy_key));
        }

        if self.is_shared_randomness_participate {
            result.push_str("shared-rand-participate\n");
        }

        for commitment in &self.shared_randomness_commitments {
            if let Some(ref reveal) = commitment.reveal {
                result.push_str(&format!(
                    "shared-rand-commit {} {} {} {} {}\n",
                    commitment.version,
                    commitment.algorithm,
                    commitment.identity,
                    commitment.commit,
                    reveal
                ));
            } else {
                result.push_str(&format!(
                    "shared-rand-commit {} {} {} {}\n",
                    commitment.version,
                    commitment.algorithm,
                    commitment.identity,
                    commitment.commit
                ));
            }
        }

        if let (Some(count), Some(ref value)) = (
            self.shared_randomness_previous_reveal_count,
            &self.shared_randomness_previous_value,
        ) {
            result.push_str(&format!("shared-rand-previous-value {} {}\n", count, value));
        }

        if let (Some(count), Some(ref value)) = (
            self.shared_randomness_current_reveal_count,
            &self.shared_randomness_current_value,
        ) {
            result.push_str(&format!("shared-rand-current-value {} {}\n", count, value));
        }

        if let Some(ref digest) = self.vote_digest {
            result.push_str(&format!("vote-digest {}\n", digest));
        }

        if let Some(ref cert) = self.key_certificate {
            result.push_str(&cert.to_descriptor_string());
        }

        result
    }
}

impl FromStr for DirectoryAuthority {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s, false)
    }
}

impl fmt::Display for DirectoryAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_descriptor_string())
    }
}

/// Validates that a string is a valid relay fingerprint.
///
/// A valid fingerprint consists of exactly 40 hexadecimal characters
/// (case-insensitive), representing a 160-bit SHA-1 hash.
fn is_valid_fingerprint(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validates that a string is a valid relay nickname.
///
/// A valid nickname is 1-19 characters consisting of alphanumeric
/// characters, underscores, or hyphens.
fn is_valid_nickname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 19
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Parses a shared randomness commitment from its string representation.
///
/// Format: `version algorithm identity commit [reveal]`
fn parse_shared_rand_commit(value: &str) -> Option<SharedRandomnessCommitment> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() >= 4 {
        Some(SharedRandomnessCommitment {
            version: parts[0].parse().ok()?,
            algorithm: parts[1].to_string(),
            identity: parts[2].to_string(),
            commit: parts[3].to_string(),
            reveal: parts.get(4).map(|s| s.to_string()),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR_SOURCE_LINE: &str =
        "turtles 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090";

    const MINIMAL_CONSENSUS_AUTHORITY: &str = r#"dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090
contact Mike Perry <email>
vote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956
"#;

    const LEGACY_AUTHORITY: &str =
        "dir-source gabelmoo-legacy 81349FC1F2DBA2C2C11B45CB9706637D480AB913 131.188.40.189 131.188.40.189 80 443";

    const MINIMAL_KEY_CERT: &str = r#"dir-key-certificate-version 3
fingerprint BCB380A633592C218757BEE11E630511A485658A
dir-key-published 2017-05-25 04:45:52
dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-key-certification
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;

    #[test]
    fn test_minimal_consensus_authority() {
        let authority = DirectoryAuthority::parse(MINIMAL_CONSENSUS_AUTHORITY, false).unwrap();

        assert_eq!("Unnamed", authority.nickname);
        assert_eq!(40, authority.v3ident.len());
        assert_eq!("no.place.com", authority.hostname);
        assert_eq!(Some(9030), authority.dir_port);
        assert_eq!(9090, authority.or_port);
        assert!(!authority.is_legacy);
        assert_eq!(Some("Mike Perry <email>".to_string()), authority.contact);
        assert_eq!(40, authority.vote_digest.as_ref().unwrap().len());
        assert_eq!(None, authority.legacy_dir_key);
        assert_eq!(None, authority.key_certificate);
        assert!(authority.unrecognized_lines().is_empty());
    }

    #[test]
    fn test_minimal_vote_authority() {
        let content = format!(
            "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\ncontact Mike Perry <email>\n{}",
            MINIMAL_KEY_CERT
        );
        let authority = DirectoryAuthority::parse(&content, true).unwrap();

        assert_eq!("Unnamed", authority.nickname);
        assert_eq!(40, authority.v3ident.len());
        assert_eq!("no.place.com", authority.hostname);
        assert_eq!(Some(9030), authority.dir_port);
        assert_eq!(9090, authority.or_port);
        assert!(!authority.is_legacy);
        assert_eq!(Some("Mike Perry <email>".to_string()), authority.contact);
        assert_eq!(None, authority.vote_digest);
        assert_eq!(None, authority.legacy_dir_key);
        assert!(authority.key_certificate.is_some());
        assert!(authority.unrecognized_lines().is_empty());
    }

    #[test]
    fn test_unrecognized_line() {
        let content = "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\ncontact Mike Perry <email>\npepperjack is oh so tasty!\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n".to_string();
        let authority = DirectoryAuthority::parse(&content, false).unwrap();
        assert_eq!(
            vec!["pepperjack is oh so tasty!"],
            authority.unrecognized_lines()
        );
    }

    #[test]
    fn test_legacy_authority() {
        let authority = DirectoryAuthority::parse(LEGACY_AUTHORITY, false).unwrap();

        assert_eq!("gabelmoo-legacy", authority.nickname);
        assert_eq!(
            "81349FC1F2DBA2C2C11B45CB9706637D480AB913",
            authority.v3ident
        );
        assert_eq!("131.188.40.189", authority.hostname);
        assert_eq!(
            "131.188.40.189".parse::<IpAddr>().unwrap(),
            authority.address
        );
        assert_eq!(Some(80), authority.dir_port);
        assert_eq!(443, authority.or_port);
        assert!(authority.is_legacy);
        assert_eq!(None, authority.contact);
        assert_eq!(None, authority.vote_digest);
        assert_eq!(None, authority.legacy_dir_key);
        assert_eq!(None, authority.key_certificate);
        assert!(authority.unrecognized_lines().is_empty());
    }

    #[test]
    fn test_first_line_validation() {
        let content = format!("ho-hum 567\n{}", MINIMAL_CONSENSUS_AUTHORITY);
        let result = DirectoryAuthority::parse(&content, false);
        assert!(result.is_err());

        let authority = DirectoryAuthority::parse_with_validation(&content, false, false).unwrap();
        assert_eq!(vec!["ho-hum 567"], authority.unrecognized_lines());
    }

    #[test]
    fn test_missing_dir_source() {
        let content =
            "contact Mike Perry <email>\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n";
        let result = DirectoryAuthority::parse(content, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_contact() {
        let content = "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n";
        let result = DirectoryAuthority::parse(content, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_blank_lines() {
        let content = format!(
            "dir-source {} \n\n\ncontact Mike Perry <email>\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n",
            DIR_SOURCE_LINE.replace("dir-source ", "")
        );
        let authority = DirectoryAuthority::parse(&content, false).unwrap();
        assert_eq!(Some("Mike Perry <email>".to_string()), authority.contact);
    }

    #[test]
    fn test_missing_dir_source_field() {
        let content = "dir-source 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\ncontact test\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n";
        let result = DirectoryAuthority::parse(content, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_fingerprint() {
        let test_values = ["", "zzzzz", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"];

        for value in &test_values {
            let content = format!(
                "dir-source turtles {} no.place.com 76.73.17.194 9030 9090\ncontact test\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n",
                value
            );
            let result = DirectoryAuthority::parse(&content, false);
            assert!(result.is_err(), "Expected error for fingerprint: {}", value);

            let authority =
                DirectoryAuthority::parse_with_validation(&content, false, false).unwrap();
            assert!(authority.v3ident.is_empty() || authority.v3ident == *value);
        }
    }

    #[test]
    fn test_malformed_address() {
        let test_values = [
            "",
            "71.35.150.",
            "71.35..29",
            "71.35.150",
            "71.35.150.256",
            "[fd9f:2e19:3bcf::02:9970]",
        ];

        for value in &test_values {
            let content = format!(
                "dir-source turtles 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com {} 9030 9090\ncontact test\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n",
                value
            );
            let result = DirectoryAuthority::parse(&content, false);
            assert!(result.is_err(), "Expected error for address: {}", value);
        }
    }

    #[test]
    fn test_malformed_port() {
        let test_values = ["", "-1", "399482", "blarg"];

        for value in &test_values {
            let content = format!(
                "dir-source turtles 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 {}\ncontact test\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n",
                value
            );
            let result = DirectoryAuthority::parse(&content, false);
            assert!(result.is_err(), "Expected error for or_port: {}", value);

            let content = format!(
                "dir-source turtles 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 {} 9090\ncontact test\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n",
                value
            );
            let result = DirectoryAuthority::parse(&content, false);
            assert!(result.is_err(), "Expected error for dir_port: {}", value);
        }
    }

    #[test]
    fn test_legacy_dir_key() {
        let test_value = "65968CCB6BECB5AA88459C5A072624C6995B6B72";
        let content = format!(
            "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\ncontact Mike Perry <email>\nlegacy-dir-key {}\n{}",
            test_value, MINIMAL_KEY_CERT
        );
        let authority = DirectoryAuthority::parse(&content, true).unwrap();
        assert_eq!(Some(test_value.to_string()), authority.legacy_dir_key);

        let content = format!(
            "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\ncontact Mike Perry <email>\nlegacy-dir-key {}\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n",
            test_value
        );
        let result = DirectoryAuthority::parse(&content, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_legacy_dir_key() {
        let test_values = ["", "zzzzz", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"];

        for value in &test_values {
            let content = format!(
                "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\ncontact Mike Perry <email>\nlegacy-dir-key {}\n{}",
                value, MINIMAL_KEY_CERT
            );
            let result = DirectoryAuthority::parse(&content, true);
            assert!(
                result.is_err(),
                "Expected error for legacy-dir-key: {}",
                value
            );
        }
    }

    #[test]
    fn test_key_certificate_in_consensus() {
        let content = format!(
            "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\ncontact Mike Perry <email>\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n{}",
            MINIMAL_KEY_CERT
        );
        let result = DirectoryAuthority::parse(&content, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_key_certificate_in_vote() {
        let content = "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\ncontact Mike Perry <email>\n";
        let result = DirectoryAuthority::parse(content, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_vote_digest_in_vote() {
        let content = format!(
            "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090\ncontact Mike Perry <email>\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n{}",
            MINIMAL_KEY_CERT
        );
        let result = DirectoryAuthority::parse(&content, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_dir_port_zero() {
        let content = "dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 0 9090\ncontact Mike Perry <email>\nvote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956\n";
        let authority = DirectoryAuthority::parse(content, false).unwrap();
        assert_eq!(None, authority.dir_port);
    }

    #[test]
    fn test_shared_randomness() {
        let content = r#"dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090
contact Mike Perry <email>
shared-rand-participate
shared-rand-commit 1 sha3-256 27B6B5996C426270A5C95488AA5BCEB6BCC86956 AAAA
shared-rand-previous-value 5 BBBB
shared-rand-current-value 3 CCCC
vote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956
"#;
        let authority = DirectoryAuthority::parse(content, false).unwrap();

        assert!(authority.is_shared_randomness_participate);
        assert_eq!(1, authority.shared_randomness_commitments.len());
        let commitment = &authority.shared_randomness_commitments[0];
        assert_eq!(1, commitment.version);
        assert_eq!("sha3-256", commitment.algorithm);
        assert_eq!(
            "27B6B5996C426270A5C95488AA5BCEB6BCC86956",
            commitment.identity
        );
        assert_eq!("AAAA", commitment.commit);
        assert_eq!(None, commitment.reveal);

        assert_eq!(Some(5), authority.shared_randomness_previous_reveal_count);
        assert_eq!(
            Some("BBBB".to_string()),
            authority.shared_randomness_previous_value
        );
        assert_eq!(Some(3), authority.shared_randomness_current_reveal_count);
        assert_eq!(
            Some("CCCC".to_string()),
            authority.shared_randomness_current_value
        );
    }

    #[test]
    fn test_shared_rand_commit_with_reveal() {
        let content = r#"dir-source Unnamed 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090
contact Mike Perry <email>
shared-rand-commit 1 sha3-256 27B6B5996C426270A5C95488AA5BCEB6BCC86956 AAAA REVEAL
vote-digest 27B6B5996C426270A5C95488AA5BCEB6BCC86956
"#;
        let authority = DirectoryAuthority::parse(content, false).unwrap();

        assert_eq!(1, authority.shared_randomness_commitments.len());
        let commitment = &authority.shared_randomness_commitments[0];
        assert_eq!(Some("REVEAL".to_string()), commitment.reveal);
    }

    #[test]
    fn test_to_descriptor_string() {
        let authority = DirectoryAuthority::parse(MINIMAL_CONSENSUS_AUTHORITY, false).unwrap();
        let output = authority.to_descriptor_string();

        assert!(output.contains("dir-source Unnamed"));
        assert!(output.contains("27B6B5996C426270A5C95488AA5BCEB6BCC86956"));
        assert!(output.contains("no.place.com"));
        assert!(output.contains("76.73.17.194"));
        assert!(output.contains("9030"));
        assert!(output.contains("9090"));
        assert!(output.contains("contact Mike Perry <email>"));
        assert!(output.contains("vote-digest"));
    }

    #[test]
    fn test_from_str() {
        let authority: DirectoryAuthority = MINIMAL_CONSENSUS_AUTHORITY.parse().unwrap();
        assert_eq!("Unnamed", authority.nickname);
    }

    #[test]
    fn test_display() {
        let authority = DirectoryAuthority::parse(MINIMAL_CONSENSUS_AUTHORITY, false).unwrap();
        let display = format!("{}", authority);
        assert!(display.contains("dir-source Unnamed"));
    }
}
