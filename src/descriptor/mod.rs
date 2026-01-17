//! Descriptor parsing for Tor network documents.
//!
//! This module provides types for parsing various Tor descriptor formats
//! including server descriptors, microdescriptors, consensus documents,
//! and hidden service descriptors.
//!
//! # Overview
//!
//! Tor relays and directory authorities publish various types of descriptors
//! that describe the network topology, relay capabilities, and routing
//! information. This module provides parsers for all major descriptor types:
//!
//! - [`ServerDescriptor`] - Full relay metadata including keys, policies, and capabilities
//! - [`Microdescriptor`] - Compact client-side descriptors with essential routing info
//! - [`NetworkStatusDocument`] - Consensus documents listing all relays and their status
//! - [`ExtraInfoDescriptor`] - Bandwidth statistics and additional relay information
//! - [`HiddenServiceDescriptorV2`] / [`HiddenServiceDescriptorV3`] - Onion service descriptors
//! - [`Ed25519Certificate`] - Ed25519 certificates used by relays
//! - [`KeyCertificate`] - Directory authority key certificates
//! - [`BandwidthFile`] - Bandwidth authority measurement files
//! - [`TorDNSEL`] - Exit list data from TorDNSEL
//!
//! # Descriptor Sources
//!
//! Descriptors can be obtained from several sources:
//!
//! - **Tor's data directory**: Cached files like `cached-descriptors`, `cached-consensus`
//! - **Directory authorities**: Via the [`remote`] module's download functions
//! - **CollecTor archives**: Historical descriptors with `@type` annotations
//!
//! # Type Annotations
//!
//! Descriptors from [CollecTor](https://metrics.torproject.org/collector.html) include
//! a type annotation on the first line in the format `@type <name> <major>.<minor>`.
//! The [`TypeAnnotation`] struct parses these annotations, and [`parse_file`] handles
//! them automatically.
//!
//! # Compression
//!
//! Downloaded descriptors are often compressed. This module supports automatic
//! decompression via [`auto_decompress`] for:
//!
//! - **Plaintext** - Uncompressed data
//! - **Gzip** - Standard gzip compression (fully supported)
//! - **Zstd** - Zstandard compression (detection only, requires external crate)
//! - **LZMA** - LZMA/XZ compression (detection only, requires external crate)
//!
//! # Digests
//!
//! Descriptors have cryptographic digests used for identification and verification.
//! The [`compute_digest`] function and [`Descriptor::digest`] method support:
//!
//! - [`DigestHash::Sha1`] - SHA-1 hash (legacy, used by older descriptors)
//! - [`DigestHash::Sha256`] - SHA-256 hash (modern descriptors)
//!
//! With encodings:
//!
//! - [`DigestEncoding::Raw`] - Raw bytes as characters
//! - [`DigestEncoding::Hex`] - Uppercase hexadecimal
//! - [`DigestEncoding::Base64`] - Base64 without padding
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::descriptor::{parse_file, ServerDescriptor, Descriptor};
//! use stem_rs::descriptor::{DigestHash, DigestEncoding};
//!
//! // Parse a server descriptor from file contents
//! let content = std::fs::read("cached-descriptors").unwrap();
//! let descriptor: ServerDescriptor = parse_file(&content).unwrap();
//!
//! // Access descriptor fields
//! println!("Nickname: {}", descriptor.nickname);
//! println!("Address: {}", descriptor.address);
//!
//! // Compute the descriptor's digest
//! let digest = descriptor.digest(DigestHash::Sha1, DigestEncoding::Hex).unwrap();
//! println!("Digest: {}", digest);
//! ```
//!
//! # See Also
//!
//! - [`remote`] - Download descriptors from directory authorities
//! - [`server`] - Server descriptor parsing
//! - [`micro`] - Microdescriptor parsing
//! - [`consensus`] - Network status document parsing
//! - [`hidden`] - Hidden service descriptor parsing
//!
//! # See Also
//!
//! - [Tor Directory Protocol Specification](https://spec.torproject.org/dir-spec)
//! - [Python Stem descriptor module](https://stem.torproject.org/api/descriptor/descriptor.html)

pub mod authority;
pub mod bandwidth_file;
pub mod cache;
pub mod certificate;
pub mod consensus;
pub mod extra_info;
pub mod hidden;
pub mod key_cert;
pub mod micro;
pub mod remote;
pub mod router_status;
pub mod server;
pub mod tordnsel;

pub use authority::{DirectoryAuthority, SharedRandomnessCommitment};
pub use bandwidth_file::{BandwidthFile, BandwidthMeasurement, RecentStats, RelayFailures};
pub use cache::{CacheStats, DescriptorCache};
pub use certificate::{
    Ed25519Certificate, Ed25519Extension, ExtensionFlag, ExtensionType, ED25519_HEADER_LENGTH,
    ED25519_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
};
pub use consensus::{
    DocumentSignature, NetworkStatusDocument, NetworkStatusDocumentBuilder, SharedRandomness,
};
pub use extra_info::{
    BandwidthHistory, DirResponse, DirStat, ExtraInfoDescriptor, ExtraInfoDescriptorBuilder,
    PortKey, Transport,
};
pub use hidden::{
    AuthorizedClient, HiddenServiceDescriptorV2, HiddenServiceDescriptorV3, InnerLayer,
    IntroductionPointV2, IntroductionPointV3, LinkSpecifier, OuterLayer,
};
pub use key_cert::KeyCertificate;
pub use micro::{Microdescriptor, MicrodescriptorBuilder};
pub use remote::{
    download_bandwidth_file, download_consensus, download_detached_signatures,
    download_extrainfo_descriptors, download_from_dirport, download_key_certificates,
    download_microdescriptors, download_server_descriptors, get_authorities, Compression, DirPort,
    DownloadResult,
};
pub use router_status::{MicrodescriptorHash, RouterStatusEntry, RouterStatusEntryType};
pub use server::{ServerDescriptor, ServerDescriptorBuilder};
pub use tordnsel::{parse_exit_list, parse_exit_list_bytes, TorDNSEL};

use crate::Error;
use flate2::read::GzDecoder;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use std::io::Read;
use std::path::Path;
use thiserror::Error as ThisError;

/// Errors that can occur when parsing network status consensus documents.
///
/// This error type provides specific information about what went wrong during
/// consensus parsing, making it easier to diagnose and fix issues with malformed
/// consensus documents.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::ConsensusError;
///
/// fn handle_consensus_error(err: ConsensusError) {
///     match err {
///         ConsensusError::InvalidFingerprint(fp) => {
///             eprintln!("Invalid relay fingerprint: {}", fp);
///         }
///         ConsensusError::TimestampOrderingViolation(msg) => {
///             eprintln!("Timestamp ordering issue: {}", msg);
///         }
///         _ => eprintln!("Consensus parse error: {}", err),
///     }
/// }
/// ```
#[derive(Debug, ThisError)]
pub enum ConsensusError {
    /// IO error occurred while reading consensus data.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Network status version is not supported.
    #[error("Invalid network status version: expected 3, got {0}")]
    InvalidNetworkStatusVersion(String),

    /// Vote status field has invalid value.
    #[error("Invalid vote status: expected 'vote' or 'consensus', got {0}")]
    InvalidVoteStatus(String),

    /// Timestamp format is invalid or unparseable.
    #[error("Invalid timestamp format: {0}")]
    InvalidTimestamp(String),

    /// Voting delay line has wrong number of values.
    #[error("Invalid voting delay: expected 2 values, got {0}")]
    InvalidVotingDelay(String),

    /// Relay fingerprint format is invalid.
    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    /// IP address format is invalid.
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(#[from] std::net::AddrParseError),

    /// Port number is invalid or out of range.
    #[error("Invalid port number: {0}")]
    InvalidPort(#[from] std::num::ParseIntError),

    /// Bandwidth value is invalid or unparseable.
    #[error("Invalid bandwidth value: {0}")]
    InvalidBandwidth(String),

    /// Relay flag is not recognized.
    #[error("Invalid flag: {0}")]
    InvalidFlag(String),

    /// Protocol version string is malformed.
    #[error("Invalid protocol version: {0}")]
    InvalidProtocolVersion(String),

    /// Base64 encoding is invalid.
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    /// Cryptographic signature is invalid.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Required field is missing from consensus.
    #[error("Missing required field: {0}")]
    MissingRequiredField(String),

    /// Timestamps are not in correct order (valid-after < fresh-until < valid-until).
    #[error("Timestamp ordering violation: {0}")]
    TimestampOrderingViolation(String),

    /// Line format is invalid at specific location.
    #[error("Invalid line format at line {line}: {reason}")]
    InvalidLineFormat {
        /// Line number where error occurred.
        line: usize,
        /// Description of the format error.
        reason: String,
    },
}

/// Errors that can occur when parsing server descriptors.
///
/// Server descriptors contain full relay metadata including identity keys,
/// exit policies, bandwidth information, and platform details.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::ServerDescriptorError;
///
/// fn handle_server_error(err: ServerDescriptorError) {
///     match err {
///         ServerDescriptorError::InvalidNickname(nick) => {
///             eprintln!("Invalid relay nickname: {}", nick);
///         }
///         ServerDescriptorError::MissingRequiredField(field) => {
///             eprintln!("Missing required field: {}", field);
///         }
///         _ => eprintln!("Server descriptor parse error: {}", err),
///     }
/// }
/// ```
#[derive(Debug, ThisError)]
pub enum ServerDescriptorError {
    /// IO error occurred while reading descriptor data.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Router line has wrong number of components.
    #[error("Invalid router line format: expected 5 parts, got {actual}")]
    InvalidRouterFormat {
        /// Actual number of parts found.
        actual: usize,
    },

    /// Relay nickname is invalid (must be 1-19 alphanumeric characters).
    #[error("Invalid nickname: {0}")]
    InvalidNickname(String),

    /// IP address format is invalid.
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(#[from] std::net::AddrParseError),

    /// Port number is invalid or out of range.
    #[error("Invalid port number: {0}")]
    InvalidPort(#[from] std::num::ParseIntError),

    /// Bandwidth line has wrong number of values.
    #[error("Invalid bandwidth line format: expected 3 parts, got {actual}")]
    InvalidBandwidthFormat {
        /// Actual number of parts found.
        actual: usize,
    },

    /// Bandwidth value is invalid or unparseable.
    #[error("Invalid bandwidth value: {0}")]
    InvalidBandwidth(String),

    /// Published date format is invalid.
    #[error("Invalid published date format: {0}")]
    InvalidPublishedDate(String),

    /// Fingerprint format is invalid (must be 40 hex characters).
    #[error("Invalid fingerprint format: {0}")]
    InvalidFingerprint(String),

    /// RSA public key is malformed or invalid.
    #[error("Invalid RSA public key: {0}")]
    InvalidRsaKey(String),

    /// Ed25519 identity key is invalid.
    #[error("Invalid Ed25519 identity: {0}")]
    InvalidEd25519Identity(String),

    /// Exit policy format is invalid.
    #[error("Invalid exit policy format: {0}")]
    InvalidExitPolicy(String),

    /// Protocol version string is malformed.
    #[error("Invalid protocol version: {0}")]
    InvalidProtocolVersion(String),

    /// Required field is missing from descriptor.
    #[error("Missing required field: {0}")]
    MissingRequiredField(String),

    /// Line format is invalid at specific location.
    #[error("Invalid line format at line {line}: {reason}")]
    InvalidLineFormat {
        /// Line number where error occurred.
        line: usize,
        /// Description of the format error.
        reason: String,
    },
}

/// Errors that can occur when parsing microdescriptors.
///
/// Microdescriptors are compact descriptors used by clients for building
/// circuits with minimal bandwidth overhead.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::MicrodescriptorError;
///
/// fn handle_micro_error(err: MicrodescriptorError) {
///     match err {
///         MicrodescriptorError::InvalidOnionKey(msg) => {
///             eprintln!("Invalid onion key: {}", msg);
///         }
///         MicrodescriptorError::MissingRequiredField(field) => {
///             eprintln!("Missing required field: {}", field);
///         }
///         _ => eprintln!("Microdescriptor parse error: {}", err),
///     }
/// }
/// ```
#[derive(Debug, ThisError)]
pub enum MicrodescriptorError {
    /// IO error occurred while reading descriptor data.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Onion key format is invalid.
    #[error("Invalid onion key format: {0}")]
    InvalidOnionKey(String),

    /// Ntor onion key format is invalid.
    #[error("Invalid ntor onion key format: {0}")]
    InvalidNtorOnionKey(String),

    /// Socket address format is invalid.
    #[error("Invalid socket address: {0}")]
    InvalidSocketAddress(#[from] std::net::AddrParseError),

    /// Relay family specification is invalid.
    #[error("Invalid relay family: {0}")]
    InvalidRelayFamily(String),

    /// Port policy format is invalid.
    #[error("Invalid port policy: {0}")]
    InvalidPortPolicy(String),

    /// Base64 encoding is invalid.
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    /// Identity key has wrong length for algorithm.
    #[error("Invalid identity length for {algorithm}: expected {expected}, got {actual}")]
    InvalidIdentityLength {
        /// Algorithm name (e.g., "ed25519").
        algorithm: String,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length found.
        actual: usize,
    },

    /// Identity algorithm is not recognized.
    #[error("Unknown identity algorithm: {0}")]
    UnknownIdentityAlgorithm(String),

    /// Cryptographic block is incomplete.
    #[error("Incomplete crypto block for key type: {0}")]
    IncompleteCryptoBlock(String),

    /// Required field is missing from descriptor.
    #[error("Missing required field: {0}")]
    MissingRequiredField(String),
}

/// Errors that can occur when parsing extra-info descriptors.
///
/// Extra-info descriptors contain bandwidth statistics and additional
/// relay information not included in server descriptors.
#[derive(Debug, ThisError)]
pub enum ExtraInfoError {
    /// IO error occurred while reading descriptor data.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Extra-info line has wrong number of components.
    #[error("Invalid extra-info line format: expected 3 parts, got {actual}")]
    InvalidExtraInfoFormat {
        /// Actual number of parts found.
        actual: usize,
    },

    /// Relay nickname is invalid.
    #[error("Invalid nickname: {0}")]
    InvalidNickname(String),

    /// Fingerprint format is invalid.
    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    /// Published date format is invalid.
    #[error("Invalid published date format: {0}")]
    InvalidPublishedDate(String),

    /// Bandwidth history format is invalid.
    #[error("Invalid bandwidth history format: {0}")]
    InvalidBandwidthHistory(String),

    /// Timestamp format is invalid.
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// Required field is missing from descriptor.
    #[error("Missing required field: {0}")]
    MissingRequiredField(String),
}

/// Errors that can occur when parsing hidden service descriptors.
///
/// Hidden service descriptors (v2 and v3) contain information needed
/// to connect to onion services.
#[derive(Debug, ThisError)]
pub enum HiddenServiceDescriptorError {
    /// IO error occurred while reading descriptor data.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Descriptor version is not supported.
    #[error("Invalid descriptor version: expected 2 or 3, got {0}")]
    InvalidDescriptorVersion(u32),

    /// Onion address format is invalid.
    #[error("Invalid onion address: {0}")]
    InvalidOnionAddress(String),

    /// Introduction point specification is invalid.
    #[error("Invalid introduction point: {0}")]
    InvalidIntroductionPoint(String),

    /// Encryption key is malformed.
    #[error("Invalid encryption key: {0}")]
    InvalidEncryptionKey(String),

    /// Cryptographic signature is invalid.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Base64 encoding is invalid.
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    /// Required field is missing from descriptor.
    #[error("Missing required field: {0}")]
    MissingRequiredField(String),
}

/// Errors that can occur when parsing directory key certificates.
///
/// Key certificates bind directory authority signing keys to their
/// long-term identity keys.
#[derive(Debug, ThisError)]
pub enum KeyCertificateError {
    /// IO error occurred while reading certificate data.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Certificate version is not supported.
    #[error("Invalid certificate version: expected 3, got {0}")]
    InvalidCertificateVersion(u32),

    /// Fingerprint format is invalid.
    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    /// Timestamp format is invalid.
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// RSA key is malformed.
    #[error("Invalid RSA key: {0}")]
    InvalidRsaKey(String),

    /// Cryptographic signature is invalid.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Required field is missing from certificate.
    #[error("Missing required field: {0}")]
    MissingRequiredField(String),
}

/// Errors that can occur when parsing bandwidth measurement files.
///
/// Bandwidth files contain relay capacity measurements from bandwidth
/// authorities used to compute consensus weights.
#[derive(Debug, ThisError)]
pub enum BandwidthFileError {
    /// IO error occurred while reading bandwidth file.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Header format is invalid.
    #[error("Invalid header format: {0}")]
    InvalidHeaderFormat(String),

    /// Timestamp format is invalid.
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// Bandwidth value is invalid or unparseable.
    #[error("Invalid bandwidth value: {0}")]
    InvalidBandwidth(String),

    /// Fingerprint format is invalid.
    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    /// Required header field is missing.
    #[error("Missing required header field: {0}")]
    MissingRequiredHeaderField(String),
}

/// Errors that can occur when parsing TorDNSEL exit lists.
///
/// TorDNSEL exit lists contain IP addresses of Tor exit relays.
#[derive(Debug, ThisError)]
pub enum TorDNSELError {
    /// IO error occurred while reading exit list.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// IP address format is invalid.
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(#[from] std::net::AddrParseError),

    /// Timestamp format is invalid.
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// Exit address line format is invalid.
    #[error("Invalid exit address format: {0}")]
    InvalidExitAddressFormat(String),
}

/// Unified error type for all descriptor parsing operations.
///
/// This enum wraps all descriptor-specific error types, providing a single
/// error type that can represent failures from any descriptor parser.
///
/// # Design
///
/// Following the library-rs reference implementation, this uses transparent
/// error forwarding with `#[error(transparent)]` to preserve the underlying
/// error's Display implementation and source chain.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::DescriptorError;
///
/// fn handle_descriptor_error(err: DescriptorError) {
///     match err {
///         DescriptorError::Consensus(e) => {
///             eprintln!("Consensus error: {}", e);
///         }
///         DescriptorError::ServerDescriptor(e) => {
///             eprintln!("Server descriptor error: {}", e);
///         }
///         DescriptorError::UnsupportedCompression(format) => {
///             eprintln!("Unsupported compression: {}", format);
///         }
///         _ => eprintln!("Descriptor error: {}", err),
///     }
/// }
/// ```
#[derive(Debug, ThisError)]
pub enum DescriptorError {
    /// Error parsing network status consensus document.
    #[error(transparent)]
    Consensus(#[from] ConsensusError),

    /// Error parsing server descriptor.
    #[error(transparent)]
    ServerDescriptor(#[from] ServerDescriptorError),

    /// Error parsing microdescriptor.
    #[error(transparent)]
    Microdescriptor(#[from] MicrodescriptorError),

    /// Error parsing extra-info descriptor.
    #[error(transparent)]
    ExtraInfo(#[from] ExtraInfoError),

    /// Error parsing hidden service descriptor.
    #[error(transparent)]
    HiddenService(#[from] HiddenServiceDescriptorError),

    /// Error parsing directory key certificate.
    #[error(transparent)]
    KeyCertificate(#[from] KeyCertificateError),

    /// Error parsing bandwidth measurement file.
    #[error(transparent)]
    BandwidthFile(#[from] BandwidthFileError),

    /// Error parsing TorDNSEL exit list.
    #[error(transparent)]
    TorDNSEL(#[from] TorDNSELError),

    /// Compression format is not supported.
    #[error("Unsupported compression format: {0}")]
    UnsupportedCompression(String),

    /// Decompression failed.
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),

    /// Descriptor contains invalid UTF-8.
    #[error("Invalid UTF-8 in descriptor: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

/// A type annotation from CollecTor descriptor archives.
///
/// CollecTor archives include a type annotation on the first line of each
/// descriptor file in the format `@type <name> <major>.<minor>`. This struct
/// represents that parsed annotation.
///
/// # Format
///
/// ```text
/// @type server-descriptor 1.0
/// @type network-status-consensus-3 1.0
/// @type microdescriptor 1.0
/// ```
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::TypeAnnotation;
///
/// let annotation = TypeAnnotation::parse("@type server-descriptor 1.0").unwrap();
/// assert_eq!(annotation.name, "server-descriptor");
/// assert_eq!(annotation.major_version, 1);
/// assert_eq!(annotation.minor_version, 0);
///
/// // Convert back to string
/// assert_eq!(annotation.to_string(), "@type server-descriptor 1.0");
/// ```
///
/// # See Also
///
/// - [`DescriptorType`] - Enum of known descriptor types
/// - [`strip_type_annotation`] - Extract annotation from content
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAnnotation {
    /// The descriptor type name (e.g., "server-descriptor", "microdescriptor").
    pub name: String,
    /// The major version number.
    pub major_version: u32,
    /// The minor version number.
    pub minor_version: u32,
}

impl TypeAnnotation {
    /// Creates a new type annotation with the given name and version.
    ///
    /// # Arguments
    ///
    /// * `name` - The descriptor type name
    /// * `major_version` - The major version number
    /// * `minor_version` - The minor version number
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::TypeAnnotation;
    ///
    /// let annotation = TypeAnnotation::new("server-descriptor", 1, 0);
    /// assert_eq!(annotation.to_string(), "@type server-descriptor 1.0");
    /// ```
    pub fn new(name: impl Into<String>, major_version: u32, minor_version: u32) -> Self {
        Self {
            name: name.into(),
            major_version,
            minor_version,
        }
    }

    /// Parses a type annotation from a line of text.
    ///
    /// Returns `None` if the line is not a valid type annotation.
    ///
    /// # Arguments
    ///
    /// * `line` - The line to parse
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::TypeAnnotation;
    ///
    /// // Valid annotation
    /// let annotation = TypeAnnotation::parse("@type extra-info 1.0").unwrap();
    /// assert_eq!(annotation.name, "extra-info");
    ///
    /// // Invalid - not an annotation
    /// assert!(TypeAnnotation::parse("router test 127.0.0.1").is_none());
    ///
    /// // Invalid - missing version
    /// assert!(TypeAnnotation::parse("@type server-descriptor").is_none());
    /// ```
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if !line.starts_with("@type ") {
            return None;
        }

        let rest = &line[6..];
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() != 2 {
            return None;
        }

        let name = parts[0];
        let version_parts: Vec<&str> = parts[1].split('.').collect();
        if version_parts.len() != 2 {
            return None;
        }

        let major_version = version_parts[0].parse().ok()?;
        let minor_version = version_parts[1].parse().ok()?;

        Some(Self {
            name: name.to_string(),
            major_version,
            minor_version,
        })
    }
}

impl std::fmt::Display for TypeAnnotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "@type {} {}.{}",
            self.name, self.major_version, self.minor_version
        )
    }
}

/// Known descriptor types in the Tor network.
///
/// This enum represents all descriptor types that can be identified from
/// type annotations or filenames. Each variant corresponds to a specific
/// descriptor format defined in the Tor directory protocol specification.
///
/// # Stability
///
/// This enum is non-exhaustive. New descriptor types may be added in future
/// Tor versions.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::{DescriptorType, TypeAnnotation};
///
/// // From type annotation
/// let annotation = TypeAnnotation::new("server-descriptor", 1, 0);
/// let desc_type = DescriptorType::from_annotation(&annotation);
/// assert_eq!(desc_type, Some(DescriptorType::ServerDescriptor));
///
/// // From filename
/// let desc_type = DescriptorType::from_filename("cached-consensus");
/// assert_eq!(desc_type, Some(DescriptorType::NetworkStatusConsensusV3));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorType {
    /// Server descriptor containing full relay metadata.
    ///
    /// Includes identity keys, exit policy, bandwidth, and other relay information.
    /// Annotation name: `server-descriptor`
    ServerDescriptor,
    /// Extra-info descriptor with bandwidth statistics.
    ///
    /// Contains detailed statistics about relay operation.
    /// Annotation name: `extra-info`
    ExtraInfo,
    /// Microdescriptor with compact routing information.
    ///
    /// Used by clients for building circuits with minimal data.
    /// Annotation name: `microdescriptor`
    Microdescriptor,
    /// Network status consensus document (v3).
    ///
    /// The agreed-upon view of the network signed by directory authorities.
    /// Annotation name: `network-status-consensus-3`
    NetworkStatusConsensusV3,
    /// Network status vote document (v3).
    ///
    /// Individual directory authority's view before consensus.
    /// Annotation name: `network-status-vote-3`
    NetworkStatusVoteV3,
    /// Microdescriptor-flavored consensus document (v3).
    ///
    /// Consensus using microdescriptor hashes instead of full descriptors.
    /// Annotation name: `network-status-microdesc-consensus-3`
    NetworkStatusMicrodescConsensusV3,
    /// Bridge network status document.
    ///
    /// Network status for bridge relays (not publicly listed).
    /// Annotation name: `bridge-network-status`
    BridgeNetworkStatus,
    /// Bridge server descriptor.
    ///
    /// Server descriptor for bridge relays with some fields redacted.
    /// Annotation name: `bridge-server-descriptor`
    BridgeServerDescriptor,
    /// Bridge extra-info descriptor.
    ///
    /// Extra-info for bridge relays.
    /// Annotation name: `bridge-extra-info`
    BridgeExtraInfo,
    /// Directory key certificate (v3).
    ///
    /// Certificate binding a directory authority's signing key to its identity.
    /// Annotation name: `dir-key-certificate-3`
    DirKeyCertificateV3,
    /// TorDNSEL exit list.
    ///
    /// List of exit relay IP addresses from the TorDNSEL service.
    /// Annotation name: `tordnsel`
    TorDNSEL,
    /// Hidden service descriptor.
    ///
    /// Descriptor for onion services (v2 or v3).
    /// Annotation name: `hidden-service-descriptor`
    HiddenServiceDescriptor,
    /// Bandwidth authority measurement file.
    ///
    /// Bandwidth measurements from bandwidth authorities.
    /// Annotation name: `bandwidth-file`
    BandwidthFile,
}

impl DescriptorType {
    /// Returns the annotation name for this descriptor type.
    ///
    /// This is the name used in `@type` annotations in CollecTor archives.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::DescriptorType;
    ///
    /// assert_eq!(DescriptorType::ServerDescriptor.annotation_name(), "server-descriptor");
    /// assert_eq!(DescriptorType::Microdescriptor.annotation_name(), "microdescriptor");
    /// ```
    pub fn annotation_name(&self) -> &'static str {
        match self {
            Self::ServerDescriptor => "server-descriptor",
            Self::ExtraInfo => "extra-info",
            Self::Microdescriptor => "microdescriptor",
            Self::NetworkStatusConsensusV3 => "network-status-consensus-3",
            Self::NetworkStatusVoteV3 => "network-status-vote-3",
            Self::NetworkStatusMicrodescConsensusV3 => "network-status-microdesc-consensus-3",
            Self::BridgeNetworkStatus => "bridge-network-status",
            Self::BridgeServerDescriptor => "bridge-server-descriptor",
            Self::BridgeExtraInfo => "bridge-extra-info",
            Self::DirKeyCertificateV3 => "dir-key-certificate-3",
            Self::TorDNSEL => "tordnsel",
            Self::HiddenServiceDescriptor => "hidden-service-descriptor",
            Self::BandwidthFile => "bandwidth-file",
        }
    }

    /// Determines the descriptor type from a type annotation.
    ///
    /// Returns `None` if the annotation name is not recognized.
    ///
    /// # Arguments
    ///
    /// * `annotation` - The type annotation to match
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::{DescriptorType, TypeAnnotation};
    ///
    /// let annotation = TypeAnnotation::new("extra-info", 1, 0);
    /// assert_eq!(
    ///     DescriptorType::from_annotation(&annotation),
    ///     Some(DescriptorType::ExtraInfo)
    /// );
    ///
    /// let unknown = TypeAnnotation::new("unknown-type", 1, 0);
    /// assert_eq!(DescriptorType::from_annotation(&unknown), None);
    /// ```
    pub fn from_annotation(annotation: &TypeAnnotation) -> Option<Self> {
        match annotation.name.as_str() {
            "server-descriptor" => Some(Self::ServerDescriptor),
            "extra-info" => Some(Self::ExtraInfo),
            "microdescriptor" => Some(Self::Microdescriptor),
            "network-status-consensus-3" => Some(Self::NetworkStatusConsensusV3),
            "network-status-vote-3" => Some(Self::NetworkStatusVoteV3),
            "network-status-microdesc-consensus-3" => Some(Self::NetworkStatusMicrodescConsensusV3),
            "bridge-network-status" => Some(Self::BridgeNetworkStatus),
            "bridge-server-descriptor" => Some(Self::BridgeServerDescriptor),
            "bridge-extra-info" => Some(Self::BridgeExtraInfo),
            "dir-key-certificate-3" => Some(Self::DirKeyCertificateV3),
            "tordnsel" => Some(Self::TorDNSEL),
            "hidden-service-descriptor" => Some(Self::HiddenServiceDescriptor),
            "bandwidth-file" => Some(Self::BandwidthFile),
            _ => None,
        }
    }

    /// Determines the descriptor type from a filename.
    ///
    /// This is useful for parsing descriptors from Tor's data directory
    /// where files have conventional names like `cached-descriptors` or
    /// `cached-consensus`.
    ///
    /// Returns `None` if the filename doesn't match a known pattern.
    ///
    /// # Arguments
    ///
    /// * `filename` - The filename to match (path components are stripped)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::DescriptorType;
    ///
    /// assert_eq!(
    ///     DescriptorType::from_filename("cached-descriptors"),
    ///     Some(DescriptorType::ServerDescriptor)
    /// );
    /// assert_eq!(
    ///     DescriptorType::from_filename("cached-extrainfo"),
    ///     Some(DescriptorType::ExtraInfo)
    /// );
    /// assert_eq!(
    ///     DescriptorType::from_filename("/var/lib/tor/cached-consensus"),
    ///     Some(DescriptorType::NetworkStatusConsensusV3)
    /// );
    /// assert_eq!(DescriptorType::from_filename("unknown-file"), None);
    /// ```
    pub fn from_filename(filename: &str) -> Option<Self> {
        let filename = Path::new(filename)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(filename);

        if filename.contains("cached-consensus") || filename.contains("consensus") {
            Some(Self::NetworkStatusConsensusV3)
        } else if filename.contains("cached-microdesc-consensus") {
            Some(Self::NetworkStatusMicrodescConsensusV3)
        } else if filename.contains("cached-microdescs") || filename.contains("microdescriptor") {
            Some(Self::Microdescriptor)
        } else if filename.contains("cached-descriptors") || filename.contains("server-descriptor")
        {
            Some(Self::ServerDescriptor)
        } else if filename.contains("cached-extrainfo") || filename.contains("extra-info") {
            Some(Self::ExtraInfo)
        } else if filename.contains("exit-list") || filename.contains("tordnsel") {
            Some(Self::TorDNSEL)
        } else if filename.contains("bandwidth") {
            Some(Self::BandwidthFile)
        } else {
            None
        }
    }
}

/// Hash algorithm used for computing descriptor digests.
///
/// Tor uses cryptographic hashes to identify and verify descriptors.
/// Older descriptor types use SHA-1, while newer ones use SHA-256.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::{compute_digest, DigestHash, DigestEncoding};
///
/// let content = b"example content";
/// let sha1_digest = compute_digest(content, DigestHash::Sha1, DigestEncoding::Hex);
/// let sha256_digest = compute_digest(content, DigestHash::Sha256, DigestEncoding::Hex);
///
/// assert_eq!(sha1_digest.len(), 40);  // SHA-1 produces 20 bytes = 40 hex chars
/// assert_eq!(sha256_digest.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestHash {
    /// SHA-1 hash algorithm (160 bits / 20 bytes).
    ///
    /// Used by legacy descriptor types including server descriptors and
    /// v2 hidden service descriptors. While SHA-1 is considered weak for
    /// collision resistance, it remains in use for backward compatibility.
    Sha1,
    /// SHA-256 hash algorithm (256 bits / 32 bytes).
    ///
    /// Used by modern descriptor types including microdescriptors and
    /// v3 hidden service descriptors.
    Sha256,
}

/// Encoding format for descriptor digests.
///
/// Digests can be represented in different formats depending on the use case.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::{compute_digest, DigestHash, DigestEncoding};
///
/// let content = b"test";
///
/// // Hexadecimal encoding (uppercase)
/// let hex = compute_digest(content, DigestHash::Sha1, DigestEncoding::Hex);
/// assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
///
/// // Base64 encoding (without padding)
/// let b64 = compute_digest(content, DigestHash::Sha1, DigestEncoding::Base64);
/// assert!(b64.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestEncoding {
    /// Raw bytes represented as characters.
    ///
    /// Each byte is converted directly to a char. This is primarily useful
    /// for internal processing rather than display.
    Raw,
    /// Uppercase hexadecimal encoding.
    ///
    /// Each byte becomes two hex characters (0-9, A-F).
    /// This is the most common format for displaying fingerprints.
    Hex,
    /// Base64 encoding without trailing padding.
    ///
    /// Uses the standard Base64 alphabet (A-Z, a-z, 0-9, +, /).
    /// Padding characters ('=') are omitted.
    Base64,
}

/// Trait for parsing and serializing Tor descriptors.
///
/// This trait defines the common interface for all descriptor types in the
/// library. Implementors can parse descriptor content, serialize back to
/// the canonical string format, and compute cryptographic digests.
///
/// # Contract
///
/// Implementations must satisfy these invariants:
///
/// 1. **Round-trip consistency**: For any valid descriptor content,
///    `parse(content).to_descriptor_string()` should produce semantically
///    equivalent content (though whitespace may differ).
///
/// 2. **Digest stability**: The `digest()` method must return consistent
///    results for the same descriptor content.
///
/// 3. **Error handling**: `parse()` should return `Error::Parse` for
///    malformed content with a descriptive error message.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::descriptor::{Descriptor, DigestHash, DigestEncoding};
/// use stem_rs::descriptor::ServerDescriptor;
///
/// let content = "router example 127.0.0.1 9001 0 0\n...";
/// let descriptor = ServerDescriptor::parse(content).unwrap();
///
/// // Serialize back to string
/// let serialized = descriptor.to_descriptor_string();
///
/// // Compute digest
/// let digest = descriptor.digest(DigestHash::Sha1, DigestEncoding::Hex).unwrap();
///
/// // Access raw content
/// let raw = descriptor.raw_content();
///
/// // Check for unrecognized lines
/// let unknown = descriptor.unrecognized_lines();
/// ```
///
/// # Implementors
///
/// - [`ServerDescriptor`] - Server descriptors
/// - [`Microdescriptor`] - Microdescriptors
/// - [`ExtraInfoDescriptor`] - Extra-info descriptors
/// - [`NetworkStatusDocument`] - Consensus documents
pub trait Descriptor: Sized {
    /// Parses a descriptor from its string content.
    ///
    /// # Arguments
    ///
    /// * `content` - The descriptor content as a string
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if the content is malformed or missing
    /// required fields.
    fn parse(content: &str) -> Result<Self, Error>;

    /// Serializes the descriptor to its canonical string format.
    ///
    /// The output should be valid descriptor content that can be parsed
    /// again with `parse()`.
    fn to_descriptor_string(&self) -> String;

    /// Computes the cryptographic digest of the descriptor.
    ///
    /// The digest is computed over the appropriate portion of the descriptor
    /// content (which varies by descriptor type).
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash algorithm to use
    /// * `encoding` - The output encoding format
    ///
    /// # Errors
    ///
    /// Returns an error if the digest cannot be computed (e.g., if the
    /// descriptor content is invalid).
    fn digest(&self, hash: DigestHash, encoding: DigestEncoding) -> Result<String, Error>;

    /// Returns the raw bytes of the original descriptor content.
    ///
    /// This is the exact content that was parsed, preserving original
    /// formatting and whitespace.
    fn raw_content(&self) -> &[u8];

    /// Returns lines from the descriptor that were not recognized.
    ///
    /// These are lines that don't match any known keyword for this
    /// descriptor type. This is useful for forward compatibility when
    /// new fields are added to the descriptor format.
    fn unrecognized_lines(&self) -> &[String];
}

/// Detects the compression format of binary content.
///
/// Examines the magic bytes at the start of the content to determine
/// the compression format. This is useful for automatically decompressing
/// downloaded descriptors.
///
/// # Arguments
///
/// * `content` - The binary content to examine
///
/// # Returns
///
/// The detected [`Compression`] format, or [`Compression::Plaintext`] if
/// no compression is detected or the content is too short.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::{detect_compression, Compression};
///
/// // Gzip magic bytes
/// let gzip_content = &[0x1f, 0x8b, 0x08, 0x00];
/// assert_eq!(detect_compression(gzip_content), Compression::Gzip);
///
/// // Plain text
/// let plain = b"router example";
/// assert_eq!(detect_compression(plain), Compression::Plaintext);
/// ```
pub fn detect_compression(content: &[u8]) -> Compression {
    if content.len() < 2 {
        return Compression::Plaintext;
    }

    if content[0] == 0x1f && content[1] == 0x8b {
        return Compression::Gzip;
    }

    if content.len() >= 4
        && content[0] == 0x28
        && content[1] == 0xb5
        && content[2] == 0x2f
        && content[3] == 0xfd
    {
        return Compression::Zstd;
    }

    if content.len() >= 6
        && content[0] == 0xfd
        && content[1] == 0x37
        && content[2] == 0x7a
        && content[3] == 0x58
        && content[4] == 0x5a
        && content[5] == 0x00
    {
        return Compression::Lzma;
    }

    Compression::Plaintext
}

/// Decompresses content using the specified compression format.
///
/// # Arguments
///
/// * `content` - The compressed content
/// * `compression` - The compression format to use
///
/// # Returns
///
/// The decompressed content as a byte vector.
///
/// # Errors
///
/// Returns [`Error::Parse`] if:
/// - Decompression fails (corrupted data)
/// - The compression format is not supported (Zstd, LZMA)
///
/// # Supported Formats
///
/// - [`Compression::Plaintext`] - Returns content unchanged
/// - [`Compression::Gzip`] - Full support via flate2
/// - [`Compression::Zstd`] - Detection only, returns error
/// - [`Compression::Lzma`] - Detection only, returns error
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::{decompress, Compression};
///
/// // Plaintext passes through unchanged
/// let content = b"Hello, World!";
/// let result = decompress(content, Compression::Plaintext).unwrap();
/// assert_eq!(result, content);
/// ```
pub fn decompress(content: &[u8], compression: Compression) -> Result<Vec<u8>, Error> {
    match compression {
        Compression::Plaintext => Ok(content.to_vec()),
        Compression::Gzip => decompress_gzip(content),
        Compression::Zstd => Err(Error::Descriptor(DescriptorError::UnsupportedCompression(
            "Zstd decompression not supported (requires zstd crate)".into(),
        ))),
        Compression::Lzma => Err(Error::Descriptor(DescriptorError::UnsupportedCompression(
            "LZMA decompression not supported (requires lzma crate)".into(),
        ))),
    }
}

fn decompress_gzip(content: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoder = GzDecoder::new(content);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|e| {
        Error::Descriptor(DescriptorError::DecompressionFailed(format!(
            "Failed to decompress gzip: {}",
            e
        )))
    })?;
    Ok(decompressed)
}

/// Automatically detects and decompresses content.
///
/// This is a convenience function that combines [`detect_compression`] and
/// [`decompress`]. It examines the content's magic bytes to determine the
/// compression format and decompresses accordingly.
///
/// # Arguments
///
/// * `content` - The potentially compressed content
///
/// # Returns
///
/// The decompressed content. If the content is not compressed, it is
/// returned unchanged.
///
/// # Errors
///
/// Returns [`Error::Parse`] if decompression fails or the detected
/// compression format is not supported.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::auto_decompress;
///
/// // Plain text passes through
/// let plain = b"router example 127.0.0.1";
/// let result = auto_decompress(plain).unwrap();
/// assert_eq!(result, plain);
/// ```
pub fn auto_decompress(content: &[u8]) -> Result<Vec<u8>, Error> {
    let compression = detect_compression(content);
    decompress(content, compression)
}

/// Computes a cryptographic digest of content.
///
/// This is a low-level function for computing digests. For descriptor
/// digests, prefer using the [`Descriptor::digest`] method which knows
/// the correct content range to hash.
///
/// # Arguments
///
/// * `content` - The content to hash
/// * `hash` - The hash algorithm to use
/// * `encoding` - The output encoding format
///
/// # Returns
///
/// The digest as a string in the specified encoding.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::{compute_digest, DigestHash, DigestEncoding};
///
/// let content = b"test content";
///
/// // SHA-1 in hex
/// let sha1_hex = compute_digest(content, DigestHash::Sha1, DigestEncoding::Hex);
/// assert_eq!(sha1_hex.len(), 40);
///
/// // SHA-256 in base64
/// let sha256_b64 = compute_digest(content, DigestHash::Sha256, DigestEncoding::Base64);
/// ```
pub fn compute_digest(content: &[u8], hash: DigestHash, encoding: DigestEncoding) -> String {
    match hash {
        DigestHash::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(content);
            let result = hasher.finalize();
            encode_digest(&result, encoding)
        }
        DigestHash::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(content);
            let result = hasher.finalize();
            encode_digest(&result, encoding)
        }
    }
}

fn encode_digest(bytes: &[u8], encoding: DigestEncoding) -> String {
    match encoding {
        DigestEncoding::Raw => bytes.iter().map(|b| *b as char).collect(),
        DigestEncoding::Hex => bytes.iter().map(|b| format!("{:02X}", b)).collect(),
        DigestEncoding::Base64 => base64_encode(bytes),
    }
}

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

/// Parses a descriptor from file content with automatic decompression.
///
/// This function handles the common case of reading a descriptor from a file:
/// 1. Automatically decompresses the content if compressed
/// 2. Strips any `@type` annotation from the beginning
/// 3. Parses the descriptor using the type's `parse` method
///
/// # Type Parameters
///
/// * `T` - The descriptor type to parse (must implement [`Descriptor`])
///
/// # Arguments
///
/// * `content` - The raw file content (possibly compressed)
///
/// # Returns
///
/// The parsed descriptor.
///
/// # Errors
///
/// Returns [`Error::Parse`] if:
/// - Decompression fails
/// - The content is not valid UTF-8
/// - The descriptor content is malformed
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::descriptor::{parse_file, ServerDescriptor};
///
/// let content = std::fs::read("cached-descriptors").unwrap();
/// let descriptor: ServerDescriptor = parse_file(&content).unwrap();
/// println!("Parsed descriptor for: {}", descriptor.nickname);
/// ```
///
/// # See Also
///
/// - [`parse_file_with_annotation`] - Also returns the type annotation if present
/// - [`Descriptor::parse`] - Parse from string without decompression
pub fn parse_file<T: Descriptor>(content: &[u8]) -> Result<T, Error> {
    let decompressed = auto_decompress(content)?;
    let content_str = String::from_utf8_lossy(&decompressed);
    let (_, stripped) = strip_type_annotation(&content_str);
    T::parse(stripped)
}

/// Parses a descriptor from file content, returning the type annotation.
///
/// Like [`parse_file`], but also returns the `@type` annotation if one
/// was present at the beginning of the content.
///
/// # Type Parameters
///
/// * `T` - The descriptor type to parse (must implement [`Descriptor`])
///
/// # Arguments
///
/// * `content` - The raw file content (possibly compressed)
///
/// # Returns
///
/// A tuple of:
/// - `Option<TypeAnnotation>` - The type annotation if present
/// - `T` - The parsed descriptor
///
/// # Errors
///
/// Returns [`Error::Parse`] if decompression or parsing fails.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::descriptor::{parse_file_with_annotation, ServerDescriptor};
///
/// let content = std::fs::read("server-descriptor").unwrap();
/// let (annotation, descriptor): (_, ServerDescriptor) =
///     parse_file_with_annotation(&content).unwrap();
///
/// if let Some(ann) = annotation {
///     println!("Type: {} v{}.{}", ann.name, ann.major_version, ann.minor_version);
/// }
/// ```
pub fn parse_file_with_annotation<T: Descriptor>(
    content: &[u8],
) -> Result<(Option<TypeAnnotation>, T), Error> {
    let decompressed = auto_decompress(content)?;
    let content_str = String::from_utf8_lossy(&decompressed);
    let (annotation, stripped) = strip_type_annotation(&content_str);
    let descriptor = T::parse(stripped)?;
    Ok((annotation, descriptor))
}

/// Strips a type annotation from the beginning of descriptor content.
///
/// If the first line is a valid `@type` annotation, it is parsed and
/// removed from the content. Otherwise, the content is returned unchanged.
///
/// # Arguments
///
/// * `content` - The descriptor content
///
/// # Returns
///
/// A tuple of:
/// - `Option<TypeAnnotation>` - The parsed annotation if present
/// - `&str` - The remaining content after the annotation
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::strip_type_annotation;
///
/// let content = "@type server-descriptor 1.0\nrouter example 127.0.0.1";
/// let (annotation, rest) = strip_type_annotation(content);
///
/// assert!(annotation.is_some());
/// assert_eq!(annotation.unwrap().name, "server-descriptor");
/// assert_eq!(rest, "router example 127.0.0.1");
///
/// // Without annotation
/// let content = "router example 127.0.0.1";
/// let (annotation, rest) = strip_type_annotation(content);
/// assert!(annotation.is_none());
/// assert_eq!(rest, content);
/// ```
pub fn strip_type_annotation(content: &str) -> (Option<TypeAnnotation>, &str) {
    let first_line_end = content.find('\n').unwrap_or(content.len());
    let first_line = &content[..first_line_end];

    if let Some(annotation) = TypeAnnotation::parse(first_line) {
        let rest = if first_line_end < content.len() {
            &content[first_line_end + 1..]
        } else {
            ""
        };
        (Some(annotation), rest)
    } else {
        (None, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_compression_plaintext() {
        let content = b"@type server-descriptor 1.0\nrouter test";
        assert_eq!(detect_compression(content), Compression::Plaintext);
    }

    #[test]
    fn test_detect_compression_gzip() {
        let content = &[0x1f, 0x8b, 0x08, 0x00];
        assert_eq!(detect_compression(content), Compression::Gzip);
    }

    #[test]
    fn test_detect_compression_zstd() {
        let content = &[0x28, 0xb5, 0x2f, 0xfd, 0x00];
        assert_eq!(detect_compression(content), Compression::Zstd);
    }

    #[test]
    fn test_detect_compression_lzma() {
        let content = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
        assert_eq!(detect_compression(content), Compression::Lzma);
    }

    #[test]
    fn test_decompress_plaintext() {
        let content = b"Hello, World!";
        let result = decompress(content, Compression::Plaintext).unwrap();
        assert_eq!(result, content);
    }

    #[test]
    fn test_auto_decompress_plaintext() {
        let content = b"Hello, World!";
        let result = auto_decompress(content).unwrap();
        assert_eq!(result, content);
    }

    #[test]
    fn test_decompress_gzip() {
        let compressed = &[
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xf3, 0x48, 0xcd, 0xc9,
            0xc9, 0x07, 0x00, 0x82, 0x89, 0xd1, 0xf7, 0x05, 0x00, 0x00, 0x00,
        ];
        let result = decompress(compressed, Compression::Gzip).unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_type_annotation_parse() {
        let annotation = TypeAnnotation::parse("@type server-descriptor 1.0").unwrap();
        assert_eq!(annotation.name, "server-descriptor");
        assert_eq!(annotation.major_version, 1);
        assert_eq!(annotation.minor_version, 0);
    }

    #[test]
    fn test_type_annotation_parse_extra_info() {
        let annotation = TypeAnnotation::parse("@type extra-info 1.0").unwrap();
        assert_eq!(annotation.name, "extra-info");
        assert_eq!(annotation.major_version, 1);
        assert_eq!(annotation.minor_version, 0);
    }

    #[test]
    fn test_type_annotation_parse_bridge_extra_info() {
        let annotation = TypeAnnotation::parse("@type bridge-extra-info 1.2").unwrap();
        assert_eq!(annotation.name, "bridge-extra-info");
        assert_eq!(annotation.major_version, 1);
        assert_eq!(annotation.minor_version, 2);
    }

    #[test]
    fn test_type_annotation_parse_invalid() {
        assert!(TypeAnnotation::parse("router test").is_none());
        assert!(TypeAnnotation::parse("@type").is_none());
        assert!(TypeAnnotation::parse("@type server-descriptor").is_none());
        assert!(TypeAnnotation::parse("@type server-descriptor 1").is_none());
    }

    #[test]
    fn test_type_annotation_display() {
        let annotation = TypeAnnotation::new("server-descriptor", 1, 0);
        assert_eq!(annotation.to_string(), "@type server-descriptor 1.0");
    }

    #[test]
    fn test_strip_type_annotation() {
        let content = "@type server-descriptor 1.0\nrouter test 127.0.0.1";
        let (annotation, rest) = strip_type_annotation(content);
        assert!(annotation.is_some());
        assert_eq!(annotation.unwrap().name, "server-descriptor");
        assert_eq!(rest, "router test 127.0.0.1");
    }

    #[test]
    fn test_strip_type_annotation_no_annotation() {
        let content = "router test 127.0.0.1";
        let (annotation, rest) = strip_type_annotation(content);
        assert!(annotation.is_none());
        assert_eq!(rest, content);
    }

    #[test]
    fn test_descriptor_type_from_annotation() {
        let annotation = TypeAnnotation::new("server-descriptor", 1, 0);
        assert_eq!(
            DescriptorType::from_annotation(&annotation),
            Some(DescriptorType::ServerDescriptor)
        );

        let annotation = TypeAnnotation::new("extra-info", 1, 0);
        assert_eq!(
            DescriptorType::from_annotation(&annotation),
            Some(DescriptorType::ExtraInfo)
        );

        let annotation = TypeAnnotation::new("tordnsel", 1, 0);
        assert_eq!(
            DescriptorType::from_annotation(&annotation),
            Some(DescriptorType::TorDNSEL)
        );
    }

    #[test]
    fn test_descriptor_type_from_filename() {
        assert_eq!(
            DescriptorType::from_filename("cached-consensus"),
            Some(DescriptorType::NetworkStatusConsensusV3)
        );
        assert_eq!(
            DescriptorType::from_filename("cached-descriptors"),
            Some(DescriptorType::ServerDescriptor)
        );
        assert_eq!(
            DescriptorType::from_filename("cached-extrainfo"),
            Some(DescriptorType::ExtraInfo)
        );
        assert_eq!(
            DescriptorType::from_filename("exit-list"),
            Some(DescriptorType::TorDNSEL)
        );
    }
}
