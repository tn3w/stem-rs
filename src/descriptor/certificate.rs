//! Ed25519 certificate parsing for Tor descriptors.
//!
//! This module provides parsing for [Ed25519 certificates] used throughout the Tor
//! network for cryptographic identity and signing key validation. These certificates
//! are a fundamental building block of Tor's identity system, enabling:
//!
//! - Validating signing keys of server descriptors
//! - Validating signing keys of hidden service v3 descriptors
//! - Signing and encrypting hidden service v3 introduction points
//! - Cross-certifying relay identity keys
//!
//! # Certificate Structure
//!
//! Ed25519 certificates follow the format specified in [cert-spec.txt]. Each
//! certificate contains:
//!
//! - A version number (currently only version 1 is supported)
//! - A certificate type indicating its purpose
//! - An expiration time (in hours since Unix epoch)
//! - A certified key (32 bytes)
//! - Optional extensions (e.g., the signing key)
//! - A signature over the certificate body
//!
//! # Security Considerations
//!
//! - Always check [`Ed25519Certificate::is_expired`] before trusting a certificate
//! - Certificate validation requires the `cryptography` feature for signature verification
//! - The signing key may be embedded in an extension or provided externally
//! - Certificates with unknown types are rejected to prevent security issues
//!
//! # Example
//!
//! ```rust
//! use stem_rs::descriptor::certificate::Ed25519Certificate;
//!
//! let cert_pem = r#"-----BEGIN ED25519 CERT-----
//! AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABnprVR
//! ptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8sGG8lTjx1
//! g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98Ljhdp2w4=
//! -----END ED25519 CERT-----"#;
//!
//! let cert = Ed25519Certificate::from_base64(cert_pem).unwrap();
//! println!("Certificate type: {:?}", cert.cert_type);
//! println!("Expires: {}", cert.expiration);
//! println!("Is expired: {}", cert.is_expired());
//!
//! // Extract signing key if present
//! if let Some(signing_key) = cert.signing_key() {
//!     println!("Signing key: {} bytes", signing_key.len());
//! }
//! ```
//!
//! # See Also
//!
//! - [`crate::descriptor::server`] - Server descriptors that contain Ed25519 certificates
//! - [`crate::descriptor::hidden`] - Hidden service descriptors using Ed25519 certificates
//! - [`crate::client::datatype`] - Low-level certificate types for ORPort communication
//!
//! [Ed25519 certificates]: https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt
//! [cert-spec.txt]: https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt

use chrono::{DateTime, TimeZone, Utc};
use std::fmt;

use crate::client::datatype::{CertType, Size};
use crate::Error;

/// Length of an Ed25519 public key in bytes.
///
/// Ed25519 keys are always exactly 32 bytes (256 bits).
pub const ED25519_KEY_LENGTH: usize = 32;

/// Length of the Ed25519 certificate header in bytes.
///
/// The header contains: version (1) + type (1) + expiration (4) + key_type (1) +
/// key (32) + extension_count (1) = 40 bytes.
pub const ED25519_HEADER_LENGTH: usize = 40;

/// Length of an Ed25519 signature in bytes.
///
/// Ed25519 signatures are always exactly 64 bytes (512 bits).
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Types of extensions that can appear in an Ed25519 certificate.
///
/// Extensions provide additional data within a certificate, such as the
/// signing key used to create the certificate.
///
/// # Stability
///
/// This enum is non-exhaustive. New extension types may be added in future
/// Tor protocol versions.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::certificate::ExtensionType;
///
/// let ext_type = ExtensionType::from_int(4);
/// assert_eq!(ext_type, ExtensionType::HasSigningKey);
///
/// let unknown = ExtensionType::from_int(99);
/// assert_eq!(unknown, ExtensionType::Unknown);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionType {
    /// Extension contains the 32-byte Ed25519 public key used to sign this certificate.
    ///
    /// When present, this extension's data field contains the signing key that
    /// can be used to verify the certificate's signature.
    HasSigningKey = 4,

    /// An unrecognized extension type.
    ///
    /// Extensions with unknown types are preserved but their semantics are not
    /// interpreted. If the extension has the `AffectsValidation` flag set,
    /// the certificate should be considered invalid.
    Unknown,
}

impl ExtensionType {
    /// Converts an integer value to an [`ExtensionType`].
    ///
    /// # Arguments
    ///
    /// * `val` - The integer extension type value from the certificate
    ///
    /// # Returns
    ///
    /// The corresponding [`ExtensionType`], or [`ExtensionType::Unknown`] if
    /// the value is not recognized.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::ExtensionType;
    ///
    /// assert_eq!(ExtensionType::from_int(4), ExtensionType::HasSigningKey);
    /// assert_eq!(ExtensionType::from_int(0), ExtensionType::Unknown);
    /// ```
    pub fn from_int(val: u8) -> Self {
        match val {
            4 => ExtensionType::HasSigningKey,
            _ => ExtensionType::Unknown,
        }
    }

    /// Returns the integer value of this extension type.
    ///
    /// # Returns
    ///
    /// The integer representation of this extension type, or 0 for unknown types.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::ExtensionType;
    ///
    /// assert_eq!(ExtensionType::HasSigningKey.value(), 4);
    /// ```
    pub fn value(&self) -> u8 {
        match self {
            ExtensionType::HasSigningKey => 4,
            ExtensionType::Unknown => 0,
        }
    }
}

/// Flags that can be assigned to Ed25519 certificate extensions.
///
/// These flags modify how an extension should be interpreted during
/// certificate validation.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::certificate::ExtensionFlag;
///
/// // Check if an extension affects validation
/// let flags = vec![ExtensionFlag::AffectsValidation];
/// if flags.contains(&ExtensionFlag::AffectsValidation) {
///     println!("This extension must be understood for validation");
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionFlag {
    /// Indicates that this extension affects whether the certificate is valid.
    ///
    /// If an extension has this flag set and the extension type is not
    /// understood, the certificate MUST be considered invalid. This ensures
    /// forward compatibility - new critical extensions won't be silently ignored.
    AffectsValidation,

    /// Indicates that the extension contains flags not recognized by this parser.
    ///
    /// This flag is set when the extension's flag byte contains bits that
    /// are not part of the known flag set.
    Unknown,
}

/// An extension within an Ed25519 certificate.
///
/// Extensions provide additional data within a certificate. The most common
/// extension type is [`ExtensionType::HasSigningKey`], which embeds the
/// public key used to sign the certificate.
///
/// # Structure
///
/// Each extension consists of:
/// - A 2-byte length field (big-endian)
/// - A 1-byte extension type
/// - A 1-byte flags field
/// - Variable-length data
///
/// # Flags
///
/// The flags field is a bitmask:
/// - Bit 0 (0x01): [`ExtensionFlag::AffectsValidation`] - Extension is critical
/// - Other bits: Reserved, set [`ExtensionFlag::Unknown`] if present
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::certificate::{Ed25519Extension, ExtensionType, ExtensionFlag};
///
/// // Create a signing key extension
/// let signing_key = vec![0u8; 32]; // 32-byte Ed25519 public key
/// let ext = Ed25519Extension::new(4, 0, signing_key).unwrap();
///
/// assert_eq!(ext.ext_type, ExtensionType::HasSigningKey);
/// assert!(ext.flags.is_empty()); // No flags set
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Extension {
    /// The parsed extension type.
    ///
    /// This is the semantic interpretation of [`type_int`](Self::type_int).
    pub ext_type: ExtensionType,

    /// The raw integer value of the extension type.
    ///
    /// Preserved for round-trip encoding of unknown extension types.
    pub type_int: u8,

    /// Flags associated with this extension.
    ///
    /// See [`ExtensionFlag`] for the meaning of each flag.
    pub flags: Vec<ExtensionFlag>,

    /// The raw integer value of the flags byte.
    ///
    /// Preserved for round-trip encoding.
    pub flag_int: u8,

    /// The extension's data payload.
    ///
    /// For [`ExtensionType::HasSigningKey`], this is a 32-byte Ed25519 public key.
    pub data: Vec<u8>,
}

impl Ed25519Extension {
    /// Creates a new Ed25519 certificate extension.
    ///
    /// # Arguments
    ///
    /// * `ext_type` - The extension type as an integer
    /// * `flag_val` - The flags byte
    /// * `data` - The extension's data payload
    ///
    /// # Returns
    ///
    /// A new [`Ed25519Extension`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The extension type is [`ExtensionType::HasSigningKey`] but the data
    ///   is not exactly 32 bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Extension;
    ///
    /// // Create a signing key extension (type 4)
    /// let key_data = vec![0u8; 32];
    /// let ext = Ed25519Extension::new(4, 0, key_data).unwrap();
    ///
    /// // Invalid: signing key must be 32 bytes
    /// let result = Ed25519Extension::new(4, 0, vec![0u8; 16]);
    /// assert!(result.is_err());
    /// ```
    pub fn new(ext_type: u8, flag_val: u8, data: Vec<u8>) -> Result<Self, Error> {
        let extension_type = ExtensionType::from_int(ext_type);
        let mut flags = Vec::new();
        let mut remaining_flags = flag_val;

        if remaining_flags % 2 == 1 {
            flags.push(ExtensionFlag::AffectsValidation);
            remaining_flags -= 1;
        }

        if remaining_flags != 0 {
            flags.push(ExtensionFlag::Unknown);
        }

        if extension_type == ExtensionType::HasSigningKey && data.len() != 32 {
            return Err(Error::Parse {
                location: "Ed25519Extension".to_string(),
                reason: format!(
                    "Ed25519 HAS_SIGNING_KEY extension must be 32 bytes, but was {}",
                    data.len()
                ),
            });
        }

        Ok(Ed25519Extension {
            ext_type: extension_type,
            type_int: ext_type,
            flags,
            flag_int: flag_val,
            data,
        })
    }

    /// Encodes this extension to its binary representation.
    ///
    /// The encoded format is:
    /// - 2 bytes: data length (big-endian)
    /// - 1 byte: extension type
    /// - 1 byte: flags
    /// - N bytes: data
    ///
    /// # Returns
    ///
    /// A byte vector containing the encoded extension.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Extension;
    ///
    /// let ext = Ed25519Extension::new(4, 0, vec![0u8; 32]).unwrap();
    /// let packed = ext.pack();
    ///
    /// // 2 (length) + 1 (type) + 1 (flags) + 32 (data) = 36 bytes
    /// assert_eq!(packed.len(), 36);
    /// ```
    pub fn pack(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&Size::Short.pack(self.data.len() as u64));
        encoded.push(self.type_int);
        encoded.push(self.flag_int);
        encoded.extend_from_slice(&self.data);
        encoded
    }

    /// Parses an extension from the beginning of a byte slice.
    ///
    /// This method reads one extension from the input and returns both the
    /// parsed extension and the remaining unparsed bytes.
    ///
    /// # Arguments
    ///
    /// * `content` - The byte slice to parse from
    ///
    /// # Returns
    ///
    /// A tuple of (parsed extension, remaining bytes) on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The input is too short to contain the extension header (< 4 bytes)
    /// - The input is truncated (data length exceeds available bytes)
    /// - The extension data is invalid (e.g., wrong size for signing key)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Extension;
    ///
    /// // Extension: length=2, type=5, flags=0, data=[0x11, 0x22]
    /// let data = [0x00, 0x02, 0x05, 0x00, 0x11, 0x22, 0xFF];
    /// let (ext, remaining) = Ed25519Extension::pop(&data).unwrap();
    ///
    /// assert_eq!(ext.type_int, 5);
    /// assert_eq!(ext.data, vec![0x11, 0x22]);
    /// assert_eq!(remaining, &[0xFF]); // Remaining byte
    /// ```
    pub fn pop(content: &[u8]) -> Result<(Self, &[u8]), Error> {
        if content.len() < 4 {
            return Err(Error::Parse {
                location: "Ed25519Extension".to_string(),
                reason: "Ed25519 extension is missing header fields".to_string(),
            });
        }

        let (data_size, content) = Size::Short.pop(content)?;
        let data_size = data_size as usize;
        let (ext_type, content) = (content[0], &content[1..]);
        let (flags, content) = (content[0], &content[1..]);

        if content.len() < data_size {
            return Err(Error::Parse {
                location: "Ed25519Extension".to_string(),
                reason: format!(
                    "Ed25519 extension is truncated. It should have {} bytes of data but there's only {}",
                    data_size,
                    content.len()
                ),
            });
        }

        let (data, content) = content.split_at(data_size);
        let extension = Ed25519Extension::new(ext_type, flags, data.to_vec())?;

        Ok((extension, content))
    }
}

/// A version 1 Ed25519 certificate used in Tor descriptors.
///
/// Ed25519 certificates are used throughout Tor to bind Ed25519 keys to
/// identities and validate signatures on descriptors. They are found in:
///
/// - Server descriptors (signing key certificates)
/// - Hidden service v3 descriptors (blinded key certificates)
/// - Introduction point authentication
///
/// # Certificate Types
///
/// The certificate type indicates its purpose. Common types include:
///
/// | Type | Name | Purpose |
/// |------|------|---------|
/// | 4 | Ed25519 Signing | Signs server descriptors |
/// | 5 | Link Auth | TLS link authentication |
/// | 6 | Ed25519 Auth | Ed25519 authentication |
/// | 8 | Short-term Signing | Short-term descriptor signing |
/// | 9 | Intro Point Auth | HS introduction point auth |
/// | 11 | Ntor Onion Key | Ntor key cross-certification |
///
/// # Invariants
///
/// - Version is always 1 (only supported version)
/// - Key is always exactly 32 bytes
/// - Signature is always exactly 64 bytes
/// - Certificate types 1, 2, 3, and 7 are reserved and rejected
///
/// # Security Considerations
///
/// - Always verify [`is_expired`](Self::is_expired) before trusting a certificate
/// - The signature should be verified against the signing key
/// - Unknown certificate types are rejected for security
/// - Extensions with [`ExtensionFlag::AffectsValidation`] must be understood
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::certificate::Ed25519Certificate;
///
/// let cert_b64 = "AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABn\
///                 prVRptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8s\
///                 GG8lTjx1g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98L\
///                 jhdp2w4=";
///
/// let cert = Ed25519Certificate::from_base64(cert_b64).unwrap();
///
/// // Check certificate properties
/// assert_eq!(cert.version, 1);
/// println!("Type: {:?}", cert.cert_type);
/// println!("Expires: {}", cert.expiration);
///
/// // Check if expired
/// if cert.is_expired() {
///     println!("Certificate has expired!");
/// }
///
/// // Get signing key if present
/// if let Some(key) = cert.signing_key() {
///     println!("Signing key: {} bytes", key.len());
/// }
/// ```
///
/// # See Also
///
/// - [`Ed25519Extension`] - Extensions within certificates
/// - [`CertType`](crate::client::datatype::CertType) - Certificate type enumeration
/// - [cert-spec.txt](https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt) - Tor specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Certificate {
    /// Certificate format version.
    ///
    /// Currently only version 1 is supported. Future versions may have
    /// different structures.
    pub version: u8,

    /// The parsed certificate type.
    ///
    /// Indicates the purpose of this certificate. See [`CertType`](crate::client::datatype::CertType)
    /// for the full enumeration.
    pub cert_type: CertType,

    /// The raw integer value of the certificate type.
    ///
    /// Preserved for round-trip encoding and debugging.
    pub type_int: u8,

    /// When this certificate expires.
    ///
    /// Certificates should not be trusted after this time. Use [`is_expired`](Self::is_expired)
    /// to check validity.
    ///
    /// # Note
    ///
    /// The expiration is stored in the certificate as hours since Unix epoch,
    /// so the precision is limited to one hour.
    pub expiration: DateTime<Utc>,

    /// The key type (always 1 for Ed25519).
    ///
    /// This field indicates the type of key in the [`key`](Self::key) field.
    /// Currently only type 1 (Ed25519) is defined.
    pub key_type: u8,

    /// The certified Ed25519 public key.
    ///
    /// This is the key being certified by this certificate. Its meaning
    /// depends on the certificate type.
    pub key: [u8; ED25519_KEY_LENGTH],

    /// Extensions included in this certificate.
    ///
    /// Extensions provide additional data such as the signing key.
    /// See [`Ed25519Extension`] for details.
    pub extensions: Vec<Ed25519Extension>,

    /// The Ed25519 signature over the certificate body.
    ///
    /// This signature covers all certificate data except the signature itself.
    /// It should be verified using the signing key (from an extension or
    /// provided externally).
    pub signature: [u8; ED25519_SIGNATURE_LENGTH],
}

impl Ed25519Certificate {
    /// Parses an Ed25519 certificate from its binary representation.
    ///
    /// This method decodes a certificate from raw bytes as they appear in
    /// descriptors after base64 decoding.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw certificate bytes
    ///
    /// # Returns
    ///
    /// The parsed [`Ed25519Certificate`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The input is too short (minimum 104 bytes: 40 header + 64 signature)
    /// - The version is not 1
    /// - The certificate type is reserved (1, 2, 3, 7) or unknown (0)
    /// - The expiration timestamp is invalid
    /// - Extension parsing fails
    /// - There is unused data after parsing extensions
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Certificate;
    ///
    /// // Typically you'd get these bytes from base64 decoding
    /// // let cert = Ed25519Certificate::unpack(&decoded_bytes)?;
    /// ```
    pub fn unpack(content: &[u8]) -> Result<Self, Error> {
        if content.len() < ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH {
            return Err(Error::Parse {
                location: "Ed25519Certificate".to_string(),
                reason: format!(
                    "Ed25519 certificate was {} bytes, but should be at least {}",
                    content.len(),
                    ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH
                ),
            });
        }

        let (header, signature_bytes) = content.split_at(content.len() - ED25519_SIGNATURE_LENGTH);

        let (version, header) = Size::Char.pop(header)?;
        let version = version as u8;

        if version != 1 {
            return Err(Error::Parse {
                location: "Ed25519Certificate".to_string(),
                reason: format!(
                    "Ed25519 certificate is version {}. Parser presently only supports version 1",
                    version
                ),
            });
        }

        let (cert_type_int, header) = Size::Char.pop(header)?;
        let cert_type_int = cert_type_int as u8;
        let (cert_type, _) = CertType::get(cert_type_int);

        Self::validate_cert_type(cert_type, cert_type_int)?;

        let (expiration_hours, header) = Size::Long.pop(header)?;
        let expiration = Utc
            .timestamp_opt((expiration_hours * 3600) as i64, 0)
            .single()
            .ok_or_else(|| Error::Parse {
                location: "Ed25519Certificate".to_string(),
                reason: "Invalid expiration timestamp".to_string(),
            })?;

        let (key_type, header) = Size::Char.pop(header)?;
        let key_type = key_type as u8;

        let (key_bytes, header) = header.split_at(ED25519_KEY_LENGTH);
        let mut key = [0u8; ED25519_KEY_LENGTH];
        key.copy_from_slice(key_bytes);

        let (extension_count, mut extension_data) = Size::Char.pop(header)?;
        let extension_count = extension_count as usize;

        let mut extensions = Vec::new();
        for _ in 0..extension_count {
            let (extension, remainder) = Ed25519Extension::pop(extension_data)?;
            extensions.push(extension);
            extension_data = remainder;
        }

        if !extension_data.is_empty() {
            return Err(Error::Parse {
                location: "Ed25519Certificate".to_string(),
                reason: format!(
                    "Ed25519 certificate had {} bytes of unused extension data",
                    extension_data.len()
                ),
            });
        }

        let mut signature = [0u8; ED25519_SIGNATURE_LENGTH];
        signature.copy_from_slice(signature_bytes);

        Ok(Ed25519Certificate {
            version,
            cert_type,
            type_int: cert_type_int,
            expiration,
            key_type,
            key,
            extensions,
            signature,
        })
    }

    /// Validates that the certificate type is allowed for Ed25519 certificates.
    ///
    /// Certain certificate types are reserved for other purposes (CERTS cells,
    /// RSA cross-certification) and cannot be used in Ed25519 certificates.
    fn validate_cert_type(cert_type: CertType, cert_type_int: u8) -> Result<(), Error> {
        match cert_type {
            CertType::Link | CertType::Identity | CertType::Authenticate => {
                Err(Error::Parse {
                    location: "Ed25519Certificate".to_string(),
                    reason: format!(
                        "Ed25519 certificate cannot have a type of {}. This is reserved for CERTS cells",
                        cert_type_int
                    ),
                })
            }
            CertType::Ed25519Identity => {
                Err(Error::Parse {
                    location: "Ed25519Certificate".to_string(),
                    reason: "Ed25519 certificate cannot have a type of 7. This is reserved for RSA identity cross-certification".to_string(),
                })
            }
            CertType::Unknown => {
                Err(Error::Parse {
                    location: "Ed25519Certificate".to_string(),
                    reason: format!("Ed25519 certificate type {} is unrecognized", cert_type_int),
                })
            }
            _ => Ok(()),
        }
    }

    /// Parses an Ed25519 certificate from a base64-encoded string.
    ///
    /// This method handles both raw base64 and PEM-formatted certificates
    /// (with `-----BEGIN ED25519 CERT-----` headers).
    ///
    /// # Arguments
    ///
    /// * `content` - The base64-encoded certificate string
    ///
    /// # Returns
    ///
    /// The parsed [`Ed25519Certificate`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The input is empty
    /// - The base64 encoding is invalid
    /// - The decoded certificate is malformed (see [`unpack`](Self::unpack))
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Certificate;
    ///
    /// // Raw base64
    /// let cert_b64 = "AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABn\
    ///                 prVRptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8s\
    ///                 GG8lTjx1g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98L\
    ///                 jhdp2w4=";
    /// let cert = Ed25519Certificate::from_base64(cert_b64).unwrap();
    ///
    /// // PEM format also works
    /// let pem = format!(
    ///     "-----BEGIN ED25519 CERT-----\n{}\n-----END ED25519 CERT-----",
    ///     cert_b64
    /// );
    /// let cert2 = Ed25519Certificate::from_base64(&pem).unwrap();
    /// ```
    pub fn from_base64(content: &str) -> Result<Self, Error> {
        let content = content.trim();

        let content = if content.starts_with("-----BEGIN ED25519 CERT-----") {
            content
                .strip_prefix("-----BEGIN ED25519 CERT-----")
                .and_then(|s| s.strip_suffix("-----END ED25519 CERT-----"))
                .map(|s| s.trim())
                .unwrap_or(content)
        } else {
            content
        };

        let content: String = content.chars().filter(|c| !c.is_whitespace()).collect();

        if content.is_empty() {
            return Err(Error::Parse {
                location: "Ed25519Certificate".to_string(),
                reason: "Ed25519 certificate wasn't properly base64 encoded (empty):".to_string(),
            });
        }

        let decoded = base64_decode(&content).ok_or_else(|| Error::Parse {
            location: "Ed25519Certificate".to_string(),
            reason: format!(
                "Ed25519 certificate wasn't properly base64 encoded (Incorrect padding):\n{}",
                content
            ),
        })?;

        Self::unpack(&decoded)
    }

    /// Encodes this certificate to its binary representation.
    ///
    /// The encoded format matches the Tor specification and can be decoded
    /// with [`unpack`](Self::unpack).
    ///
    /// # Returns
    ///
    /// A byte vector containing the encoded certificate.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Certificate;
    ///
    /// let cert_b64 = "AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABn\
    ///                 prVRptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8s\
    ///                 GG8lTjx1g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98L\
    ///                 jhdp2w4=";
    /// let cert = Ed25519Certificate::from_base64(cert_b64).unwrap();
    ///
    /// let packed = cert.pack();
    /// let reparsed = Ed25519Certificate::unpack(&packed).unwrap();
    /// assert_eq!(cert, reparsed);
    /// ```
    pub fn pack(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.push(self.version);
        encoded.push(self.type_int);
        encoded.extend_from_slice(&Size::Long.pack((self.expiration.timestamp() / 3600) as u64));
        encoded.push(self.key_type);
        encoded.extend_from_slice(&self.key);
        encoded.push(self.extensions.len() as u8);

        for extension in &self.extensions {
            encoded.extend_from_slice(&extension.pack());
        }

        encoded.extend_from_slice(&self.signature);
        encoded
    }

    /// Encodes this certificate to a base64 string.
    ///
    /// The output is formatted with line breaks every 64 characters,
    /// suitable for embedding in descriptors.
    ///
    /// # Returns
    ///
    /// A base64-encoded string representation of the certificate.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Certificate;
    ///
    /// let cert_b64 = "AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABn\
    ///                 prVRptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8s\
    ///                 GG8lTjx1g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98L\
    ///                 jhdp2w4=";
    /// let cert = Ed25519Certificate::from_base64(cert_b64).unwrap();
    ///
    /// let encoded = cert.to_base64();
    /// // Can be decoded back
    /// let decoded = Ed25519Certificate::from_base64(&encoded).unwrap();
    /// ```
    pub fn to_base64(&self) -> String {
        let packed = self.pack();
        let encoded = base64_encode(&packed);

        encoded
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Encodes this certificate to a PEM-formatted string.
    ///
    /// The output includes `-----BEGIN ED25519 CERT-----` and
    /// `-----END ED25519 CERT-----` headers.
    ///
    /// # Returns
    ///
    /// A PEM-formatted string representation of the certificate.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Certificate;
    ///
    /// let cert_b64 = "AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABn\
    ///                 prVRptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8s\
    ///                 GG8lTjx1g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98L\
    ///                 jhdp2w4=";
    /// let cert = Ed25519Certificate::from_base64(cert_b64).unwrap();
    ///
    /// let pem = cert.to_base64_pem();
    /// assert!(pem.starts_with("-----BEGIN ED25519 CERT-----"));
    /// assert!(pem.ends_with("-----END ED25519 CERT-----"));
    /// ```
    pub fn to_base64_pem(&self) -> String {
        format!(
            "-----BEGIN ED25519 CERT-----\n{}\n-----END ED25519 CERT-----",
            self.to_base64()
        )
    }

    /// Checks if this certificate has expired.
    ///
    /// A certificate is considered expired if the current time is past
    /// the certificate's expiration time.
    ///
    /// # Returns
    ///
    /// `true` if the certificate has expired, `false` otherwise.
    ///
    /// # Security
    ///
    /// Always check expiration before trusting a certificate. Expired
    /// certificates should not be used for validation, even if their
    /// signatures are valid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Certificate;
    ///
    /// let cert_b64 = "AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABn\
    ///                 prVRptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8s\
    ///                 GG8lTjx1g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98L\
    ///                 jhdp2w4=";
    /// let cert = Ed25519Certificate::from_base64(cert_b64).unwrap();
    ///
    /// if cert.is_expired() {
    ///     println!("Certificate expired on {}", cert.expiration);
    /// }
    /// ```
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expiration
    }

    /// Extracts the signing key from this certificate's extensions.
    ///
    /// The signing key is the Ed25519 public key used to sign this certificate.
    /// It is typically embedded in an extension of type [`ExtensionType::HasSigningKey`].
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` - A reference to the 32-byte signing key if present
    /// - `None` - If no signing key extension exists
    ///
    /// # Security
    ///
    /// The signing key should be used to verify the certificate's signature.
    /// If no signing key is embedded, it must be obtained from another source
    /// (e.g., the descriptor's master key).
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::certificate::Ed25519Certificate;
    ///
    /// let cert_b64 = "AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABn\
    ///                 prVRptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8s\
    ///                 GG8lTjx1g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98L\
    ///                 jhdp2w4=";
    /// let cert = Ed25519Certificate::from_base64(cert_b64).unwrap();
    ///
    /// match cert.signing_key() {
    ///     Some(key) => println!("Signing key: {} bytes", key.len()),
    ///     None => println!("No embedded signing key"),
    /// }
    /// ```
    pub fn signing_key(&self) -> Option<&[u8]> {
        for extension in &self.extensions {
            if extension.ext_type == ExtensionType::HasSigningKey {
                return Some(&extension.data);
            }
        }
        None
    }
}

impl fmt::Display for Ed25519Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64_pem())
    }
}

/// Decodes a base64-encoded string to bytes.
///
/// This is a simple base64 decoder that handles standard base64 alphabet
/// (A-Z, a-z, 0-9, +, /) with optional padding.
///
/// # Arguments
///
/// * `input` - The base64-encoded string (padding characters are optional)
///
/// # Returns
///
/// - `Some(Vec<u8>)` - The decoded bytes on success
/// - `None` - If the input contains invalid base64 characters
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
/// This is a simple base64 encoder that produces standard base64 output
/// with padding.
///
/// # Arguments
///
/// * `bytes` - The bytes to encode
///
/// # Returns
///
/// A base64-encoded string with appropriate padding.
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
        } else {
            result.push('=');
        }

        if i + 2 < bytes.len() {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_CERT: &str = r#"
AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABnprVR
ptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8sGG8lTjx1
g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98Ljhdp2w4=
"#;

    const EXPECTED_CERT_KEY: [u8; 32] = [
        0xa5, 0xb6, 0x1a, 0x80, 0x44, 0x0f, 0x52, 0x23, 0x63, 0x70, 0x3a, 0x7f, 0xa1, 0x8d, 0xa8,
        0x11, 0x25, 0xe4, 0x0f, 0x37, 0x7c, 0x3d, 0x99, 0x6b, 0xdb, 0xa9, 0x1a, 0x47, 0xb9, 0xd4,
        0x91, 0xaa,
    ];

    const EXPECTED_EXTENSION_DATA: [u8; 32] = [
        0x67, 0xa6, 0xb5, 0x51, 0xa6, 0xd2, 0x2b, 0xe3, 0x76, 0xd6, 0x3e, 0x8d, 0x9f, 0x23, 0x3a,
        0x37, 0xb8, 0xec, 0xb0, 0x7e, 0x83, 0x2b, 0xaf, 0x2a, 0x6b, 0xa5, 0xb9, 0xb8, 0x1e, 0x10,
        0xa4, 0x64,
    ];

    const EXPECTED_SIGNATURE: [u8; 64] = [
        0xc6, 0x8e, 0xd3, 0xae, 0x0b, 0x3f, 0xed, 0x4a, 0x36, 0xe2, 0xef, 0x95, 0xcf, 0x2c, 0x18,
        0x6f, 0x25, 0x4e, 0x3c, 0x75, 0x83, 0x89, 0x37, 0x10, 0xbb, 0x96, 0x62, 0x01, 0xd8, 0x59,
        0x4e, 0x6b, 0x02, 0x26, 0xbb, 0x9e, 0x5e, 0x20, 0x51, 0xf0, 0x59, 0x38, 0x47, 0xc7, 0x01,
        0xf2, 0x84, 0x4b, 0xb9, 0x77, 0x77, 0xad, 0xdd, 0x04, 0x48, 0xc4, 0x5f, 0xdf, 0x0b, 0x8e,
        0x17, 0x69, 0xdb, 0x0e,
    ];

    fn create_test_certificate(
        version: u8,
        cert_type: u8,
        extension_data: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let mut cert = Vec::new();
        cert.push(version);
        cert.push(cert_type);
        cert.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        cert.push(0x01);
        cert.extend_from_slice(&[0x03; 32]);
        cert.push(extension_data.len() as u8);
        for ext in extension_data {
            cert.extend_from_slice(&ext);
        }
        cert.extend_from_slice(&[0x01; ED25519_SIGNATURE_LENGTH]);
        cert
    }

    fn encode_test_certificate(version: u8, cert_type: u8, extension_data: Vec<Vec<u8>>) -> String {
        let cert = create_test_certificate(version, cert_type, extension_data);
        base64_encode(&cert)
    }

    #[test]
    fn test_basic_parsing() {
        let signing_key = vec![0x11u8; 32];
        let mut ext1 = vec![0x00, 0x20, 0x04, 0x07];
        ext1.extend_from_slice(&signing_key);
        let ext2 = vec![0x00, 0x00, 0x05, 0x04];

        let cert_b64 = encode_test_certificate(1, 4, vec![ext1, ext2]);
        let cert = Ed25519Certificate::from_base64(&cert_b64).unwrap();

        assert_eq!(1, cert.version);
        assert_eq!(CertType::Ed25519Signing, cert.cert_type);
        assert_eq!(Utc.timestamp_opt(0, 0).unwrap(), cert.expiration);
        assert_eq!(1, cert.key_type);
        assert_eq!([0x03u8; 32], cert.key);
        assert_eq!([0x01u8; 64], cert.signature);
        assert_eq!(2, cert.extensions.len());

        assert_eq!(ExtensionType::HasSigningKey, cert.extensions[0].ext_type);
        assert_eq!(4, cert.extensions[0].type_int);
        assert_eq!(7, cert.extensions[0].flag_int);
        assert_eq!(signing_key, cert.extensions[0].data);
        assert!(cert.extensions[0]
            .flags
            .contains(&ExtensionFlag::AffectsValidation));
        assert!(cert.extensions[0].flags.contains(&ExtensionFlag::Unknown));

        assert_eq!(ExtensionType::Unknown, cert.extensions[1].ext_type);
        assert_eq!(5, cert.extensions[1].type_int);
        assert!(cert.extensions[1].data.is_empty());

        assert!(cert.is_expired());
    }

    #[test]
    fn test_with_real_cert() {
        let cert = Ed25519Certificate::from_base64(ED25519_CERT).unwrap();

        assert_eq!(1, cert.version);
        assert_eq!(CertType::Ed25519Signing, cert.cert_type);
        assert_eq!(
            Utc.with_ymd_and_hms(2015, 8, 28, 17, 0, 0).unwrap(),
            cert.expiration
        );
        assert_eq!(1, cert.key_type);
        assert_eq!(EXPECTED_CERT_KEY, cert.key);
        assert_eq!(1, cert.extensions.len());
        assert_eq!(ExtensionType::HasSigningKey, cert.extensions[0].ext_type);
        assert_eq!(EXPECTED_EXTENSION_DATA.to_vec(), cert.extensions[0].data);
        assert_eq!(EXPECTED_SIGNATURE, cert.signature);
    }

    #[test]
    fn test_extension_encoding() {
        let cert = Ed25519Certificate::from_base64(ED25519_CERT).unwrap();
        let extension = &cert.extensions[0];

        let mut expected = Vec::new();
        expected.extend_from_slice(&Size::Short.pack(EXPECTED_EXTENSION_DATA.len() as u64));
        expected.push(4);
        expected.push(0);
        expected.extend_from_slice(&EXPECTED_EXTENSION_DATA);

        assert_eq!(4, extension.type_int);
        assert_eq!(0, extension.flag_int);
        assert_eq!(EXPECTED_EXTENSION_DATA.to_vec(), extension.data);
        assert_eq!(expected, extension.pack());
    }

    #[test]
    fn test_certificate_encoding() {
        let cert = Ed25519Certificate::from_base64(ED25519_CERT).unwrap();
        let encoded = cert.to_base64();
        let expected: String = ED25519_CERT
            .trim()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let actual: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_non_base64() {
        let result = Ed25519Certificate::from_base64("\x02\x0323\x04");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("base64"));
    }

    #[test]
    fn test_too_short() {
        let result = Ed25519Certificate::from_base64("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));

        let result = Ed25519Certificate::from_base64("AQQABhtZAaW2GoBED1IjY3A6");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("18 bytes"));
        assert!(err.to_string().contains("at least 104"));
    }

    #[test]
    fn test_with_invalid_version() {
        let cert_b64 = encode_test_certificate(2, 4, vec![]);
        let result = Ed25519Certificate::from_base64(&cert_b64);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("version 2"));
        assert!(err.to_string().contains("only supports version 1"));
    }

    #[test]
    fn test_with_invalid_cert_type_zero() {
        let cert_b64 = encode_test_certificate(1, 0, vec![]);
        let result = Ed25519Certificate::from_base64(&cert_b64);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("type 0"));
        assert!(err.to_string().contains("unrecognized"));
    }

    #[test]
    fn test_with_invalid_cert_type_reserved() {
        let cert_b64 = encode_test_certificate(1, 1, vec![]);
        let result = Ed25519Certificate::from_base64(&cert_b64);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("type of 1"));
        assert!(err.to_string().contains("CERTS cells"));
    }

    #[test]
    fn test_with_invalid_cert_type_rsa_crosscert() {
        let cert_b64 = encode_test_certificate(1, 7, vec![]);
        let result = Ed25519Certificate::from_base64(&cert_b64);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("type of 7"));
        assert!(err.to_string().contains("RSA identity"));
    }

    #[test]
    fn test_truncated_extension() {
        let cert_b64 = encode_test_certificate(1, 4, vec![vec![]]);
        let result = Ed25519Certificate::from_base64(&cert_b64);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing header"));

        let ext = vec![0x50, 0x00, 0x00, 0x00, 0x15, 0x12];
        let cert_b64 = encode_test_certificate(1, 4, vec![ext]);
        let result = Ed25519Certificate::from_base64(&cert_b64);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn test_extra_extension_data() {
        let ext = vec![0x00, 0x01, 0x00, 0x00, 0x15, 0x12];
        let cert_b64 = encode_test_certificate(1, 4, vec![ext]);
        let result = Ed25519Certificate::from_base64(&cert_b64);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unused extension data"));
    }

    #[test]
    fn test_truncated_signing_key() {
        let ext = vec![0x00, 0x02, 0x04, 0x07, 0x11, 0x12];
        let cert_b64 = encode_test_certificate(1, 4, vec![ext]);
        let result = Ed25519Certificate::from_base64(&cert_b64);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("HAS_SIGNING_KEY"));
        assert!(err.to_string().contains("32 bytes"));
        assert!(err.to_string().contains("was 2"));
    }

    #[test]
    fn test_signing_key_extraction() {
        let signing_key = vec![0x11u8; 32];
        let mut ext = vec![0x00, 0x20, 0x04, 0x00];
        ext.extend_from_slice(&signing_key);

        let cert_b64 = encode_test_certificate(1, 4, vec![ext]);
        let cert = Ed25519Certificate::from_base64(&cert_b64).unwrap();

        assert_eq!(Some(signing_key.as_slice()), cert.signing_key());
    }

    #[test]
    fn test_signing_key_not_present() {
        let cert_b64 = encode_test_certificate(1, 4, vec![]);
        let cert = Ed25519Certificate::from_base64(&cert_b64).unwrap();

        assert_eq!(None, cert.signing_key());
    }

    #[test]
    fn test_pem_format() {
        let pem_cert = format!(
            "-----BEGIN ED25519 CERT-----\n{}\n-----END ED25519 CERT-----",
            ED25519_CERT.trim()
        );
        let cert = Ed25519Certificate::from_base64(&pem_cert).unwrap();
        assert_eq!(1, cert.version);
        assert_eq!(CertType::Ed25519Signing, cert.cert_type);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, World!";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn test_base64_with_padding() {
        for len in 1..20 {
            let original: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let encoded = base64_encode(&original);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }
}
