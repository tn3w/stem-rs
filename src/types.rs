//! Type-safe wrappers for Tor-specific identifiers and values.
//!
//! This module provides newtype wrappers that enforce validation at
//! construction time, preventing invalid values from being created.
//! These types improve API safety and clarity by making invalid states
//! unrepresentable.
//!
//! # Design Philosophy
//!
//! Following the library-rs reference implementation, these types:
//! - Validate input at construction time
//! - Provide infallible access after construction
//! - Implement standard traits (Display, Debug, FromStr)
//! - Use efficient internal representations
//!
//! # Available Types
//!
//! - [`Fingerprint`] - Relay identity fingerprint (40 hex chars)
//! - [`Nickname`] - Relay nickname (1-19 alphanumeric)
//! - [`Ed25519PublicKey`] - Ed25519 public key (base64)
//! - [`Ed25519Identity`] - Ed25519 identity (32 bytes)
//!
//! # Example
//!
//! ```rust
//! use stem_rs::types::{Fingerprint, Nickname};
//! use std::str::FromStr;
//!
//! let fp = Fingerprint::from_str(
//!     "9695DFC35FFEB861329B9F1AB04C46397020CE31"
//! ).unwrap();
//! println!("Fingerprint: {}", fp);
//!
//! let nick = Nickname::from_str("MyRelay").unwrap();
//! println!("Nickname: {}", nick);
//!
//! let invalid = Nickname::from_str("invalid-name");
//! assert!(invalid.is_err());
//! ```

use std::fmt;
use std::str::FromStr;
use thiserror::Error;

const MAX_NICKNAME_LENGTH: usize = 19;
const FINGERPRINT_LENGTH: usize = 40;
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Errors that can occur when parsing or validating fingerprints.
#[derive(Debug, Error)]
pub enum FingerprintError {
    /// Fingerprint is not exactly 40 characters long.
    #[error("fingerprint must be exactly 40 hexadecimal characters")]
    InvalidLength,
    /// Fingerprint contains non-hexadecimal characters.
    #[error("fingerprint contains invalid characters")]
    InvalidCharacters,
}

/// Errors that can occur when parsing or validating nicknames.
#[derive(Debug, Error)]
pub enum NicknameError {
    /// Nickname length is not between 1 and 19 characters.
    #[error("nickname must be 1-19 characters long")]
    InvalidLength,
    /// Nickname contains non-alphanumeric characters.
    #[error("nickname must contain only alphanumeric characters")]
    InvalidCharacters,
}

/// Errors that can occur when parsing Ed25519 public keys.
#[derive(Debug, Error)]
pub enum Ed25519PublicKeyError {
    /// Base64 decoding failed.
    #[error("invalid base64 encoding")]
    InvalidBase64,
    /// Decoded key has wrong length.
    #[error("invalid key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
}

/// Errors that can occur when parsing Ed25519 identities.
#[derive(Debug, Error)]
pub enum Ed25519IdentityError {
    /// Base64 decoding failed.
    #[error("invalid base64 encoding")]
    InvalidBase64,
    /// Decoded identity has wrong length.
    #[error("invalid identity length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
}

/// A validated relay fingerprint.
///
/// Fingerprints are 40-character hexadecimal strings representing the
/// SHA-1 hash of a relay's RSA identity key. This type ensures the
/// fingerprint is valid at construction time.
///
/// # Format
///
/// - Length: exactly 40 characters
/// - Characters: hexadecimal (0-9, a-f, A-F)
/// - Stored in uppercase for consistency
///
/// # Example
///
/// ```rust
/// use stem_rs::types::Fingerprint;
/// use std::str::FromStr;
///
/// let fp = Fingerprint::from_str(
///     "9695DFC35FFEB861329B9F1AB04C46397020CE31"
/// ).unwrap();
/// assert_eq!(fp.as_str(), "9695DFC35FFEB861329B9F1AB04C46397020CE31");
///
/// let invalid = Fingerprint::from_str("ABCD");
/// assert!(invalid.is_err());
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Creates a new fingerprint from a string.
    ///
    /// The input is validated and converted to uppercase.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not exactly 40 hexadecimal characters.
    pub fn new(s: impl Into<String>) -> Result<Self, FingerprintError> {
        let s = s.into();
        if s.len() != FINGERPRINT_LENGTH {
            return Err(FingerprintError::InvalidLength);
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(FingerprintError::InvalidCharacters);
        }
        Ok(Self(s.to_uppercase()))
    }

    /// Returns the fingerprint as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the fingerprint in lowercase.
    pub fn to_lowercase(&self) -> String {
        self.0.to_lowercase()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.0)
    }
}

impl FromStr for Fingerprint {
    type Err = FingerprintError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// A validated relay nickname.
///
/// Nicknames are human-readable identifiers for relays, consisting of
/// 1 to 19 alphanumeric ASCII characters. This type ensures the nickname
/// is valid at construction time.
///
/// # Format
///
/// - Length: 1 to 19 characters
/// - Characters: ASCII alphanumeric only (a-z, A-Z, 0-9)
///
/// # Example
///
/// ```rust
/// use stem_rs::types::Nickname;
/// use std::str::FromStr;
///
/// let nick = Nickname::from_str("MyRelay").unwrap();
/// assert_eq!(nick.as_str(), "MyRelay");
///
/// let invalid = Nickname::from_str("my-relay");
/// assert!(invalid.is_err());
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Nickname(String);

impl Nickname {
    /// Creates a new nickname from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not 1-19 alphanumeric characters.
    pub fn new(s: impl Into<String>) -> Result<Self, NicknameError> {
        let s = s.into();
        let len = s.len();
        if !(1..=MAX_NICKNAME_LENGTH).contains(&len) {
            return Err(NicknameError::InvalidLength);
        }
        if !s.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(NicknameError::InvalidCharacters);
        }
        Ok(Self(s))
    }

    /// Returns the nickname as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Nickname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Nickname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nickname({})", self.0)
    }
}

impl FromStr for Nickname {
    type Err = NicknameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// A validated Ed25519 public key.
///
/// Ed25519 public keys are 32-byte values used for modern Tor relay
/// identity and signing operations. This type ensures the key is valid
/// at construction time.
///
/// # Example
///
/// ```rust
/// use stem_rs::types::Ed25519PublicKey;
///
/// let bytes = [42u8; 32];
/// let key = Ed25519PublicKey::new(bytes);
/// let base64 = key.to_base64();
/// let decoded = Ed25519PublicKey::from_base64(&base64).unwrap();
/// assert_eq!(key, decoded);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey([u8; ED25519_PUBLIC_KEY_LENGTH]);

impl Ed25519PublicKey {
    /// Creates a new Ed25519 public key from raw bytes.
    pub fn new(bytes: [u8; ED25519_PUBLIC_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a new Ed25519 public key from base64-encoded string.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 is invalid or decodes to wrong length.
    pub fn from_base64(s: &str) -> Result<Self, Ed25519PublicKeyError> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let bytes = engine
            .decode(s)
            .map_err(|_| Ed25519PublicKeyError::InvalidBase64)?;

        if bytes.len() != ED25519_PUBLIC_KEY_LENGTH {
            return Err(Ed25519PublicKeyError::InvalidLength(bytes.len()));
        }

        let mut array = [0u8; ED25519_PUBLIC_KEY_LENGTH];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }

    /// Returns the key as a byte array reference.
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        &self.0
    }

    /// Encodes the key as base64.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        engine.encode(self.0)
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey({})", self.to_base64())
    }
}

impl FromStr for Ed25519PublicKey {
    type Err = Ed25519PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base64(s)
    }
}

/// A validated Ed25519 identity.
///
/// Ed25519 identities are 32-byte values that uniquely identify relays
/// in the modern Tor network. This type ensures the identity is valid
/// at construction time.
///
/// # Example
///
/// ```rust
/// use stem_rs::types::Ed25519Identity;
///
/// let bytes = [99u8; 32];
/// let identity = Ed25519Identity::new(bytes);
/// let base64 = identity.to_base64();
/// let decoded = Ed25519Identity::from_base64(&base64).unwrap();
/// assert_eq!(identity, decoded);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519Identity([u8; ED25519_PUBLIC_KEY_LENGTH]);

impl Ed25519Identity {
    /// Creates a new Ed25519 identity from raw bytes.
    pub fn new(bytes: [u8; ED25519_PUBLIC_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a new Ed25519 identity from base64-encoded string.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 is invalid or decodes to wrong length.
    pub fn from_base64(s: &str) -> Result<Self, Ed25519IdentityError> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let bytes = engine
            .decode(s)
            .map_err(|_| Ed25519IdentityError::InvalidBase64)?;

        if bytes.len() != ED25519_PUBLIC_KEY_LENGTH {
            return Err(Ed25519IdentityError::InvalidLength(bytes.len()));
        }

        let mut array = [0u8; ED25519_PUBLIC_KEY_LENGTH];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }

    /// Returns the identity as a byte array reference.
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        &self.0
    }

    /// Encodes the identity as base64.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        engine.encode(self.0)
    }
}

impl fmt::Display for Ed25519Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl fmt::Debug for Ed25519Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Identity({})", self.to_base64())
    }
}

impl FromStr for Ed25519Identity {
    type Err = Ed25519IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base64(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_valid() {
        let fp = Fingerprint::from_str("9695DFC35FFEB861329B9F1AB04C46397020CE31").unwrap();
        assert_eq!(fp.as_str(), "9695DFC35FFEB861329B9F1AB04C46397020CE31");
    }

    #[test]
    fn test_fingerprint_lowercase() {
        let fp = Fingerprint::from_str("9695dfc35ffeb861329b9f1ab04c46397020ce31").unwrap();
        assert_eq!(fp.as_str(), "9695DFC35FFEB861329B9F1AB04C46397020CE31");
    }

    #[test]
    fn test_fingerprint_invalid_length() {
        let result = Fingerprint::from_str("ABCD");
        assert!(matches!(result, Err(FingerprintError::InvalidLength)));
    }

    #[test]
    fn test_fingerprint_invalid_chars() {
        let result = Fingerprint::from_str("ZZZZDFC35FFEB861329B9F1AB04C46397020CE31");
        assert!(matches!(result, Err(FingerprintError::InvalidCharacters)));
    }

    #[test]
    fn test_nickname_valid() {
        let nick = Nickname::from_str("MyRelay").unwrap();
        assert_eq!(nick.as_str(), "MyRelay");
    }

    #[test]
    fn test_nickname_single_char() {
        let nick = Nickname::from_str("A").unwrap();
        assert_eq!(nick.as_str(), "A");
    }

    #[test]
    fn test_nickname_max_length() {
        let nick = Nickname::from_str("1234567890123456789").unwrap();
        assert_eq!(nick.as_str(), "1234567890123456789");
    }

    #[test]
    fn test_nickname_too_long() {
        let result = Nickname::from_str("12345678901234567890");
        assert!(matches!(result, Err(NicknameError::InvalidLength)));
    }

    #[test]
    fn test_nickname_empty() {
        let result = Nickname::from_str("");
        assert!(matches!(result, Err(NicknameError::InvalidLength)));
    }

    #[test]
    fn test_nickname_invalid_chars() {
        let result = Nickname::from_str("my-relay");
        assert!(matches!(result, Err(NicknameError::InvalidCharacters)));
    }

    #[test]
    fn test_ed25519_public_key_roundtrip() {
        let bytes = [42u8; 32];
        let key = Ed25519PublicKey::new(bytes);
        let base64 = key.to_base64();
        let decoded = Ed25519PublicKey::from_base64(&base64).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_ed25519_identity_roundtrip() {
        let bytes = [99u8; 32];
        let identity = Ed25519Identity::new(bytes);
        let base64 = identity.to_base64();
        let decoded = Ed25519Identity::from_base64(&base64).unwrap();
        assert_eq!(identity, decoded);
    }
}
