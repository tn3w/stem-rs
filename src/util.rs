//! Validation and helper functions for Tor-related data.
//!
//! This module provides utilities for validating Tor-specific identifiers and
//! performing secure operations. These functions are used throughout the library
//! to ensure data integrity and prevent protocol injection attacks.
//!
//! # Conceptual Role
//!
//! The validation functions in this module check format correctness for:
//! - Relay fingerprints (40-character hex strings)
//! - Relay nicknames (1-19 alphanumeric characters)
//! - Circuit and stream identifiers
//! - Hidden service addresses (v2 and v3)
//! - IP addresses and ports
//!
//! # Security Considerations
//!
//! - [`secure_compare`] uses constant-time comparison to prevent timing attacks
//! - Input validation prevents protocol injection in control commands
//! - All validation functions are pure and have no side effects
//!
//! # Example
//!
//! ```rust
//! use stem_rs::util::{is_valid_fingerprint, is_valid_nickname, is_valid_hidden_service_address};
//!
//! // Validate a relay fingerprint
//! assert!(is_valid_fingerprint("9695DFC35FFEB861329B9F1AB04C46397020CE31"));
//!
//! // Validate a relay nickname
//! assert!(is_valid_nickname("MyRelay"));
//! assert!(!is_valid_nickname("invalid-name")); // hyphens not allowed
//!
//! // Validate hidden service addresses
//! assert!(is_valid_hidden_service_address("facebookcorewwwi")); // v2
//! ```
//!
//! # See Also
//!
//! - [`Controller`](crate::Controller) - Uses these validators for input checking
//! - Python Stem equivalent: `stem.util.tor_tools`

/// Validates a relay fingerprint string.
///
/// A valid fingerprint consists of exactly 40 hexadecimal characters
/// (case-insensitive), representing a 160-bit SHA-1 hash of the relay's
/// identity key.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid fingerprint, `false` otherwise.
///
/// # Format
///
/// - Length: exactly 40 characters
/// - Characters: hexadecimal digits (0-9, a-f, A-F)
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_fingerprint;
///
/// // Valid fingerprints (case-insensitive)
/// assert!(is_valid_fingerprint("9695DFC35FFEB861329B9F1AB04C46397020CE31"));
/// assert!(is_valid_fingerprint("9695dfc35ffeb861329b9f1ab04c46397020ce31"));
///
/// // Invalid fingerprints
/// assert!(!is_valid_fingerprint("9695DFC35FFEB861329B9F1AB04C4639702")); // Too short
/// assert!(!is_valid_fingerprint("ZZZZDFC35FFEB861329B9F1AB04C46397020CE31")); // Invalid chars
/// ```
///
/// # This Compiles But Is Wrong
///
/// ```rust
/// use stem_rs::util::is_valid_fingerprint;
///
/// // Don't include the "$" prefix - that's for fingerprint references
/// let with_prefix = "$9695DFC35FFEB861329B9F1AB04C46397020CE31";
/// assert!(!is_valid_fingerprint(with_prefix)); // Returns false!
///
/// // Use is_valid_fingerprint_with_prefix for prefixed fingerprints
/// use stem_rs::util::is_valid_fingerprint_with_prefix;
/// assert!(is_valid_fingerprint_with_prefix(with_prefix));
/// ```
pub fn is_valid_fingerprint(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validates a relay fingerprint with optional `$` prefix.
///
/// This function accepts fingerprints with or without the `$` prefix
/// commonly used in Tor control protocol responses.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid fingerprint (with or without `$` prefix).
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_fingerprint_with_prefix;
///
/// // Both formats are valid
/// assert!(is_valid_fingerprint_with_prefix("$9695DFC35FFEB861329B9F1AB04C46397020CE31"));
/// assert!(is_valid_fingerprint_with_prefix("9695DFC35FFEB861329B9F1AB04C46397020CE31"));
///
/// // Invalid
/// assert!(!is_valid_fingerprint_with_prefix("$ABCD")); // Too short
/// ```
pub fn is_valid_fingerprint_with_prefix(s: &str) -> bool {
    if let Some(stripped) = s.strip_prefix('$') {
        is_valid_fingerprint(stripped)
    } else {
        is_valid_fingerprint(s)
    }
}

/// Validates a relay nickname.
///
/// A valid nickname consists of 1 to 19 alphanumeric ASCII characters.
/// Nicknames are used to identify relays in a human-readable format.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid nickname, `false` otherwise.
///
/// # Format
///
/// - Length: 1 to 19 characters
/// - Characters: ASCII alphanumeric only (a-z, A-Z, 0-9)
/// - No spaces, hyphens, underscores, or special characters
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_nickname;
///
/// // Valid nicknames
/// assert!(is_valid_nickname("MyRelay"));
/// assert!(is_valid_nickname("relay123"));
/// assert!(is_valid_nickname("A")); // Single character is valid
/// assert!(is_valid_nickname("1234567890123456789")); // 19 chars max
///
/// // Invalid nicknames
/// assert!(!is_valid_nickname("")); // Empty
/// assert!(!is_valid_nickname("12345678901234567890")); // 20 chars - too long
/// assert!(!is_valid_nickname("my-relay")); // Hyphens not allowed
/// assert!(!is_valid_nickname("my_relay")); // Underscores not allowed
/// assert!(!is_valid_nickname("my relay")); // Spaces not allowed
/// ```
///
/// # This Compiles But Is Wrong
///
/// ```rust
/// use stem_rs::util::is_valid_nickname;
///
/// // Nicknames are NOT case-insensitive identifiers
/// // "MyRelay" and "myrelay" are different nicknames
/// let nick1 = "MyRelay";
/// let nick2 = "myrelay";
/// assert!(is_valid_nickname(nick1));
/// assert!(is_valid_nickname(nick2));
/// // But they refer to different relays!
/// ```
pub fn is_valid_nickname(s: &str) -> bool {
    let len = s.len();
    (1..=19).contains(&len) && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Validates a circuit identifier.
///
/// Circuit IDs are numeric strings used to identify circuits in the
/// Tor control protocol.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid circuit ID, `false` otherwise.
///
/// # Format
///
/// - Non-empty string
/// - Contains only ASCII digits (0-9)
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_circuit_id;
///
/// assert!(is_valid_circuit_id("1"));
/// assert!(is_valid_circuit_id("123"));
/// assert!(is_valid_circuit_id("999999"));
///
/// assert!(!is_valid_circuit_id("")); // Empty
/// assert!(!is_valid_circuit_id("abc")); // Non-numeric
/// assert!(!is_valid_circuit_id("12a")); // Mixed
/// ```
pub fn is_valid_circuit_id(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// Validates a stream identifier.
///
/// Stream IDs are numeric strings used to identify streams in the
/// Tor control protocol. This function has the same validation rules
/// as [`is_valid_circuit_id`].
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid stream ID, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_stream_id;
///
/// assert!(is_valid_stream_id("1"));
/// assert!(is_valid_stream_id("456"));
///
/// assert!(!is_valid_stream_id("")); // Empty
/// assert!(!is_valid_stream_id("xyz")); // Non-numeric
/// ```
pub fn is_valid_stream_id(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// Validates an IPv4 address string.
///
/// Checks if the string is a valid IPv4 address in dotted-decimal notation.
/// Leading zeros in octets are not allowed (to avoid octal interpretation).
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid IPv4 address, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_ipv4_address;
///
/// assert!(is_valid_ipv4_address("127.0.0.1"));
/// assert!(is_valid_ipv4_address("192.168.1.1"));
/// assert!(is_valid_ipv4_address("0.0.0.0"));
/// assert!(is_valid_ipv4_address("255.255.255.255"));
///
/// assert!(!is_valid_ipv4_address("256.0.0.1")); // Octet > 255
/// assert!(!is_valid_ipv4_address("01.02.03.04")); // Leading zeros
/// assert!(!is_valid_ipv4_address("127.0.0")); // Missing octet
/// ```
pub fn is_valid_ipv4_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in &parts {
        if part.is_empty() {
            return false;
        }
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
        if part.parse::<u8>().is_err() {
            return false;
        }
    }
    true
}

/// Validates an IPv6 address string.
///
/// Checks if the string is a valid IPv6 address. Supports compressed
/// notation with `::` for consecutive zero groups.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid IPv6 address, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_ipv6_address;
///
/// assert!(is_valid_ipv6_address("2001:0db8:0000:0000:0000:ff00:0042:8329"));
/// assert!(is_valid_ipv6_address("2001:db8::ff00:42:8329")); // Compressed
/// assert!(is_valid_ipv6_address("::1")); // Loopback
/// assert!(is_valid_ipv6_address("::")); // All zeros
///
/// assert!(!is_valid_ipv6_address("2001:db8::ff00::8329")); // Multiple ::
/// ```
pub fn is_valid_ipv6_address(s: &str) -> bool {
    is_valid_ipv6_address_impl(s, false)
}

/// Validates an IPv6 address string, optionally with brackets.
///
/// Like [`is_valid_ipv6_address`], but also accepts addresses enclosed
/// in square brackets (e.g., `[::1]`), which is common in URLs.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid IPv6 address (with or without brackets).
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_ipv6_address_bracketed;
///
/// assert!(is_valid_ipv6_address_bracketed("[::1]"));
/// assert!(is_valid_ipv6_address_bracketed("[2001:db8::1]"));
/// assert!(is_valid_ipv6_address_bracketed("::1")); // Without brackets also valid
/// ```
pub fn is_valid_ipv6_address_bracketed(s: &str) -> bool {
    is_valid_ipv6_address_impl(s, true)
}

/// Internal implementation for IPv6 address validation.
fn is_valid_ipv6_address_impl(s: &str, allow_brackets: bool) -> bool {
    let addr = if allow_brackets && s.starts_with('[') && s.ends_with(']') {
        &s[1..s.len() - 1]
    } else {
        s
    };

    if addr.is_empty() {
        return false;
    }

    let colon_count = addr.matches(':').count();
    if colon_count > 7 {
        return false;
    }

    let has_double_colon = addr.contains("::");
    if !has_double_colon && colon_count != 7 {
        return false;
    }
    if addr.matches("::").count() > 1 || addr.contains(":::") {
        return false;
    }

    for group in addr.split(':') {
        if group.len() > 4 {
            return false;
        }
        if !group.is_empty() && !group.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

/// Validates a port number string.
///
/// Checks if the string represents a valid TCP/UDP port number (1-65535).
/// Port 0 is not considered valid.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid port number, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_port;
///
/// assert!(is_valid_port("80"));
/// assert!(is_valid_port("443"));
/// assert!(is_valid_port("9051")); // Tor control port
/// assert!(is_valid_port("65535"));
///
/// assert!(!is_valid_port("0")); // Port 0 not valid
/// assert!(!is_valid_port("65536")); // Too large
/// assert!(!is_valid_port("abc")); // Non-numeric
/// ```
pub fn is_valid_port(s: &str) -> bool {
    s.parse::<u16>().is_ok_and(|p| p > 0)
}

/// Validates a port number.
///
/// Checks if the port number is valid (1-65535). Port 0 is not considered valid.
///
/// # Arguments
///
/// * `port` - The port number to validate
///
/// # Returns
///
/// `true` if the port is valid (non-zero), `false` otherwise.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_port_number;
///
/// assert!(is_valid_port_number(80));
/// assert!(is_valid_port_number(9051));
/// assert!(is_valid_port_number(65535));
///
/// assert!(!is_valid_port_number(0));
/// ```
pub fn is_valid_port_number(port: u16) -> bool {
    port > 0
}

/// Checks if an IPv4 address is in a private range.
///
/// Returns `Some(true)` if the address is private (RFC 1918), `Some(false)`
/// if public, or `None` if the address is invalid.
///
/// # Private Ranges
///
/// - `10.0.0.0/8` - Class A private
/// - `172.16.0.0/12` - Class B private
/// - `192.168.0.0/16` - Class C private
/// - `127.0.0.0/8` - Loopback
///
/// # Arguments
///
/// * `s` - The IPv4 address string to check
///
/// # Returns
///
/// - `Some(true)` if the address is private
/// - `Some(false)` if the address is public
/// - `None` if the address is invalid
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_private_address;
///
/// assert_eq!(is_private_address("10.0.0.1"), Some(true));
/// assert_eq!(is_private_address("192.168.1.1"), Some(true));
/// assert_eq!(is_private_address("127.0.0.1"), Some(true));
/// assert_eq!(is_private_address("8.8.8.8"), Some(false));
/// assert_eq!(is_private_address("invalid"), None);
/// ```
pub fn is_private_address(s: &str) -> Option<bool> {
    if !is_valid_ipv4_address(s) {
        return None;
    }
    let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return None;
    }
    let is_private = parts[0] == 10
        || parts[0] == 127
        || (parts[0] == 192 && parts[1] == 168)
        || (parts[0] == 172 && (16..=31).contains(&parts[1]));
    Some(is_private)
}

/// Expands a compressed IPv6 address to full notation.
///
/// Converts an IPv6 address with `::` compression to its full 8-group
/// representation with each group zero-padded to 4 digits.
///
/// # Arguments
///
/// * `s` - The IPv6 address string to expand
///
/// # Returns
///
/// - `Some(String)` with the expanded address if valid
/// - `None` if the address is invalid
///
/// # Example
///
/// ```rust
/// use stem_rs::util::expand_ipv6_address;
///
/// assert_eq!(
///     expand_ipv6_address("::1"),
///     Some("0000:0000:0000:0000:0000:0000:0000:0001".to_string())
/// );
/// assert_eq!(
///     expand_ipv6_address("2001:db8::ff00:42:8329"),
///     Some("2001:0db8:0000:0000:0000:ff00:0042:8329".to_string())
/// );
/// assert_eq!(expand_ipv6_address("invalid"), None);
/// ```
pub fn expand_ipv6_address(s: &str) -> Option<String> {
    if !is_valid_ipv6_address(s) {
        return None;
    }

    let mut groups: Vec<String> = Vec::with_capacity(8);

    if s.contains("::") {
        let parts: Vec<&str> = s.split("::").collect();
        let left: Vec<&str> = if parts[0].is_empty() {
            vec![]
        } else {
            parts[0].split(':').collect()
        };
        let right: Vec<&str> = if parts.len() > 1 && !parts[1].is_empty() {
            parts[1].split(':').collect()
        } else {
            vec![]
        };

        for g in &left {
            groups.push(format!("{:0>4}", g.to_lowercase()));
        }
        let zeros_needed = 8 - left.len() - right.len();
        for _ in 0..zeros_needed {
            groups.push("0000".to_string());
        }
        for g in &right {
            groups.push(format!("{:0>4}", g.to_lowercase()));
        }
    } else {
        for g in s.split(':') {
            groups.push(format!("{:0>4}", g.to_lowercase()));
        }
    }

    Some(groups.join(":"))
}

/// Validates a connection_id(s: &str.
///
/// Connection IDs have the same format as circuit IDs. This function
/// is an alias for [`is_valid_circuit_id`].
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid connection ID, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_connection_id;
///
/// assert!(is_valid_connection_id("1"));
/// assert!(is_valid_connection_id("123"));
/// assert!(!is_valid_connection_id(""));
/// assert!(!is_valid_connection_id("abc"));
/// ```
pub fn is_valid_connection_id(s: &str) -> bool {
    is_valid_circuit_id(s)
}

/// Validates a hidden service address (v2 or v3).
///
/// Checks if the string is a valid hidden service address, supporting both
/// v2 (16 characters) and v3 (56 characters) formats. The `.onion` suffix
/// is optional.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid v2 or v3 hidden service address.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_hidden_service_address;
///
/// // V2 addresses (16 base32 characters)
/// assert!(is_valid_hidden_service_address("facebookcorewwwi"));
/// assert!(is_valid_hidden_service_address("facebookcorewwwi.onion"));
///
/// // V3 addresses (56 base32 characters)
/// let v3_addr = "a".repeat(56);
/// assert!(is_valid_hidden_service_address(&v3_addr));
///
/// // Invalid
/// assert!(!is_valid_hidden_service_address("invalid"));
/// ```
///
/// # See Also
///
/// - [`is_valid_hidden_service_address_v2`] - V2 only validation
/// - [`is_valid_hidden_service_address_v3`] - V3 only validation
pub fn is_valid_hidden_service_address(s: &str) -> bool {
    is_valid_hidden_service_address_v2(s) || is_valid_hidden_service_address_v3(s)
}

/// Validates a v2 hidden service address.
///
/// V2 hidden service addresses are 16 lowercase base32 characters
/// (a-z, 2-7). The `.onion` suffix is optional.
///
/// # Deprecation Note
///
/// V2 hidden services are deprecated and no longer supported by Tor
/// as of version 0.4.6. Use v3 addresses for new services.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid v2 hidden service address.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_hidden_service_address_v2;
///
/// assert!(is_valid_hidden_service_address_v2("facebookcorewwwi"));
/// assert!(is_valid_hidden_service_address_v2("facebookcorewwwi.onion"));
/// assert!(is_valid_hidden_service_address_v2("aaaaaaaaaaaaaaaa"));
///
/// // Invalid - uppercase not allowed
/// assert!(!is_valid_hidden_service_address_v2("FACEBOOKCOREWWWI"));
/// // Invalid - wrong length
/// assert!(!is_valid_hidden_service_address_v2("abc"));
/// ```
pub fn is_valid_hidden_service_address_v2(s: &str) -> bool {
    let addr = s.strip_suffix(".onion").unwrap_or(s);
    addr.len() == 16 && addr.chars().all(is_base32_char)
}

/// Validates a v3 hidden service address.
///
/// V3 hidden service addresses are 56 lowercase base32 characters
/// (a-z, 2-7). The `.onion` suffix is optional.
///
/// # Format
///
/// V3 addresses encode: `base32(PUBKEY | CHECKSUM | VERSION)`
/// - PUBKEY: 32-byte Ed25519 public key
/// - CHECKSUM: 2-byte truncated SHA3-256 hash
/// - VERSION: 1-byte version (0x03)
///
/// Note: This function only validates the format (length and character set),
/// not the cryptographic checksum.
///
/// # Arguments
///
/// * `s` - The string to validate
///
/// # Returns
///
/// `true` if the string is a valid v3 hidden service address format.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_valid_hidden_service_address_v3;
///
/// let v3_addr = "a".repeat(56);
/// assert!(is_valid_hidden_service_address_v3(&v3_addr));
/// assert!(is_valid_hidden_service_address_v3(&format!("{}.onion", v3_addr)));
///
/// // Invalid - wrong length
/// assert!(!is_valid_hidden_service_address_v3(&"a".repeat(55)));
/// // Invalid - uppercase not allowed
/// assert!(!is_valid_hidden_service_address_v3(&"A".repeat(56)));
/// ```
pub fn is_valid_hidden_service_address_v3(s: &str) -> bool {
    let addr = s.strip_suffix(".onion").unwrap_or(s);
    addr.len() == 56 && addr.chars().all(is_base32_char)
}

/// Checks if a character is a valid base32 character.
///
/// Base32 characters are lowercase letters a-z and digits 2-7.
fn is_base32_char(c: char) -> bool {
    matches!(c, 'a'..='z' | '2'..='7')
}

/// Checks if a string contains exactly the specified number of hex digits.
///
/// This is a helper function for validating fixed-length hexadecimal strings
/// like fingerprints and hashes.
///
/// # Arguments
///
/// * `s` - The string to check
/// * `length` - The expected number of hex digits
///
/// # Returns
///
/// `true` if the string has exactly `length` hexadecimal characters.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::is_hex_digits;
///
/// assert!(is_hex_digits("abcd", 4));
/// assert!(is_hex_digits("ABCD1234", 8));
/// assert!(is_hex_digits("0123456789abcdef", 16));
///
/// assert!(!is_hex_digits("abcd", 5)); // Wrong length
/// assert!(!is_hex_digits("ghij", 4)); // Invalid hex chars
/// ```
pub fn is_hex_digits(s: &str, length: usize) -> bool {
    s.len() == length && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Compares two byte slices in constant time.
///
/// This function performs a timing-safe comparison of two byte slices,
/// preventing timing attacks that could leak information about the
/// contents of secret data.
///
/// # Security
///
/// This function is designed to take the same amount of time regardless
/// of where the first difference occurs. This prevents attackers from
/// using timing measurements to guess secret values byte-by-byte.
///
/// Use this function when comparing:
/// - Authentication cookies
/// - HMAC values
/// - Password hashes
/// - Any security-sensitive data
///
/// # Arguments
///
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// `true` if the slices are equal, `false` otherwise.
///
/// # Implementation
///
/// The comparison XORs all bytes and accumulates differences, ensuring
/// all bytes are always compared regardless of early mismatches.
///
/// # Example
///
/// ```rust
/// use stem_rs::util::secure_compare;
///
/// let secret = b"my_secret_cookie";
/// let attempt = b"my_secret_cookie";
/// let wrong = b"wrong_cookie_val";
///
/// assert!(secure_compare(secret, attempt));
/// assert!(!secure_compare(secret, wrong));
///
/// // Different lengths always return false
/// assert!(!secure_compare(b"short", b"longer"));
/// ```
///
/// # This Compiles But Is Wrong
///
/// ```rust
/// // DON'T use regular equality for secrets - it's vulnerable to timing attacks
/// let secret = b"authentication_cookie";
/// let attempt = b"authentication_cookie";
///
/// // This is INSECURE - timing varies based on first differing byte
/// // if secret == attempt { ... }
///
/// // Use secure_compare instead
/// use stem_rs::util::secure_compare;
/// if secure_compare(secret, attempt) {
///     // Safe comparison
/// }
/// ```
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_fingerprint() {
        assert!(is_valid_fingerprint(
            "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
        ));
        assert!(is_valid_fingerprint(
            "abcd1234abcd1234abcd1234abcd1234abcd1234"
        ));
        assert!(is_valid_fingerprint(
            "0123456789abcdef0123456789ABCDEF01234567"
        ));
    }

    #[test]
    fn test_invalid_fingerprint() {
        assert!(!is_valid_fingerprint(""));
        assert!(!is_valid_fingerprint("ABCD1234"));
        assert!(!is_valid_fingerprint(
            "GHIJ1234GHIJ1234GHIJ1234GHIJ1234GHIJ1234"
        ));
        assert!(!is_valid_fingerprint(
            "ABCD1234ABCD1234ABCD1234ABCD1234ABCD12345"
        ));
    }

    #[test]
    fn test_fingerprint_with_prefix() {
        assert!(is_valid_fingerprint_with_prefix(
            "$ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
        ));
        assert!(is_valid_fingerprint_with_prefix(
            "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
        ));
        assert!(!is_valid_fingerprint_with_prefix("$ABCD"));
    }

    #[test]
    fn test_valid_nickname() {
        assert!(is_valid_nickname("MyRelay"));
        assert!(is_valid_nickname("relay123"));
        assert!(is_valid_nickname("A"));
        assert!(is_valid_nickname("1234567890123456789"));
    }

    #[test]
    fn test_invalid_nickname() {
        assert!(!is_valid_nickname(""));
        assert!(!is_valid_nickname("12345678901234567890"));
        assert!(!is_valid_nickname("my-relay"));
        assert!(!is_valid_nickname("my_relay"));
        assert!(!is_valid_nickname("my relay"));
    }

    #[test]
    fn test_valid_circuit_id() {
        assert!(is_valid_circuit_id("1"));
        assert!(is_valid_circuit_id("123"));
        assert!(is_valid_circuit_id("999999"));
    }

    #[test]
    fn test_invalid_circuit_id() {
        assert!(!is_valid_circuit_id(""));
        assert!(!is_valid_circuit_id("abc"));
        assert!(!is_valid_circuit_id("12a"));
    }

    #[test]
    fn test_valid_stream_id() {
        assert!(is_valid_stream_id("1"));
        assert!(is_valid_stream_id("456"));
    }

    #[test]
    fn test_invalid_stream_id() {
        assert!(!is_valid_stream_id(""));
        assert!(!is_valid_stream_id("xyz"));
    }

    #[test]
    fn test_valid_ipv4_address() {
        assert!(is_valid_ipv4_address("127.0.0.1"));
        assert!(is_valid_ipv4_address("192.168.1.1"));
        assert!(is_valid_ipv4_address("0.0.0.0"));
        assert!(is_valid_ipv4_address("255.255.255.255"));
    }

    #[test]
    fn test_invalid_ipv4_address() {
        assert!(!is_valid_ipv4_address(""));
        assert!(!is_valid_ipv4_address("127.0.0"));
        assert!(!is_valid_ipv4_address("127.0.0.1.1"));
        assert!(!is_valid_ipv4_address("256.0.0.1"));
        assert!(!is_valid_ipv4_address("abc.def.ghi.jkl"));
        assert!(!is_valid_ipv4_address("localhost"));
    }

    #[test]
    fn test_valid_port() {
        assert!(is_valid_port("1"));
        assert!(is_valid_port("80"));
        assert!(is_valid_port("443"));
        assert!(is_valid_port("9051"));
        assert!(is_valid_port("65535"));
    }

    #[test]
    fn test_invalid_port() {
        assert!(!is_valid_port(""));
        assert!(!is_valid_port("0"));
        assert!(!is_valid_port("65536"));
        assert!(!is_valid_port("-1"));
        assert!(!is_valid_port("abc"));
    }

    #[test]
    fn test_valid_hidden_service_v2() {
        assert!(is_valid_hidden_service_address_v2("abcdefghijklmnop"));
        assert!(is_valid_hidden_service_address_v2("abcdefghijklmnop.onion"));
        assert!(is_valid_hidden_service_address_v2("2222222222222222"));
    }

    #[test]
    fn test_invalid_hidden_service_v2() {
        assert!(!is_valid_hidden_service_address_v2(""));
        assert!(!is_valid_hidden_service_address_v2("abc"));
        assert!(!is_valid_hidden_service_address_v2("ABCDEFGHIJKLMNOP"));
        assert!(!is_valid_hidden_service_address_v2("abcdefghijklmno1"));
    }

    #[test]
    fn test_valid_hidden_service_v3() {
        let v3_addr = "a".repeat(56);
        assert!(is_valid_hidden_service_address_v3(&v3_addr));
        assert!(is_valid_hidden_service_address_v3(&format!(
            "{}.onion",
            v3_addr
        )));
    }

    #[test]
    fn test_invalid_hidden_service_v3() {
        assert!(!is_valid_hidden_service_address_v3(""));
        assert!(!is_valid_hidden_service_address_v3(&"a".repeat(55)));
        assert!(!is_valid_hidden_service_address_v3(&"A".repeat(56)));
    }

    #[test]
    fn test_hidden_service_address_combined() {
        assert!(is_valid_hidden_service_address("abcdefghijklmnop"));
        assert!(is_valid_hidden_service_address(&"a".repeat(56)));
        assert!(!is_valid_hidden_service_address("invalid"));
    }

    #[test]
    fn test_is_hex_digits() {
        assert!(is_hex_digits("abcd", 4));
        assert!(is_hex_digits("ABCD1234", 8));
        assert!(!is_hex_digits("abcd", 5));
        assert!(!is_hex_digits("ghij", 4));
    }

    #[test]
    fn test_secure_compare_equal() {
        assert!(secure_compare(b"hello", b"hello"));
        assert!(secure_compare(b"", b""));
        assert!(secure_compare(&[0, 1, 2, 3], &[0, 1, 2, 3]));
    }

    #[test]
    fn test_secure_compare_not_equal() {
        assert!(!secure_compare(b"hello", b"world"));
        assert!(!secure_compare(b"hello", b"hell"));
        assert!(!secure_compare(&[0, 1, 2, 3], &[0, 1, 2, 4]));
    }

    #[test]
    fn test_secure_compare_different_lengths() {
        assert!(!secure_compare(b"short", b"longer"));
        assert!(!secure_compare(b"", b"x"));
    }

    #[test]
    fn test_valid_hidden_service_real_addresses() {
        assert!(is_valid_hidden_service_address_v2("facebookcorewwwi"));
        assert!(is_valid_hidden_service_address_v2("aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn test_invalid_hidden_service_v2_with_invalid_chars() {
        assert!(!is_valid_hidden_service_address_v2("facebookc0rewwwi"));
        assert!(!is_valid_hidden_service_address_v2("facebookcorew wi"));
    }

    #[test]
    fn test_valid_fingerprint_with_dollar_prefix() {
        assert!(is_valid_fingerprint_with_prefix(
            "$A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB"
        ));
        assert!(is_valid_fingerprint_with_prefix(
            "$a7569a83b5706ab1b1a9cb52eff7d2d32e4553eb"
        ));
    }

    #[test]
    fn test_invalid_fingerprint_various() {
        assert!(!is_valid_fingerprint(
            "A7569A83B5706AB1B1A9CB52EFF7D2D32E4553E"
        ));
        assert!(!is_valid_fingerprint(
            "A7569A83B5706AB1B1A9CB52EFF7D2D32E4553E33"
        ));
        assert!(!is_valid_fingerprint(
            "A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EG"
        ));
    }

    #[test]
    fn test_valid_nickname_various() {
        assert!(is_valid_nickname("caerSidi"));
        assert!(is_valid_nickname("a"));
        assert!(is_valid_nickname("abcABC123"));
    }

    #[test]
    fn test_invalid_nickname_various() {
        assert!(!is_valid_nickname("toolongggggggggggggg"));
        assert!(!is_valid_nickname("bad_character"));
        assert!(!is_valid_nickname("bad-character"));
        assert!(!is_valid_nickname("bad character"));
    }

    #[test]
    fn test_valid_circuit_id_various() {
        assert!(is_valid_circuit_id("0"));
        assert!(is_valid_circuit_id("2"));
        assert!(is_valid_circuit_id("123456789"));
    }

    #[test]
    fn test_is_hex_digits_various() {
        assert!(is_hex_digits("12345", 5));
        assert!(is_hex_digits("AbCdE", 5));
        assert!(is_hex_digits("abcdef", 6));
        assert!(is_hex_digits("ABCDEF", 6));
        assert!(!is_hex_digits("X", 1));
        assert!(!is_hex_digits("1234", 5));
        assert!(!is_hex_digits("ABCDEF", 5));
    }

    #[test]
    fn test_valid_hidden_service_v3_real_addresses() {
        let valid_base32_56 = "a".repeat(56);
        assert!(is_valid_hidden_service_address_v3(&valid_base32_56));

        let too_short = "a".repeat(55);
        assert!(!is_valid_hidden_service_address_v3(&too_short));

        let too_long = "a".repeat(57);
        assert!(!is_valid_hidden_service_address_v3(&too_long));
    }

    #[test]
    fn test_hidden_service_with_onion_suffix() {
        assert!(is_valid_hidden_service_address_v2("facebookcorewwwi.onion"));
        let v3_addr = format!("{}.onion", "a".repeat(56));
        assert!(is_valid_hidden_service_address_v3(&v3_addr));
    }

    #[test]
    fn test_secure_compare_timing_safety() {
        let a = b"secret_cookie_value_1234567890ab";
        let b = b"secret_cookie_value_1234567890ab";
        let c = b"secret_cookie_value_1234567890ac";
        let d = b"different_length";

        assert!(secure_compare(a, b));
        assert!(!secure_compare(a, c));
        assert!(!secure_compare(a, d));

        assert!(secure_compare(&[], &[]));

        let base = b"0123456789abcdef";
        let diff_start = b"X123456789abcdef";
        let diff_middle = b"01234567X9abcdef";
        let diff_end = b"0123456789abcdeX";

        assert!(!secure_compare(base, diff_start));
        assert!(!secure_compare(base, diff_middle));
        assert!(!secure_compare(base, diff_end));
    }

    #[test]
    fn test_valid_ipv6_address() {
        assert!(is_valid_ipv6_address(
            "2001:0db8:0000:0000:0000:ff00:0042:8329"
        ));
        assert!(is_valid_ipv6_address("2001:db8::ff00:42:8329"));
        assert!(is_valid_ipv6_address("::1"));
        assert!(is_valid_ipv6_address("::"));
        assert!(is_valid_ipv6_address("fe80::1"));
        assert!(!is_valid_ipv6_address("::ffff:192.0.2.1")); // ipv4-mapped not supported
    }

    #[test]
    fn test_invalid_ipv6_address() {
        assert!(!is_valid_ipv6_address(""));
        assert!(!is_valid_ipv6_address("2001:db8::ff00::8329")); // multiple ::
        assert!(!is_valid_ipv6_address("2001:db8:ff00:42:8329")); // too few groups
        assert!(!is_valid_ipv6_address("2001:db8:::ff00:42:8329")); // :::
        assert!(!is_valid_ipv6_address(
            "2001:db8:0000:0000:0000:0000:0000:0000:0000"
        )); // too many
        assert!(!is_valid_ipv6_address("gggg:db8::1")); // invalid hex
    }

    #[test]
    fn test_ipv6_address_bracketed() {
        assert!(is_valid_ipv6_address_bracketed("[::1]"));
        assert!(is_valid_ipv6_address_bracketed("[2001:db8::1]"));
        assert!(is_valid_ipv6_address_bracketed("::1"));
        assert!(!is_valid_ipv6_address_bracketed("[invalid]"));
    }

    #[test]
    fn test_is_private_address() {
        assert_eq!(is_private_address("10.0.0.1"), Some(true));
        assert_eq!(is_private_address("10.255.255.255"), Some(true));
        assert_eq!(is_private_address("192.168.1.1"), Some(true));
        assert_eq!(is_private_address("172.16.0.1"), Some(true));
        assert_eq!(is_private_address("172.31.255.255"), Some(true));
        assert_eq!(is_private_address("127.0.0.1"), Some(true));
        assert_eq!(is_private_address("8.8.8.8"), Some(false));
        assert_eq!(is_private_address("172.15.0.1"), Some(false));
        assert_eq!(is_private_address("172.32.0.1"), Some(false));
        assert_eq!(is_private_address("invalid"), None);
    }

    #[test]
    fn test_expand_ipv6_address() {
        assert_eq!(
            expand_ipv6_address("2001:db8::ff00:42:8329"),
            Some("2001:0db8:0000:0000:0000:ff00:0042:8329".to_string())
        );
        assert_eq!(
            expand_ipv6_address("::"),
            Some("0000:0000:0000:0000:0000:0000:0000:0000".to_string())
        );
        assert_eq!(
            expand_ipv6_address("::1"),
            Some("0000:0000:0000:0000:0000:0000:0000:0001".to_string())
        );
        assert_eq!(
            expand_ipv6_address("fe80::"),
            Some("fe80:0000:0000:0000:0000:0000:0000:0000".to_string())
        );
        assert_eq!(expand_ipv6_address("invalid"), None);
    }

    #[test]
    fn test_is_valid_connection_id() {
        assert!(is_valid_connection_id("1"));
        assert!(is_valid_connection_id("123"));
        assert!(!is_valid_connection_id(""));
        assert!(!is_valid_connection_id("abc"));
    }

    #[test]
    fn test_is_valid_port_number() {
        assert!(is_valid_port_number(1));
        assert!(is_valid_port_number(80));
        assert!(is_valid_port_number(65535));
        assert!(!is_valid_port_number(0));
    }

    #[test]
    fn test_ipv4_leading_zeros() {
        assert!(!is_valid_ipv4_address("01.02.03.04"));
        assert!(!is_valid_ipv4_address("1.2.3.001"));
        assert!(is_valid_ipv4_address("1.2.3.0"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::char::range as char_range;
    use proptest::prelude::*;

    fn hex_char() -> impl Strategy<Value = char> {
        prop_oneof![
            char_range('a', 'f'),
            char_range('A', 'F'),
            char_range('0', '9'),
        ]
    }

    fn valid_fingerprint_strategy() -> impl Strategy<Value = String> {
        proptest::collection::vec(hex_char(), 40).prop_map(|chars| chars.into_iter().collect())
    }

    fn alphanumeric_char() -> impl Strategy<Value = char> {
        prop_oneof![
            char_range('a', 'z'),
            char_range('A', 'Z'),
            char_range('0', '9'),
        ]
    }

    fn valid_nickname_strategy() -> impl Strategy<Value = String> {
        proptest::collection::vec(alphanumeric_char(), 1..=19)
            .prop_map(|chars| chars.into_iter().collect())
    }

    fn base32_char() -> impl Strategy<Value = char> {
        prop_oneof![char_range('a', 'z'), char_range('2', '7'),]
    }

    fn valid_v2_address_strategy() -> impl Strategy<Value = String> {
        proptest::collection::vec(base32_char(), 16).prop_map(|chars| chars.into_iter().collect())
    }

    fn valid_v3_address_strategy() -> impl Strategy<Value = String> {
        proptest::collection::vec(base32_char(), 56).prop_map(|chars| chars.into_iter().collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_valid_fingerprint_accepted(fp in valid_fingerprint_strategy()) {
            prop_assert!(is_valid_fingerprint(&fp), "valid fingerprint rejected: {}", fp);
        }

        #[test]
        fn prop_invalid_fingerprint_wrong_length(
            chars in proptest::collection::vec(hex_char(), 0..40usize)
        ) {
            let s: String = chars.into_iter().collect();
            prop_assert!(!is_valid_fingerprint(&s), "short fingerprint accepted: {}", s);
        }

        #[test]
        fn prop_invalid_fingerprint_too_long(
            chars in proptest::collection::vec(hex_char(), 41..60usize)
        ) {
            let s: String = chars.into_iter().collect();
            prop_assert!(!is_valid_fingerprint(&s), "long fingerprint accepted: {}", s);
        }

        #[test]
        fn prop_valid_nickname_accepted(nick in valid_nickname_strategy()) {
            prop_assert!(is_valid_nickname(&nick), "valid nickname rejected: {}", nick);
        }

        #[test]
        fn prop_invalid_nickname_too_long(
            chars in proptest::collection::vec(alphanumeric_char(), 20..30usize)
        ) {
            let s: String = chars.into_iter().collect();
            prop_assert!(!is_valid_nickname(&s), "long nickname accepted: {}", s);
        }

        #[test]
        fn prop_valid_v2_address_accepted(addr in valid_v2_address_strategy()) {
            prop_assert!(
                is_valid_hidden_service_address_v2(&addr),
                "valid v2 address rejected: {}", addr
            );
            prop_assert!(
                is_valid_hidden_service_address(&addr),
                "valid v2 address rejected by combined check: {}", addr
            );
        }

        #[test]
        fn prop_valid_v3_address_accepted(addr in valid_v3_address_strategy()) {
            prop_assert!(
                is_valid_hidden_service_address_v3(&addr),
                "valid v3 address rejected: {}", addr
            );
            prop_assert!(
                is_valid_hidden_service_address(&addr),
                "valid v3 address rejected by combined check: {}", addr
            );
        }

        #[test]
        fn prop_invalid_v2_address_wrong_length(
            chars in proptest::collection::vec(base32_char(), 0..16usize)
        ) {
            let s: String = chars.into_iter().collect();
            prop_assert!(
                !is_valid_hidden_service_address_v2(&s),
                "short v2 address accepted: {}", s
            );
        }

        #[test]
        fn prop_invalid_v3_address_wrong_length(
            chars in proptest::collection::vec(base32_char(), 0..56usize)
        ) {
            let s: String = chars.into_iter().collect();
            if s.len() != 16 {
                prop_assert!(
                    !is_valid_hidden_service_address(&s),
                    "wrong length address accepted: {}", s
                );
            }
        }
    }

    #[test]
    fn prop_invalid_nickname_empty() {
        assert!(!is_valid_nickname(""));
    }
}
