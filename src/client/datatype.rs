//! Data types for the Tor relay protocol.
//!
//! This module provides low-level data types used in ORPort communication
//! with Tor relays. These types handle the binary encoding and decoding
//! of protocol messages as defined in the
//! [Tor specification](https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt).
//!
//! # Overview
//!
//! The module contains several categories of types:
//!
//! - **Size types**: [`Size`] for packing/unpacking integers of various widths
//! - **Protocol versioning**: [`LinkProtocol`] for version-dependent constants
//! - **Addressing**: [`Address`], [`AddrType`], and [`LinkSpecifier`] for relay addresses
//! - **Certificates**: [`Certificate`] and [`CertType`] for relay certificates
//! - **Commands**: [`RelayCommand`] and [`CloseReason`] for circuit operations
//! - **Key derivation**: [`KDF`] for cryptographic key material
//!
//! # Conceptual Role
//!
//! These types form the foundation of the ORPort protocol implementation.
//! They handle the serialization and deserialization of binary data according
//! to Tor's wire format, which uses big-endian byte ordering throughout.
//!
//! Most users should interact with the higher-level [`Relay`](super::Relay)
//! and [`RelayCircuit`](super::RelayCircuit) types rather than using these
//! primitives directly.
//!
//! # Wire Format
//!
//! All multi-byte integers are encoded in network byte order (big-endian).
//! Variable-length fields are typically prefixed with their length.
//!
//! # Example
//!
//! ```rust
//! use stem_rs::client::datatype::{Size, Address, AddrType};
//!
//! // Pack and unpack integers
//! let packed = Size::Short.pack(9001);
//! assert_eq!(packed, vec![0x23, 0x29]);
//!
//! let unpacked = Size::Short.unpack(&packed).unwrap();
//! assert_eq!(unpacked, 9001);
//!
//! // Parse an IPv4 address
//! let addr = Address::new("127.0.0.1").unwrap();
//! assert_eq!(addr.addr_type, AddrType::IPv4);
//! ```
//!
//! # Security Considerations
//!
//! These types handle untrusted network data. All parsing functions validate
//! input lengths and return errors for malformed data rather than panicking.
//!
//! # See Also
//!
//! - [`cell`](super::cell) - Cell types that use these data types for encoding
//! - [`Relay`](super::Relay) - High-level relay connection interface
//! - [`RelayCircuit`](super::RelayCircuit) - Circuit management using these primitives

use crate::Error;
use sha1::{Digest, Sha1};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Null byte constant used for padding in the Tor protocol.
pub const ZERO: u8 = 0x00;

/// Length of SHA-1 hash output in bytes (160 bits).
///
/// Used throughout the Tor protocol for identity fingerprints and
/// key derivation functions.
pub const HASH_LEN: usize = 20;

/// Length of symmetric encryption keys in bytes (128 bits).
///
/// Used for AES-128-CTR encryption in relay cells.
pub const KEY_LEN: usize = 16;

/// Splits a byte slice at the given position, clamping to the slice length.
///
/// This is a helper function for parsing binary data that safely handles
/// cases where the requested split position exceeds the slice length.
///
/// # Arguments
///
/// * `content` - The byte slice to split
/// * `size` - The position at which to split (clamped to `content.len()`)
///
/// # Returns
///
/// A tuple of `(left, right)` where:
/// - `left` contains bytes `[0..min(size, len))`
/// - `right` contains the remaining bytes
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::split;
///
/// let data = b"hello";
/// let (left, right) = split(data, 2);
/// assert_eq!(left, b"he");
/// assert_eq!(right, b"llo");
///
/// // Size exceeds length - returns entire slice and empty remainder
/// let (left, right) = split(data, 100);
/// assert_eq!(left, b"hello");
/// assert_eq!(right, b"");
/// ```
pub fn split(content: &[u8], size: usize) -> (&[u8], &[u8]) {
    content.split_at(size.min(content.len()))
}

/// Integer size types for packing and unpacking binary data.
///
/// The Tor protocol uses fixed-width unsigned integers in network byte order
/// (big-endian). This enum provides methods for encoding and decoding these
/// integers according to the
/// [struct pack format](https://docs.python.org/3/library/struct.html#format-characters).
///
/// # Variants
///
/// | Variant    | Size    | Range                    |
/// |------------|---------|--------------------------|
/// | `Char`     | 1 byte  | 0 to 255                 |
/// | `Short`    | 2 bytes | 0 to 65,535              |
/// | `Long`     | 4 bytes | 0 to 4,294,967,295       |
/// | `LongLong` | 8 bytes | 0 to 18,446,744,073,709,551,615 |
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::Size;
///
/// // Pack a 16-bit port number
/// let port: u64 = 9001;
/// let packed = Size::Short.pack(port);
/// assert_eq!(packed, vec![0x23, 0x29]);
///
/// // Unpack it back
/// let unpacked = Size::Short.unpack(&packed).unwrap();
/// assert_eq!(unpacked, 9001);
///
/// // Pop from a larger buffer
/// let buffer = vec![0x23, 0x29, 0xFF, 0xFF];
/// let (value, remainder) = Size::Short.pop(&buffer).unwrap();
/// assert_eq!(value, 9001);
/// assert_eq!(remainder, &[0xFF, 0xFF]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Size {
    /// Unsigned 8-bit integer (1 byte).
    Char,
    /// Unsigned 16-bit integer (2 bytes, big-endian).
    Short,
    /// Unsigned 32-bit integer (4 bytes, big-endian).
    Long,
    /// Unsigned 64-bit integer (8 bytes, big-endian).
    LongLong,
}

impl Size {
    /// Returns the size in bytes for this integer type.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::Size;
    ///
    /// assert_eq!(Size::Char.size(), 1);
    /// assert_eq!(Size::Short.size(), 2);
    /// assert_eq!(Size::Long.size(), 4);
    /// assert_eq!(Size::LongLong.size(), 8);
    /// ```
    pub fn size(&self) -> usize {
        match self {
            Size::Char => 1,
            Size::Short => 2,
            Size::Long => 4,
            Size::LongLong => 8,
        }
    }

    /// Packs an integer value into big-endian bytes.
    ///
    /// # Arguments
    ///
    /// * `value` - The integer value to pack (truncated to fit the size)
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the packed bytes in network byte order.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::Size;
    ///
    /// assert_eq!(Size::Char.pack(0x12), vec![0x12]);
    /// assert_eq!(Size::Short.pack(0x1234), vec![0x12, 0x34]);
    /// assert_eq!(Size::Long.pack(0x12345678), vec![0x12, 0x34, 0x56, 0x78]);
    /// ```
    pub fn pack(&self, value: u64) -> Vec<u8> {
        match self {
            Size::Char => vec![value as u8],
            Size::Short => (value as u16).to_be_bytes().to_vec(),
            Size::Long => (value as u32).to_be_bytes().to_vec(),
            Size::LongLong => value.to_be_bytes().to_vec(),
        }
    }

    /// Unpacks big-endian bytes into an integer value.
    ///
    /// # Arguments
    ///
    /// * `data` - The bytes to unpack (must be exactly `self.size()` bytes)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if `data.len()` does not match `self.size()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::Size;
    ///
    /// assert_eq!(Size::Char.unpack(&[0x12]).unwrap(), 0x12);
    /// assert_eq!(Size::Short.unpack(&[0x12, 0x34]).unwrap(), 0x1234);
    ///
    /// // Wrong size returns an error
    /// assert!(Size::Short.unpack(&[0x12]).is_err());
    /// ```
    pub fn unpack(&self, data: &[u8]) -> Result<u64, Error> {
        if data.len() != self.size() {
            return Err(Error::Protocol(format!(
                "{:?} is the wrong size for a {:?} field",
                data, self
            )));
        }
        Ok(match self {
            Size::Char => data[0] as u64,
            Size::Short => u16::from_be_bytes([data[0], data[1]]) as u64,
            Size::Long => u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64,
            Size::LongLong => u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
        })
    }

    /// Unpacks an integer from the start of a byte slice, returning the remainder.
    ///
    /// This is useful for parsing sequential fields from a binary buffer.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice to read from (must have at least `self.size()` bytes)
    ///
    /// # Returns
    ///
    /// A tuple of `(value, remainder)` where:
    /// - `value` is the unpacked integer
    /// - `remainder` is the unconsumed portion of the input
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if `data.len()` is less than `self.size()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::Size;
    ///
    /// let data = vec![0x00, 0x12, 0xFF, 0xFF];
    /// let (value, rest) = Size::Short.pop(&data).unwrap();
    /// assert_eq!(value, 18);
    /// assert_eq!(rest, &[0xFF, 0xFF]);
    /// ```
    pub fn pop<'a>(&self, data: &'a [u8]) -> Result<(u64, &'a [u8]), Error> {
        if data.len() < self.size() {
            return Err(Error::Protocol(format!(
                "{:?} is the wrong size for a {:?} field",
                data, self
            )));
        }
        let (to_unpack, remainder) = split(data, self.size());
        Ok((self.unpack(to_unpack)?, remainder))
    }
}

/// Link protocol version with version-dependent constants.
///
/// The Tor link protocol has evolved over time, with different versions
/// using different field sizes and constants. This struct encapsulates
/// the version-specific parameters needed for cell encoding and decoding.
///
/// # Version Differences
///
/// | Version | Circuit ID Size | First Circuit ID | Fixed Cell Length |
/// |---------|-----------------|------------------|-------------------|
/// | 1-3     | 2 bytes (Short) | 0x0001           | 512 bytes         |
/// | 4+      | 4 bytes (Long)  | 0x80000000       | 514 bytes         |
///
/// The `first_circ_id` determines the starting point for client-initiated
/// circuit identifiers. Clients use IDs with the high bit set (version 4+)
/// or starting from 1 (version 1-3).
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::{LinkProtocol, Size};
///
/// // Version 3 uses 2-byte circuit IDs
/// let v3 = LinkProtocol::new(3);
/// assert_eq!(v3.circ_id_size, Size::Short);
/// assert_eq!(v3.first_circ_id, 0x01);
///
/// // Version 5 uses 4-byte circuit IDs
/// let v5 = LinkProtocol::new(5);
/// assert_eq!(v5.circ_id_size, Size::Long);
/// assert_eq!(v5.first_circ_id, 0x80000000);
/// ```
///
/// # Equality
///
/// `LinkProtocol` can be compared directly with `u32` version numbers:
///
/// ```rust
/// use stem_rs::client::datatype::LinkProtocol;
///
/// let protocol = LinkProtocol::new(5);
/// assert!(protocol == 5);
/// assert!(protocol != 4);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkProtocol {
    /// The link protocol version number.
    pub version: u32,
    /// Size of circuit identifier fields (2 or 4 bytes).
    pub circ_id_size: Size,
    /// Total length of fixed-size cells in bytes.
    pub fixed_cell_length: usize,
    /// First circuit ID to use when creating circuits.
    ///
    /// Clients pick circuit IDs from a range determined by the protocol version
    /// to avoid collisions with relay-initiated circuits.
    pub first_circ_id: u32,
}

impl LinkProtocol {
    /// Creates a new `LinkProtocol` for the given version number.
    ///
    /// This automatically configures all version-dependent constants based
    /// on the protocol specification.
    ///
    /// # Arguments
    ///
    /// * `version` - The link protocol version (typically 4 or 5 for modern Tor)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::LinkProtocol;
    ///
    /// let protocol = LinkProtocol::new(5);
    /// assert_eq!(protocol.version, 5);
    /// assert_eq!(protocol.fixed_cell_length, 514);
    /// ```
    pub fn new(version: u32) -> Self {
        let circ_id_size = if version > 3 { Size::Long } else { Size::Short };
        let first_circ_id = if version > 3 { 0x80000000 } else { 0x01 };
        let cell_header_size = circ_id_size.size() + 1;
        let fixed_cell_length = cell_header_size + super::cell::FIXED_PAYLOAD_LEN;

        LinkProtocol {
            version,
            circ_id_size,
            fixed_cell_length,
            first_circ_id,
        }
    }
}

impl From<u32> for LinkProtocol {
    /// Creates a `LinkProtocol` from a version number.
    fn from(version: u32) -> Self {
        LinkProtocol::new(version)
    }
}

impl PartialEq<u32> for LinkProtocol {
    /// Compares the protocol version with a `u32`.
    fn eq(&self, other: &u32) -> bool {
        self.version == *other
    }
}

/// Address type identifier for relay addresses.
///
/// Indicates the format of an address in the Tor protocol. This is used
/// in NETINFO cells and other places where addresses are exchanged.
///
/// # Variants
///
/// | Variant          | Value | Description                              |
/// |------------------|-------|------------------------------------------|
/// | `Hostname`       | 0     | DNS hostname (not typically used)        |
/// | `IPv4`           | 4     | IPv4 address (4 bytes)                   |
/// | `IPv6`           | 6     | IPv6 address (16 bytes)                  |
/// | `ErrorTransient` | 16    | Temporary error retrieving address       |
/// | `ErrorPermanent` | 17    | Permanent error retrieving address       |
/// | `Unknown`        | -     | Unrecognized address type                |
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::AddrType;
///
/// let (addr_type, raw_value) = AddrType::get(4);
/// assert_eq!(addr_type, AddrType::IPv4);
/// assert_eq!(raw_value, 4);
///
/// // Unknown types preserve the raw value
/// let (addr_type, raw_value) = AddrType::get(99);
/// assert_eq!(addr_type, AddrType::Unknown);
/// assert_eq!(raw_value, 99);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrType {
    /// DNS hostname.
    Hostname = 0,
    /// IPv4 address (4 bytes).
    IPv4 = 4,
    /// IPv6 address (16 bytes).
    IPv6 = 6,
    /// Temporary error retrieving the address.
    ErrorTransient = 16,
    /// Permanent error retrieving the address.
    ErrorPermanent = 17,
    /// Unrecognized address type.
    Unknown,
}

impl AddrType {
    /// Converts a raw byte value to an `AddrType` and its integer representation.
    ///
    /// # Arguments
    ///
    /// * `val` - The raw address type byte from the protocol
    ///
    /// # Returns
    ///
    /// A tuple of `(AddrType, u8)` where the second element is the original
    /// byte value. This preserves unknown type values for round-tripping.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::AddrType;
    ///
    /// assert_eq!(AddrType::get(4), (AddrType::IPv4, 4));
    /// assert_eq!(AddrType::get(6), (AddrType::IPv6, 6));
    /// assert_eq!(AddrType::get(99), (AddrType::Unknown, 99));
    /// ```
    pub fn get(val: u8) -> (AddrType, u8) {
        match val {
            0 => (AddrType::Hostname, 0),
            4 => (AddrType::IPv4, 4),
            6 => (AddrType::IPv6, 6),
            16 => (AddrType::ErrorTransient, 16),
            17 => (AddrType::ErrorPermanent, 17),
            _ => (AddrType::Unknown, val),
        }
    }

    /// Returns the integer value for this address type.
    ///
    /// Returns 255 for `Unknown` types (the original value is lost).
    pub fn value(&self) -> u8 {
        match self {
            AddrType::Hostname => 0,
            AddrType::IPv4 => 4,
            AddrType::IPv6 => 6,
            AddrType::ErrorTransient => 16,
            AddrType::ErrorPermanent => 17,
            AddrType::Unknown => 255,
        }
    }
}

/// A relay address with type information.
///
/// Represents an address in the Tor protocol, supporting IPv4, IPv6, and
/// other address types. Addresses are encoded with a type byte, length byte,
/// and variable-length value.
///
/// # Wire Format
///
/// ```text
/// +----------+--------+------------------+
/// | Type (1) | Len (1)| Value (Len bytes)|
/// +----------+--------+------------------+
/// ```
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::{Address, AddrType};
///
/// // Create from string
/// let addr = Address::new("127.0.0.1").unwrap();
/// assert_eq!(addr.addr_type, AddrType::IPv4);
/// assert_eq!(addr.value, Some("127.0.0.1".to_string()));
///
/// // Pack and unpack
/// let packed = addr.pack();
/// let unpacked = Address::unpack(&packed).unwrap();
/// assert_eq!(addr, unpacked);
/// ```
///
/// # IPv6 Handling
///
/// IPv6 addresses are normalized to their fully expanded form:
///
/// ```rust
/// use stem_rs::client::datatype::Address;
///
/// let addr = Address::new("::1").unwrap();
/// assert_eq!(addr.value, Some("0000:0000:0000:0000:0000:0000:0000:0001".to_string()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The type of this address.
    pub addr_type: AddrType,
    /// The raw type byte (preserved for unknown types).
    pub type_int: u8,
    /// The human-readable address string (if applicable).
    ///
    /// This is `None` for error types and unknown address types.
    pub value: Option<String>,
    /// The raw binary representation of the address.
    pub value_bin: Vec<u8>,
}

impl Address {
    /// Creates a new `Address` from an IP address string.
    ///
    /// Automatically detects whether the address is IPv4 or IPv6.
    ///
    /// # Arguments
    ///
    /// * `value` - An IPv4 or IPv6 address string
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the string is not a valid IPv4 or IPv6 address.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::{Address, AddrType};
    ///
    /// let ipv4 = Address::new("192.168.1.1").unwrap();
    /// assert_eq!(ipv4.addr_type, AddrType::IPv4);
    ///
    /// let ipv6 = Address::new("2001:db8::1").unwrap();
    /// assert_eq!(ipv6.addr_type, AddrType::IPv6);
    ///
    /// // Invalid addresses return an error
    /// assert!(Address::new("not-an-address").is_err());
    /// ```
    pub fn new(value: &str) -> Result<Self, Error> {
        if let Ok(ipv4) = value.parse::<Ipv4Addr>() {
            return Ok(Address {
                addr_type: AddrType::IPv4,
                type_int: 4,
                value: Some(value.to_string()),
                value_bin: ipv4.octets().to_vec(),
            });
        }
        if let Ok(ipv6) = value.parse::<Ipv6Addr>() {
            let expanded = format!(
                "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                ipv6.segments()[0],
                ipv6.segments()[1],
                ipv6.segments()[2],
                ipv6.segments()[3],
                ipv6.segments()[4],
                ipv6.segments()[5],
                ipv6.segments()[6],
                ipv6.segments()[7]
            );
            return Ok(Address {
                addr_type: AddrType::IPv6,
                type_int: 6,
                value: Some(expanded),
                value_bin: ipv6.octets().to_vec(),
            });
        }
        Err(Error::Protocol(format!(
            "'{}' isn't an IPv4 or IPv6 address",
            value
        )))
    }

    /// Creates an `Address` from raw bytes with a specified type.
    ///
    /// This is used when parsing addresses from the wire format where
    /// the type is already known.
    ///
    /// # Arguments
    ///
    /// * `value` - The raw address bytes
    /// * `addr_type` - The address type byte
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - `addr_type` is 4 (IPv4) but `value` is not 4 bytes
    /// - `addr_type` is 6 (IPv6) but `value` is not 16 bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::{Address, AddrType};
    ///
    /// let addr = Address::with_type(&[127, 0, 0, 1], 4).unwrap();
    /// assert_eq!(addr.value, Some("127.0.0.1".to_string()));
    ///
    /// // Unknown types are accepted
    /// let unknown = Address::with_type(b"data", 99).unwrap();
    /// assert_eq!(unknown.addr_type, AddrType::Unknown);
    /// ```
    pub fn with_type(value: &[u8], addr_type: u8) -> Result<Self, Error> {
        let (atype, type_int) = AddrType::get(addr_type);
        match atype {
            AddrType::IPv4 => {
                if value.len() != 4 {
                    return Err(Error::Protocol(format!(
                        "Packed IPv4 addresses should be four bytes, but was: {:?}",
                        value
                    )));
                }
                let addr_str = format!("{}.{}.{}.{}", value[0], value[1], value[2], value[3]);
                Ok(Address {
                    addr_type: atype,
                    type_int,
                    value: Some(addr_str),
                    value_bin: value.to_vec(),
                })
            }
            AddrType::IPv6 => {
                if value.len() != 16 {
                    return Err(Error::Protocol(format!(
                        "Packed IPv6 addresses should be sixteen bytes, but was: {:?}",
                        value
                    )));
                }
                let addr_str = unpack_ipv6_address(value);
                Ok(Address {
                    addr_type: atype,
                    type_int,
                    value: Some(addr_str),
                    value_bin: value.to_vec(),
                })
            }
            _ => Ok(Address {
                addr_type: atype,
                type_int,
                value: None,
                value_bin: value.to_vec(),
            }),
        }
    }

    /// Packs the address into its wire format.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing: `[type, length, value...]`
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::Address;
    ///
    /// let addr = Address::new("127.0.0.1").unwrap();
    /// let packed = addr.pack();
    /// assert_eq!(packed, vec![0x04, 0x04, 127, 0, 0, 1]);
    /// ```
    pub fn pack(&self) -> Vec<u8> {
        let mut cell = Vec::new();
        cell.push(self.type_int);
        cell.push(self.value_bin.len() as u8);
        cell.extend_from_slice(&self.value_bin);
        cell
    }

    /// Unpacks an address from its wire format.
    ///
    /// # Arguments
    ///
    /// * `data` - The packed address bytes (must be exactly the right size)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The data is too short
    /// - There are extra bytes after the address
    /// - The address type/length combination is invalid
    pub fn unpack(data: &[u8]) -> Result<Self, Error> {
        let (addr, remainder) = Self::pop(data)?;
        if !remainder.is_empty() {
            return Err(Error::Protocol(format!(
                "Address had {} extra bytes",
                remainder.len()
            )));
        }
        Ok(addr)
    }

    /// Unpacks an address from the start of a byte slice, returning the remainder.
    ///
    /// # Arguments
    ///
    /// * `content` - The byte slice to read from
    ///
    /// # Returns
    ///
    /// A tuple of `(Address, remainder)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the data is malformed.
    pub fn pop(content: &[u8]) -> Result<(Self, &[u8]), Error> {
        if content.len() < 2 {
            return Err(Error::Protocol(
                "Address requires at least 2 bytes".to_string(),
            ));
        }
        let (addr_type, content) = (content[0], &content[1..]);
        let (addr_length, content) = (content[0] as usize, &content[1..]);
        if content.len() < addr_length {
            return Err(Error::Protocol(format!(
                "Address specified a payload of {} bytes, but only had {}",
                addr_length,
                content.len()
            )));
        }
        let (addr_value, content) = split(content, addr_length);
        Ok((Address::with_type(addr_value, addr_type)?, content))
    }
}

/// Unpacks a 16-byte IPv6 address into its colon-separated hex string form.
fn unpack_ipv6_address(value: &[u8]) -> String {
    let segments: Vec<String> = (0..8)
        .map(|i| {
            let high = value[i * 2] as u16;
            let low = value[i * 2 + 1] as u16;
            format!("{:04x}", (high << 8) | low)
        })
        .collect();
    segments.join(":")
}

/// Certificate type identifier.
///
/// Identifies the purpose of a certificate in the Tor protocol. Different
/// certificate types are used for different authentication and signing purposes.
///
/// For more information, see:
/// - [tor-spec.txt section 4.2](https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt)
/// - [cert-spec.txt section A.1](https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt)
/// - [rend-spec-v3.txt appendix E](https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt)
///
/// # Variants
///
/// | Variant              | Value | Description                                    |
/// |----------------------|-------|------------------------------------------------|
/// | `Link`               | 1     | Link key certificate (RSA1024 identity)        |
/// | `Identity`           | 2     | RSA1024 identity certificate                   |
/// | `Authenticate`       | 3     | RSA1024 AUTHENTICATE cell link certificate     |
/// | `Ed25519Signing`     | 4     | Ed25519 signing key (signed with identity)     |
/// | `LinkCert`           | 5     | TLS link cert (signed with Ed25519 signing)    |
/// | `Ed25519Authenticate`| 6     | Ed25519 AUTHENTICATE cell key                  |
/// | `Ed25519Identity`    | 7     | Ed25519 identity (signed with RSA identity)    |
/// | `HsV3DescSigning`    | 8     | HS v3 short-term descriptor signing key        |
/// | `HsV3IntroAuth`      | 9     | HS v3 introduction point authentication key    |
/// | `NtorOnionKey`       | 10    | ntor onion key cross-certifying Ed25519        |
/// | `HsV3NtorEnc`        | 11    | HS v3 ntor-extra encryption key                |
/// | `Unknown`            | -     | Unrecognized certificate type                  |
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::CertType;
///
/// let (cert_type, raw) = CertType::get(4);
/// assert_eq!(cert_type, CertType::Ed25519Signing);
/// assert_eq!(format!("{}", cert_type), "ED25519_SIGNING");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertType {
    /// Link key certificate certified by RSA1024 identity.
    Link = 1,
    /// RSA1024 identity certificate.
    Identity = 2,
    /// RSA1024 AUTHENTICATE cell link certificate.
    Authenticate = 3,
    /// Ed25519 signing key, signed with identity key.
    Ed25519Signing = 4,
    /// TLS link certificate, signed with Ed25519 signing key.
    LinkCert = 5,
    /// Ed25519 AUTHENTICATE cell key, signed with Ed25519 signing key.
    Ed25519Authenticate = 6,
    /// Ed25519 identity, signed with RSA identity.
    Ed25519Identity = 7,
    /// Hidden service v3 short-term descriptor signing key.
    HsV3DescSigning = 8,
    /// Hidden service v3 introduction point authentication key.
    HsV3IntroAuth = 9,
    /// ntor onion key cross-certifying Ed25519 identity key.
    NtorOnionKey = 10,
    /// Hidden service v3 ntor-extra encryption key.
    HsV3NtorEnc = 11,
    /// Unrecognized certificate type.
    Unknown,
}

impl CertType {
    /// Converts a raw byte value to a `CertType` and its integer representation.
    ///
    /// # Arguments
    ///
    /// * `val` - The raw certificate type byte from the protocol
    ///
    /// # Returns
    ///
    /// A tuple of `(CertType, u8)` where the second element is the original
    /// byte value. This preserves unknown type values for round-tripping.
    pub fn get(val: u8) -> (CertType, u8) {
        match val {
            1 => (CertType::Link, 1),
            2 => (CertType::Identity, 2),
            3 => (CertType::Authenticate, 3),
            4 => (CertType::Ed25519Signing, 4),
            5 => (CertType::LinkCert, 5),
            6 => (CertType::Ed25519Authenticate, 6),
            7 => (CertType::Ed25519Identity, 7),
            8 => (CertType::HsV3DescSigning, 8),
            9 => (CertType::HsV3IntroAuth, 9),
            10 => (CertType::NtorOnionKey, 10),
            11 => (CertType::HsV3NtorEnc, 11),
            _ => (CertType::Unknown, val),
        }
    }

    /// Returns the integer value for this certificate type.
    ///
    /// Returns 255 for `Unknown` types.
    pub fn value(&self) -> u8 {
        match self {
            CertType::Link => 1,
            CertType::Identity => 2,
            CertType::Authenticate => 3,
            CertType::Ed25519Signing => 4,
            CertType::LinkCert => 5,
            CertType::Ed25519Authenticate => 6,
            CertType::Ed25519Identity => 7,
            CertType::HsV3DescSigning => 8,
            CertType::HsV3IntroAuth => 9,
            CertType::NtorOnionKey => 10,
            CertType::HsV3NtorEnc => 11,
            CertType::Unknown => 255,
        }
    }
}

impl fmt::Display for CertType {
    /// Formats the certificate type as its canonical string name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertType::Link => write!(f, "LINK"),
            CertType::Identity => write!(f, "IDENTITY"),
            CertType::Authenticate => write!(f, "AUTHENTICATE"),
            CertType::Ed25519Signing => write!(f, "ED25519_SIGNING"),
            CertType::LinkCert => write!(f, "LINK_CERT"),
            CertType::Ed25519Authenticate => write!(f, "ED25519_AUTHENTICATE"),
            CertType::Ed25519Identity => write!(f, "ED25519_IDENTITY"),
            CertType::HsV3DescSigning => write!(f, "HS_V3_DESC_SIGNING"),
            CertType::HsV3IntroAuth => write!(f, "HS_V3_INTRO_AUTH"),
            CertType::NtorOnionKey => write!(f, "NTOR_ONION_KEY"),
            CertType::HsV3NtorEnc => write!(f, "HS_V3_NTOR_ENC"),
            CertType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// A relay certificate as defined in tor-spec section 4.2.
///
/// Certificates are used in CERTS cells to authenticate relays during
/// the link handshake. Each certificate has a type and a variable-length
/// value containing the actual certificate data.
///
/// # Wire Format
///
/// ```text
/// +----------+------------+------------------+
/// | Type (1) | Length (2) | Value (Len bytes)|
/// +----------+------------+------------------+
/// ```
///
/// Note that the length field is 2 bytes (unlike Address which uses 1 byte).
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::{Certificate, CertType};
///
/// // Create a certificate
/// let cert = Certificate::new(CertType::Link, vec![0x01, 0x02, 0x03]);
/// assert_eq!(cert.cert_type, CertType::Link);
///
/// // Pack and unpack
/// let packed = cert.pack();
/// let (unpacked, _) = Certificate::pop(&packed).unwrap();
/// assert_eq!(cert, unpacked);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The type of this certificate.
    pub cert_type: CertType,
    /// The raw type byte (preserved for unknown types).
    pub type_int: u8,
    /// The certificate data.
    pub value: Vec<u8>,
}

impl Certificate {
    /// Creates a new certificate with the given type and value.
    ///
    /// # Arguments
    ///
    /// * `cert_type` - The certificate type
    /// * `value` - The certificate data
    pub fn new(cert_type: CertType, value: Vec<u8>) -> Self {
        Certificate {
            type_int: cert_type.value(),
            cert_type,
            value,
        }
    }

    /// Creates a certificate from a raw type byte and value.
    ///
    /// This is used when parsing certificates from the wire format.
    ///
    /// # Arguments
    ///
    /// * `cert_type` - The raw certificate type byte
    /// * `value` - The certificate data
    pub fn from_int(cert_type: u8, value: Vec<u8>) -> Self {
        let (ctype, type_int) = CertType::get(cert_type);
        Certificate {
            cert_type: ctype,
            type_int,
            value,
        }
    }

    /// Packs the certificate into its wire format.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing: `[type (1), length (2), value...]`
    pub fn pack(&self) -> Vec<u8> {
        let mut cell = Vec::new();
        cell.push(self.type_int);
        cell.extend_from_slice(&Size::Short.pack(self.value.len() as u64));
        cell.extend_from_slice(&self.value);
        cell
    }

    /// Unpacks a certificate from the start of a byte slice, returning the remainder.
    ///
    /// # Arguments
    ///
    /// * `content` - The byte slice to read from
    ///
    /// # Returns
    ///
    /// A tuple of `(Certificate, remainder)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The data is too short for the header
    /// - The specified length exceeds the available data
    pub fn pop(content: &[u8]) -> Result<(Self, &[u8]), Error> {
        if content.is_empty() {
            return Err(Error::Protocol(
                "Certificate requires at least 1 byte".to_string(),
            ));
        }
        let (cert_type, content) = (content[0], &content[1..]);
        let (cert_size, content) = Size::Short.pop(content)?;
        let cert_size = cert_size as usize;
        if cert_size > content.len() {
            return Err(Error::Protocol(format!(
                "CERTS cell should have a certificate with {} bytes, but only had {} remaining",
                cert_size,
                content.len()
            )));
        }
        let (cert_bytes, content) = split(content, cert_size);
        Ok((
            Certificate::from_int(cert_type, cert_bytes.to_vec()),
            content,
        ))
    }
}

/// Relay cell command types.
///
/// Commands used within relay cells to manage streams and circuits.
/// These commands have two characteristics:
///
/// - **Direction**: Forward commands originate from the client; backward
///   commands come from the relay.
/// - **Scope**: Stream commands affect individual streams; circuit commands
///   affect the entire circuit.
///
/// # Variants
///
/// | Command     | Value | Direction        | Scope   | Description                    |
/// |-------------|-------|------------------|---------|--------------------------------|
/// | `Begin`     | 1     | Forward          | Stream  | Begin a new stream             |
/// | `Data`      | 2     | Forward/Backward | Stream  | Transmit data                  |
/// | `End`       | 3     | Forward/Backward | Stream  | End a stream                   |
/// | `Connected` | 4     | Backward         | Stream  | Reply to BEGIN                 |
/// | `SendMe`    | 5     | Forward/Backward | Both    | Flow control acknowledgment    |
/// | `Extend`    | 6     | Forward          | Circuit | Extend circuit (legacy)        |
/// | `Extended`  | 7     | Backward         | Circuit | Reply to EXTEND                |
/// | `Truncate`  | 8     | Forward          | Circuit | Remove last hop                |
/// | `Truncated` | 9     | Backward         | Circuit | Reply to TRUNCATE              |
/// | `Drop`      | 10    | Forward/Backward | Circuit | Ignorable no-op                |
/// | `Resolve`   | 11    | Forward          | Stream  | DNS resolution request         |
/// | `Resolved`  | 12    | Backward         | Stream  | Reply to RESOLVE               |
/// | `BeginDir`  | 13    | Forward          | Stream  | Request directory info         |
/// | `Extend2`   | 14    | Forward          | Circuit | Extend circuit (ntor)          |
/// | `Extended2` | 15    | Backward         | Circuit | Reply to EXTEND2               |
/// | `Unknown`   | -     | -                | -       | Unrecognized command           |
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::RelayCommand;
///
/// let (cmd, raw) = RelayCommand::get(1);
/// assert_eq!(cmd, RelayCommand::Begin);
/// assert_eq!(format!("{}", cmd), "RELAY_BEGIN");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayCommand {
    /// Begin a new stream (forward, stream).
    Begin = 1,
    /// Transmit data (forward/backward, stream).
    Data = 2,
    /// End a stream (forward/backward, stream).
    End = 3,
    /// Reply to BEGIN (backward, stream).
    Connected = 4,
    /// Flow control - ready for more cells (forward/backward, stream/circuit).
    SendMe = 5,
    /// Extend circuit through another relay - legacy (forward, circuit).
    Extend = 6,
    /// Reply to EXTEND (backward, circuit).
    Extended = 7,
    /// Remove last circuit hop (forward, circuit).
    Truncate = 8,
    /// Reply to TRUNCATE (backward, circuit).
    Truncated = 9,
    /// Ignorable no-op (forward/backward, circuit).
    Drop = 10,
    /// Request DNS resolution (forward, stream).
    Resolve = 11,
    /// Reply to RESOLVE (backward, stream).
    Resolved = 12,
    /// Request directory information (forward, stream).
    BeginDir = 13,
    /// Extend circuit - ntor handshake (forward, circuit).
    Extend2 = 14,
    /// Reply to EXTEND2 (backward, circuit).
    Extended2 = 15,
    /// Unrecognized command.
    Unknown,
}

impl RelayCommand {
    /// Converts a raw byte value to a `RelayCommand` and its integer representation.
    ///
    /// # Arguments
    ///
    /// * `val` - The raw command byte from the relay cell
    ///
    /// # Returns
    ///
    /// A tuple of `(RelayCommand, u8)` where the second element is the original
    /// byte value.
    pub fn get(val: u8) -> (RelayCommand, u8) {
        match val {
            1 => (RelayCommand::Begin, 1),
            2 => (RelayCommand::Data, 2),
            3 => (RelayCommand::End, 3),
            4 => (RelayCommand::Connected, 4),
            5 => (RelayCommand::SendMe, 5),
            6 => (RelayCommand::Extend, 6),
            7 => (RelayCommand::Extended, 7),
            8 => (RelayCommand::Truncate, 8),
            9 => (RelayCommand::Truncated, 9),
            10 => (RelayCommand::Drop, 10),
            11 => (RelayCommand::Resolve, 11),
            12 => (RelayCommand::Resolved, 12),
            13 => (RelayCommand::BeginDir, 13),
            14 => (RelayCommand::Extend2, 14),
            15 => (RelayCommand::Extended2, 15),
            _ => (RelayCommand::Unknown, val),
        }
    }

    /// Returns the integer value for this relay command.
    ///
    /// Returns 255 for `Unknown` commands.
    pub fn value(&self) -> u8 {
        match self {
            RelayCommand::Begin => 1,
            RelayCommand::Data => 2,
            RelayCommand::End => 3,
            RelayCommand::Connected => 4,
            RelayCommand::SendMe => 5,
            RelayCommand::Extend => 6,
            RelayCommand::Extended => 7,
            RelayCommand::Truncate => 8,
            RelayCommand::Truncated => 9,
            RelayCommand::Drop => 10,
            RelayCommand::Resolve => 11,
            RelayCommand::Resolved => 12,
            RelayCommand::BeginDir => 13,
            RelayCommand::Extend2 => 14,
            RelayCommand::Extended2 => 15,
            RelayCommand::Unknown => 255,
        }
    }
}

impl fmt::Display for RelayCommand {
    /// Formats the relay command as its canonical string name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayCommand::Begin => write!(f, "RELAY_BEGIN"),
            RelayCommand::Data => write!(f, "RELAY_DATA"),
            RelayCommand::End => write!(f, "RELAY_END"),
            RelayCommand::Connected => write!(f, "RELAY_CONNECTED"),
            RelayCommand::SendMe => write!(f, "RELAY_SENDME"),
            RelayCommand::Extend => write!(f, "RELAY_EXTEND"),
            RelayCommand::Extended => write!(f, "RELAY_EXTENDED"),
            RelayCommand::Truncate => write!(f, "RELAY_TRUNCATE"),
            RelayCommand::Truncated => write!(f, "RELAY_TRUNCATED"),
            RelayCommand::Drop => write!(f, "RELAY_DROP"),
            RelayCommand::Resolve => write!(f, "RELAY_RESOLVE"),
            RelayCommand::Resolved => write!(f, "RELAY_RESOLVED"),
            RelayCommand::BeginDir => write!(f, "RELAY_BEGIN_DIR"),
            RelayCommand::Extend2 => write!(f, "RELAY_EXTEND2"),
            RelayCommand::Extended2 => write!(f, "RELAY_EXTENDED2"),
            RelayCommand::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Reason for closing a circuit or stream.
///
/// These codes indicate why a relay closed a circuit or stream. They are
/// used in DESTROY cells and RELAY_END cells.
///
/// # Variants
///
/// | Reason          | Value | Description                                    |
/// |-----------------|-------|------------------------------------------------|
/// | `None`          | 0     | No reason given                                |
/// | `Protocol`      | 1     | Tor protocol violation                         |
/// | `Internal`      | 2     | Internal error                                 |
/// | `Requested`     | 3     | Client sent TRUNCATE command                   |
/// | `Hibernating`   | 4     | Relay suspended to save bandwidth              |
/// | `ResourceLimit` | 5     | Out of memory, sockets, or circuit IDs         |
/// | `ConnectFailed` | 6     | Unable to reach relay                          |
/// | `OrIdentity`    | 7     | Connected but OR identity was wrong            |
/// | `ChannelClosed` | 8     | Connection carrying this circuit died          |
/// | `Finished`      | 9     | Circuit expired (dirty or old)                 |
/// | `Timeout`       | 10    | Circuit construction took too long             |
/// | `Destroyed`     | 11    | Circuit destroyed without client TRUNCATE      |
/// | `NoSuchService` | 12    | Request for unknown hidden service             |
/// | `Unknown`       | -     | Unrecognized reason                            |
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::CloseReason;
///
/// let (reason, raw) = CloseReason::get(3);
/// assert_eq!(reason, CloseReason::Requested);
/// assert_eq!(format!("{}", reason), "REQUESTED");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// No reason given.
    None = 0,
    /// Tor protocol violation.
    Protocol = 1,
    /// Internal error.
    Internal = 2,
    /// Client sent a TRUNCATE command.
    Requested = 3,
    /// Relay suspended, trying to save bandwidth.
    Hibernating = 4,
    /// Out of memory, sockets, or circuit IDs.
    ResourceLimit = 5,
    /// Unable to reach relay.
    ConnectFailed = 6,
    /// Connected, but its OR identity was not as expected.
    OrIdentity = 7,
    /// Connection that was carrying this circuit died.
    ChannelClosed = 8,
    /// Circuit has expired for being dirty or old.
    Finished = 9,
    /// Circuit construction took too long.
    Timeout = 10,
    /// Circuit was destroyed without a client TRUNCATE.
    Destroyed = 11,
    /// Request was for an unknown hidden service.
    NoSuchService = 12,
    /// Unrecognized reason.
    Unknown,
}

impl CloseReason {
    /// Converts a raw byte value to a `CloseReason` and its integer representation.
    ///
    /// # Arguments
    ///
    /// * `val` - The raw reason byte from the protocol
    ///
    /// # Returns
    ///
    /// A tuple of `(CloseReason, u8)` where the second element is the original
    /// byte value.
    pub fn get(val: u8) -> (CloseReason, u8) {
        match val {
            0 => (CloseReason::None, 0),
            1 => (CloseReason::Protocol, 1),
            2 => (CloseReason::Internal, 2),
            3 => (CloseReason::Requested, 3),
            4 => (CloseReason::Hibernating, 4),
            5 => (CloseReason::ResourceLimit, 5),
            6 => (CloseReason::ConnectFailed, 6),
            7 => (CloseReason::OrIdentity, 7),
            8 => (CloseReason::ChannelClosed, 8),
            9 => (CloseReason::Finished, 9),
            10 => (CloseReason::Timeout, 10),
            11 => (CloseReason::Destroyed, 11),
            12 => (CloseReason::NoSuchService, 12),
            _ => (CloseReason::Unknown, val),
        }
    }

    /// Returns the integer value for this close reason.
    ///
    /// Returns 255 for `Unknown` reasons.
    pub fn value(&self) -> u8 {
        match self {
            CloseReason::None => 0,
            CloseReason::Protocol => 1,
            CloseReason::Internal => 2,
            CloseReason::Requested => 3,
            CloseReason::Hibernating => 4,
            CloseReason::ResourceLimit => 5,
            CloseReason::ConnectFailed => 6,
            CloseReason::OrIdentity => 7,
            CloseReason::ChannelClosed => 8,
            CloseReason::Finished => 9,
            CloseReason::Timeout => 10,
            CloseReason::Destroyed => 11,
            CloseReason::NoSuchService => 12,
            CloseReason::Unknown => 255,
        }
    }
}

impl fmt::Display for CloseReason {
    /// Formats the close reason as its canonical string name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloseReason::None => write!(f, "NONE"),
            CloseReason::Protocol => write!(f, "PROTOCOL"),
            CloseReason::Internal => write!(f, "INTERNAL"),
            CloseReason::Requested => write!(f, "REQUESTED"),
            CloseReason::Hibernating => write!(f, "HIBERNATING"),
            CloseReason::ResourceLimit => write!(f, "RESOURCELIMIT"),
            CloseReason::ConnectFailed => write!(f, "CONNECTFAILED"),
            CloseReason::OrIdentity => write!(f, "OR_IDENTITY"),
            CloseReason::ChannelClosed => write!(f, "CHANNEL_CLOSED"),
            CloseReason::Finished => write!(f, "FINISHED"),
            CloseReason::Timeout => write!(f, "TIMEOUT"),
            CloseReason::Destroyed => write!(f, "DESTROYED"),
            CloseReason::NoSuchService => write!(f, "NOSUCHSERVICE"),
            CloseReason::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Method of communicating with a relay in a circuit.
///
/// Link specifiers describe how to connect to a relay when extending a circuit.
/// They are used in EXTEND2 cells to specify the next hop. Multiple specifiers
/// can be provided to give the extending relay options for how to connect.
///
/// For more information, see the
/// [EXTEND cell specification](https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n975).
///
/// # Wire Format
///
/// ```text
/// +----------+--------+------------------+
/// | Type (1) | Len (1)| Value (Len bytes)|
/// +----------+--------+------------------+
/// ```
///
/// # Variants
///
/// | Type | Value Size | Description                          |
/// |------|------------|--------------------------------------|
/// | 0    | 6 bytes    | IPv4 address (4) + port (2)          |
/// | 1    | 18 bytes   | IPv6 address (16) + port (2)         |
/// | 2    | 20 bytes   | SHA-1 identity fingerprint           |
/// | 3    | 32 bytes   | Ed25519 identity fingerprint         |
/// | 4+   | variable   | Unknown/future types                 |
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::LinkSpecifier;
///
/// // Create an IPv4 link specifier
/// let spec = LinkSpecifier::IPv4 {
///     address: "192.168.1.1".to_string(),
///     port: 9001,
/// };
///
/// // Pack and unpack
/// let packed = spec.pack();
/// let (unpacked, _) = LinkSpecifier::pop(&packed).unwrap();
///
/// match unpacked {
///     LinkSpecifier::IPv4 { address, port } => {
///         assert_eq!(address, "192.168.1.1");
///         assert_eq!(port, 9001);
///     }
///     _ => panic!("Expected IPv4"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSpecifier {
    /// TLS connection to an IPv4 address.
    IPv4 {
        /// The relay's IPv4 address.
        address: String,
        /// The relay's ORPort.
        port: u16,
    },
    /// TLS connection to an IPv6 address.
    IPv6 {
        /// The relay's IPv6 address (fully expanded form).
        address: String,
        /// The relay's ORPort.
        port: u16,
    },
    /// SHA-1 identity fingerprint (20 bytes).
    Fingerprint {
        /// The relay's SHA-1 identity fingerprint.
        fingerprint: [u8; 20],
    },
    /// Ed25519 identity fingerprint (32 bytes).
    Ed25519 {
        /// The relay's Ed25519 identity fingerprint.
        fingerprint: [u8; 32],
    },
    /// Unrecognized link specifier type.
    Unknown {
        /// The raw link type byte.
        link_type: u8,
        /// The raw value bytes.
        value: Vec<u8>,
    },
}

impl LinkSpecifier {
    /// Returns the link type byte for this specifier.
    ///
    /// | Type | Meaning     |
    /// |------|-------------|
    /// | 0    | IPv4        |
    /// | 1    | IPv6        |
    /// | 2    | Fingerprint |
    /// | 3    | Ed25519     |
    /// | 4+   | Unknown     |
    pub fn link_type(&self) -> u8 {
        match self {
            LinkSpecifier::IPv4 { .. } => 0,
            LinkSpecifier::IPv6 { .. } => 1,
            LinkSpecifier::Fingerprint { .. } => 2,
            LinkSpecifier::Ed25519 { .. } => 3,
            LinkSpecifier::Unknown { link_type, .. } => *link_type,
        }
    }

    /// Returns the encoded value bytes for this specifier.
    ///
    /// The format depends on the specifier type:
    /// - IPv4: 4-byte address + 2-byte port
    /// - IPv6: 16-byte address + 2-byte port
    /// - Fingerprint: 20-byte SHA-1 hash
    /// - Ed25519: 32-byte public key
    pub fn value(&self) -> Vec<u8> {
        match self {
            LinkSpecifier::IPv4 { address, port } => {
                let mut value = pack_ipv4_address(address);
                value.extend_from_slice(&port.to_be_bytes());
                value
            }
            LinkSpecifier::IPv6 { address, port } => {
                let mut value = pack_ipv6_address(address);
                value.extend_from_slice(&port.to_be_bytes());
                value
            }
            LinkSpecifier::Fingerprint { fingerprint } => fingerprint.to_vec(),
            LinkSpecifier::Ed25519 { fingerprint } => fingerprint.to_vec(),
            LinkSpecifier::Unknown { value, .. } => value.clone(),
        }
    }

    /// Packs the link specifier into its wire format.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing: `[type (1), length (1), value...]`
    pub fn pack(&self) -> Vec<u8> {
        let value = self.value();
        let mut cell = Vec::new();
        cell.push(self.link_type());
        cell.push(value.len() as u8);
        cell.extend_from_slice(&value);
        cell
    }

    /// Unpacks a link specifier from its wire format.
    ///
    /// # Arguments
    ///
    /// * `data` - The packed link specifier bytes
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the data is malformed.
    pub fn unpack(data: &[u8]) -> Result<Self, Error> {
        let (spec, _) = Self::pop(data)?;
        Ok(spec)
    }

    /// Unpacks a link specifier from the start of a byte slice, returning the remainder.
    ///
    /// # Arguments
    ///
    /// * `packed` - The byte slice to read from
    ///
    /// # Returns
    ///
    /// A tuple of `(LinkSpecifier, remainder)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The data is too short for the header
    /// - The specified length exceeds the available data
    /// - The value size doesn't match the expected size for the type
    pub fn pop(packed: &[u8]) -> Result<(Self, &[u8]), Error> {
        if packed.len() < 2 {
            return Err(Error::Protocol(
                "Link specifier requires at least 2 bytes".to_string(),
            ));
        }
        let (link_type, packed) = (packed[0], &packed[1..]);
        let (value_size, packed) = (packed[0] as usize, &packed[1..]);
        if value_size > packed.len() {
            return Err(Error::Protocol(format!(
                "Link specifier should have {} bytes, but only had {} remaining",
                value_size,
                packed.len()
            )));
        }
        let (value, packed) = split(packed, value_size);

        let specifier = match link_type {
            0 => {
                if value.len() != 6 {
                    return Err(Error::Protocol(format!(
                        "IPv4 link specifiers should be six bytes, but was {} instead",
                        value.len()
                    )));
                }
                let (addr, port_bytes) = split(value, 4);
                let address = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                LinkSpecifier::IPv4 { address, port }
            }
            1 => {
                if value.len() != 18 {
                    return Err(Error::Protocol(format!(
                        "IPv6 link specifiers should be eighteen bytes, but was {} instead",
                        value.len()
                    )));
                }
                let (addr, port_bytes) = split(value, 16);
                let address = unpack_ipv6_address(addr);
                let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                LinkSpecifier::IPv6 { address, port }
            }
            2 => {
                if value.len() != 20 {
                    return Err(Error::Protocol(format!(
                        "Fingerprint link specifiers should be twenty bytes, but was {} instead",
                        value.len()
                    )));
                }
                let mut fingerprint = [0u8; 20];
                fingerprint.copy_from_slice(value);
                LinkSpecifier::Fingerprint { fingerprint }
            }
            3 => {
                if value.len() != 32 {
                    return Err(Error::Protocol(format!(
                        "Ed25519 link specifiers should be thirty two bytes, but was {} instead",
                        value.len()
                    )));
                }
                let mut fingerprint = [0u8; 32];
                fingerprint.copy_from_slice(value);
                LinkSpecifier::Ed25519 { fingerprint }
            }
            _ => LinkSpecifier::Unknown {
                link_type,
                value: value.to_vec(),
            },
        };

        Ok((specifier, packed))
    }
}

/// Packs an IPv4 address string into 4 bytes.
fn pack_ipv4_address(address: &str) -> Vec<u8> {
    address
        .split('.')
        .filter_map(|s| s.parse::<u8>().ok())
        .collect()
}

/// Packs an IPv6 address string into 16 bytes.
fn pack_ipv6_address(address: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(16);
    for segment in address.split(':') {
        if let Ok(val) = u16::from_str_radix(segment, 16) {
            result.extend_from_slice(&val.to_be_bytes());
        }
    }
    result
}

/// KDF-TOR derived key material.
///
/// Contains the cryptographic keys and digests derived from shared key material
/// during circuit creation. This implements the KDF-TOR key derivation function
/// as defined in tor-spec section 5.2.1.
///
/// The derivation uses SHA-1 in a counter mode:
/// ```text
/// K = H(K0 | [00]) | H(K0 | [01]) | H(K0 | [02]) | ...
/// ```
///
/// Where `K0` is the input key material and `H` is SHA-1.
///
/// # Fields
///
/// The derived key material is split into five parts:
///
/// | Field            | Size     | Purpose                              |
/// |------------------|----------|--------------------------------------|
/// | `key_hash`       | 20 bytes | Proves knowledge of shared key       |
/// | `forward_digest` | 20 bytes | Forward digest hash seed             |
/// | `backward_digest`| 20 bytes | Backward digest hash seed            |
/// | `forward_key`    | 16 bytes | Forward encryption key (AES-128)     |
/// | `backward_key`   | 16 bytes | Backward encryption key (AES-128)    |
///
/// # Example
///
/// ```rust
/// use stem_rs::client::datatype::KDF;
///
/// // Derive keys from shared secret (e.g., from CREATE_FAST handshake)
/// let key_material = b"shared_secret_from_handshake____";
/// let kdf = KDF::from_value(key_material);
///
/// // Use the derived keys for encryption
/// assert_eq!(kdf.forward_key.len(), 16);
/// assert_eq!(kdf.backward_key.len(), 16);
/// ```
///
/// # Security
///
/// This KDF is used with the TAP and CREATE_FAST handshakes. Modern Tor
/// circuits use the ntor handshake with a different KDF (HKDF-SHA256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KDF {
    /// Hash that proves knowledge of the shared key.
    ///
    /// This is compared with the value sent by the relay to verify
    /// both parties derived the same key material.
    pub key_hash: [u8; HASH_LEN],
    /// Forward digest hash seed.
    ///
    /// Used to initialize the running digest for cells sent from
    /// client to relay.
    pub forward_digest: [u8; HASH_LEN],
    /// Backward digest hash seed.
    ///
    /// Used to initialize the running digest for cells sent from
    /// relay to client.
    pub backward_digest: [u8; HASH_LEN],
    /// Forward encryption key (AES-128-CTR).
    ///
    /// Used to encrypt relay cells sent from client to relay.
    pub forward_key: [u8; KEY_LEN],
    /// Backward encryption key (AES-128-CTR).
    ///
    /// Used to decrypt relay cells received from relay.
    pub backward_key: [u8; KEY_LEN],
}

impl KDF {
    /// Derives key material from a shared secret.
    ///
    /// Implements the KDF-TOR key derivation function from tor-spec section 5.2.1.
    /// The input key material is expanded using SHA-1 in counter mode to produce
    /// the required key material.
    ///
    /// # Arguments
    ///
    /// * `key_material` - The shared secret from the circuit handshake
    ///
    /// # Returns
    ///
    /// A `KDF` struct containing all derived keys and digests.
    ///
    /// # Algorithm
    ///
    /// ```text
    /// derived = H(key_material | 0x00) | H(key_material | 0x01) | ...
    /// key_hash       = derived[0..20]
    /// forward_digest = derived[20..40]
    /// backward_digest= derived[40..60]
    /// forward_key    = derived[60..76]
    /// backward_key   = derived[76..92]
    /// ```
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::datatype::KDF;
    ///
    /// let shared_secret = b"example_shared_secret___________";
    /// let kdf = KDF::from_value(shared_secret);
    ///
    /// // All fields are populated
    /// assert_eq!(kdf.key_hash.len(), 20);
    /// assert_eq!(kdf.forward_key.len(), 16);
    /// ```
    pub fn from_value(key_material: &[u8]) -> Self {
        let mut derived_key = Vec::new();
        let mut counter: u8 = 0;

        while derived_key.len() < KEY_LEN * 2 + HASH_LEN * 3 {
            let mut hasher = Sha1::new();
            hasher.update(key_material);
            hasher.update([counter]);
            derived_key.extend_from_slice(&hasher.finalize());
            counter += 1;
        }

        let (key_hash, rest) = split(&derived_key, HASH_LEN);
        let (forward_digest, rest) = split(rest, HASH_LEN);
        let (backward_digest, rest) = split(rest, HASH_LEN);
        let (forward_key, rest) = split(rest, KEY_LEN);
        let (backward_key, _) = split(rest, KEY_LEN);

        let mut kdf = KDF {
            key_hash: [0u8; HASH_LEN],
            forward_digest: [0u8; HASH_LEN],
            backward_digest: [0u8; HASH_LEN],
            forward_key: [0u8; KEY_LEN],
            backward_key: [0u8; KEY_LEN],
        };

        kdf.key_hash.copy_from_slice(key_hash);
        kdf.forward_digest.copy_from_slice(forward_digest);
        kdf.backward_digest.copy_from_slice(backward_digest);
        kdf.forward_key.copy_from_slice(forward_key);
        kdf.backward_key.copy_from_slice(backward_key);

        kdf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_attributes() {
        assert_eq!(1, Size::Char.size());
        assert_eq!(2, Size::Short.size());
        assert_eq!(4, Size::Long.size());
        assert_eq!(8, Size::LongLong.size());
    }

    #[test]
    fn test_size_pack() {
        assert_eq!(vec![0x12], Size::Char.pack(18));
        assert_eq!(vec![0x00, 0x12], Size::Short.pack(18));
        assert_eq!(vec![0x00, 0x00, 0x00, 0x12], Size::Long.pack(18));
        assert_eq!(
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12],
            Size::LongLong.pack(18)
        );
    }

    #[test]
    fn test_size_unpack() {
        assert_eq!(18, Size::Char.unpack(&[0x12]).unwrap());
        assert_eq!(18, Size::Short.unpack(&[0x00, 0x12]).unwrap());
        assert_eq!(18, Size::Long.unpack(&[0x00, 0x00, 0x00, 0x12]).unwrap());
        assert_eq!(
            18,
            Size::LongLong
                .unpack(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12])
                .unwrap()
        );
        assert_eq!(97, Size::Char.unpack(b"a").unwrap());
        assert_eq!(24930, Size::Short.unpack(b"ab").unwrap());
        assert!(Size::Char.unpack(&[0x00, 0x12]).is_err());
    }

    #[test]
    fn test_size_pop() {
        assert_eq!((18, &[][..]), Size::Char.pop(&[0x12]).unwrap());
        assert_eq!((0, &[0x12][..]), Size::Char.pop(&[0x00, 0x12]).unwrap());
        assert_eq!((18, &[][..]), Size::Short.pop(&[0x00, 0x12]).unwrap());
        assert!(Size::Char.pop(&[]).is_err());
        assert!(Size::Short.pop(&[0x12]).is_err());
    }

    #[test]
    fn test_link_protocol_attributes() {
        let protocol = LinkProtocol::new(1);
        assert_eq!(1, protocol.version);
        assert_eq!(Size::Short, protocol.circ_id_size);
        assert_eq!(512, protocol.fixed_cell_length);
        assert_eq!(0x01, protocol.first_circ_id);

        let protocol = LinkProtocol::new(10);
        assert_eq!(10, protocol.version);
        assert_eq!(Size::Long, protocol.circ_id_size);
        assert_eq!(514, protocol.fixed_cell_length);
        assert_eq!(0x80000000, protocol.first_circ_id);
    }

    #[test]
    fn test_link_protocol_equality() {
        let protocol = LinkProtocol::new(1);
        assert_eq!(LinkProtocol::new(1), protocol);
        assert_ne!(LinkProtocol::new(2), protocol);
        assert!(protocol == 1);
        assert!(protocol != 2);
    }

    #[test]
    fn test_address_ipv4() {
        let addr = Address::new("127.0.0.1").unwrap();
        assert_eq!(AddrType::IPv4, addr.addr_type);
        assert_eq!(4, addr.type_int);
        assert_eq!(Some("127.0.0.1".to_string()), addr.value);
        assert_eq!(vec![127, 0, 0, 1], addr.value_bin);
    }

    #[test]
    fn test_address_ipv6() {
        let addr = Address::new("2001:0db8:0000:0000:0000:ff00:0042:8329").unwrap();
        assert_eq!(AddrType::IPv6, addr.addr_type);
        assert_eq!(6, addr.type_int);
        assert_eq!(
            Some("2001:0db8:0000:0000:0000:ff00:0042:8329".to_string()),
            addr.value
        );
    }

    #[test]
    fn test_address_invalid() {
        assert!(Address::new("nope").is_err());
    }

    #[test]
    fn test_address_packing() {
        let addr = Address::new("127.0.0.1").unwrap();
        let packed = addr.pack();
        assert_eq!(vec![0x04, 0x04, 0x7f, 0x00, 0x00, 0x01], packed);

        let unpacked = Address::unpack(&packed).unwrap();
        assert_eq!(addr, unpacked);
    }

    #[test]
    fn test_address_pop() {
        let data = b"\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00";
        let (addr, content) = Address::pop(data).unwrap();
        assert_eq!(b"\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00", content);
        assert_eq!(AddrType::IPv4, addr.addr_type);
        assert_eq!(4, addr.type_int);
        assert_eq!(Some("127.0.0.1".to_string()), addr.value);
        assert_eq!(vec![0x7f, 0x00, 0x00, 0x01], addr.value_bin);
    }

    #[test]
    fn test_certificate_pack_pop() {
        let cert = Certificate::from_int(1, vec![0x08]);
        let packed = cert.pack();
        assert_eq!(vec![0x01, 0x00, 0x01, 0x08], packed);

        let (unpacked, remainder) = Certificate::pop(&packed).unwrap();
        assert_eq!(cert, unpacked);
        assert!(remainder.is_empty());
    }

    #[test]
    fn test_kdf_from_value() {
        let key_material = b"\xec\xec.\xeb7R\xf2\n\xcb\xce\x97\xf4\x86\x82\x19#\x10\x0f\x08\xf0\xa2Z\xdeJ\x8f2\x8cc\xf6\xfa\x0e\t\x83f\xc5\xe2\xb3\x94\xa8\x13";
        let kdf = KDF::from_value(key_material);

        assert_eq!(
            b"\xca+\x81\x05\x14\x9d)o\xa6\x82\xe9B\xa8?\xf2\xaf\x85\x1b]6",
            &kdf.key_hash
        );
        assert_eq!(
            b"\xac\xcc\xbc\x91\xb1\xaf\xd7\xe0\xe9\x9dF#\xd8\xdbz\xe8\xe6\xca\x83,",
            &kdf.forward_digest
        );
        assert_eq!(
            b"*\xe5scX\xbb+\xca \xcb\xa4\xbc\xad\x0f\x95\x0cO\xcc\xac\xf1",
            &kdf.backward_digest
        );
        assert_eq!(
            b"\xc3\xbe\xc9\xe1\xf4\x90f\xdai\xf3\xf3\xf5\x14\xb5\xb9\x03",
            &kdf.forward_key
        );
        assert_eq!(
            b"U\xaf\x1e\x1b\xb1q||\x86A<_\xf7\xa0%\x86",
            &kdf.backward_key
        );
    }

    #[test]
    fn test_link_specifier_ipv4() {
        let data = b"\x00\x06\x01\x02\x03\x04#)";
        let (spec, _) = LinkSpecifier::pop(data).unwrap();

        match spec {
            LinkSpecifier::IPv4 { address, port } => {
                assert_eq!("1.2.3.4", address);
                assert_eq!(9001, port);
            }
            _ => panic!("Expected IPv4 link specifier"),
        }

        let spec = LinkSpecifier::IPv4 {
            address: "1.2.3.4".to_string(),
            port: 9001,
        };
        assert_eq!(data.to_vec(), spec.pack());
    }

    #[test]
    fn test_link_specifier_ipv6() {
        let data = b"\x01\x12&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#)";
        let (spec, _) = LinkSpecifier::pop(data).unwrap();

        match spec {
            LinkSpecifier::IPv6 { address, port } => {
                assert_eq!("2600:0000:0000:0000:0000:0000:0000:0001", address);
                assert_eq!(9001, port);
            }
            _ => panic!("Expected IPv6 link specifier"),
        }
    }

    #[test]
    fn test_link_specifier_fingerprint() {
        let data = b"\x02\x14CCCCCCCCCCCCCCCCCCCC";
        let (spec, _) = LinkSpecifier::pop(data).unwrap();

        match spec {
            LinkSpecifier::Fingerprint { fingerprint } => {
                assert_eq!(b"CCCCCCCCCCCCCCCCCCCC", &fingerprint);
            }
            _ => panic!("Expected Fingerprint link specifier"),
        }
    }

    #[test]
    fn test_link_specifier_ed25519() {
        let data = b"\x03\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let (spec, _) = LinkSpecifier::pop(data).unwrap();

        match spec {
            LinkSpecifier::Ed25519 { fingerprint } => {
                assert_eq!(b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", &fingerprint);
            }
            _ => panic!("Expected Ed25519 link specifier"),
        }
    }

    #[test]
    fn test_link_specifier_unknown() {
        let data = b"\x04\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let (spec, _) = LinkSpecifier::pop(data).unwrap();

        match spec {
            LinkSpecifier::Unknown { link_type, value } => {
                assert_eq!(4, link_type);
                assert_eq!(b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_vec(), value);
            }
            _ => panic!("Expected Unknown link specifier"),
        }
    }

    #[test]
    fn test_link_specifier_wrong_size() {
        let data = b"\x04\x20CCCCCCC";
        assert!(LinkSpecifier::pop(data).is_err());
    }

    #[test]
    fn test_link_specifier_pack_roundtrip() {
        let test_inputs = [
            b"\x03\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_vec(),
            b"\x04\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_vec(),
            b"\x01\x12&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#)".to_vec(),
            b"\x00\x06\x01\x02\x03\x04#)".to_vec(),
        ];

        for val in test_inputs {
            let (spec, _) = LinkSpecifier::pop(&val).unwrap();
            assert_eq!(val, spec.pack());
        }
    }

    #[test]
    fn test_address_unknown_type() {
        let addr = Address::with_type(b"hello", 12).unwrap();
        assert_eq!(AddrType::Unknown, addr.addr_type);
        assert_eq!(12, addr.type_int);
        assert_eq!(None, addr.value);
        assert_eq!(b"hello".to_vec(), addr.value_bin);
    }

    #[test]
    fn test_address_ipv6_collapsed() {
        let addr = Address::new("2001:0DB8:AC10:FE01::").unwrap();
        assert_eq!(AddrType::IPv6, addr.addr_type);
        assert_eq!(6, addr.type_int);
        assert_eq!(
            Some("2001:0db8:ac10:fe01:0000:0000:0000:0000".to_string()),
            addr.value
        );
    }

    #[test]
    fn test_address_ipv4_wrong_size() {
        let result = Address::with_type(&[0x7f, 0x00], 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_address_ipv6_wrong_size() {
        let result = Address::with_type(&[0x7f, 0x00], 6);
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_unknown_type() {
        let cert = Certificate::from_int(12, b"hello".to_vec());
        assert_eq!(CertType::Unknown, cert.cert_type);
        assert_eq!(12, cert.type_int);
        assert_eq!(b"hello".to_vec(), cert.value);
    }

    #[test]
    fn test_certificate_all_types() {
        let test_data = [
            (1, CertType::Link),
            (2, CertType::Identity),
            (3, CertType::Authenticate),
            (4, CertType::Ed25519Signing),
            (5, CertType::LinkCert),
            (6, CertType::Ed25519Authenticate),
            (7, CertType::Ed25519Identity),
        ];

        for (type_int, expected_type) in test_data {
            let cert = Certificate::from_int(type_int, vec![0x7f, 0x00, 0x00, 0x01]);
            assert_eq!(expected_type, cert.cert_type);
            assert_eq!(type_int, cert.type_int);
            assert_eq!(vec![0x7f, 0x00, 0x00, 0x01], cert.value);
        }
    }

    #[test]
    fn test_addr_type_get() {
        assert_eq!((AddrType::IPv4, 4), AddrType::get(4));
        assert_eq!((AddrType::IPv6, 6), AddrType::get(6));
        assert_eq!((AddrType::Hostname, 0), AddrType::get(0));
        assert_eq!((AddrType::ErrorTransient, 16), AddrType::get(16));
        assert_eq!((AddrType::ErrorPermanent, 17), AddrType::get(17));
        assert_eq!((AddrType::Unknown, 25), AddrType::get(25));
    }

    #[test]
    fn test_relay_command_get() {
        assert_eq!((RelayCommand::Begin, 1), RelayCommand::get(1));
        assert_eq!((RelayCommand::Data, 2), RelayCommand::get(2));
        assert_eq!((RelayCommand::End, 3), RelayCommand::get(3));
        assert_eq!((RelayCommand::BeginDir, 13), RelayCommand::get(13));
        assert_eq!((RelayCommand::Unknown, 99), RelayCommand::get(99));
    }

    #[test]
    fn test_close_reason_get() {
        assert_eq!((CloseReason::None, 0), CloseReason::get(0));
        assert_eq!((CloseReason::Protocol, 1), CloseReason::get(1));
        assert_eq!((CloseReason::Requested, 3), CloseReason::get(3));
        assert_eq!((CloseReason::Finished, 9), CloseReason::get(9));
        assert_eq!((CloseReason::Unknown, 99), CloseReason::get(99));
    }

    #[test]
    fn test_link_protocol_version_3_boundary() {
        let protocol = LinkProtocol::new(3);
        assert_eq!(Size::Short, protocol.circ_id_size);
        assert_eq!(0x01, protocol.first_circ_id);

        let protocol = LinkProtocol::new(4);
        assert_eq!(Size::Long, protocol.circ_id_size);
        assert_eq!(0x80000000, protocol.first_circ_id);
    }

    #[test]
    fn test_link_specifier_ipv4_wrong_size() {
        let data = b"\x00\x04\x01\x02\x03\x04";
        let result = LinkSpecifier::pop(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_link_specifier_ipv6_wrong_size() {
        let data = b"\x01\x10&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let result = LinkSpecifier::pop(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_link_specifier_fingerprint_wrong_size() {
        let data = b"\x02\x10CCCCCCCCCCCCCCCC";
        let result = LinkSpecifier::pop(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_link_specifier_ed25519_wrong_size() {
        let data = b"\x03\x10CCCCCCCCCCCCCCCC";
        let result = LinkSpecifier::pop(data);
        assert!(result.is_err());
    }
}
