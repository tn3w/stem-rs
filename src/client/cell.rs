//! Cell types for the Tor relay protocol.
//!
//! This module provides cell types used in ORPort communication as defined in
//! the Tor protocol specification (tor-spec.txt). Cells are the fundamental
//! unit of communication in the Tor relay protocol.
//!
//! # Overview
//!
//! Cells are fixed-size or variable-size messages exchanged between Tor relays
//! and clients. Each cell has a circuit ID, command type, and payload. The
//! format depends on the link protocol version negotiated during connection.
//!
//! # Cell Types
//!
//! Cells are categorized by their function:
//!
//! ## Connection Setup
//! - [`VersionsCell`] - Link protocol version negotiation (section 4)
//! - [`NetinfoCell`] - Time and address information exchange (section 4.5)
//! - [`CertsCell`] - Relay certificates (section 4.2)
//! - [`AuthChallengeCell`] - Authentication challenge (section 4.3)
//!
//! ## Circuit Management
//! - [`CreateFastCell`] - Create circuit without public key (section 5.1)
//! - [`CreatedFastCell`] - Circuit creation acknowledgment (section 5.1)
//! - [`DestroyCell`] - Tear down a circuit (section 5.4)
//!
//! ## Data Transfer
//! - [`RelayCell`] - End-to-end encrypted data (section 6.1)
//!
//! ## Padding
//! - [`PaddingCell`] - Fixed-size padding for traffic analysis resistance
//! - [`VPaddingCell`] - Variable-size padding
//!
//! # Cell Format
//!
//! Fixed-size cells (link protocol 4+):
//! ```text
//! [ CircID (4 bytes) ][ Command (1 byte) ][ Payload (509 bytes) ]
//! ```
//!
//! Variable-size cells:
//! ```text
//! [ CircID (4 bytes) ][ Command (1 byte) ][ Length (2 bytes) ][ Payload ]
//! ```
//!
//! # Example
//!
//! ```rust
//! use stem_rs::client::cell::{VersionsCell, Cell, CellType};
//! use stem_rs::client::datatype::LinkProtocol;
//!
//! // Create a VERSIONS cell for protocol negotiation
//! let versions = VersionsCell::new(vec![3, 4, 5]);
//! let packed = versions.pack(&LinkProtocol::new(2));
//!
//! // Parse a cell from bytes
//! let (cell, remainder) = Cell::pop(&packed, 2).unwrap();
//! ```
//!
//! # See Also
//!
//! - [`datatype`](super::datatype) for data types used in cell construction
//! - [Tor Protocol Specification](https://spec.torproject.org/tor-spec)

use crate::client::datatype::{
    split, Address, Certificate, CloseReason, LinkProtocol, RelayCommand, Size, ZERO,
};
use crate::Error;
use chrono::{DateTime, TimeZone, Utc};

/// Fixed payload length for fixed-size cells (509 bytes).
///
/// All fixed-size cells have exactly this many bytes of payload,
/// padded with zeros if the actual data is shorter.
pub const FIXED_PAYLOAD_LEN: usize = 509;

/// Size of the authentication challenge in AUTH_CHALLENGE cells (32 bytes).
pub const AUTH_CHALLENGE_SIZE: usize = 32;

/// Length of SHA-1 hash used for key material (20 bytes).
///
/// Used in CREATE_FAST/CREATED_FAST handshakes for key derivation.
pub const HASH_LEN: usize = 20;

/// Size type for cell command field (1 byte).
pub const CELL_TYPE_SIZE: Size = Size::Char;

/// Size type for variable cell payload length field (2 bytes).
pub const PAYLOAD_LEN_SIZE: Size = Size::Short;

/// Size type for relay cell digest field (4 bytes).
pub const RELAY_DIGEST_SIZE: Size = Size::Long;

/// Relay commands that require a non-zero stream ID.
///
/// These commands operate on specific streams within a circuit and must
/// have a stream ID to identify which stream they affect.
pub const STREAM_ID_REQUIRED: &[RelayCommand] = &[
    RelayCommand::Begin,
    RelayCommand::Data,
    RelayCommand::End,
    RelayCommand::Connected,
    RelayCommand::Resolve,
    RelayCommand::Resolved,
    RelayCommand::BeginDir,
];

/// Relay commands that must have a zero stream ID.
///
/// These commands operate on the circuit itself rather than a specific
/// stream, so they cannot have a stream ID.
pub const STREAM_ID_DISALLOWED: &[RelayCommand] = &[
    RelayCommand::Extend,
    RelayCommand::Extended,
    RelayCommand::Truncate,
    RelayCommand::Truncated,
    RelayCommand::Drop,
    RelayCommand::Extend2,
    RelayCommand::Extended2,
];

/// Cell command types in the Tor relay protocol.
///
/// Each cell type has a unique command value that identifies its purpose.
/// Cell types are divided into fixed-size (values 0-127) and variable-size
/// (values 128+) categories.
///
/// # Fixed-Size Cells
///
/// These cells always have a 509-byte payload, padded with zeros if needed:
/// - `Padding` (0), `Create` (1), `Created` (2), `Relay` (3), `Destroy` (4)
/// - `CreateFast` (5), `CreatedFast` (6), `Netinfo` (8), `RelayEarly` (9)
/// - `Create2` (10), `Created2` (11), `PaddingNegotiate` (12)
///
/// # Variable-Size Cells
///
/// These cells have a 2-byte length field followed by variable payload:
/// - `Versions` (7), `VPadding` (128), `Certs` (129)
/// - `AuthChallenge` (130), `Authenticate` (131), `Authorize` (132)
///
/// # Example
///
/// ```rust
/// use stem_rs::client::cell::{CellType, cell_by_name, cell_by_value};
///
/// let cell_type = cell_by_name("NETINFO").unwrap();
/// assert_eq!(cell_type.value(), 8);
/// assert!(cell_type.is_fixed_size());
///
/// let cell_type = cell_by_value(7).unwrap();
/// assert_eq!(cell_type.name(), "VERSIONS");
/// assert!(!cell_type.is_fixed_size());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellType {
    /// Keep-alive padding cell (command 0).
    Padding,
    /// Create a circuit using public key crypto (command 1).
    Create,
    /// Acknowledge circuit creation (command 2).
    Created,
    /// End-to-end encrypted relay data (command 3).
    Relay,
    /// Tear down a circuit (command 4).
    Destroy,
    /// Create circuit without public key (command 5).
    CreateFast,
    /// Acknowledge fast circuit creation (command 6).
    CreatedFast,
    /// Link protocol version negotiation (command 7).
    Versions,
    /// Time and address information (command 8).
    Netinfo,
    /// Relay data with hop limit (command 9).
    RelayEarly,
    /// Extended circuit creation (command 10).
    Create2,
    /// Acknowledge extended creation (command 11).
    Created2,
    /// Padding negotiation (command 12).
    PaddingNegotiate,
    /// Variable-length padding (command 128).
    VPadding,
    /// Relay certificates (command 129).
    Certs,
    /// Authentication challenge (command 130).
    AuthChallenge,
    /// Client authentication (command 131).
    Authenticate,
    /// Client authorization (command 132).
    Authorize,
}

impl CellType {
    /// Returns the protocol name for this cell type.
    ///
    /// Names match the Tor specification (e.g., "PADDING", "VERSIONS", "RELAY").
    pub fn name(&self) -> &'static str {
        match self {
            CellType::Padding => "PADDING",
            CellType::Create => "CREATE",
            CellType::Created => "CREATED",
            CellType::Relay => "RELAY",
            CellType::Destroy => "DESTROY",
            CellType::CreateFast => "CREATE_FAST",
            CellType::CreatedFast => "CREATED_FAST",
            CellType::Versions => "VERSIONS",
            CellType::Netinfo => "NETINFO",
            CellType::RelayEarly => "RELAY_EARLY",
            CellType::Create2 => "CREATE2",
            CellType::Created2 => "CREATED2",
            CellType::PaddingNegotiate => "PADDING_NEGOTIATE",
            CellType::VPadding => "VPADDING",
            CellType::Certs => "CERTS",
            CellType::AuthChallenge => "AUTH_CHALLENGE",
            CellType::Authenticate => "AUTHENTICATE",
            CellType::Authorize => "AUTHORIZE",
        }
    }

    /// Returns the numeric command value for this cell type.
    ///
    /// Values 0-127 are fixed-size cells, 128+ are variable-size.
    pub fn value(&self) -> u8 {
        match self {
            CellType::Padding => 0,
            CellType::Create => 1,
            CellType::Created => 2,
            CellType::Relay => 3,
            CellType::Destroy => 4,
            CellType::CreateFast => 5,
            CellType::CreatedFast => 6,
            CellType::Versions => 7,
            CellType::Netinfo => 8,
            CellType::RelayEarly => 9,
            CellType::Create2 => 10,
            CellType::Created2 => 11,
            CellType::PaddingNegotiate => 12,
            CellType::VPadding => 128,
            CellType::Certs => 129,
            CellType::AuthChallenge => 130,
            CellType::Authenticate => 131,
            CellType::Authorize => 132,
        }
    }

    /// Returns whether this cell type has a fixed-size payload.
    ///
    /// Fixed-size cells have exactly 509 bytes of payload.
    /// Variable-size cells have a 2-byte length field.
    pub fn is_fixed_size(&self) -> bool {
        !matches!(
            self,
            CellType::Versions
                | CellType::VPadding
                | CellType::Certs
                | CellType::AuthChallenge
                | CellType::Authenticate
                | CellType::Authorize
        )
    }
}

/// Looks up a cell type by its protocol name.
///
/// Names are case-sensitive and must match the Tor specification exactly
/// (e.g., "PADDING", "VERSIONS", "RELAY").
///
/// # Arguments
///
/// * `name` - The cell type name to look up
///
/// # Errors
///
/// Returns [`Error::Protocol`] if the name is not a valid cell type.
///
/// # Example
///
/// ```rust
/// use stem_rs::client::cell::cell_by_name;
///
/// let cell_type = cell_by_name("NETINFO").unwrap();
/// assert_eq!(cell_type.value(), 8);
///
/// assert!(cell_by_name("INVALID").is_err());
/// ```
pub fn cell_by_name(name: &str) -> Result<CellType, Error> {
    match name {
        "PADDING" => Ok(CellType::Padding),
        "CREATE" => Ok(CellType::Create),
        "CREATED" => Ok(CellType::Created),
        "RELAY" => Ok(CellType::Relay),
        "DESTROY" => Ok(CellType::Destroy),
        "CREATE_FAST" => Ok(CellType::CreateFast),
        "CREATED_FAST" => Ok(CellType::CreatedFast),
        "VERSIONS" => Ok(CellType::Versions),
        "NETINFO" => Ok(CellType::Netinfo),
        "RELAY_EARLY" => Ok(CellType::RelayEarly),
        "CREATE2" => Ok(CellType::Create2),
        "CREATED2" => Ok(CellType::Created2),
        "PADDING_NEGOTIATE" => Ok(CellType::PaddingNegotiate),
        "VPADDING" => Ok(CellType::VPadding),
        "CERTS" => Ok(CellType::Certs),
        "AUTH_CHALLENGE" => Ok(CellType::AuthChallenge),
        "AUTHENTICATE" => Ok(CellType::Authenticate),
        "AUTHORIZE" => Ok(CellType::Authorize),
        _ => Err(Error::Protocol(format!(
            "'{}' isn't a valid cell type",
            name
        ))),
    }
}

/// Looks up a cell type by its numeric command value.
///
/// Values 0-127 are fixed-size cells, 128+ are variable-size cells.
///
/// # Arguments
///
/// * `value` - The cell command value to look up
///
/// # Errors
///
/// Returns [`Error::Protocol`] if the value is not a valid cell type.
///
/// # Example
///
/// ```rust
/// use stem_rs::client::cell::cell_by_value;
///
/// let cell_type = cell_by_value(8).unwrap();
/// assert_eq!(cell_type.name(), "NETINFO");
///
/// assert!(cell_by_value(255).is_err());
/// ```
pub fn cell_by_value(value: u8) -> Result<CellType, Error> {
    match value {
        0 => Ok(CellType::Padding),
        1 => Ok(CellType::Create),
        2 => Ok(CellType::Created),
        3 => Ok(CellType::Relay),
        4 => Ok(CellType::Destroy),
        5 => Ok(CellType::CreateFast),
        6 => Ok(CellType::CreatedFast),
        7 => Ok(CellType::Versions),
        8 => Ok(CellType::Netinfo),
        9 => Ok(CellType::RelayEarly),
        10 => Ok(CellType::Create2),
        11 => Ok(CellType::Created2),
        12 => Ok(CellType::PaddingNegotiate),
        128 => Ok(CellType::VPadding),
        129 => Ok(CellType::Certs),
        130 => Ok(CellType::AuthChallenge),
        131 => Ok(CellType::Authenticate),
        132 => Ok(CellType::Authorize),
        _ => Err(Error::Protocol(format!(
            "'{}' isn't a valid cell value",
            value
        ))),
    }
}

/// Parsed cell from the Tor relay protocol.
///
/// This enum represents all supported cell types that can be parsed from
/// or serialized to the wire format. Each variant wraps a specific cell
/// type struct with its associated data.
///
/// # Parsing
///
/// Use [`Cell::pop`] to parse a single cell from bytes, or [`Cell::unpack_all`]
/// to parse multiple cells.
///
/// # Serialization
///
/// Use [`Cell::pack`] to serialize a cell to bytes for transmission.
///
/// # Example
///
/// ```rust
/// use stem_rs::client::cell::{Cell, VersionsCell};
/// use stem_rs::client::datatype::LinkProtocol;
///
/// // Create and pack a cell
/// let versions = VersionsCell::new(vec![3, 4, 5]);
/// let packed = versions.pack(&LinkProtocol::new(2));
///
/// // Parse the cell back
/// let (cell, _) = Cell::pop(&packed, 2).unwrap();
/// match cell {
///     Cell::Versions(v) => assert_eq!(v.versions, vec![3, 4, 5]),
///     _ => panic!("Expected VersionsCell"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    /// Fixed-size padding cell.
    Padding(PaddingCell),
    /// Link protocol version negotiation.
    Versions(VersionsCell),
    /// Time and address information.
    Netinfo(NetinfoCell),
    /// Create circuit without public key.
    CreateFast(CreateFastCell),
    /// Acknowledge fast circuit creation.
    CreatedFast(CreatedFastCell),
    /// End-to-end encrypted relay data.
    Relay(RelayCell),
    /// Tear down a circuit.
    Destroy(DestroyCell),
    /// Variable-length padding.
    VPadding(VPaddingCell),
    /// Relay certificates.
    Certs(CertsCell),
    /// Authentication challenge.
    AuthChallenge(AuthChallengeCell),
}

impl Cell {
    /// Packs this cell into bytes for transmission.
    ///
    /// The output format depends on the link protocol version and cell type.
    ///
    /// # Arguments
    ///
    /// * `link_protocol` - Link protocol version (affects circuit ID size)
    pub fn pack(&self, link_protocol: u32) -> Vec<u8> {
        let lp = LinkProtocol::new(link_protocol);
        match self {
            Cell::Padding(c) => c.pack(&lp),
            Cell::Versions(c) => c.pack(&lp),
            Cell::Netinfo(c) => c.pack(&lp),
            Cell::CreateFast(c) => c.pack(&lp),
            Cell::CreatedFast(c) => c.pack(&lp),
            Cell::Relay(c) => c.pack(&lp),
            Cell::Destroy(c) => c.pack(&lp),
            Cell::VPadding(c) => c.pack(&lp),
            Cell::Certs(c) => c.pack(&lp),
            Cell::AuthChallenge(c) => c.pack(&lp),
        }
    }

    /// Parses a single cell from bytes and returns the remainder.
    ///
    /// This is the primary method for parsing cells from received data.
    /// It handles both fixed-size and variable-size cells based on the
    /// command type.
    ///
    /// # Arguments
    ///
    /// * `content` - Bytes to parse
    /// * `link_protocol` - Link protocol version (affects circuit ID size)
    ///
    /// # Returns
    ///
    /// A tuple of (parsed cell, remaining bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - Content is too short for the cell header
    /// - Content is too short for the declared payload
    /// - Cell type is unknown or not yet implemented
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::client::cell::{Cell, VersionsCell};
    /// use stem_rs::client::datatype::LinkProtocol;
    ///
    /// let versions = VersionsCell::new(vec![3, 4, 5]);
    /// let packed = versions.pack(&LinkProtocol::new(2));
    ///
    /// let (cell, remainder) = Cell::pop(&packed, 2).unwrap();
    /// assert!(remainder.is_empty());
    /// ```
    pub fn pop(content: &[u8], link_protocol: u32) -> Result<(Cell, Vec<u8>), Error> {
        let lp = LinkProtocol::new(link_protocol);
        let circ_id_size = lp.circ_id_size.size();

        if content.len() < circ_id_size + CELL_TYPE_SIZE.size() {
            return Err(Error::Protocol(
                "Cell content too short for header".to_string(),
            ));
        }

        let (circ_id, rest) = lp.circ_id_size.pop(content)?;
        let (command, rest) = CELL_TYPE_SIZE.pop(rest)?;
        let cell_type = cell_by_value(command as u8)?;

        let payload_len = if cell_type.is_fixed_size() {
            FIXED_PAYLOAD_LEN
        } else {
            if rest.len() < PAYLOAD_LEN_SIZE.size() {
                return Err(Error::Protocol(
                    "Cell content too short for payload length".to_string(),
                ));
            }
            let (len, _) = PAYLOAD_LEN_SIZE.pop(rest)?;
            len as usize
        };

        let header_size = if cell_type.is_fixed_size() {
            circ_id_size + CELL_TYPE_SIZE.size()
        } else {
            circ_id_size + CELL_TYPE_SIZE.size() + PAYLOAD_LEN_SIZE.size()
        };

        let total_size = header_size + payload_len;
        if content.len() < total_size {
            return Err(Error::Protocol(format!(
                "{} cell should have a payload of {} bytes, but only had {}",
                cell_type.name(),
                payload_len,
                content.len() - header_size
            )));
        }

        let (_, payload_start) = split(content, header_size);
        let (payload, _) = split(payload_start, payload_len);
        let remainder = content[total_size..].to_vec();

        let cell = match cell_type {
            CellType::Padding => Cell::Padding(PaddingCell::unpack(payload)?),
            CellType::Versions => Cell::Versions(VersionsCell::unpack(payload)?),
            CellType::Netinfo => Cell::Netinfo(NetinfoCell::unpack(payload)?),
            CellType::CreateFast => {
                Cell::CreateFast(CreateFastCell::unpack(payload, circ_id as u32)?)
            }
            CellType::CreatedFast => {
                Cell::CreatedFast(CreatedFastCell::unpack(payload, circ_id as u32)?)
            }
            CellType::Relay => Cell::Relay(RelayCell::unpack(payload, circ_id as u32)?),
            CellType::Destroy => Cell::Destroy(DestroyCell::unpack(payload, circ_id as u32)?),
            CellType::VPadding => Cell::VPadding(VPaddingCell::unpack(payload)?),
            CellType::Certs => Cell::Certs(CertsCell::unpack(payload)?),
            CellType::AuthChallenge => Cell::AuthChallenge(AuthChallengeCell::unpack(payload)?),
            _ => {
                return Err(Error::Protocol(format!(
                    "Unpacking not yet implemented for {} cells",
                    cell_type.name()
                )))
            }
        };

        Ok((cell, remainder))
    }

    /// Parses all cells from a byte buffer.
    ///
    /// Repeatedly calls [`Cell::pop`] until all bytes are consumed.
    ///
    /// # Arguments
    ///
    /// * `content` - Bytes containing one or more cells
    /// * `link_protocol` - Link protocol version
    ///
    /// # Errors
    ///
    /// Returns an error if any cell fails to parse.
    pub fn unpack_all(content: &[u8], link_protocol: u32) -> Result<Vec<Cell>, Error> {
        let mut cells = Vec::new();
        let mut remaining = content.to_vec();
        while !remaining.is_empty() {
            let (cell, rest) = Cell::pop(&remaining, link_protocol)?;
            cells.push(cell);
            remaining = rest;
        }
        Ok(cells)
    }
}

/// Fixed-size padding cell for traffic analysis resistance.
///
/// Padding cells are used to maintain constant traffic patterns and prevent
/// traffic analysis attacks. The payload is random data that is ignored by
/// the receiver.
///
/// # Wire Format
///
/// ```text
/// [ CircID ][ 0 (PADDING) ][ 509 bytes random payload ]
/// ```
///
/// # Example
///
/// ```rust
/// use stem_rs::client::cell::PaddingCell;
/// use stem_rs::client::datatype::LinkProtocol;
///
/// // Create with random payload
/// let cell = PaddingCell::new();
///
/// // Create with specific payload
/// let payload = vec![0u8; 509];
/// let cell = PaddingCell::with_payload(payload).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PaddingCell {
    /// The padding payload (exactly 509 bytes).
    pub payload: Vec<u8>,
}

impl PaddingCell {
    /// Creates a new padding cell with random payload.
    ///
    /// The payload is filled with cryptographically random bytes.
    pub fn new() -> Self {
        let mut payload = vec![0u8; FIXED_PAYLOAD_LEN];
        getrandom::fill(&mut payload).expect("Failed to generate random bytes");
        PaddingCell { payload }
    }

    /// Creates a padding cell with a specific payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - Must be exactly 509 bytes
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if payload is not exactly 509 bytes.
    pub fn with_payload(payload: Vec<u8>) -> Result<Self, Error> {
        if payload.len() != FIXED_PAYLOAD_LEN {
            return Err(Error::Protocol(format!(
                "Padding payload should be {} bytes, but was {}",
                FIXED_PAYLOAD_LEN,
                payload.len()
            )));
        }
        Ok(PaddingCell { payload })
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        pack_fixed_cell(
            link_protocol,
            CellType::Padding.value(),
            &self.payload,
            None,
        )
    }

    /// Unpacks a PADDING cell from payload bytes.
    pub fn unpack(payload: &[u8]) -> Result<Self, Error> {
        Ok(PaddingCell {
            payload: payload.to_vec(),
        })
    }
}

impl Default for PaddingCell {
    fn default() -> Self {
        Self::new()
    }
}

/// Link protocol version negotiation cell.
///
/// VERSIONS cells are exchanged at the start of a connection to negotiate
/// the link protocol version. Both sides send their supported versions,
/// and the highest mutually supported version is selected.
///
/// # Wire Format
///
/// Variable-size cell:
/// ```text
/// [ CircID (0) ][ 7 (VERSIONS) ][ Length ][ Version1 (2 bytes) ][ Version2 ]...
/// ```
///
/// # Protocol Notes
///
/// - VERSIONS cells always use circuit ID 0
/// - The first VERSIONS cell uses 2-byte circuit IDs for backward compatibility
/// - Versions are encoded as 2-byte big-endian integers
///
/// # Example
///
/// ```rust
/// use stem_rs::client::cell::VersionsCell;
/// use stem_rs::client::datatype::LinkProtocol;
///
/// let cell = VersionsCell::new(vec![3, 4, 5]);
/// let packed = cell.pack(&LinkProtocol::new(2));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct VersionsCell {
    /// Supported link protocol versions.
    pub versions: Vec<u32>,
}

impl VersionsCell {
    /// Creates a new VERSIONS cell with the specified protocol versions.
    ///
    /// # Arguments
    ///
    /// * `versions` - List of supported link protocol versions
    pub fn new(versions: Vec<u32>) -> Self {
        VersionsCell { versions }
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        let payload: Vec<u8> = self
            .versions
            .iter()
            .flat_map(|v| Size::Short.pack(*v as u64))
            .collect();
        pack_variable_cell(link_protocol, CellType::Versions.value(), &payload, None)
    }

    /// Unpacks a VERSIONS cell from payload bytes.
    pub fn unpack(payload: &[u8]) -> Result<Self, Error> {
        let mut versions = Vec::new();
        let mut content = payload;
        while !content.is_empty() {
            let (version, rest) = Size::Short.pop(content)?;
            versions.push(version as u32);
            content = rest;
        }
        Ok(VersionsCell { versions })
    }
}

/// Network information exchange cell.
///
/// NETINFO cells are exchanged after version negotiation to share time
/// and address information. This helps relays detect clock skew and
/// verify connectivity.
///
/// # Wire Format
///
/// Fixed-size cell:
/// ```text
/// [ CircID (0) ][ 8 (NETINFO) ][ Timestamp (4) ][ Receiver Addr ][ Sender Count ][ Sender Addrs ]
/// ```
///
/// # Example
///
/// ```rust
/// use stem_rs::client::cell::NetinfoCell;
/// use stem_rs::client::datatype::{Address, LinkProtocol};
///
/// let receiver = Address::new("127.0.0.1").unwrap();
/// let cell = NetinfoCell::new(receiver, vec![], None);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct NetinfoCell {
    /// Current timestamp from the sender.
    pub timestamp: DateTime<Utc>,
    /// The receiver's address as seen by the sender.
    pub receiver_address: Address,
    /// The sender's own addresses.
    pub sender_addresses: Vec<Address>,
    /// Unused padding bytes.
    pub unused: Vec<u8>,
}

impl NetinfoCell {
    /// Creates a new NETINFO cell.
    ///
    /// # Arguments
    ///
    /// * `receiver_address` - The receiver's address as seen by sender
    /// * `sender_addresses` - The sender's own addresses
    /// * `timestamp` - Optional timestamp (defaults to current time)
    pub fn new(
        receiver_address: Address,
        sender_addresses: Vec<Address>,
        timestamp: Option<DateTime<Utc>>,
    ) -> Self {
        NetinfoCell {
            timestamp: timestamp.unwrap_or_else(Utc::now),
            receiver_address,
            sender_addresses,
            unused: Vec::new(),
        }
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&Size::Long.pack(self.timestamp.timestamp() as u64));
        payload.extend_from_slice(&self.receiver_address.pack());
        payload.push(self.sender_addresses.len() as u8);
        for addr in &self.sender_addresses {
            payload.extend_from_slice(&addr.pack());
        }
        pack_fixed_cell(
            link_protocol,
            CellType::Netinfo.value(),
            &payload,
            Some(&self.unused),
        )
    }

    /// Unpacks a NETINFO cell from payload bytes.
    pub fn unpack(payload: &[u8]) -> Result<Self, Error> {
        let (timestamp, content) = Size::Long.pop(payload)?;
        let (receiver_address, content) = Address::pop(content)?;
        let (sender_addr_count, mut content) = Size::Char.pop(content)?;

        let mut sender_addresses = Vec::new();
        for _ in 0..sender_addr_count {
            let (addr, rest) = Address::pop(content)?;
            sender_addresses.push(addr);
            content = rest;
        }

        Ok(NetinfoCell {
            timestamp: Utc.timestamp_opt(timestamp as i64, 0).unwrap(),
            receiver_address,
            sender_addresses,
            unused: content.to_vec(),
        })
    }
}

/// Circuit creation cell using fast handshake (no public key).
///
/// CREATE_FAST cells are used to create circuits with the first hop (guard)
/// relay. This is faster than the full CREATE handshake because the TLS
/// connection already authenticates the relay.
///
/// # Security
///
/// CREATE_FAST does not provide forward secrecy because it doesn't use
/// public key cryptography. It relies on the TLS connection for security.
/// For multi-hop circuits, subsequent hops should use CREATE2.
///
/// # Wire Format
///
/// ```text
/// [ CircID ][ 5 (CREATE_FAST) ][ Key Material (20 bytes) ][ Padding ]
/// ```
///
/// # Example
///
/// ```rust
/// use stem_rs::client::cell::CreateFastCell;
///
/// // Create with random key material
/// let cell = CreateFastCell::new(1);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CreateFastCell {
    /// Circuit ID for the new circuit.
    pub circ_id: u32,
    /// Random key material (20 bytes) for key derivation.
    pub key_material: [u8; HASH_LEN],
    /// Unused padding bytes.
    pub unused: Vec<u8>,
}

impl CreateFastCell {
    /// Creates a new CREATE_FAST cell with random key material.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID for the new circuit
    pub fn new(circ_id: u32) -> Self {
        let mut key_material = [0u8; HASH_LEN];
        getrandom::fill(&mut key_material).expect("Failed to generate random bytes");
        CreateFastCell {
            circ_id,
            key_material,
            unused: Vec::new(),
        }
    }

    /// Creates a CREATE_FAST cell with specific key material.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID for the new circuit
    /// * `key_material` - 20 bytes of key material
    pub fn with_key_material(circ_id: u32, key_material: [u8; HASH_LEN]) -> Self {
        CreateFastCell {
            circ_id,
            key_material,
            unused: Vec::new(),
        }
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        pack_fixed_cell(
            link_protocol,
            CellType::CreateFast.value(),
            &self.key_material,
            Some(&self.unused),
        )
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if i < link_protocol.circ_id_size.size() {
                let circ_id_bytes = if link_protocol.circ_id_size == Size::Long {
                    self.circ_id.to_be_bytes().to_vec()
                } else {
                    (self.circ_id as u16).to_be_bytes().to_vec()
                };
                circ_id_bytes.get(i).copied().unwrap_or(b)
            } else {
                b
            }
        })
        .collect()
    }

    /// Unpacks a CREATE_FAST cell from payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if payload is too short for key material.
    pub fn unpack(payload: &[u8], circ_id: u32) -> Result<Self, Error> {
        if payload.len() < HASH_LEN {
            return Err(Error::Protocol(format!(
                "Key material should be {} bytes, but was {}",
                HASH_LEN,
                payload.len()
            )));
        }
        let (key_material_slice, unused) = split(payload, HASH_LEN);
        let mut key_material = [0u8; HASH_LEN];
        key_material.copy_from_slice(key_material_slice);

        Ok(CreateFastCell {
            circ_id,
            key_material,
            unused: unused.to_vec(),
        })
    }
}

/// Response to CREATE_FAST circuit creation.
///
/// CREATED_FAST cells are sent by relays in response to CREATE_FAST cells.
/// They contain the relay's key material and a derivative key that proves
/// the relay knows the shared secret.
///
/// # Key Derivation
///
/// The shared key material is: `client_key_material || relay_key_material`
/// This is used with KDF-TOR to derive encryption keys.
///
/// # Wire Format
///
/// ```text
/// [ CircID ][ 6 (CREATED_FAST) ][ Key Material (20) ][ Derivative Key (20) ][ Padding ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CreatedFastCell {
    /// Circuit ID this response is for.
    pub circ_id: u32,
    /// Relay's random key material (20 bytes).
    pub key_material: [u8; HASH_LEN],
    /// Hash proving relay knows the shared key (20 bytes).
    pub derivative_key: [u8; HASH_LEN],
    /// Unused padding bytes.
    pub unused: Vec<u8>,
}

impl CreatedFastCell {
    /// Creates a new CREATED_FAST cell with random key material.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID this response is for
    /// * `derivative_key` - Hash proving knowledge of shared key
    pub fn new(circ_id: u32, derivative_key: [u8; HASH_LEN]) -> Self {
        let mut key_material = [0u8; HASH_LEN];
        getrandom::fill(&mut key_material).expect("Failed to generate random bytes");
        CreatedFastCell {
            circ_id,
            key_material,
            derivative_key,
            unused: Vec::new(),
        }
    }

    /// Creates a CREATED_FAST cell with specific key material.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID this response is for
    /// * `key_material` - Relay's 20 bytes of key material
    /// * `derivative_key` - Hash proving knowledge of shared key
    pub fn with_key_material(
        circ_id: u32,
        key_material: [u8; HASH_LEN],
        derivative_key: [u8; HASH_LEN],
    ) -> Self {
        CreatedFastCell {
            circ_id,
            key_material,
            derivative_key,
            unused: Vec::new(),
        }
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.key_material);
        payload.extend_from_slice(&self.derivative_key);
        let mut cell = pack_fixed_cell(
            link_protocol,
            CellType::CreatedFast.value(),
            &payload,
            Some(&self.unused),
        );
        let circ_id_bytes = if link_protocol.circ_id_size == Size::Long {
            self.circ_id.to_be_bytes().to_vec()
        } else {
            (self.circ_id as u16).to_be_bytes().to_vec()
        };
        for (i, &b) in circ_id_bytes.iter().enumerate() {
            cell[i] = b;
        }
        cell
    }

    /// Unpacks a CREATED_FAST cell from payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if payload is too short.
    pub fn unpack(payload: &[u8], circ_id: u32) -> Result<Self, Error> {
        if payload.len() < HASH_LEN * 2 {
            return Err(Error::Protocol(format!(
                "Key material and derivative key should be {} bytes, but was {}",
                HASH_LEN * 2,
                payload.len()
            )));
        }
        let (key_material_slice, rest) = split(payload, HASH_LEN);
        let (derivative_key_slice, unused) = split(rest, HASH_LEN);

        let mut key_material = [0u8; HASH_LEN];
        let mut derivative_key = [0u8; HASH_LEN];
        key_material.copy_from_slice(key_material_slice);
        derivative_key.copy_from_slice(derivative_key_slice);

        Ok(CreatedFastCell {
            circ_id,
            key_material,
            derivative_key,
            unused: unused.to_vec(),
        })
    }
}

/// End-to-end encrypted relay cell.
///
/// RELAY cells carry encrypted data through circuits. Each relay cell is
/// encrypted/decrypted at each hop using the circuit's encryption keys.
///
/// # Wire Format
///
/// ```text
/// [ CircID ][ 3 (RELAY) ][ Command (1) ][ Recognized (2) ][ StreamID (2) ]
/// [ Digest (4) ][ Length (2) ][ Data ][ Padding ]
/// ```
///
/// # Fields
///
/// - `command` - Relay sub-command (DATA, BEGIN, END, etc.)
/// - `recognized` - Zero if cell is for us (used for decryption check)
/// - `stream_id` - Stream identifier within the circuit
/// - `digest` - Running digest for integrity verification
/// - `data` - Payload data
///
/// # Stream ID Rules
///
/// Some commands require a stream ID, others forbid it:
/// - Required: BEGIN, DATA, END, CONNECTED, RESOLVE, RESOLVED, BEGIN_DIR
/// - Forbidden: EXTEND, EXTENDED, TRUNCATE, TRUNCATED, DROP, EXTEND2, EXTENDED2
#[derive(Debug, Clone, PartialEq)]
pub struct RelayCell {
    /// Circuit ID this cell belongs to.
    pub circ_id: u32,
    /// Relay sub-command.
    pub command: RelayCommand,
    /// Integer value of the command.
    pub command_int: u8,
    /// Recognition field (0 if cell is for us).
    pub recognized: u16,
    /// Stream identifier within the circuit.
    pub stream_id: u16,
    /// Running digest for integrity.
    pub digest: u32,
    /// Payload data.
    pub data: Vec<u8>,
    /// Unused padding bytes.
    pub unused: Vec<u8>,
}

impl RelayCell {
    /// Creates a new RELAY cell.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID
    /// * `command` - Relay sub-command
    /// * `data` - Payload data
    /// * `digest` - Running digest (0 for unencrypted cells)
    /// * `stream_id` - Stream identifier
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - `stream_id` is 0 but command requires a stream ID
    /// - `stream_id` is non-zero but command forbids stream IDs
    pub fn new(
        circ_id: u32,
        command: RelayCommand,
        data: Vec<u8>,
        digest: u32,
        stream_id: u16,
    ) -> Result<Self, Error> {
        if digest == 0 {
            if stream_id == 0 && STREAM_ID_REQUIRED.contains(&command) {
                return Err(Error::Protocol(format!(
                    "{} relay cells require a stream id",
                    command
                )));
            }
            if stream_id != 0 && STREAM_ID_DISALLOWED.contains(&command) {
                return Err(Error::Protocol(format!(
                    "{} relay cells concern the circuit itself and cannot have a stream id",
                    command
                )));
            }
        }

        Ok(RelayCell {
            circ_id,
            command_int: command.value(),
            command,
            recognized: 0,
            stream_id,
            digest,
            data,
            unused: Vec::new(),
        })
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(self.command_int);
        payload.extend_from_slice(&self.recognized.to_be_bytes());
        payload.extend_from_slice(&self.stream_id.to_be_bytes());
        payload.extend_from_slice(&self.digest.to_be_bytes());
        payload.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        payload.extend_from_slice(&self.data);

        let mut cell = pack_fixed_cell(
            link_protocol,
            CellType::Relay.value(),
            &payload,
            Some(&self.unused),
        );
        let circ_id_bytes = if link_protocol.circ_id_size == Size::Long {
            self.circ_id.to_be_bytes().to_vec()
        } else {
            (self.circ_id as u16).to_be_bytes().to_vec()
        };
        for (i, &b) in circ_id_bytes.iter().enumerate() {
            cell[i] = b;
        }
        cell
    }

    /// Unpacks a RELAY cell from payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if payload is malformed.
    pub fn unpack(payload: &[u8], circ_id: u32) -> Result<Self, Error> {
        let (command, content) = Size::Char.pop(payload)?;
        let (recognized, content) = Size::Short.pop(content)?;
        let (stream_id, content) = Size::Short.pop(content)?;
        let (digest, content) = Size::Long.pop(content)?;
        let (data_len, content) = Size::Short.pop(content)?;
        let data_len = data_len as usize;

        if content.len() < data_len {
            return Err(Error::Protocol(format!(
                "RELAY cell said it had {} bytes of data, but only had {}",
                data_len,
                content.len()
            )));
        }

        let (data, unused) = split(content, data_len);
        let (cmd, cmd_int) = RelayCommand::get(command as u8);

        Ok(RelayCell {
            circ_id,
            command: cmd,
            command_int: cmd_int,
            recognized: recognized as u16,
            stream_id: stream_id as u16,
            digest: digest as u32,
            data: data.to_vec(),
            unused: unused.to_vec(),
        })
    }
}

/// Circuit teardown cell.
///
/// DESTROY cells are sent to tear down a circuit. They include a reason
/// code explaining why the circuit is being closed.
///
/// # Wire Format
///
/// ```text
/// [ CircID ][ 4 (DESTROY) ][ Reason (1) ][ Padding ]
/// ```
///
/// # Example
///
/// ```rust
/// use stem_rs::client::cell::DestroyCell;
/// use stem_rs::client::datatype::CloseReason;
///
/// let cell = DestroyCell::new(1, CloseReason::Requested);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DestroyCell {
    /// Circuit ID to destroy.
    pub circ_id: u32,
    /// Reason for closing the circuit.
    pub reason: CloseReason,
    /// Integer value of the reason.
    pub reason_int: u8,
    /// Unused padding bytes.
    pub unused: Vec<u8>,
}

impl DestroyCell {
    /// Creates a new DESTROY cell.
    ///
    /// # Arguments
    ///
    /// * `circ_id` - Circuit ID to destroy
    /// * `reason` - Reason for closing the circuit
    pub fn new(circ_id: u32, reason: CloseReason) -> Self {
        DestroyCell {
            circ_id,
            reason_int: reason.value(),
            reason,
            unused: Vec::new(),
        }
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        let payload = vec![self.reason_int];
        let mut cell = pack_fixed_cell(
            link_protocol,
            CellType::Destroy.value(),
            &payload,
            Some(&self.unused),
        );
        let circ_id_bytes = if link_protocol.circ_id_size == Size::Long {
            self.circ_id.to_be_bytes().to_vec()
        } else {
            (self.circ_id as u16).to_be_bytes().to_vec()
        };
        for (i, &b) in circ_id_bytes.iter().enumerate() {
            cell[i] = b;
        }
        cell
    }

    /// Unpacks a DESTROY cell from payload bytes.
    pub fn unpack(payload: &[u8], circ_id: u32) -> Result<Self, Error> {
        let (reason, unused) = Size::Char.pop(payload)?;
        let (close_reason, reason_int) = CloseReason::get(reason as u8);

        Ok(DestroyCell {
            circ_id,
            reason: close_reason,
            reason_int,
            unused: unused.to_vec(),
        })
    }
}

/// Variable-length padding cell.
///
/// VPADDING cells are similar to PADDING cells but have variable length.
/// They are used for traffic analysis resistance when variable-size
/// padding is needed.
///
/// # Wire Format
///
/// Variable-size cell:
/// ```text
/// [ CircID (0) ][ 128 (VPADDING) ][ Length ][ Random Payload ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct VPaddingCell {
    /// Random padding payload.
    pub payload: Vec<u8>,
}

impl VPaddingCell {
    /// Creates a new VPADDING cell with random payload of specified size.
    ///
    /// # Arguments
    ///
    /// * `size` - Number of random bytes to generate
    pub fn new(size: usize) -> Self {
        let mut payload = vec![0u8; size];
        if size > 0 {
            getrandom::fill(&mut payload).expect("Failed to generate random bytes");
        }
        VPaddingCell { payload }
    }

    /// Creates a VPADDING cell with a specific payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The padding bytes
    pub fn with_payload(payload: Vec<u8>) -> Self {
        VPaddingCell { payload }
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        pack_variable_cell(
            link_protocol,
            CellType::VPadding.value(),
            &self.payload,
            None,
        )
    }

    /// Unpacks a VPADDING cell from payload bytes.
    pub fn unpack(payload: &[u8]) -> Result<Self, Error> {
        Ok(VPaddingCell {
            payload: payload.to_vec(),
        })
    }
}

/// Relay certificates cell.
///
/// CERTS cells contain certificates used to authenticate the relay.
/// They are sent during the link handshake after VERSIONS negotiation.
///
/// # Wire Format
///
/// Variable-size cell:
/// ```text
/// [ CircID (0) ][ 129 (CERTS) ][ Length ][ Cert Count (1) ][ Certificates... ]
/// ```
///
/// Each certificate is encoded as:
/// ```text
/// [ Type (1) ][ Length (2) ][ Certificate Data ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CertsCell {
    /// List of certificates.
    pub certificates: Vec<Certificate>,
    /// Unused trailing bytes.
    pub unused: Vec<u8>,
}

impl CertsCell {
    /// Creates a new CERTS cell with the specified certificates.
    ///
    /// # Arguments
    ///
    /// * `certificates` - List of certificates to include
    pub fn new(certificates: Vec<Certificate>) -> Self {
        CertsCell {
            certificates,
            unused: Vec::new(),
        }
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(self.certificates.len() as u8);
        for cert in &self.certificates {
            payload.extend_from_slice(&cert.pack());
        }
        payload.extend_from_slice(&self.unused);
        pack_variable_cell(link_protocol, CellType::Certs.value(), &payload, None)
    }

    /// Unpacks a CERTS cell from payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the certificate count doesn't match
    /// the actual number of certificates in the payload.
    pub fn unpack(payload: &[u8]) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(CertsCell {
                certificates: Vec::new(),
                unused: Vec::new(),
            });
        }

        let (cert_count, mut content) = Size::Char.pop(payload)?;
        let mut certificates = Vec::new();

        for _ in 0..cert_count {
            if content.is_empty() {
                return Err(Error::Protocol(format!(
                    "CERTS cell indicates it should have {} certificates, but only contained {}",
                    cert_count,
                    certificates.len()
                )));
            }
            let (cert, rest) = Certificate::pop(content)?;
            certificates.push(cert);
            content = rest;
        }

        Ok(CertsCell {
            certificates,
            unused: content.to_vec(),
        })
    }
}

/// Authentication challenge cell.
///
/// AUTH_CHALLENGE cells are sent by relays to initiate optional client
/// authentication. They contain a random challenge and list of supported
/// authentication methods.
///
/// # Wire Format
///
/// Variable-size cell:
/// ```text
/// [ CircID (0) ][ 130 (AUTH_CHALLENGE) ][ Length ]
/// [ Challenge (32 bytes) ][ Method Count (2) ][ Methods (2 bytes each) ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AuthChallengeCell {
    /// Random challenge bytes (32 bytes).
    pub challenge: [u8; AUTH_CHALLENGE_SIZE],
    /// Supported authentication methods.
    pub methods: Vec<u16>,
    /// Unused trailing bytes.
    pub unused: Vec<u8>,
}

impl AuthChallengeCell {
    /// Creates a new AUTH_CHALLENGE cell with random challenge.
    ///
    /// # Arguments
    ///
    /// * `methods` - Supported authentication methods
    pub fn new(methods: Vec<u16>) -> Self {
        let mut challenge = [0u8; AUTH_CHALLENGE_SIZE];
        getrandom::fill(&mut challenge).expect("Failed to generate random bytes");
        AuthChallengeCell {
            challenge,
            methods,
            unused: Vec::new(),
        }
    }

    /// Creates an AUTH_CHALLENGE cell with a specific challenge.
    ///
    /// # Arguments
    ///
    /// * `challenge` - 32-byte challenge value
    /// * `methods` - Supported authentication methods
    pub fn with_challenge(challenge: [u8; AUTH_CHALLENGE_SIZE], methods: Vec<u16>) -> Self {
        AuthChallengeCell {
            challenge,
            methods,
            unused: Vec::new(),
        }
    }

    /// Packs this cell into bytes for transmission.
    pub fn pack(&self, link_protocol: &LinkProtocol) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.challenge);
        payload.extend_from_slice(&(self.methods.len() as u16).to_be_bytes());
        for method in &self.methods {
            payload.extend_from_slice(&method.to_be_bytes());
        }
        payload.extend_from_slice(&self.unused);
        pack_variable_cell(
            link_protocol,
            CellType::AuthChallenge.value(),
            &payload,
            None,
        )
    }

    /// Unpacks an AUTH_CHALLENGE cell from payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if payload is too short for challenge
    /// or declared number of methods.
    pub fn unpack(payload: &[u8]) -> Result<Self, Error> {
        let min_size = AUTH_CHALLENGE_SIZE + Size::Short.size();
        if payload.len() < min_size {
            return Err(Error::Protocol(format!(
                "AUTH_CHALLENGE payload should be at least {} bytes, but was {}",
                min_size,
                payload.len()
            )));
        }

        let (challenge_slice, content) = split(payload, AUTH_CHALLENGE_SIZE);
        let (method_count, mut content) = Size::Short.pop(content)?;

        if content.len() < (method_count as usize) * Size::Short.size() {
            return Err(Error::Protocol(format!(
                "AUTH_CHALLENGE should have {} methods, but only had {} bytes for it",
                method_count,
                content.len()
            )));
        }

        let mut methods = Vec::new();
        for _ in 0..method_count {
            let (method, rest) = Size::Short.pop(content)?;
            methods.push(method as u16);
            content = rest;
        }

        let mut challenge = [0u8; AUTH_CHALLENGE_SIZE];
        challenge.copy_from_slice(challenge_slice);

        Ok(AuthChallengeCell {
            challenge,
            methods,
            unused: content.to_vec(),
        })
    }
}

/// Packs a fixed-size cell into bytes.
///
/// Fixed-size cells have a 509-byte payload, padded with zeros if needed.
///
/// # Arguments
///
/// * `link_protocol` - Link protocol version (affects circuit ID size)
/// * `command` - Cell command value
/// * `payload` - Cell payload data
/// * `unused` - Optional unused bytes to include before padding
fn pack_fixed_cell(
    link_protocol: &LinkProtocol,
    command: u8,
    payload: &[u8],
    unused: Option<&[u8]>,
) -> Vec<u8> {
    let mut cell = Vec::new();

    cell.extend_from_slice(&vec![0u8; link_protocol.circ_id_size.size()]);

    cell.push(command);

    cell.extend_from_slice(payload);

    if let Some(unused_bytes) = unused {
        cell.extend_from_slice(unused_bytes);
    }

    let padding_needed = link_protocol.fixed_cell_length.saturating_sub(cell.len());
    cell.extend(std::iter::repeat_n(ZERO, padding_needed));

    cell
}

/// Packs a variable-size cell into bytes.
///
/// Variable-size cells have a 2-byte length field followed by the payload.
///
/// # Arguments
///
/// * `link_protocol` - Link protocol version (affects circuit ID size)
/// * `command` - Cell command value
/// * `payload` - Cell payload data
/// * `_unused` - Unused parameter (for API consistency)
fn pack_variable_cell(
    link_protocol: &LinkProtocol,
    command: u8,
    payload: &[u8],
    _unused: Option<&[u8]>,
) -> Vec<u8> {
    let mut cell = Vec::new();

    cell.extend_from_slice(&vec![0u8; link_protocol.circ_id_size.size()]);

    cell.push(command);

    cell.extend_from_slice(&(payload.len() as u16).to_be_bytes());

    cell.extend_from_slice(payload);

    cell
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_by_name() {
        let cell_type = cell_by_name("NETINFO").unwrap();
        assert_eq!("NETINFO", cell_type.name());
        assert_eq!(8, cell_type.value());
        assert!(cell_type.is_fixed_size());

        assert!(cell_by_name("NOPE").is_err());
    }

    #[test]
    fn test_cell_by_value() {
        let cell_type = cell_by_value(8).unwrap();
        assert_eq!("NETINFO", cell_type.name());
        assert_eq!(8, cell_type.value());
        assert!(cell_type.is_fixed_size());

        assert!(cell_by_value(85).is_err());
    }

    #[test]
    fn test_versions_cell() {
        let versions = vec![1, 2, 3];
        let cell = VersionsCell::new(versions.clone());
        let packed = cell.pack(&LinkProtocol::new(2));

        let expected = b"\x00\x00\x07\x00\x06\x00\x01\x00\x02\x00\x03";
        assert_eq!(expected.to_vec(), packed);

        let (unpacked, _) = Cell::pop(&packed, 2).unwrap();
        match unpacked {
            Cell::Versions(v) => assert_eq!(versions, v.versions),
            _ => panic!("Expected VersionsCell"),
        }
    }

    #[test]
    fn test_versions_cell_empty() {
        let cell = VersionsCell::new(vec![]);
        let packed = cell.pack(&LinkProtocol::new(2));

        let expected = b"\x00\x00\x07\x00\x00";
        assert_eq!(expected.to_vec(), packed);
    }

    #[test]
    fn test_vpadding_cell() {
        let cell = VPaddingCell::with_payload(vec![]);
        let packed = cell.pack(&LinkProtocol::new(2));

        let expected = b"\x00\x00\x80\x00\x00";
        assert_eq!(expected.to_vec(), packed);

        let (unpacked, _) = Cell::pop(&packed, 2).unwrap();
        match unpacked {
            Cell::VPadding(v) => assert!(v.payload.is_empty()),
            _ => panic!("Expected VPaddingCell"),
        }
    }

    #[test]
    fn test_vpadding_cell_with_data() {
        let cell = VPaddingCell::with_payload(vec![0x08, 0x11]);
        let packed = cell.pack(&LinkProtocol::new(2));

        let expected = b"\x00\x00\x80\x00\x02\x08\x11";
        assert_eq!(expected.to_vec(), packed);
    }

    #[test]
    fn test_destroy_cell() {
        let cell = DestroyCell::new(2147483648, CloseReason::None);
        let packed = cell.pack(&LinkProtocol::new(5));

        assert_eq!(0x80, packed[0]);
        assert_eq!(0x00, packed[1]);
        assert_eq!(0x00, packed[2]);
        assert_eq!(0x00, packed[3]);
        assert_eq!(4, packed[4]);
        assert_eq!(0, packed[5]);

        let (unpacked, _) = Cell::pop(&packed, 5).unwrap();
        match unpacked {
            Cell::Destroy(d) => {
                assert_eq!(2147483648, d.circ_id);
                assert_eq!(CloseReason::None, d.reason);
            }
            _ => panic!("Expected DestroyCell"),
        }
    }

    #[test]
    fn test_create_fast_cell() {
        let key_material: [u8; HASH_LEN] = [
            0x92, 0x4f, 0x0c, 0xcb, 0xa8, 0xac, 0xfb, 0xc9, 0x7f, 0xd0, 0x0d, 0x7a, 0x1a, 0x03,
            0x75, 0x91, 0xce, 0x61, 0x73, 0xce,
        ];
        let cell = CreateFastCell::with_key_material(2147483648, key_material);
        let packed = cell.pack(&LinkProtocol::new(5));

        assert_eq!(0x80, packed[0]);
        assert_eq!(0x00, packed[1]);
        assert_eq!(0x00, packed[2]);
        assert_eq!(0x00, packed[3]);
        assert_eq!(5, packed[4]);

        let (unpacked, _) = Cell::pop(&packed, 5).unwrap();
        match unpacked {
            Cell::CreateFast(c) => {
                assert_eq!(2147483648, c.circ_id);
                assert_eq!(key_material, c.key_material);
            }
            _ => panic!("Expected CreateFastCell"),
        }
    }

    #[test]
    fn test_created_fast_cell() {
        let key_material: [u8; HASH_LEN] = [
            0x92, 0x4f, 0x0c, 0xcb, 0xa8, 0xac, 0xfb, 0xc9, 0x7f, 0xd0, 0x0d, 0x7a, 0x1a, 0x03,
            0x75, 0x91, 0xce, 0x61, 0x73, 0xce,
        ];
        let derivative_key: [u8; HASH_LEN] = [
            0x13, 0x5a, 0x99, 0xb2, 0x1e, 0xb6, 0x05, 0x85, 0x17, 0xfc, 0x1c, 0x00, 0x7b, 0xa9,
            0xae, 0x83, 0x5e, 0x4b, 0x99, 0xb2,
        ];
        let cell = CreatedFastCell::with_key_material(2147483648, key_material, derivative_key);
        let packed = cell.pack(&LinkProtocol::new(5));

        let (unpacked, _) = Cell::pop(&packed, 5).unwrap();
        match unpacked {
            Cell::CreatedFast(c) => {
                assert_eq!(2147483648, c.circ_id);
                assert_eq!(key_material, c.key_material);
                assert_eq!(derivative_key, c.derivative_key);
            }
            _ => panic!("Expected CreatedFastCell"),
        }
    }

    #[test]
    fn test_relay_cell() {
        let cell = RelayCell::new(1, RelayCommand::BeginDir, vec![], 564346860, 1).unwrap();
        let packed = cell.pack(&LinkProtocol::new(2));

        let (unpacked, _) = Cell::pop(&packed, 2).unwrap();
        match unpacked {
            Cell::Relay(r) => {
                assert_eq!(1, r.circ_id);
                assert_eq!(RelayCommand::BeginDir, r.command);
                assert_eq!(564346860, r.digest);
                assert_eq!(1, r.stream_id);
            }
            _ => panic!("Expected RelayCell"),
        }
    }

    #[test]
    fn test_certs_cell_empty() {
        let cell = CertsCell::new(vec![]);
        let packed = cell.pack(&LinkProtocol::new(2));

        let expected = b"\x00\x00\x81\x00\x01\x00";
        assert_eq!(expected.to_vec(), packed);
    }

    #[test]
    fn test_certs_cell_with_cert() {
        let cert = Certificate::from_int(1, vec![]);
        let cell = CertsCell::new(vec![cert]);
        let packed = cell.pack(&LinkProtocol::new(2));

        let expected = b"\x00\x00\x81\x00\x04\x01\x01\x00\x00";
        assert_eq!(expected.to_vec(), packed);
    }

    #[test]
    fn test_auth_challenge_cell() {
        let challenge: [u8; AUTH_CHALLENGE_SIZE] = [
            0x89, 0x59, 0x09, 0x99, 0xb2, 0x1e, 0xd9, 0x2a, 0x56, 0xb6, 0x1b, 0x6e, 0x0a, 0x05,
            0xd8, 0x2f, 0xe3, 0x51, 0x48, 0x85, 0x13, 0x5a, 0x17, 0xfc, 0x1c, 0x00, 0x7b, 0xa9,
            0xae, 0x83, 0x5e, 0x4b,
        ];
        let cell = AuthChallengeCell::with_challenge(challenge, vec![1, 3]);
        let packed = cell.pack(&LinkProtocol::new(2));

        let (unpacked, _) = Cell::pop(&packed, 2).unwrap();
        match unpacked {
            Cell::AuthChallenge(a) => {
                assert_eq!(challenge, a.challenge);
                assert_eq!(vec![1, 3], a.methods);
            }
            _ => panic!("Expected AuthChallengeCell"),
        }
    }

    #[test]
    fn test_netinfo_cell() {
        use chrono::TimeZone;
        let timestamp = Utc.with_ymd_and_hms(2018, 1, 14, 1, 46, 56).unwrap();
        let receiver = Address::new("127.0.0.1").unwrap();
        let sender = Address::new("97.113.15.2").unwrap();

        let cell = NetinfoCell::new(receiver.clone(), vec![sender.clone()], Some(timestamp));
        let packed = cell.pack(&LinkProtocol::new(2));

        let (unpacked, _) = Cell::pop(&packed, 2).unwrap();
        match unpacked {
            Cell::Netinfo(n) => {
                assert_eq!(timestamp, n.timestamp);
                assert_eq!(receiver, n.receiver_address);
                assert_eq!(vec![sender], n.sender_addresses);
            }
            _ => panic!("Expected NetinfoCell"),
        }
    }

    #[test]
    fn test_relay_cell_with_data() {
        let data = b"GET /tor/server/authority HTTP/1.0\r\n\r\n";
        let cell = RelayCell::new(1, RelayCommand::Data, data.to_vec(), 356150752, 1).unwrap();
        let packed = cell.pack(&LinkProtocol::new(2));

        let (unpacked, _) = Cell::pop(&packed, 2).unwrap();
        match unpacked {
            Cell::Relay(r) => {
                assert_eq!(1, r.circ_id);
                assert_eq!(RelayCommand::Data, r.command);
                assert_eq!(2, r.command_int);
                assert_eq!(data.to_vec(), r.data);
                assert_eq!(356150752, r.digest);
                assert_eq!(1, r.stream_id);
            }
            _ => panic!("Expected RelayCell"),
        }
    }

    #[test]
    fn test_relay_cell_stream_id_required() {
        let result = RelayCell::new(1, RelayCommand::BeginDir, vec![], 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_cell_stream_id_disallowed() {
        let result = RelayCell::new(1, RelayCommand::Extend, vec![], 0, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_cell_mismatched_data_length() {
        let mismatched_data = [
            0x00, 0x01, 0x03, 0x02, 0x00, 0x00, 0x00, 0x01, 0x15, 0x3a, 0x6d, 0xe0, 0xFF, 0xFF,
        ];
        let mut cell_bytes = mismatched_data.to_vec();
        cell_bytes.extend(vec![0u8; 498]);

        let result = Cell::pop(&cell_bytes, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_versions_cell_protocol_4() {
        let versions = vec![1, 2, 3, 4];
        let cell = VersionsCell::new(versions.clone());
        let packed = cell.pack(&LinkProtocol::new(4));

        let expected = b"\x00\x00\x00\x00\x07\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04";
        assert_eq!(expected.to_vec(), packed);

        let (unpacked, _) = Cell::pop(&packed, 4).unwrap();
        match unpacked {
            Cell::Versions(v) => assert_eq!(versions, v.versions),
            _ => panic!("Expected VersionsCell"),
        }
    }

    #[test]
    fn test_certs_cell_truncated() {
        let truncated = b"\x00\x00\x81\x00\x05\x02\x01\x00\x01\x08";
        let result = Cell::pop(truncated, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_certs_cell_cert_too_short() {
        let short_cert = b"\x00\x00\x81\x00\x05\x01\x01\x00\x03\x08";
        let result = Cell::pop(short_cert, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_challenge_cell_truncated() {
        let challenge: [u8; 32] = [
            0x89, 0x59, 0x09, 0x99, 0xb2, 0x1e, 0xd9, 0x2a, 0x56, 0xb6, 0x1b, 0x6e, 0x0a, 0x05,
            0xd8, 0x2f, 0xe3, 0x51, 0x48, 0x85, 0x13, 0x5a, 0x17, 0xfc, 0x1c, 0x00, 0x7b, 0xa9,
            0xae, 0x83, 0x5e, 0x4b,
        ];
        let mut truncated = vec![0x00, 0x00, 0x82, 0x00, 0x26];
        truncated.extend_from_slice(&challenge[..10]);
        truncated.extend_from_slice(&[0x00, 0x02, 0x00, 0x01, 0x00, 0x03]);

        let result = Cell::pop(&truncated, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_challenge_cell_methods_truncated() {
        let challenge: [u8; 32] = [
            0x89, 0x59, 0x09, 0x99, 0xb2, 0x1e, 0xd9, 0x2a, 0x56, 0xb6, 0x1b, 0x6e, 0x0a, 0x05,
            0xd8, 0x2f, 0xe3, 0x51, 0x48, 0x85, 0x13, 0x5a, 0x17, 0xfc, 0x1c, 0x00, 0x7b, 0xa9,
            0xae, 0x83, 0x5e, 0x4b,
        ];
        let mut truncated = vec![0x00, 0x00, 0x82, 0x00, 0x26];
        truncated.extend_from_slice(&challenge);
        truncated.extend_from_slice(&[0x00, 0x03, 0x00, 0x01, 0x00, 0x03]);

        let result = Cell::pop(&truncated, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_padding_cell_roundtrip() {
        let payload = vec![0x42u8; FIXED_PAYLOAD_LEN];
        let cell = PaddingCell::with_payload(payload.clone()).unwrap();
        let packed = cell.pack(&LinkProtocol::new(2));

        let (unpacked, _) = Cell::pop(&packed, 2).unwrap();
        match unpacked {
            Cell::Padding(p) => {
                assert_eq!(payload, p.payload);
            }
            _ => panic!("Expected PaddingCell"),
        }
    }

    #[test]
    fn test_padding_cell_wrong_size() {
        let result = PaddingCell::with_payload(vec![0x42u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cell_unpack_all() {
        let versions = VersionsCell::new(vec![3, 4, 5]);
        let vpadding = VPaddingCell::with_payload(vec![0x08, 0x11]);

        let mut combined = versions.pack(&LinkProtocol::new(2));
        combined.extend(vpadding.pack(&LinkProtocol::new(2)));

        let cells = Cell::unpack_all(&combined, 2).unwrap();
        assert_eq!(2, cells.len());

        match &cells[0] {
            Cell::Versions(v) => assert_eq!(vec![3, 4, 5], v.versions),
            _ => panic!("Expected VersionsCell"),
        }

        match &cells[1] {
            Cell::VPadding(v) => assert_eq!(vec![0x08, 0x11], v.payload),
            _ => panic!("Expected VPaddingCell"),
        }
    }

    #[test]
    fn test_destroy_cell_reasons() {
        let reasons = [
            (CloseReason::None, 0),
            (CloseReason::Protocol, 1),
            (CloseReason::Requested, 3),
            (CloseReason::Finished, 9),
        ];

        for (reason, reason_int) in reasons {
            let cell = DestroyCell::new(1, reason);
            let packed = cell.pack(&LinkProtocol::new(5));

            let (unpacked, _) = Cell::pop(&packed, 5).unwrap();
            match unpacked {
                Cell::Destroy(d) => {
                    assert_eq!(1, d.circ_id);
                    assert_eq!(reason, d.reason);
                    assert_eq!(reason_int, d.reason_int);
                }
                _ => panic!("Expected DestroyCell"),
            }
        }
    }
}
