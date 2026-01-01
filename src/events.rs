//! Event types and handling for Tor control protocol async notifications.
//!
//! This module provides comprehensive event types for all Tor control protocol
//! asynchronous events, as described in section 4.1 of the
//! [control-spec](https://spec.torproject.org/control-spec/replies.html#asynchronous-events).
//!
//! # Overview
//!
//! Tor emits asynchronous events to notify controllers about state changes,
//! bandwidth usage, circuit activity, and other important occurrences. Events
//! are received after subscribing via the `SETEVENTS` command through the
//! [`Controller`](crate::Controller).
//!
//! # Event Categories
//!
//! Events are organized into several categories:
//!
//! - **Bandwidth Events**: [`BandwidthEvent`], [`CircuitBandwidthEvent`],
//!   [`ConnectionBandwidthEvent`] - Track data transfer rates
//! - **Circuit Events**: [`CircuitEvent`] - Monitor circuit lifecycle
//! - **Stream Events**: [`StreamEvent`] - Track stream connections
//! - **Connection Events**: [`OrConnEvent`] - Monitor OR connections
//! - **Log Events**: [`LogEvent`] - Receive Tor log messages
//! - **Status Events**: [`StatusEvent`] - Bootstrap progress and status changes
//! - **Guard Events**: [`GuardEvent`] - Guard relay changes
//! - **Hidden Service Events**: [`HsDescEvent`] - Hidden service descriptor activity
//! - **Configuration Events**: [`ConfChangedEvent`] - Configuration changes
//! - **Network Events**: [`NetworkLivenessEvent`] - Network connectivity status
//!
//! # Event Subscription
//!
//! To receive events, subscribe using the controller's `set_events` method:
//!
//! ```rust,no_run
//! use stem_rs::{controller::Controller, EventType};
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! // Subscribe to bandwidth and circuit events
//! controller.set_events(&[EventType::Bw, EventType::Circ]).await?;
//!
//! // Events will now be delivered asynchronously
//! # Ok(())
//! # }
//! ```
//!
//! # Event Parsing
//!
//! Raw event data from Tor is parsed into strongly-typed event structs using
//! [`ParsedEvent::parse`]. Each event type provides access to its specific
//! fields while also preserving the raw content for debugging.
//!
//! # Thread Safety
//!
//! All event types implement [`Send`] and [`Sync`], allowing them to be safely
//! shared across threads. The [`Event`] trait requires these bounds.
//!
//! # See Also
//!
//! - [`crate::controller`] - High-level controller API for event subscription
//! - [`crate::protocol`] - Low-level protocol message handling

use std::collections::HashMap;
use std::time::Instant;

use chrono::{DateTime, Local, Utc};

use crate::controller::{CircuitId, StreamId};
use crate::protocol::ControlLine;
use crate::{
    CircBuildFlag, CircClosureReason, CircPurpose, CircStatus, ConnectionType, Error, EventType,
    GuardStatus, GuardType, HiddenServiceState, HsAuth, HsDescAction, HsDescReason,
    OrClosureReason, OrStatus, Runlevel, Signal, StatusType, StreamClosureReason, StreamPurpose,
    StreamSource, StreamStatus, TimeoutSetType,
};

/// Trait implemented by all Tor control protocol events.
///
/// This trait provides a common interface for accessing event metadata
/// regardless of the specific event type. All event types must be thread-safe
/// (`Send + Sync`) to support concurrent event handling.
///
/// # Implementors
///
/// All event structs in this module implement this trait:
/// - [`BandwidthEvent`], [`LogEvent`], [`CircuitEvent`], [`StreamEvent`]
/// - [`OrConnEvent`], [`AddrMapEvent`], [`BuildTimeoutSetEvent`]
/// - [`GuardEvent`], [`NewDescEvent`], [`SignalEvent`], [`StatusEvent`]
/// - [`ConfChangedEvent`], [`NetworkLivenessEvent`], [`CircuitBandwidthEvent`]
/// - [`ConnectionBandwidthEvent`], [`HsDescEvent`]
///
/// # Example
///
/// ```rust,ignore
/// fn handle_event(event: &dyn Event) {
///     println!("Received {:?} event at {:?}", event.event_type(), event.arrived_at());
///     println!("Raw content: {}", event.raw_content());
/// }
/// ```
pub trait Event: Send + Sync {
    /// Returns the type of this event.
    ///
    /// This corresponds to the event keyword used in `SETEVENTS` commands.
    fn event_type(&self) -> EventType;

    /// Returns the raw, unparsed content of the event.
    ///
    /// Useful for debugging or when additional parsing is needed beyond
    /// what the typed event provides.
    fn raw_content(&self) -> &str;

    /// Returns the instant when this event was received.
    ///
    /// This is the local time when the event was parsed, not when Tor
    /// generated it. Useful for measuring event latency or ordering events.
    fn arrived_at(&self) -> Instant;
}

/// Event emitted every second with the bytes sent and received by Tor.
///
/// The BW event is one of the most commonly used events for monitoring
/// Tor's bandwidth usage. It provides a snapshot of data transfer rates
/// over the last second.
///
/// # Event Format
///
/// The raw event format is: `BW <bytes_read> <bytes_written>`
///
/// # Use Cases
///
/// - Monitoring bandwidth consumption
/// - Building bandwidth graphs
/// - Detecting network activity
/// - Rate limiting applications
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::BandwidthEvent;
///
/// fn handle_bandwidth(event: &BandwidthEvent) {
///     let read_kbps = event.read as f64 / 1024.0;
///     let written_kbps = event.written as f64 / 1024.0;
///     println!("Bandwidth: {:.2} KB/s read, {:.2} KB/s written", read_kbps, written_kbps);
/// }
/// ```
///
/// # See Also
///
/// - [`CircuitBandwidthEvent`] - Per-circuit bandwidth tracking
/// - [`ConnectionBandwidthEvent`] - Per-connection bandwidth tracking
#[derive(Debug, Clone)]
pub struct BandwidthEvent {
    /// Bytes received by Tor in the last second.
    pub read: u64,
    /// Bytes sent by Tor in the last second.
    pub written: u64,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for BandwidthEvent {
    fn event_type(&self) -> EventType {
        EventType::Bw
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl BandwidthEvent {
    /// Parses a bandwidth event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type, e.g., "15 25"
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The content is missing required values
    /// - The read or written values are not valid integers
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let event = BandwidthEvent::parse("1024 2048")?;
    /// assert_eq!(event.read, 1024);
    /// assert_eq!(event.written, 2048);
    /// ```
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let read_str = line.pop(false, false)?;
        let written_str = line.pop(false, false)?;

        let read: u64 = read_str.parse().map_err(|_| {
            Error::Protocol(format!("invalid read value in BW event: {}", read_str))
        })?;
        let written: u64 = written_str.parse().map_err(|_| {
            Error::Protocol(format!(
                "invalid written value in BW event: {}",
                written_str
            ))
        })?;

        Ok(Self {
            read,
            written,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Tor logging event for receiving log messages from the Tor process.
///
/// These are the most visible kind of event since, by default, Tor logs
/// at the NOTICE [`Runlevel`] to stdout. Log events allow controllers to
/// receive and process Tor's log output programmatically.
///
/// # Runlevels
///
/// Log events are categorized by severity:
/// - [`Runlevel::Debug`] - Verbose debugging information
/// - [`Runlevel::Info`] - Informational messages
/// - [`Runlevel::Notice`] - Normal operational messages (default)
/// - [`Runlevel::Warn`] - Warning conditions
/// - [`Runlevel::Err`] - Error conditions
///
/// # Event Types
///
/// Each runlevel corresponds to a separate event type:
/// - `DEBUG`, `INFO`, `NOTICE`, `WARN`, `ERR`
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::{EventType, Runlevel};
/// use stem_rs::events::LogEvent;
///
/// fn handle_log(event: &LogEvent) {
///     match event.runlevel {
///         Runlevel::Err | Runlevel::Warn => {
///             eprintln!("[{}] {}", event.runlevel, event.message);
///         }
///         _ => {
///             println!("[{}] {}", event.runlevel, event.message);
///         }
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`Runlevel`] - Log severity levels
/// - [`StatusEvent`] - Structured status messages
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// Severity level of the log message.
    pub runlevel: Runlevel,
    /// The log message content.
    pub message: String,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for LogEvent {
    fn event_type(&self) -> EventType {
        match self.runlevel {
            Runlevel::Debug => EventType::Debug,
            Runlevel::Info => EventType::Info,
            Runlevel::Notice => EventType::Notice,
            Runlevel::Warn => EventType::Warn,
            Runlevel::Err => EventType::Err,
        }
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl LogEvent {
    /// Parses a log event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `runlevel` - The severity level of the log message
    /// * `message` - The log message content
    ///
    /// # Errors
    ///
    /// This method currently does not return errors but returns `Result`
    /// for API consistency with other event parsers.
    pub fn parse(runlevel: Runlevel, message: &str) -> Result<Self, Error> {
        Ok(Self {
            runlevel,
            message: message.to_string(),
            raw_content: message.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating that a circuit's status has changed.
///
/// Circuit events are fundamental to understanding Tor's operation. They
/// track the lifecycle of circuits from creation through closure, including
/// the relays involved and the purpose of each circuit.
///
/// # Circuit Lifecycle
///
/// Circuits progress through these states:
/// 1. [`CircStatus::Launched`] - Circuit creation initiated
/// 2. [`CircStatus::Extended`] - Circuit extended to additional hops
/// 3. [`CircStatus::Built`] - Circuit fully constructed and ready
/// 4. [`CircStatus::Failed`] or [`CircStatus::Closed`] - Circuit terminated
///
/// # Path Information
///
/// The `path` field contains the relays in the circuit as `(fingerprint, nickname)`
/// tuples. The fingerprint is always present; the nickname may be `None` if
/// the `VERBOSE_NAMES` feature isn't enabled (on by default since Tor 0.2.2.1).
///
/// # Hidden Service Circuits
///
/// For hidden service circuits, additional fields provide context:
/// - `hs_state` - Current state in the hidden service protocol
/// - `rend_query` - The rendezvous point address
/// - `purpose` - Indicates the circuit's role (intro, rend, etc.)
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::CircuitEvent;
/// use stem_rs::CircStatus;
///
/// fn handle_circuit(event: &CircuitEvent) {
///     match event.status {
///         CircStatus::Built => {
///             println!("Circuit {} built with {} hops", event.id, event.path.len());
///             for (fingerprint, nickname) in &event.path {
///                 println!("  - {} ({:?})", fingerprint, nickname);
///             }
///         }
///         CircStatus::Failed => {
///             println!("Circuit {} failed: {:?}", event.id, event.reason);
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`CircStatus`] - Circuit status values
/// - [`CircPurpose`] - Circuit purpose types
/// - [`CircClosureReason`] - Closure reasons
#[derive(Debug, Clone)]
pub struct CircuitEvent {
    /// Unique identifier for this circuit.
    pub id: CircuitId,
    /// Current status of the circuit.
    pub status: CircStatus,
    /// Relays in the circuit path as `(fingerprint, nickname)` tuples.
    pub path: Vec<(String, Option<String>)>,
    /// Flags governing how the circuit was built.
    pub build_flags: Option<Vec<CircBuildFlag>>,
    /// Purpose that the circuit is intended for.
    pub purpose: Option<CircPurpose>,
    /// Hidden service state if this is an HS circuit.
    pub hs_state: Option<HiddenServiceState>,
    /// Rendezvous query if this is a hidden service circuit.
    pub rend_query: Option<String>,
    /// Time when the circuit was created or cannibalized.
    pub created: Option<DateTime<Utc>>,
    /// Reason for circuit closure (local).
    pub reason: Option<CircClosureReason>,
    /// Reason for circuit closure (from remote side).
    pub remote_reason: Option<CircClosureReason>,
    /// SOCKS username for stream isolation.
    pub socks_username: Option<String>,
    /// SOCKS password for stream isolation.
    pub socks_password: Option<String>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for CircuitEvent {
    fn event_type(&self) -> EventType {
        EventType::Circ
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl CircuitEvent {
    /// Parses a circuit event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// CircuitID CircStatus [Path] [BUILD_FLAGS=...] [PURPOSE=...] [HS_STATE=...]
    /// [REND_QUERY=...] [TIME_CREATED=...] [REASON=...] [REMOTE_REASON=...]
    /// [SOCKS_USERNAME="..."] [SOCKS_PASSWORD="..."]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The circuit ID or status is missing
    /// - The status is not a recognized value
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let id_str = line.pop(false, false)?;
        let status_str = line.pop(false, false)?;
        let status = parse_circ_status(&status_str)?;

        let mut path = Vec::new();
        let mut build_flags = None;
        let mut purpose = None;
        let mut hs_state = None;
        let mut rend_query = None;
        let mut created = None;
        let mut reason = None;
        let mut remote_reason = None;
        let mut socks_username = None;
        let mut socks_password = None;

        while !line.is_empty() {
            if line.is_next_mapping(Some("BUILD_FLAGS"), false) {
                let (_, flags_str) = line.pop_mapping(false, false)?;
                build_flags = Some(parse_build_flags(&flags_str));
            } else if line.is_next_mapping(Some("PURPOSE"), false) {
                let (_, p) = line.pop_mapping(false, false)?;
                purpose = parse_circ_purpose(&p).ok();
            } else if line.is_next_mapping(Some("HS_STATE"), false) {
                let (_, s) = line.pop_mapping(false, false)?;
                hs_state = parse_hs_state(&s).ok();
            } else if line.is_next_mapping(Some("REND_QUERY"), false) {
                let (_, q) = line.pop_mapping(false, false)?;
                rend_query = Some(q);
            } else if line.is_next_mapping(Some("TIME_CREATED"), false) {
                let (_, t) = line.pop_mapping(false, false)?;
                created = parse_iso_timestamp(&t).ok();
            } else if line.is_next_mapping(Some("REASON"), false) {
                let (_, r) = line.pop_mapping(false, false)?;
                reason = parse_circ_closure_reason(&r).ok();
            } else if line.is_next_mapping(Some("REMOTE_REASON"), false) {
                let (_, r) = line.pop_mapping(false, false)?;
                remote_reason = parse_circ_closure_reason(&r).ok();
            } else if line.is_next_mapping(Some("SOCKS_USERNAME"), true) {
                let (_, u) = line.pop_mapping(true, true)?;
                socks_username = Some(u);
            } else if line.is_next_mapping(Some("SOCKS_PASSWORD"), true) {
                let (_, p) = line.pop_mapping(true, true)?;
                socks_password = Some(p);
            } else {
                let token = line.pop(false, false)?;
                if token.starts_with('$') || token.contains('~') || token.contains(',') {
                    path = parse_circuit_path(&token);
                }
            }
        }

        Ok(Self {
            id: CircuitId::new(id_str),
            status,
            path,
            build_flags,
            purpose,
            hs_state,
            rend_query,
            created,
            reason,
            remote_reason,
            socks_username,
            socks_password,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating that a stream's status has changed.
///
/// Stream events track the lifecycle of TCP connections made through Tor.
/// Each stream is associated with a circuit and connects to a specific
/// target host and port.
///
/// # Stream Lifecycle
///
/// Streams progress through these states:
/// 1. [`StreamStatus::New`] - New stream request received
/// 2. [`StreamStatus::SentConnect`] - CONNECT sent to exit relay
/// 3. [`StreamStatus::Remap`] - Address remapped (e.g., DNS resolution)
/// 4. [`StreamStatus::Succeeded`] - Connection established
/// 5. [`StreamStatus::Closed`] or [`StreamStatus::Failed`] - Stream terminated
///
/// # Circuit Association
///
/// The `circuit_id` field indicates which circuit carries this stream.
/// A value of `None` (circuit ID "0") means the stream is not yet
/// attached to a circuit.
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::StreamEvent;
/// use stem_rs::StreamStatus;
///
/// fn handle_stream(event: &StreamEvent) {
///     match event.status {
///         StreamStatus::New => {
///             println!("New stream {} to {}:{}",
///                 event.id, event.target_host, event.target_port);
///         }
///         StreamStatus::Succeeded => {
///             println!("Stream {} connected via circuit {:?}",
///                 event.id, event.circuit_id);
///         }
///         StreamStatus::Closed | StreamStatus::Failed => {
///             println!("Stream {} ended: {:?}", event.id, event.reason);
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`StreamStatus`] - Stream status values
/// - [`StreamPurpose`] - Stream purpose types
/// - [`StreamClosureReason`] - Closure reasons
#[derive(Debug, Clone)]
pub struct StreamEvent {
    /// Unique identifier for this stream.
    pub id: StreamId,
    /// Current status of the stream.
    pub status: StreamStatus,
    /// Circuit carrying this stream, or `None` if unattached.
    pub circuit_id: Option<CircuitId>,
    /// Target hostname or IP address.
    pub target_host: String,
    /// Target port number.
    pub target_port: u16,
    /// Reason for stream closure (local).
    pub reason: Option<StreamClosureReason>,
    /// Reason for stream closure (from remote side).
    pub remote_reason: Option<StreamClosureReason>,
    /// Source of address resolution (cache or exit).
    pub source: Option<StreamSource>,
    /// Source address of the client connection.
    pub source_addr: Option<String>,
    /// Purpose of this stream.
    pub purpose: Option<StreamPurpose>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for StreamEvent {
    fn event_type(&self) -> EventType {
        EventType::Stream
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl StreamEvent {
    /// Parses a stream event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// StreamID StreamStatus CircuitID Target [REASON=...] [REMOTE_REASON=...]
    /// [SOURCE=...] [SOURCE_ADDR=...] [PURPOSE=...]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - Required fields are missing
    /// - The status is not a recognized value
    /// - The target format is invalid
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let id_str = line.pop(false, false)?;
        let status_str = line.pop(false, false)?;
        let circuit_id_str = line.pop(false, false)?;
        let target = line.pop(false, false)?;

        let status = parse_stream_status(&status_str)?;
        let circuit_id = if circuit_id_str == "0" {
            None
        } else {
            Some(CircuitId::new(circuit_id_str))
        };
        let (target_host, target_port) = parse_target(&target)?;

        let mut reason = None;
        let mut remote_reason = None;
        let mut source = None;
        let mut source_addr = None;
        let mut purpose = None;

        while !line.is_empty() {
            if line.is_next_mapping(Some("REASON"), false) {
                let (_, r) = line.pop_mapping(false, false)?;
                reason = parse_stream_closure_reason(&r).ok();
            } else if line.is_next_mapping(Some("REMOTE_REASON"), false) {
                let (_, r) = line.pop_mapping(false, false)?;
                remote_reason = parse_stream_closure_reason(&r).ok();
            } else if line.is_next_mapping(Some("SOURCE"), false) {
                let (_, s) = line.pop_mapping(false, false)?;
                source = parse_stream_source(&s).ok();
            } else if line.is_next_mapping(Some("SOURCE_ADDR"), false) {
                let (_, a) = line.pop_mapping(false, false)?;
                source_addr = Some(a);
            } else if line.is_next_mapping(Some("PURPOSE"), false) {
                let (_, p) = line.pop_mapping(false, false)?;
                purpose = parse_stream_purpose(&p).ok();
            } else {
                let _ = line.pop(false, false)?;
            }
        }

        Ok(Self {
            id: StreamId::new(id_str),
            status,
            circuit_id,
            target_host,
            target_port,
            reason,
            remote_reason,
            source,
            source_addr,
            purpose,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating that an OR (Onion Router) connection status has changed.
///
/// OR connection events track the status of connections between Tor relays.
/// These are the TLS connections that carry circuit traffic between nodes
/// in the Tor network.
///
/// # Connection Lifecycle
///
/// OR connections progress through these states:
/// 1. [`OrStatus::New`] - Connection initiated
/// 2. [`OrStatus::Launched`] - Connection attempt in progress
/// 3. [`OrStatus::Connected`] - TLS handshake completed
/// 4. [`OrStatus::Failed`] or [`OrStatus::Closed`] - Connection terminated
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::OrConnEvent;
/// use stem_rs::OrStatus;
///
/// fn handle_orconn(event: &OrConnEvent) {
///     match event.status {
///         OrStatus::Connected => {
///             println!("Connected to relay: {}", event.target);
///         }
///         OrStatus::Failed | OrStatus::Closed => {
///             println!("Connection to {} ended: {:?}", event.target, event.reason);
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`OrStatus`] - OR connection status values
/// - [`OrClosureReason`] - Closure reasons
#[derive(Debug, Clone)]
pub struct OrConnEvent {
    /// Connection identifier (may be `None` for older Tor versions).
    pub id: Option<String>,
    /// Current status of the OR connection.
    pub status: OrStatus,
    /// Target relay address (IP:port or fingerprint).
    pub target: String,
    /// Reason for connection closure.
    pub reason: Option<OrClosureReason>,
    /// Number of circuits using this connection.
    pub num_circuits: Option<u32>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for OrConnEvent {
    fn event_type(&self) -> EventType {
        EventType::OrConn
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl OrConnEvent {
    /// Parses an OR connection event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// Target Status [REASON=...] [NCIRCS=...] [ID=...]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - Required fields are missing
    /// - The status is not a recognized value
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let target = line.pop(false, false)?;
        let status_str = line.pop(false, false)?;
        let status = parse_or_status(&status_str)?;

        let mut id = None;
        let mut reason = None;
        let mut num_circuits = None;

        while !line.is_empty() {
            if line.is_next_mapping(Some("REASON"), false) {
                let (_, r) = line.pop_mapping(false, false)?;
                reason = parse_or_closure_reason(&r).ok();
            } else if line.is_next_mapping(Some("NCIRCS"), false) {
                let (_, n) = line.pop_mapping(false, false)?;
                num_circuits = n.parse().ok();
            } else if line.is_next_mapping(Some("ID"), false) {
                let (_, i) = line.pop_mapping(false, false)?;
                id = Some(i);
            } else {
                let _ = line.pop(false, false)?;
            }
        }

        Ok(Self {
            id,
            status,
            target,
            reason,
            num_circuits,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating a new address mapping has been created.
///
/// Address map events are emitted when Tor creates a mapping between
/// a hostname and its resolved address. This can occur due to DNS
/// resolution, `MAPADDRESS` commands, or `TrackHostExits` configuration.
///
/// # Expiration
///
/// Address mappings have an expiration time after which they are no longer
/// valid. The `expiry` field contains the local time, while `utc_expiry`
/// contains the UTC time (if available).
///
/// # Caching
///
/// The `cached` field indicates whether the mapping will be kept until
/// expiration (`true`) or may be evicted earlier (`false`).
///
/// # Error Mappings
///
/// When DNS resolution fails, `destination` will be `None` and the `error`
/// field will contain the error code.
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::AddrMapEvent;
///
/// fn handle_addrmap(event: &AddrMapEvent) {
///     match &event.destination {
///         Some(dest) => {
///             println!("{} -> {} (expires: {:?})",
///                 event.hostname, dest, event.expiry);
///         }
///         None => {
///             println!("Resolution failed for {}: {:?}",
///                 event.hostname, event.error);
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AddrMapEvent {
    /// The hostname being resolved.
    pub hostname: String,
    /// The resolved address, or `None` if resolution failed.
    pub destination: Option<String>,
    /// Expiration time in local time.
    pub expiry: Option<DateTime<Local>>,
    /// Error code if resolution failed.
    pub error: Option<String>,
    /// Expiration time in UTC.
    pub utc_expiry: Option<DateTime<Utc>>,
    /// Whether the mapping is cached until expiration.
    pub cached: Option<bool>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for AddrMapEvent {
    fn event_type(&self) -> EventType {
        EventType::AddrMap
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl AddrMapEvent {
    /// Parses an address map event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// Hostname Destination Expiry [error=...] [EXPIRES="..."] [CACHED=YES|NO]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if required fields are missing.
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let hostname = line.pop(false, false)?;
        let dest_str = line.pop(false, false)?;
        let destination = if dest_str == "<error>" {
            None
        } else {
            Some(dest_str)
        };

        let expiry_str = if line.is_next_quoted() {
            Some(line.pop(true, false)?)
        } else {
            let token = line.pop(false, false)?;
            if token == "NEVER" {
                None
            } else {
                Some(token)
            }
        };

        let expiry = expiry_str.and_then(|s| parse_local_timestamp(&s).ok());

        let mut error = None;
        let mut utc_expiry = None;
        let mut cached = None;

        while !line.is_empty() {
            if line.is_next_mapping(Some("error"), false) {
                let (_, e) = line.pop_mapping(false, false)?;
                error = Some(e);
            } else if line.is_next_mapping(Some("EXPIRES"), true) {
                let (_, e) = line.pop_mapping(true, false)?;
                utc_expiry = parse_utc_timestamp(&e).ok();
            } else if line.is_next_mapping(Some("CACHED"), true) {
                let (_, c) = line.pop_mapping(true, false)?;
                cached = match c.as_str() {
                    "YES" => Some(true),
                    "NO" => Some(false),
                    _ => None,
                };
            } else {
                let _ = line.pop(false, false)?;
            }
        }

        Ok(Self {
            hostname,
            destination,
            expiry,
            error,
            utc_expiry,
            cached,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating that the circuit build timeout has changed.
///
/// Tor dynamically adjusts its circuit build timeout based on observed
/// circuit construction times. This event is emitted when the timeout
/// value changes, providing insight into network performance.
///
/// # Timeout Calculation
///
/// Tor uses a Pareto distribution to model circuit build times:
/// - `xm` - The Pareto Xm parameter (minimum value)
/// - `alpha` - The Pareto alpha parameter (shape)
/// - `quantile` - The CDF cutoff quantile
///
/// # Set Types
///
/// The `set_type` indicates why the timeout changed:
/// - [`TimeoutSetType::Computed`] - Calculated from observed times
/// - [`TimeoutSetType::Reset`] - Reset to default values
/// - [`TimeoutSetType::Suspended`] - Timeout learning suspended
/// - [`TimeoutSetType::Discard`] - Discarding learned values
/// - [`TimeoutSetType::Resume`] - Resuming timeout learning
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::BuildTimeoutSetEvent;
///
/// fn handle_timeout(event: &BuildTimeoutSetEvent) {
///     if let Some(timeout) = event.timeout {
///         println!("Circuit timeout set to {}ms ({:?})", timeout, event.set_type);
///     }
///     if let Some(rate) = event.timeout_rate {
///         println!("Timeout rate: {:.2}%", rate * 100.0);
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`TimeoutSetType`] - Timeout change reasons
#[derive(Debug, Clone)]
pub struct BuildTimeoutSetEvent {
    /// Type of timeout change.
    pub set_type: TimeoutSetType,
    /// Number of circuit build times used to calculate timeout.
    pub total_times: Option<u32>,
    /// Circuit build timeout in milliseconds.
    pub timeout: Option<u32>,
    /// Pareto Xm parameter in milliseconds.
    pub xm: Option<u32>,
    /// Pareto alpha parameter.
    pub alpha: Option<f64>,
    /// CDF quantile cutoff point.
    pub quantile: Option<f64>,
    /// Ratio of circuits that timed out.
    pub timeout_rate: Option<f64>,
    /// Duration to keep measurement circuits in milliseconds.
    pub close_timeout: Option<u32>,
    /// Ratio of measurement circuits that were closed.
    pub close_rate: Option<f64>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for BuildTimeoutSetEvent {
    fn event_type(&self) -> EventType {
        EventType::BuildTimeoutSet
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl BuildTimeoutSetEvent {
    /// Parses a build timeout set event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// SetType [TOTAL_TIMES=...] [TIMEOUT_MS=...] [XM=...] [ALPHA=...]
    /// [CUTOFF_QUANTILE=...] [TIMEOUT_RATE=...] [CLOSE_MS=...] [CLOSE_RATE=...]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The set type is missing or unrecognized
    /// - Numeric values cannot be parsed
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let set_type_str = line.pop(false, false)?;
        let set_type = parse_timeout_set_type(&set_type_str)?;

        let mut total_times = None;
        let mut timeout = None;
        let mut xm = None;
        let mut alpha = None;
        let mut quantile = None;
        let mut timeout_rate = None;
        let mut close_timeout = None;
        let mut close_rate = None;

        while !line.is_empty() {
            if line.is_next_mapping(Some("TOTAL_TIMES"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                total_times = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid TOTAL_TIMES: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("TIMEOUT_MS"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                timeout = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid TIMEOUT_MS: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("XM"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                xm = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid XM: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("ALPHA"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                alpha = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid ALPHA: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("CUTOFF_QUANTILE"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                quantile = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid CUTOFF_QUANTILE: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("TIMEOUT_RATE"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                timeout_rate = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid TIMEOUT_RATE: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("CLOSE_MS"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                close_timeout = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid CLOSE_MS: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("CLOSE_RATE"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                close_rate = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid CLOSE_RATE: {}", v)))?,
                );
            } else {
                let _ = line.pop(false, false)?;
            }
        }

        Ok(Self {
            set_type,
            total_times,
            timeout,
            xm,
            alpha,
            quantile,
            timeout_rate,
            close_timeout,
            close_rate,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating that guard relay status has changed.
///
/// Guard events track changes to the entry guards that Tor uses for the
/// first hop of circuits. Entry guards are a security feature that limits
/// the set of relays that can observe your traffic entering the Tor network.
///
/// # Guard Types
///
/// Currently, only [`GuardType::Entry`] is used, representing entry guards.
///
/// # Guard Status
///
/// Guards can have these statuses:
/// - [`GuardStatus::New`] - Newly selected as a guard
/// - [`GuardStatus::Up`] - Guard is reachable
/// - [`GuardStatus::Down`] - Guard is unreachable
/// - [`GuardStatus::Good`] - Guard confirmed as good
/// - [`GuardStatus::Bad`] - Guard marked as bad
/// - [`GuardStatus::Dropped`] - Guard removed from list
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::GuardEvent;
/// use stem_rs::GuardStatus;
///
/// fn handle_guard(event: &GuardEvent) {
///     match event.status {
///         GuardStatus::New => {
///             println!("New guard: {} ({:?})",
///                 event.endpoint_fingerprint, event.endpoint_nickname);
///         }
///         GuardStatus::Down => {
///             println!("Guard {} is down", event.endpoint_fingerprint);
///         }
///         GuardStatus::Dropped => {
///             println!("Guard {} dropped", event.endpoint_fingerprint);
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`GuardType`] - Guard type values
/// - [`GuardStatus`] - Guard status values
#[derive(Debug, Clone)]
pub struct GuardEvent {
    /// Type of guard (currently only Entry).
    pub guard_type: GuardType,
    /// Full endpoint string (fingerprint with optional nickname).
    pub endpoint: String,
    /// Relay fingerprint (40 hex characters).
    pub endpoint_fingerprint: String,
    /// Relay nickname if available.
    pub endpoint_nickname: Option<String>,
    /// Current status of the guard.
    pub status: GuardStatus,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for GuardEvent {
    fn event_type(&self) -> EventType {
        EventType::Guard
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl GuardEvent {
    /// Parses a guard event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// GuardType Endpoint Status
    /// ```
    ///
    /// Where Endpoint is either a fingerprint or `fingerprint=nickname`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - Required fields are missing
    /// - The guard type or status is unrecognized
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let guard_type_str = line.pop(false, false)?;
        let endpoint = line.pop(false, false)?;
        let status_str = line.pop(false, false)?;

        let guard_type = parse_guard_type(&guard_type_str)?;
        let status = parse_guard_status(&status_str)?;
        let (fingerprint, nickname) = parse_relay_endpoint(&endpoint);

        Ok(Self {
            guard_type,
            endpoint,
            endpoint_fingerprint: fingerprint,
            endpoint_nickname: nickname,
            status,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating that new relay descriptors are available.
///
/// This event is emitted when Tor receives new server descriptors for
/// relays in the network. It provides a list of relays whose descriptors
/// have been updated.
///
/// # Relay Identification
///
/// Each relay is identified by its fingerprint and optionally its nickname.
/// The `relays` field contains `(fingerprint, nickname)` tuples.
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::NewDescEvent;
///
/// fn handle_newdesc(event: &NewDescEvent) {
///     println!("Received {} new descriptors:", event.relays.len());
///     for (fingerprint, nickname) in &event.relays {
///         match nickname {
///             Some(nick) => println!("  {} ({})", fingerprint, nick),
///             None => println!("  {}", fingerprint),
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct NewDescEvent {
    /// List of relays with new descriptors as `(fingerprint, nickname)` tuples.
    pub relays: Vec<(String, Option<String>)>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for NewDescEvent {
    fn event_type(&self) -> EventType {
        EventType::NewDesc
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl NewDescEvent {
    /// Parses a new descriptor event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// Relay1 [Relay2 ...]
    /// ```
    ///
    /// Where each relay is either a fingerprint or `fingerprint=nickname`.
    ///
    /// # Errors
    ///
    /// This method currently does not return errors but returns `Result`
    /// for API consistency.
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut relays = Vec::new();
        for token in content.split_whitespace() {
            let (fingerprint, nickname) = parse_relay_endpoint(token);
            relays.push((fingerprint, nickname));
        }
        Ok(Self {
            relays,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating that Tor received a signal.
///
/// This event is emitted when Tor receives a signal, either from the
/// operating system or via the control protocol's `SIGNAL` command.
///
/// # Signals
///
/// Common signals include:
/// - [`Signal::Newnym`] - Request new circuits
/// - [`Signal::Reload`] - Reload configuration
/// - [`Signal::Shutdown`] - Graceful shutdown
/// - [`Signal::Halt`] - Immediate shutdown
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::SignalEvent;
/// use stem_rs::Signal;
///
/// fn handle_signal(event: &SignalEvent) {
///     match event.signal {
///         Signal::Newnym => println!("New identity requested"),
///         Signal::Shutdown => println!("Tor is shutting down"),
///         _ => println!("Received signal: {:?}", event.signal),
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`Signal`] - Signal types
#[derive(Debug, Clone)]
pub struct SignalEvent {
    /// The signal that was received.
    pub signal: Signal,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for SignalEvent {
    fn event_type(&self) -> EventType {
        EventType::Signal
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl SignalEvent {
    /// Parses a signal event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the signal is unrecognized.
    pub fn parse(content: &str) -> Result<Self, Error> {
        let signal = parse_signal(content.trim())?;
        Ok(Self {
            signal,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event providing status information about Tor's operation.
///
/// Status events provide structured information about Tor's operational
/// state, including bootstrap progress, circuit establishment, and
/// various warnings or errors.
///
/// # Status Types
///
/// Events are categorized by type:
/// - [`StatusType::General`] - General status (e.g., consensus arrived)
/// - [`StatusType::Client`] - Client-specific status (e.g., bootstrap progress)
/// - [`StatusType::Server`] - Server-specific status (e.g., reachability checks)
///
/// # Bootstrap Progress
///
/// The most common use of status events is tracking bootstrap progress.
/// Look for `action == "BOOTSTRAP"` and check the `PROGRESS` argument.
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::StatusEvent;
/// use stem_rs::StatusType;
///
/// fn handle_status(event: &StatusEvent) {
///     if event.action == "BOOTSTRAP" {
///         if let Some(progress) = event.arguments.get("PROGRESS") {
///             println!("Bootstrap progress: {}%", progress);
///         }
///         if let Some(summary) = event.arguments.get("SUMMARY") {
///             println!("Status: {}", summary);
///         }
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`StatusType`] - Status event types
/// - [`Runlevel`] - Severity levels
#[derive(Debug, Clone)]
pub struct StatusEvent {
    /// Type of status event (General, Client, or Server).
    pub status_type: StatusType,
    /// Severity level of the status message.
    pub runlevel: Runlevel,
    /// Action or event name (e.g., "BOOTSTRAP", "CIRCUIT_ESTABLISHED").
    pub action: String,
    /// Key-value arguments providing additional details.
    pub arguments: HashMap<String, String>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for StatusEvent {
    fn event_type(&self) -> EventType {
        EventType::Status
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl StatusEvent {
    /// Parses a status event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `status_type` - The type of status event
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// Runlevel Action [Key=Value ...]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - Required fields are missing
    /// - The runlevel is unrecognized
    pub fn parse(status_type: StatusType, content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let runlevel_str = line.pop(false, false)?;
        let action = line.pop(false, false)?;
        let runlevel = parse_runlevel(&runlevel_str)?;

        let mut arguments = HashMap::new();
        while !line.is_empty() {
            if line.peek_key().is_some() {
                let quoted = line.is_next_mapping(None, true);
                let (k, v) = line.pop_mapping(quoted, quoted)?;
                arguments.insert(k, v);
            } else {
                let _ = line.pop(false, false)?;
            }
        }

        Ok(Self {
            status_type,
            runlevel,
            action,
            arguments,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating that Tor's configuration has changed.
///
/// This event is emitted when configuration options are modified, either
/// through `SETCONF` commands or by reloading the configuration file.
///
/// # Changed vs Unset
///
/// - `changed` - Options that were set to new values
/// - `unset` - Options that were reset to defaults
///
/// Options can have multiple values (e.g., `ExitPolicy`), so `changed`
/// maps option names to a list of values.
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::ConfChangedEvent;
///
/// fn handle_conf_changed(event: &ConfChangedEvent) {
///     for (option, values) in &event.changed {
///         println!("Changed: {} = {:?}", option, values);
///     }
///     for option in &event.unset {
///         println!("Unset: {}", option);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ConfChangedEvent {
    /// Options that were changed, mapped to their new values.
    pub changed: HashMap<String, Vec<String>>,
    /// Options that were unset (reset to defaults).
    pub unset: Vec<String>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for ConfChangedEvent {
    fn event_type(&self) -> EventType {
        EventType::ConfChanged
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl ConfChangedEvent {
    /// Parses a configuration changed event from multi-line content.
    ///
    /// # Arguments
    ///
    /// * `lines` - The event content lines (excluding header/footer)
    ///
    /// # Event Format
    ///
    /// Each line is either:
    /// - `Key=Value` - Option set to a value
    /// - `Key` - Option unset
    ///
    /// # Errors
    ///
    /// This method currently does not return errors but returns `Result`
    /// for API consistency.
    pub fn parse(lines: &[String]) -> Result<Self, Error> {
        let mut changed: HashMap<String, Vec<String>> = HashMap::new();
        let mut unset = Vec::new();

        for line in lines {
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].to_string();
                let value = line[eq_pos + 1..].to_string();
                changed.entry(key).or_default().push(value);
            } else if !line.is_empty() {
                unset.push(line.clone());
            }
        }

        Ok(Self {
            changed,
            unset,
            raw_content: lines.join("\n"),
            arrived_at: Instant::now(),
        })
    }
}

/// Event indicating network connectivity status.
///
/// This event is emitted when Tor's view of network liveness changes.
/// It indicates whether Tor believes the network is reachable.
///
/// # Status Values
///
/// - `"UP"` - Network is reachable
/// - `"DOWN"` - Network is unreachable
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::NetworkLivenessEvent;
///
/// fn handle_liveness(event: &NetworkLivenessEvent) {
///     match event.status.as_str() {
///         "UP" => println!("Network is up"),
///         "DOWN" => println!("Network is down"),
///         _ => println!("Unknown network status: {}", event.status),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct NetworkLivenessEvent {
    /// Network status ("UP" or "DOWN").
    pub status: String,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for NetworkLivenessEvent {
    fn event_type(&self) -> EventType {
        EventType::NetworkLiveness
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl NetworkLivenessEvent {
    /// Parses a network liveness event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Errors
    ///
    /// This method currently does not return errors but returns `Result`
    /// for API consistency.
    pub fn parse(content: &str) -> Result<Self, Error> {
        let status = content.split_whitespace().next().unwrap_or("").to_string();
        Ok(Self {
            status,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event providing bandwidth information for a specific circuit.
///
/// Unlike [`BandwidthEvent`] which provides aggregate bandwidth, this event
/// tracks bandwidth usage per circuit. This is useful for monitoring
/// individual connections or identifying high-bandwidth circuits.
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::CircuitBandwidthEvent;
///
/// fn handle_circ_bw(event: &CircuitBandwidthEvent) {
///     println!("Circuit {} bandwidth: {} read, {} written",
///         event.id, event.read, event.written);
///     if let Some(time) = &event.time {
///         println!("  at {}", time);
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`BandwidthEvent`] - Aggregate bandwidth
/// - [`ConnectionBandwidthEvent`] - Per-connection bandwidth
#[derive(Debug, Clone)]
pub struct CircuitBandwidthEvent {
    /// Circuit identifier.
    pub id: CircuitId,
    /// Bytes read on this circuit.
    pub read: u64,
    /// Bytes written on this circuit.
    pub written: u64,
    /// Timestamp of the measurement (if available).
    pub time: Option<DateTime<Utc>>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for CircuitBandwidthEvent {
    fn event_type(&self) -> EventType {
        EventType::CircBw
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl CircuitBandwidthEvent {
    /// Parses a circuit bandwidth event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// ID=CircuitID READ=bytes WRITTEN=bytes [TIME=timestamp]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - Required fields (ID, READ, WRITTEN) are missing
    /// - Numeric values cannot be parsed
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let mut id = None;
        let mut read = None;
        let mut written = None;
        let mut time = None;

        while !line.is_empty() {
            if line.is_next_mapping(Some("ID"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                id = Some(CircuitId::new(v));
            } else if line.is_next_mapping(Some("READ"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                read = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid READ value: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("WRITTEN"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                written = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid WRITTEN value: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("TIME"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                time = parse_iso_timestamp(&v).ok();
            } else {
                let _ = line.pop(false, false)?;
            }
        }

        Ok(Self {
            id: id.ok_or_else(|| Error::Protocol("missing ID in CIRC_BW".to_string()))?,
            read: read.ok_or_else(|| Error::Protocol("missing READ in CIRC_BW".to_string()))?,
            written: written
                .ok_or_else(|| Error::Protocol("missing WRITTEN in CIRC_BW".to_string()))?,
            time,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event providing bandwidth information for a specific connection.
///
/// This event tracks bandwidth usage per connection, categorized by
/// connection type (OR, Dir, Exit). Useful for detailed bandwidth
/// analysis and monitoring.
///
/// # Connection Types
///
/// - [`ConnectionType::Or`] - Onion Router connections (relay-to-relay)
/// - [`ConnectionType::Dir`] - Directory connections
/// - [`ConnectionType::Exit`] - Exit connections to the internet
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::ConnectionBandwidthEvent;
/// use stem_rs::ConnectionType;
///
/// fn handle_conn_bw(event: &ConnectionBandwidthEvent) {
///     let type_str = match event.conn_type {
///         ConnectionType::Or => "OR",
///         ConnectionType::Dir => "Dir",
///         ConnectionType::Exit => "Exit",
///     };
///     println!("{} connection {}: {} read, {} written",
///         type_str, event.id, event.read, event.written);
/// }
/// ```
///
/// # See Also
///
/// - [`BandwidthEvent`] - Aggregate bandwidth
/// - [`CircuitBandwidthEvent`] - Per-circuit bandwidth
/// - [`ConnectionType`] - Connection types
#[derive(Debug, Clone)]
pub struct ConnectionBandwidthEvent {
    /// Connection identifier.
    pub id: String,
    /// Type of connection.
    pub conn_type: ConnectionType,
    /// Bytes read on this connection.
    pub read: u64,
    /// Bytes written on this connection.
    pub written: u64,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for ConnectionBandwidthEvent {
    fn event_type(&self) -> EventType {
        EventType::ConnBw
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl ConnectionBandwidthEvent {
    /// Parses a connection bandwidth event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// ID=ConnID TYPE=ConnType READ=bytes WRITTEN=bytes
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - Required fields (ID, TYPE, READ, WRITTEN) are missing
    /// - The connection type is unrecognized
    /// - Numeric values cannot be parsed
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let mut id = None;
        let mut conn_type = None;
        let mut read = None;
        let mut written = None;

        while !line.is_empty() {
            if line.is_next_mapping(Some("ID"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                id = Some(v);
            } else if line.is_next_mapping(Some("TYPE"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                conn_type = Some(parse_connection_type(&v)?);
            } else if line.is_next_mapping(Some("READ"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                read = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid READ value: {}", v)))?,
                );
            } else if line.is_next_mapping(Some("WRITTEN"), false) {
                let (_, v) = line.pop_mapping(false, false)?;
                written = Some(
                    v.parse()
                        .map_err(|_| Error::Protocol(format!("invalid WRITTEN value: {}", v)))?,
                );
            } else {
                let _ = line.pop(false, false)?;
            }
        }

        Ok(Self {
            id: id.ok_or_else(|| Error::Protocol("missing ID in CONN_BW".to_string()))?,
            conn_type: conn_type
                .ok_or_else(|| Error::Protocol("missing TYPE in CONN_BW".to_string()))?,
            read: read.ok_or_else(|| Error::Protocol("missing READ in CONN_BW".to_string()))?,
            written: written
                .ok_or_else(|| Error::Protocol("missing WRITTEN in CONN_BW".to_string()))?,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Event triggered when fetching or uploading hidden service descriptors.
///
/// This event tracks the lifecycle of hidden service descriptor operations,
/// including requests, uploads, and failures. It's essential for monitoring
/// hidden service connectivity.
///
/// # Actions
///
/// The `action` field indicates the operation:
/// - [`HsDescAction::Requested`] - Descriptor fetch requested
/// - [`HsDescAction::Received`] - Descriptor successfully received
/// - [`HsDescAction::Uploaded`] - Descriptor successfully uploaded
/// - [`HsDescAction::Failed`] - Operation failed (check `reason`)
/// - [`HsDescAction::Created`] - New descriptor created
/// - [`HsDescAction::Ignore`] - Descriptor ignored
///
/// # Directory Information
///
/// The `directory` field contains the HSDir relay handling the request.
/// The fingerprint and nickname are extracted into separate fields for
/// convenience.
///
/// # Example
///
/// ```rust,ignore
/// use stem_rs::events::HsDescEvent;
/// use stem_rs::HsDescAction;
///
/// fn handle_hsdesc(event: &HsDescEvent) {
///     match event.action {
///         HsDescAction::Received => {
///             println!("Got descriptor for {} from {:?}",
///                 event.address, event.directory_nickname);
///         }
///         HsDescAction::Failed => {
///             println!("Failed to get descriptor for {}: {:?}",
///                 event.address, event.reason);
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// # See Also
///
/// - [`HsDescAction`] - Descriptor actions
/// - [`HsDescReason`] - Failure reasons
/// - [`HsAuth`] - Authentication types
#[derive(Debug, Clone)]
pub struct HsDescEvent {
    /// Action being performed on the descriptor.
    pub action: HsDescAction,
    /// Hidden service address (onion address).
    pub address: String,
    /// Authentication type for the hidden service.
    pub authentication: Option<HsAuth>,
    /// Full directory relay string.
    pub directory: Option<String>,
    /// Directory relay fingerprint.
    pub directory_fingerprint: Option<String>,
    /// Directory relay nickname.
    pub directory_nickname: Option<String>,
    /// Descriptor identifier.
    pub descriptor_id: Option<String>,
    /// Reason for failure (if action is Failed).
    pub reason: Option<HsDescReason>,
    raw_content: String,
    arrived_at: Instant,
}

impl Event for HsDescEvent {
    fn event_type(&self) -> EventType {
        EventType::HsDesc
    }
    fn raw_content(&self) -> &str {
        &self.raw_content
    }
    fn arrived_at(&self) -> Instant {
        self.arrived_at
    }
}

impl HsDescEvent {
    /// Parses a hidden service descriptor event from raw control protocol content.
    ///
    /// # Arguments
    ///
    /// * `content` - The event content after the event type
    ///
    /// # Event Format
    ///
    /// ```text
    /// Action Address AuthType [Directory] [DescriptorID] [REASON=...]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - Required fields are missing
    /// - The action is unrecognized
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut line = ControlLine::new(content);
        let action_str = line.pop(false, false)?;
        let address = line.pop(false, false)?;
        let auth_str = line.pop(false, false)?;

        let action = parse_hs_desc_action(&action_str)?;
        let authentication = parse_hs_auth(&auth_str).ok();

        let mut directory = None;
        let mut directory_fingerprint = None;
        let mut directory_nickname = None;
        let mut descriptor_id = None;
        let mut reason = None;

        if !line.is_empty() {
            let dir_token = line.pop(false, false)?;
            if dir_token != "UNKNOWN" {
                directory = Some(dir_token.clone());
                let (fp, nick) = parse_relay_endpoint(&dir_token);
                directory_fingerprint = Some(fp);
                directory_nickname = nick;
            }
        }

        if !line.is_empty() && line.peek_key().is_none_or(|k| k != "REASON") {
            descriptor_id = Some(line.pop(false, false)?);
        }

        while !line.is_empty() {
            if line.is_next_mapping(Some("REASON"), false) {
                let (_, r) = line.pop_mapping(false, false)?;
                reason = parse_hs_desc_reason(&r).ok();
            } else {
                let _ = line.pop(false, false)?;
            }
        }

        Ok(Self {
            action,
            address,
            authentication,
            directory,
            directory_fingerprint,
            directory_nickname,
            descriptor_id,
            reason,
            raw_content: content.to_string(),
            arrived_at: Instant::now(),
        })
    }
}

/// Parses a circuit status string into a [`CircStatus`] enum variant.
///
/// Converts a case-insensitive string representation of a circuit status
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The circuit status string to parse (e.g., "LAUNCHED", "BUILT")
///
/// # Returns
///
/// * `Ok(CircStatus)` - The parsed circuit status variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known status
///
/// # Supported Values
///
/// - `LAUNCHED` - Circuit construction has begun
/// - `BUILT` - Circuit is fully constructed and ready for use
/// - `GUARD_WAIT` - Waiting for guard node selection
/// - `EXTENDED` - Circuit has been extended by one hop
/// - `FAILED` - Circuit construction failed
/// - `CLOSED` - Circuit has been closed
fn parse_circ_status(s: &str) -> Result<CircStatus, Error> {
    match s.to_uppercase().as_str() {
        "LAUNCHED" => Ok(CircStatus::Launched),
        "BUILT" => Ok(CircStatus::Built),
        "GUARD_WAIT" => Ok(CircStatus::GuardWait),
        "EXTENDED" => Ok(CircStatus::Extended),
        "FAILED" => Ok(CircStatus::Failed),
        "CLOSED" => Ok(CircStatus::Closed),
        _ => Err(Error::Protocol(format!("unknown circuit status: {}", s))),
    }
}

/// Parses a stream status string into a [`StreamStatus`] enum variant.
///
/// Converts a case-insensitive string representation of a stream status
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The stream status string to parse (e.g., "NEW", "SUCCEEDED")
///
/// # Returns
///
/// * `Ok(StreamStatus)` - The parsed stream status variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known status
///
/// # Supported Values
///
/// - `NEW` - New stream awaiting connection
/// - `NEWRESOLVE` - New stream awaiting DNS resolution
/// - `REMAP` - Address has been remapped
/// - `SENTCONNECT` - Connect request sent to exit
/// - `SENTRESOLVE` - Resolve request sent to exit
/// - `SUCCEEDED` - Stream connection succeeded
/// - `FAILED` - Stream connection failed
/// - `DETACHED` - Stream detached from circuit
/// - `CONTROLLER_WAIT` - Waiting for controller attachment
/// - `CLOSED` - Stream has been closed
fn parse_stream_status(s: &str) -> Result<StreamStatus, Error> {
    match s.to_uppercase().as_str() {
        "NEW" => Ok(StreamStatus::New),
        "NEWRESOLVE" => Ok(StreamStatus::NewResolve),
        "REMAP" => Ok(StreamStatus::Remap),
        "SENTCONNECT" => Ok(StreamStatus::SentConnect),
        "SENTRESOLVE" => Ok(StreamStatus::SentResolve),
        "SUCCEEDED" => Ok(StreamStatus::Succeeded),
        "FAILED" => Ok(StreamStatus::Failed),
        "DETACHED" => Ok(StreamStatus::Detached),
        "CONTROLLER_WAIT" => Ok(StreamStatus::ControllerWait),
        "CLOSED" => Ok(StreamStatus::Closed),
        _ => Err(Error::Protocol(format!("unknown stream status: {}", s))),
    }
}

/// Parses an OR (Onion Router) connection status string into an [`OrStatus`] enum variant.
///
/// Converts a case-insensitive string representation of an OR connection status
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The OR status string to parse (e.g., "NEW", "CONNECTED")
///
/// # Returns
///
/// * `Ok(OrStatus)` - The parsed OR connection status variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known status
///
/// # Supported Values
///
/// - `NEW` - New OR connection initiated
/// - `LAUNCHED` - Connection attempt launched
/// - `CONNECTED` - Successfully connected to OR
/// - `FAILED` - Connection attempt failed
/// - `CLOSED` - Connection has been closed
fn parse_or_status(s: &str) -> Result<OrStatus, Error> {
    match s.to_uppercase().as_str() {
        "NEW" => Ok(OrStatus::New),
        "LAUNCHED" => Ok(OrStatus::Launched),
        "CONNECTED" => Ok(OrStatus::Connected),
        "FAILED" => Ok(OrStatus::Failed),
        "CLOSED" => Ok(OrStatus::Closed),
        _ => Err(Error::Protocol(format!("unknown OR status: {}", s))),
    }
}

/// Parses a guard type string into a [`GuardType`] enum variant.
///
/// Converts a case-insensitive string representation of a guard node type
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The guard type string to parse (currently only "ENTRY")
///
/// # Returns
///
/// * `Ok(GuardType)` - The parsed guard type variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known type
///
/// # Supported Values
///
/// - `ENTRY` - Entry guard node
fn parse_guard_type(s: &str) -> Result<GuardType, Error> {
    match s.to_uppercase().as_str() {
        "ENTRY" => Ok(GuardType::Entry),
        _ => Err(Error::Protocol(format!("unknown guard type: {}", s))),
    }
}

/// Parses a guard status string into a [`GuardStatus`] enum variant.
///
/// Converts a case-insensitive string representation of a guard node status
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The guard status string to parse (e.g., "NEW", "UP", "DOWN")
///
/// # Returns
///
/// * `Ok(GuardStatus)` - The parsed guard status variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known status
///
/// # Supported Values
///
/// - `NEW` - Guard node newly selected
/// - `DROPPED` - Guard node dropped from selection
/// - `UP` - Guard node is reachable
/// - `DOWN` - Guard node is unreachable
/// - `BAD` - Guard node marked as bad
/// - `GOOD` - Guard node marked as good
fn parse_guard_status(s: &str) -> Result<GuardStatus, Error> {
    match s.to_uppercase().as_str() {
        "NEW" => Ok(GuardStatus::New),
        "DROPPED" => Ok(GuardStatus::Dropped),
        "UP" => Ok(GuardStatus::Up),
        "DOWN" => Ok(GuardStatus::Down),
        "BAD" => Ok(GuardStatus::Bad),
        "GOOD" => Ok(GuardStatus::Good),
        _ => Err(Error::Protocol(format!("unknown guard status: {}", s))),
    }
}

/// Parses a timeout set type string into a [`TimeoutSetType`] enum variant.
///
/// Converts a case-insensitive string representation of a circuit build
/// timeout set type from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The timeout set type string to parse (e.g., "COMPUTED", "RESET")
///
/// # Returns
///
/// * `Ok(TimeoutSetType)` - The parsed timeout set type variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known type
///
/// # Supported Values
///
/// - `COMPUTED` - Timeout computed from circuit build times
/// - `RESET` - Timeout values have been reset
/// - `SUSPENDED` - Timeout learning suspended
/// - `DISCARD` - Timeout values discarded
/// - `RESUME` - Timeout learning resumed
fn parse_timeout_set_type(s: &str) -> Result<TimeoutSetType, Error> {
    match s.to_uppercase().as_str() {
        "COMPUTED" => Ok(TimeoutSetType::Computed),
        "RESET" => Ok(TimeoutSetType::Reset),
        "SUSPENDED" => Ok(TimeoutSetType::Suspended),
        "DISCARD" => Ok(TimeoutSetType::Discard),
        "RESUME" => Ok(TimeoutSetType::Resume),
        _ => Err(Error::Protocol(format!("unknown timeout set type: {}", s))),
    }
}

/// Parses a log runlevel string into a [`Runlevel`] enum variant.
///
/// Converts a case-insensitive string representation of a Tor log severity
/// level from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The runlevel string to parse (e.g., "DEBUG", "INFO", "WARN")
///
/// # Returns
///
/// * `Ok(Runlevel)` - The parsed runlevel variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known level
///
/// # Supported Values
///
/// - `DEBUG` - Debug-level messages (most verbose)
/// - `INFO` - Informational messages
/// - `NOTICE` - Normal operational messages
/// - `WARN` - Warning messages
/// - `ERR` - Error messages (most severe)
fn parse_runlevel(s: &str) -> Result<Runlevel, Error> {
    match s.to_uppercase().as_str() {
        "DEBUG" => Ok(Runlevel::Debug),
        "INFO" => Ok(Runlevel::Info),
        "NOTICE" => Ok(Runlevel::Notice),
        "WARN" => Ok(Runlevel::Warn),
        "ERR" => Ok(Runlevel::Err),
        _ => Err(Error::Protocol(format!("unknown runlevel: {}", s))),
    }
}

/// Parses a signal string into a [`Signal`] enum variant.
///
/// Converts a case-insensitive string representation of a Tor signal
/// from the Tor control protocol into the corresponding enum variant.
/// Supports both signal names and their Unix signal equivalents.
///
/// # Arguments
///
/// * `s` - The signal string to parse (e.g., "RELOAD", "HUP", "NEWNYM")
///
/// # Returns
///
/// * `Ok(Signal)` - The parsed signal variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known signal
///
/// # Supported Values
///
/// - `RELOAD` or `HUP` - Reload configuration
/// - `SHUTDOWN` or `INT` - Controlled shutdown
/// - `DUMP` or `USR1` - Dump statistics
/// - `DEBUG` or `USR2` - Switch to debug logging
/// - `HALT` or `TERM` - Immediate shutdown
/// - `NEWNYM` - Request new circuits
/// - `CLEARDNSCACHE` - Clear DNS cache
/// - `HEARTBEAT` - Trigger heartbeat log
/// - `ACTIVE` - Wake from dormant mode
/// - `DORMANT` - Enter dormant mode
fn parse_signal(s: &str) -> Result<Signal, Error> {
    match s.to_uppercase().as_str() {
        "RELOAD" | "HUP" => Ok(Signal::Reload),
        "SHUTDOWN" | "INT" => Ok(Signal::Shutdown),
        "DUMP" | "USR1" => Ok(Signal::Dump),
        "DEBUG" | "USR2" => Ok(Signal::Debug),
        "HALT" | "TERM" => Ok(Signal::Halt),
        "NEWNYM" => Ok(Signal::Newnym),
        "CLEARDNSCACHE" => Ok(Signal::ClearDnsCache),
        "HEARTBEAT" => Ok(Signal::Heartbeat),
        "ACTIVE" => Ok(Signal::Active),
        "DORMANT" => Ok(Signal::Dormant),
        _ => Err(Error::Protocol(format!("unknown signal: {}", s))),
    }
}

/// Parses a connection type string into a [`ConnectionType`] enum variant.
///
/// Converts a case-insensitive string representation of a Tor connection type
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The connection type string to parse (e.g., "OR", "DIR", "EXIT")
///
/// # Returns
///
/// * `Ok(ConnectionType)` - The parsed connection type variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known type
///
/// # Supported Values
///
/// - `OR` - Onion Router connection (relay-to-relay)
/// - `DIR` - Directory connection
/// - `EXIT` - Exit connection to destination
fn parse_connection_type(s: &str) -> Result<ConnectionType, Error> {
    match s.to_uppercase().as_str() {
        "OR" => Ok(ConnectionType::Or),
        "DIR" => Ok(ConnectionType::Dir),
        "EXIT" => Ok(ConnectionType::Exit),
        _ => Err(Error::Protocol(format!("unknown connection type: {}", s))),
    }
}

/// Parses a hidden service descriptor action string into an [`HsDescAction`] enum variant.
///
/// Converts a case-insensitive string representation of a hidden service
/// descriptor action from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The HS_DESC action string to parse (e.g., "REQUESTED", "RECEIVED")
///
/// # Returns
///
/// * `Ok(HsDescAction)` - The parsed action variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known action
///
/// # Supported Values
///
/// - `REQUESTED` - Descriptor fetch requested
/// - `UPLOAD` - Descriptor upload initiated
/// - `RECEIVED` - Descriptor successfully received
/// - `UPLOADED` - Descriptor successfully uploaded
/// - `IGNORE` - Descriptor ignored
/// - `FAILED` - Descriptor operation failed
/// - `CREATED` - Descriptor created locally
fn parse_hs_desc_action(s: &str) -> Result<HsDescAction, Error> {
    match s.to_uppercase().as_str() {
        "REQUESTED" => Ok(HsDescAction::Requested),
        "UPLOAD" => Ok(HsDescAction::Upload),
        "RECEIVED" => Ok(HsDescAction::Received),
        "UPLOADED" => Ok(HsDescAction::Uploaded),
        "IGNORE" => Ok(HsDescAction::Ignore),
        "FAILED" => Ok(HsDescAction::Failed),
        "CREATED" => Ok(HsDescAction::Created),
        _ => Err(Error::Protocol(format!("unknown HS_DESC action: {}", s))),
    }
}

/// Parses a hidden service authentication type string into an [`HsAuth`] enum variant.
///
/// Converts a case-insensitive string representation of a hidden service
/// authentication type from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The HS auth type string to parse (e.g., "NO_AUTH", "BASIC_AUTH")
///
/// # Returns
///
/// * `Ok(HsAuth)` - The parsed authentication type variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known type
///
/// # Supported Values
///
/// - `NO_AUTH` - No authentication required
/// - `BASIC_AUTH` - Basic authentication
/// - `STEALTH_AUTH` - Stealth authentication (more private)
/// - `UNKNOWN` - Unknown authentication type
fn parse_hs_auth(s: &str) -> Result<HsAuth, Error> {
    match s.to_uppercase().as_str() {
        "NO_AUTH" => Ok(HsAuth::NoAuth),
        "BASIC_AUTH" => Ok(HsAuth::BasicAuth),
        "STEALTH_AUTH" => Ok(HsAuth::StealthAuth),
        "UNKNOWN" => Ok(HsAuth::Unknown),
        _ => Err(Error::Protocol(format!("unknown HS auth type: {}", s))),
    }
}

/// Parses a hidden service descriptor failure reason string into an [`HsDescReason`] enum variant.
///
/// Converts a case-insensitive string representation of a hidden service
/// descriptor failure reason from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The HS_DESC reason string to parse (e.g., "NOT_FOUND", "BAD_DESC")
///
/// # Returns
///
/// * `Ok(HsDescReason)` - The parsed reason variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known reason
///
/// # Supported Values
///
/// - `BAD_DESC` - Descriptor was malformed or invalid
/// - `QUERY_REJECTED` - Query was rejected by HSDir
/// - `UPLOAD_REJECTED` - Upload was rejected by HSDir
/// - `NOT_FOUND` - Descriptor not found
/// - `QUERY_NO_HSDIR` - No HSDir available for query
/// - `QUERY_RATE_LIMITED` - Query rate limited
/// - `UNEXPECTED` - Unexpected error occurred
fn parse_hs_desc_reason(s: &str) -> Result<HsDescReason, Error> {
    match s.to_uppercase().as_str() {
        "BAD_DESC" => Ok(HsDescReason::BadDesc),
        "QUERY_REJECTED" => Ok(HsDescReason::QueryRejected),
        "UPLOAD_REJECTED" => Ok(HsDescReason::UploadRejected),
        "NOT_FOUND" => Ok(HsDescReason::NotFound),
        "QUERY_NO_HSDIR" => Ok(HsDescReason::QueryNoHsDir),
        "QUERY_RATE_LIMITED" => Ok(HsDescReason::QueryRateLimited),
        "UNEXPECTED" => Ok(HsDescReason::Unexpected),
        _ => Err(Error::Protocol(format!("unknown HS_DESC reason: {}", s))),
    }
}

/// Parses a circuit purpose string into a [`CircPurpose`] enum variant.
///
/// Converts a case-insensitive string representation of a circuit purpose
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The circuit purpose string to parse (e.g., "GENERAL", "HS_CLIENT_REND")
///
/// # Returns
///
/// * `Ok(CircPurpose)` - The parsed circuit purpose variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known purpose
///
/// # Supported Values
///
/// - `GENERAL` - General-purpose circuit for user traffic
/// - `HS_CLIENT_INTRO` - Hidden service client introduction circuit
/// - `HS_CLIENT_REND` - Hidden service client rendezvous circuit
/// - `HS_SERVICE_INTRO` - Hidden service introduction point circuit
/// - `HS_SERVICE_REND` - Hidden service rendezvous circuit
/// - `TESTING` - Circuit for testing purposes
/// - `CONTROLLER` - Circuit created by controller
/// - `MEASURE_TIMEOUT` - Circuit for measuring build timeouts
/// - `HS_VANGUARDS` - Vanguard circuit for hidden services
/// - `PATH_BIAS_TESTING` - Circuit for path bias testing
/// - `CIRCUIT_PADDING` - Circuit for padding purposes
fn parse_circ_purpose(s: &str) -> Result<CircPurpose, Error> {
    match s.to_uppercase().as_str() {
        "GENERAL" => Ok(CircPurpose::General),
        "HS_CLIENT_INTRO" => Ok(CircPurpose::HsClientIntro),
        "HS_CLIENT_REND" => Ok(CircPurpose::HsClientRend),
        "HS_SERVICE_INTRO" => Ok(CircPurpose::HsServiceIntro),
        "HS_SERVICE_REND" => Ok(CircPurpose::HsServiceRend),
        "TESTING" => Ok(CircPurpose::Testing),
        "CONTROLLER" => Ok(CircPurpose::Controller),
        "MEASURE_TIMEOUT" => Ok(CircPurpose::MeasureTimeout),
        "HS_VANGUARDS" => Ok(CircPurpose::HsVanguards),
        "PATH_BIAS_TESTING" => Ok(CircPurpose::PathBiasTesting),
        "CIRCUIT_PADDING" => Ok(CircPurpose::CircuitPadding),
        _ => Err(Error::Protocol(format!("unknown circuit purpose: {}", s))),
    }
}

/// Parses a hidden service state string into a [`HiddenServiceState`] enum variant.
///
/// Converts a case-insensitive string representation of a hidden service
/// circuit state from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The HS state string to parse (e.g., "HSCI_CONNECTING", "HSCR_JOINED")
///
/// # Returns
///
/// * `Ok(HiddenServiceState)` - The parsed hidden service state variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known state
///
/// # Supported Values
///
/// Client Introduction (HSCI):
/// - `HSCI_CONNECTING` - Connecting to introduction point
/// - `HSCI_INTRO_SENT` - Introduction sent to service
/// - `HSCI_DONE` - Introduction complete
///
/// Client Rendezvous (HSCR):
/// - `HSCR_CONNECTING` - Connecting to rendezvous point
/// - `HSCR_ESTABLISHED_IDLE` - Rendezvous established, idle
/// - `HSCR_ESTABLISHED_WAITING` - Rendezvous established, waiting
/// - `HSCR_JOINED` - Rendezvous joined with service
///
/// Service Introduction (HSSI):
/// - `HSSI_CONNECTING` - Service connecting to intro point
/// - `HSSI_ESTABLISHED` - Service intro point established
///
/// Service Rendezvous (HSSR):
/// - `HSSR_CONNECTING` - Service connecting to rendezvous
/// - `HSSR_JOINED` - Service joined rendezvous
fn parse_hs_state(s: &str) -> Result<HiddenServiceState, Error> {
    match s.to_uppercase().as_str() {
        "HSCI_CONNECTING" => Ok(HiddenServiceState::HsciConnecting),
        "HSCI_INTRO_SENT" => Ok(HiddenServiceState::HsciIntroSent),
        "HSCI_DONE" => Ok(HiddenServiceState::HsciDone),
        "HSCR_CONNECTING" => Ok(HiddenServiceState::HscrConnecting),
        "HSCR_ESTABLISHED_IDLE" => Ok(HiddenServiceState::HscrEstablishedIdle),
        "HSCR_ESTABLISHED_WAITING" => Ok(HiddenServiceState::HscrEstablishedWaiting),
        "HSCR_JOINED" => Ok(HiddenServiceState::HscrJoined),
        "HSSI_CONNECTING" => Ok(HiddenServiceState::HssiConnecting),
        "HSSI_ESTABLISHED" => Ok(HiddenServiceState::HssiEstablished),
        "HSSR_CONNECTING" => Ok(HiddenServiceState::HssrConnecting),
        "HSSR_JOINED" => Ok(HiddenServiceState::HssrJoined),
        _ => Err(Error::Protocol(format!("unknown HS state: {}", s))),
    }
}

/// Parses a circuit closure reason string into a [`CircClosureReason`] enum variant.
///
/// Converts a case-insensitive string representation of a circuit closure reason
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The circuit closure reason string to parse (e.g., "FINISHED", "TIMEOUT")
///
/// # Returns
///
/// * `Ok(CircClosureReason)` - The parsed closure reason variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known reason
///
/// # Supported Values
///
/// - `NONE` - No reason given
/// - `TORPROTOCOL` - Tor protocol violation
/// - `INTERNAL` - Internal error
/// - `REQUESTED` - Closure requested by client
/// - `HIBERNATING` - Relay is hibernating
/// - `RESOURCELIMIT` - Resource limit reached
/// - `CONNECTFAILED` - Connection to relay failed
/// - `OR_IDENTITY` - OR identity mismatch
/// - `OR_CONN_CLOSED` - OR connection closed
/// - `FINISHED` - Circuit finished normally
/// - `TIMEOUT` - Circuit timed out
/// - `DESTROYED` - Circuit was destroyed
/// - `NOPATH` - No path available
/// - `NOSUCHSERVICE` - Hidden service not found
/// - `MEASUREMENT_EXPIRED` - Measurement circuit expired
/// - `IP_NOW_REDUNDANT` - Introduction point now redundant
fn parse_circ_closure_reason(s: &str) -> Result<CircClosureReason, Error> {
    match s.to_uppercase().as_str() {
        "NONE" => Ok(CircClosureReason::None),
        "TORPROTOCOL" => Ok(CircClosureReason::TorProtocol),
        "INTERNAL" => Ok(CircClosureReason::Internal),
        "REQUESTED" => Ok(CircClosureReason::Requested),
        "HIBERNATING" => Ok(CircClosureReason::Hibernating),
        "RESOURCELIMIT" => Ok(CircClosureReason::ResourceLimit),
        "CONNECTFAILED" => Ok(CircClosureReason::ConnectFailed),
        "OR_IDENTITY" => Ok(CircClosureReason::OrIdentity),
        "OR_CONN_CLOSED" => Ok(CircClosureReason::OrConnClosed),
        "FINISHED" => Ok(CircClosureReason::Finished),
        "TIMEOUT" => Ok(CircClosureReason::Timeout),
        "DESTROYED" => Ok(CircClosureReason::Destroyed),
        "NOPATH" => Ok(CircClosureReason::NoPath),
        "NOSUCHSERVICE" => Ok(CircClosureReason::NoSuchService),
        "MEASUREMENT_EXPIRED" => Ok(CircClosureReason::MeasurementExpired),
        "IP_NOW_REDUNDANT" => Ok(CircClosureReason::IpNowRedundant),
        _ => Err(Error::Protocol(format!(
            "unknown circuit closure reason: {}",
            s
        ))),
    }
}

/// Parses a stream closure reason string into a [`StreamClosureReason`] enum variant.
///
/// Converts a case-insensitive string representation of a stream closure reason
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The stream closure reason string to parse (e.g., "DONE", "TIMEOUT")
///
/// # Returns
///
/// * `Ok(StreamClosureReason)` - The parsed closure reason variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known reason
///
/// # Supported Values
///
/// - `MISC` - Miscellaneous error
/// - `RESOLVEFAILED` - DNS resolution failed
/// - `CONNECTREFUSED` - Connection refused by destination
/// - `EXITPOLICY` - Exit policy rejected connection
/// - `DESTROY` - Circuit was destroyed
/// - `DONE` - Stream completed normally
/// - `TIMEOUT` - Stream timed out
/// - `NOROUTE` - No route to destination
/// - `HIBERNATING` - Relay is hibernating
/// - `INTERNAL` - Internal error
/// - `RESOURCELIMIT` - Resource limit reached
/// - `CONNRESET` - Connection reset
/// - `TORPROTOCOL` - Tor protocol violation
/// - `NOTDIRECTORY` - Not a directory server
/// - `END` - Stream ended
/// - `PRIVATE_ADDR` - Private address rejected
fn parse_stream_closure_reason(s: &str) -> Result<StreamClosureReason, Error> {
    match s.to_uppercase().as_str() {
        "MISC" => Ok(StreamClosureReason::Misc),
        "RESOLVEFAILED" => Ok(StreamClosureReason::ResolveFailed),
        "CONNECTREFUSED" => Ok(StreamClosureReason::ConnectRefused),
        "EXITPOLICY" => Ok(StreamClosureReason::ExitPolicy),
        "DESTROY" => Ok(StreamClosureReason::Destroy),
        "DONE" => Ok(StreamClosureReason::Done),
        "TIMEOUT" => Ok(StreamClosureReason::Timeout),
        "NOROUTE" => Ok(StreamClosureReason::NoRoute),
        "HIBERNATING" => Ok(StreamClosureReason::Hibernating),
        "INTERNAL" => Ok(StreamClosureReason::Internal),
        "RESOURCELIMIT" => Ok(StreamClosureReason::ResourceLimit),
        "CONNRESET" => Ok(StreamClosureReason::ConnReset),
        "TORPROTOCOL" => Ok(StreamClosureReason::TorProtocol),
        "NOTDIRECTORY" => Ok(StreamClosureReason::NotDirectory),
        "END" => Ok(StreamClosureReason::End),
        "PRIVATE_ADDR" => Ok(StreamClosureReason::PrivateAddr),
        _ => Err(Error::Protocol(format!(
            "unknown stream closure reason: {}",
            s
        ))),
    }
}

/// Parses a stream source string into a [`StreamSource`] enum variant.
///
/// Converts a case-insensitive string representation of a stream source
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The stream source string to parse (e.g., "CACHE", "EXIT")
///
/// # Returns
///
/// * `Ok(StreamSource)` - The parsed stream source variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known source
///
/// # Supported Values
///
/// - `CACHE` - Data from cache
/// - `EXIT` - Data from exit node
fn parse_stream_source(s: &str) -> Result<StreamSource, Error> {
    match s.to_uppercase().as_str() {
        "CACHE" => Ok(StreamSource::Cache),
        "EXIT" => Ok(StreamSource::Exit),
        _ => Err(Error::Protocol(format!("unknown stream source: {}", s))),
    }
}

/// Parses a stream purpose string into a [`StreamPurpose`] enum variant.
///
/// Converts a case-insensitive string representation of a stream purpose
/// from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The stream purpose string to parse (e.g., "USER", "DIR_FETCH")
///
/// # Returns
///
/// * `Ok(StreamPurpose)` - The parsed stream purpose variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known purpose
///
/// # Supported Values
///
/// - `DIR_FETCH` - Directory fetch operation
/// - `DIR_UPLOAD` - Directory upload operation
/// - `DNS_REQUEST` - DNS resolution request
/// - `DIRPORT_TEST` - Directory port testing
/// - `USER` - User-initiated stream
fn parse_stream_purpose(s: &str) -> Result<StreamPurpose, Error> {
    match s.to_uppercase().as_str() {
        "DIR_FETCH" => Ok(StreamPurpose::DirFetch),
        "DIR_UPLOAD" => Ok(StreamPurpose::DirUpload),
        "DNS_REQUEST" => Ok(StreamPurpose::DnsRequest),
        "DIRPORT_TEST" => Ok(StreamPurpose::DirportTest),
        "USER" => Ok(StreamPurpose::User),
        _ => Err(Error::Protocol(format!("unknown stream purpose: {}", s))),
    }
}

/// Parses an OR connection closure reason string into an [`OrClosureReason`] enum variant.
///
/// Converts a case-insensitive string representation of an OR connection
/// closure reason from the Tor control protocol into the corresponding enum variant.
///
/// # Arguments
///
/// * `s` - The OR closure reason string to parse (e.g., "DONE", "TIMEOUT")
///
/// # Returns
///
/// * `Ok(OrClosureReason)` - The parsed closure reason variant
/// * `Err(Error::Protocol)` - If the string doesn't match any known reason
///
/// # Supported Values
///
/// - `DONE` - Connection completed normally
/// - `CONNECTREFUSED` - Connection refused
/// - `IDENTITY` - Identity verification failed
/// - `CONNECTRESET` - Connection reset
/// - `TIMEOUT` - Connection timed out
/// - `NOROUTE` - No route to relay
/// - `IOERROR` - I/O error occurred
/// - `RESOURCELIMIT` - Resource limit reached
/// - `MISC` - Miscellaneous error
/// - `PT_MISSING` - Pluggable transport missing
fn parse_or_closure_reason(s: &str) -> Result<OrClosureReason, Error> {
    match s.to_uppercase().as_str() {
        "DONE" => Ok(OrClosureReason::Done),
        "CONNECTREFUSED" => Ok(OrClosureReason::ConnectRefused),
        "IDENTITY" => Ok(OrClosureReason::Identity),
        "CONNECTRESET" => Ok(OrClosureReason::ConnectReset),
        "TIMEOUT" => Ok(OrClosureReason::Timeout),
        "NOROUTE" => Ok(OrClosureReason::NoRoute),
        "IOERROR" => Ok(OrClosureReason::IoError),
        "RESOURCELIMIT" => Ok(OrClosureReason::ResourceLimit),
        "MISC" => Ok(OrClosureReason::Misc),
        "PT_MISSING" => Ok(OrClosureReason::PtMissing),
        _ => Err(Error::Protocol(format!("unknown OR closure reason: {}", s))),
    }
}

/// Parses a comma-separated string of circuit build flags into a vector of [`CircBuildFlag`].
///
/// Converts a comma-separated string of circuit build flags from the Tor
/// control protocol into a vector of enum variants. Unknown flags are silently ignored.
///
/// # Arguments
///
/// * `s` - The comma-separated build flags string (e.g., "ONEHOP_TUNNEL,IS_INTERNAL")
///
/// # Returns
///
/// A vector of recognized [`CircBuildFlag`] variants. Unknown flags are filtered out.
///
/// # Supported Values
///
/// - `ONEHOP_TUNNEL` - Single-hop circuit (for directory connections)
/// - `IS_INTERNAL` - Internal circuit (not for user traffic)
/// - `NEED_CAPACITY` - Circuit needs high-capacity relays
/// - `NEED_UPTIME` - Circuit needs high-uptime relays
fn parse_build_flags(s: &str) -> Vec<CircBuildFlag> {
    s.split(',')
        .filter_map(|f| match f.to_uppercase().as_str() {
            "ONEHOP_TUNNEL" => Some(CircBuildFlag::OneHopTunnel),
            "IS_INTERNAL" => Some(CircBuildFlag::IsInternal),
            "NEED_CAPACITY" => Some(CircBuildFlag::NeedCapacity),
            "NEED_UPTIME" => Some(CircBuildFlag::NeedUptime),
            _ => None,
        })
        .collect()
}

/// Parses a circuit path string into a vector of relay fingerprint and nickname pairs.
///
/// Converts a comma-separated circuit path string from the Tor control protocol
/// into a vector of tuples containing relay fingerprints and optional nicknames.
///
/// # Arguments
///
/// * `s` - The circuit path string (e.g., "$FP1~nick1,$FP2=nick2,$FP3")
///
/// # Returns
///
/// A vector of tuples where each tuple contains:
/// - The relay fingerprint (with leading `$` stripped)
/// - An optional nickname (if present after `~` or `=`)
///
/// # Format
///
/// Each relay in the path can be specified as:
/// - `$FINGERPRINT~nickname` - Fingerprint with nickname (tilde separator)
/// - `$FINGERPRINT=nickname` - Fingerprint with nickname (equals separator)
/// - `$FINGERPRINT` - Fingerprint only
/// - `FINGERPRINT` - Fingerprint without `$` prefix
fn parse_circuit_path(s: &str) -> Vec<(String, Option<String>)> {
    s.split(',')
        .map(|relay| {
            let relay = relay.trim_start_matches('$');
            if let Some((fp, nick)) = relay.split_once('~') {
                (fp.to_string(), Some(nick.to_string()))
            } else if let Some((fp, nick)) = relay.split_once('=') {
                (fp.to_string(), Some(nick.to_string()))
            } else {
                (relay.to_string(), None)
            }
        })
        .collect()
}

/// Parses a relay endpoint string into a fingerprint and optional nickname.
///
/// Converts a relay endpoint string from the Tor control protocol into a tuple
/// containing the relay fingerprint and optional nickname.
///
/// # Arguments
///
/// * `s` - The relay endpoint string (e.g., "$FP~nickname" or "$FP=nickname")
///
/// # Returns
///
/// A tuple containing:
/// - The relay fingerprint (with leading `$` stripped)
/// - An optional nickname (if present after `~` or `=`)
///
/// # Format
///
/// The relay can be specified as:
/// - `$FINGERPRINT~nickname` - Fingerprint with nickname (tilde separator)
/// - `$FINGERPRINT=nickname` - Fingerprint with nickname (equals separator)
/// - `$FINGERPRINT` - Fingerprint only
/// - `FINGERPRINT` - Fingerprint without `$` prefix
fn parse_relay_endpoint(s: &str) -> (String, Option<String>) {
    let s = s.trim_start_matches('$');
    if let Some((fp, nick)) = s.split_once('~') {
        (fp.to_string(), Some(nick.to_string()))
    } else if let Some((fp, nick)) = s.split_once('=') {
        (fp.to_string(), Some(nick.to_string()))
    } else {
        (s.to_string(), None)
    }
}

/// Parses a target address string into a host and port tuple.
///
/// Converts a target address string (host:port format) from the Tor control
/// protocol into a tuple containing the host and port number.
///
/// # Arguments
///
/// * `target` - The target address string (e.g., "example.com:80" or "[::1]:443")
///
/// # Returns
///
/// * `Ok((host, port))` - The parsed host string and port number
/// * `Err(Error::Protocol)` - If the port cannot be parsed as a valid u16
///
/// # Format
///
/// Supports both IPv4 and IPv6 addresses:
/// - `hostname:port` - Standard hostname with port
/// - `ip:port` - IPv4 address with port
/// - `[ipv6]:port` - IPv6 address with port (brackets preserved in host)
///
/// If no port is specified, returns port 0.
fn parse_target(target: &str) -> Result<(String, u16), Error> {
    if let Some(colon_pos) = target.rfind(':') {
        let host = target[..colon_pos].to_string();
        let port_str = &target[colon_pos + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|_| Error::Protocol(format!("invalid port: {}", port_str)))?;
        Ok((host, port))
    } else {
        Ok((target.to_string(), 0))
    }
}

/// Parses an ISO 8601 timestamp string into a UTC [`DateTime`].
///
/// Converts a timestamp string in ISO 8601 format from the Tor control
/// protocol into a [`DateTime<Utc>`] value.
///
/// # Arguments
///
/// * `s` - The timestamp string (e.g., "2024-01-15 12:30:45" or "2024-01-15T12:30:45.123")
///
/// # Returns
///
/// * `Ok(DateTime<Utc>)` - The parsed UTC datetime
/// * `Err(Error::Protocol)` - If the timestamp format is invalid
///
/// # Supported Formats
///
/// - `YYYY-MM-DD HH:MM:SS` - Standard format
/// - `YYYY-MM-DDTHH:MM:SS` - ISO 8601 with T separator
/// - `YYYY-MM-DD HH:MM:SS.fff` - With fractional seconds
/// - `YYYY-MM-DDTHH:MM:SS.fff` - ISO 8601 with fractional seconds
fn parse_iso_timestamp(s: &str) -> Result<DateTime<Utc>, Error> {
    let s = s.replace('T', " ");
    let formats = ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S"];
    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&s, fmt) {
            return Ok(DateTime::from_naive_utc_and_offset(dt, Utc));
        }
    }
    Err(Error::Protocol(format!("invalid timestamp: {}", s)))
}

/// Parses a local timestamp string into a local [`DateTime`].
///
/// Converts a timestamp string from the Tor control protocol into a
/// [`DateTime<Local>`] value using the system's local timezone offset.
///
/// # Arguments
///
/// * `s` - The timestamp string (e.g., "2024-01-15 12:30:45")
///
/// # Returns
///
/// * `Ok(DateTime<Local>)` - The parsed local datetime
/// * `Err(Error::Protocol)` - If the timestamp format is invalid
///
/// # Supported Formats
///
/// - `YYYY-MM-DD HH:MM:SS` - Standard format
/// - `YYYY-MM-DD HH:MM:SS.fff` - With fractional seconds
///
/// # Note
///
/// The timestamp is interpreted as being in the local timezone at the
/// time of parsing. The current local timezone offset is applied.
fn parse_local_timestamp(s: &str) -> Result<DateTime<Local>, Error> {
    let formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S%.f"];
    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Ok(DateTime::from_naive_utc_and_offset(
                dt,
                *Local::now().offset(),
            ));
        }
    }
    Err(Error::Protocol(format!("invalid local timestamp: {}", s)))
}

/// Parses a UTC timestamp string into a UTC [`DateTime`].
///
/// This is an alias for [`parse_iso_timestamp`] that explicitly indicates
/// the timestamp should be interpreted as UTC.
///
/// # Arguments
///
/// * `s` - The timestamp string in ISO 8601 format
///
/// # Returns
///
/// * `Ok(DateTime<Utc>)` - The parsed UTC datetime
/// * `Err(Error::Protocol)` - If the timestamp format is invalid
///
/// # See Also
///
/// - [`parse_iso_timestamp`] - The underlying implementation
fn parse_utc_timestamp(s: &str) -> Result<DateTime<Utc>, Error> {
    parse_iso_timestamp(s)
}

/// Enumeration of all parsed event types.
///
/// This enum provides a unified way to handle different event types
/// through pattern matching. Use [`ParsedEvent::parse`] to convert
/// raw event data into the appropriate variant.
///
/// # Parsing Events
///
/// Events are parsed from raw control protocol messages:
///
/// ```rust,ignore
/// use stem_rs::events::ParsedEvent;
///
/// let event = ParsedEvent::parse("BW", "1024 2048", None)?;
/// match event {
///     ParsedEvent::Bandwidth(bw) => {
///         println!("Read: {}, Written: {}", bw.read, bw.written);
///     }
///     _ => {}
/// }
/// ```
///
/// # Unknown Events
///
/// Events that don't match a known type are captured as
/// [`ParsedEvent::Unknown`], preserving the raw content for
/// debugging or custom handling.
///
/// # Display
///
/// All variants implement [`Display`](std::fmt::Display) to reconstruct
/// a human-readable representation of the event.
#[derive(Debug, Clone)]
pub enum ParsedEvent {
    /// Aggregate bandwidth event (BW).
    Bandwidth(BandwidthEvent),
    /// Log message event (DEBUG, INFO, NOTICE, WARN, ERR).
    Log(LogEvent),
    /// Circuit status change event (CIRC).
    Circuit(CircuitEvent),
    /// Stream status change event (STREAM).
    Stream(StreamEvent),
    /// OR connection status change event (ORCONN).
    OrConn(OrConnEvent),
    /// Address mapping event (ADDRMAP).
    AddrMap(AddrMapEvent),
    /// Circuit build timeout change event (BUILDTIMEOUT_SET).
    BuildTimeoutSet(BuildTimeoutSetEvent),
    /// Guard relay status change event (GUARD).
    Guard(GuardEvent),
    /// New descriptor available event (NEWDESC).
    NewDesc(NewDescEvent),
    /// Signal received event (SIGNAL).
    Signal(SignalEvent),
    /// Status event (STATUS_GENERAL, STATUS_CLIENT, STATUS_SERVER).
    Status(StatusEvent),
    /// Configuration changed event (CONF_CHANGED).
    ConfChanged(ConfChangedEvent),
    /// Network liveness event (NETWORK_LIVENESS).
    NetworkLiveness(NetworkLivenessEvent),
    /// Per-circuit bandwidth event (CIRC_BW).
    CircuitBandwidth(CircuitBandwidthEvent),
    /// Per-connection bandwidth event (CONN_BW).
    ConnectionBandwidth(ConnectionBandwidthEvent),
    /// Hidden service descriptor event (HS_DESC).
    HsDesc(HsDescEvent),
    /// Unknown or unrecognized event type.
    Unknown {
        /// The event type string.
        event_type: String,
        /// The raw event content.
        content: String,
    },
}

impl ParsedEvent {
    /// Parses raw event data into a typed event.
    ///
    /// # Arguments
    ///
    /// * `event_type` - The event type keyword (e.g., "BW", "CIRC")
    /// * `content` - The event content after the type
    /// * `lines` - Optional multi-line content for events like CONF_CHANGED
    ///
    /// # Supported Event Types
    ///
    /// - `BW` - Bandwidth events
    /// - `DEBUG`, `INFO`, `NOTICE`, `WARN`, `ERR` - Log events
    /// - `CIRC` - Circuit events
    /// - `STREAM` - Stream events
    /// - `ORCONN` - OR connection events
    /// - `ADDRMAP` - Address map events
    /// - `BUILDTIMEOUT_SET` - Build timeout events
    /// - `GUARD` - Guard events
    /// - `NEWDESC` - New descriptor events
    /// - `SIGNAL` - Signal events
    /// - `STATUS_GENERAL`, `STATUS_CLIENT`, `STATUS_SERVER` - Status events
    /// - `CONF_CHANGED` - Configuration change events
    /// - `NETWORK_LIVENESS` - Network liveness events
    /// - `CIRC_BW` - Circuit bandwidth events
    /// - `CONN_BW` - Connection bandwidth events
    /// - `HS_DESC` - Hidden service descriptor events
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the event content is malformed.
    /// Unknown event types are returned as [`ParsedEvent::Unknown`]
    /// rather than causing an error.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use stem_rs::events::ParsedEvent;
    ///
    /// // Parse a bandwidth event
    /// let event = ParsedEvent::parse("BW", "100 200", None)?;
    ///
    /// // Parse a circuit event
    /// let event = ParsedEvent::parse("CIRC", "1 BUILT $ABC...=relay", None)?;
    ///
    /// // Unknown events are captured, not rejected
    /// let event = ParsedEvent::parse("FUTURE_EVENT", "data", None)?;
    /// assert!(matches!(event, ParsedEvent::Unknown { .. }));
    /// ```
    pub fn parse(event_type: &str, content: &str, lines: Option<&[String]>) -> Result<Self, Error> {
        match event_type.to_uppercase().as_str() {
            "BW" => Ok(ParsedEvent::Bandwidth(BandwidthEvent::parse(content)?)),
            "DEBUG" => Ok(ParsedEvent::Log(LogEvent::parse(Runlevel::Debug, content)?)),
            "INFO" => Ok(ParsedEvent::Log(LogEvent::parse(Runlevel::Info, content)?)),
            "NOTICE" => Ok(ParsedEvent::Log(LogEvent::parse(
                Runlevel::Notice,
                content,
            )?)),
            "WARN" => Ok(ParsedEvent::Log(LogEvent::parse(Runlevel::Warn, content)?)),
            "ERR" => Ok(ParsedEvent::Log(LogEvent::parse(Runlevel::Err, content)?)),
            "CIRC" => Ok(ParsedEvent::Circuit(CircuitEvent::parse(content)?)),
            "STREAM" => Ok(ParsedEvent::Stream(StreamEvent::parse(content)?)),
            "ORCONN" => Ok(ParsedEvent::OrConn(OrConnEvent::parse(content)?)),
            "ADDRMAP" => Ok(ParsedEvent::AddrMap(AddrMapEvent::parse(content)?)),
            "BUILDTIMEOUT_SET" => Ok(ParsedEvent::BuildTimeoutSet(BuildTimeoutSetEvent::parse(
                content,
            )?)),
            "GUARD" => Ok(ParsedEvent::Guard(GuardEvent::parse(content)?)),
            "NEWDESC" => Ok(ParsedEvent::NewDesc(NewDescEvent::parse(content)?)),
            "SIGNAL" => Ok(ParsedEvent::Signal(SignalEvent::parse(content)?)),
            "STATUS_GENERAL" => Ok(ParsedEvent::Status(StatusEvent::parse(
                StatusType::General,
                content,
            )?)),
            "STATUS_CLIENT" => Ok(ParsedEvent::Status(StatusEvent::parse(
                StatusType::Client,
                content,
            )?)),
            "STATUS_SERVER" => Ok(ParsedEvent::Status(StatusEvent::parse(
                StatusType::Server,
                content,
            )?)),
            "CONF_CHANGED" => {
                let lines = lines.unwrap_or(&[]);
                Ok(ParsedEvent::ConfChanged(ConfChangedEvent::parse(lines)?))
            }
            "NETWORK_LIVENESS" => Ok(ParsedEvent::NetworkLiveness(NetworkLivenessEvent::parse(
                content,
            )?)),
            "CIRC_BW" => Ok(ParsedEvent::CircuitBandwidth(CircuitBandwidthEvent::parse(
                content,
            )?)),
            "CONN_BW" => Ok(ParsedEvent::ConnectionBandwidth(
                ConnectionBandwidthEvent::parse(content)?,
            )),
            "HS_DESC" => Ok(ParsedEvent::HsDesc(HsDescEvent::parse(content)?)),
            _ => Ok(ParsedEvent::Unknown {
                event_type: event_type.to_string(),
                content: content.to_string(),
            }),
        }
    }

    /// Returns the event type string for this event.
    ///
    /// This returns the canonical event type keyword as used in
    /// `SETEVENTS` commands and event responses.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let event = ParsedEvent::parse("BW", "100 200", None)?;
    /// assert_eq!(event.event_type(), "BW");
    /// ```
    pub fn event_type(&self) -> &str {
        match self {
            ParsedEvent::Bandwidth(_) => "BW",
            ParsedEvent::Log(e) => match e.runlevel {
                Runlevel::Debug => "DEBUG",
                Runlevel::Info => "INFO",
                Runlevel::Notice => "NOTICE",
                Runlevel::Warn => "WARN",
                Runlevel::Err => "ERR",
            },
            ParsedEvent::Circuit(_) => "CIRC",
            ParsedEvent::Stream(_) => "STREAM",
            ParsedEvent::OrConn(_) => "ORCONN",
            ParsedEvent::AddrMap(_) => "ADDRMAP",
            ParsedEvent::BuildTimeoutSet(_) => "BUILDTIMEOUT_SET",
            ParsedEvent::Guard(_) => "GUARD",
            ParsedEvent::NewDesc(_) => "NEWDESC",
            ParsedEvent::Signal(_) => "SIGNAL",
            ParsedEvent::Status(e) => match e.status_type {
                StatusType::General => "STATUS_GENERAL",
                StatusType::Client => "STATUS_CLIENT",
                StatusType::Server => "STATUS_SERVER",
            },
            ParsedEvent::ConfChanged(_) => "CONF_CHANGED",
            ParsedEvent::NetworkLiveness(_) => "NETWORK_LIVENESS",
            ParsedEvent::CircuitBandwidth(_) => "CIRC_BW",
            ParsedEvent::ConnectionBandwidth(_) => "CONN_BW",
            ParsedEvent::HsDesc(_) => "HS_DESC",
            ParsedEvent::Unknown { event_type, .. } => event_type,
        }
    }
}

impl std::fmt::Display for ParsedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsedEvent::Bandwidth(e) => write!(f, "650 BW {} {}", e.read, e.written),
            ParsedEvent::Log(e) => write!(f, "650 {} {}", e.runlevel, e.message),
            ParsedEvent::Circuit(e) => write!(f, "650 CIRC {} {}", e.id, e.status),
            ParsedEvent::Stream(e) => write!(f, "650 STREAM {} {}", e.id, e.status),
            ParsedEvent::OrConn(e) => write!(f, "650 ORCONN {} {}", e.target, e.status),
            ParsedEvent::AddrMap(e) => {
                write!(
                    f,
                    "650 ADDRMAP {} {}",
                    e.hostname,
                    e.destination.as_deref().unwrap_or("<error>")
                )
            }
            ParsedEvent::BuildTimeoutSet(e) => write!(f, "650 BUILDTIMEOUT_SET {:?}", e.set_type),
            ParsedEvent::Guard(e) => {
                write!(f, "650 GUARD {} {} {}", e.guard_type, e.endpoint, e.status)
            }
            ParsedEvent::NewDesc(e) => {
                let relays: Vec<String> = e
                    .relays
                    .iter()
                    .map(|(fp, nick)| match nick {
                        Some(n) => format!("{}~{}", fp, n),
                        None => fp.clone(),
                    })
                    .collect();
                write!(f, "650 NEWDESC {}", relays.join(" "))
            }
            ParsedEvent::Signal(e) => write!(f, "650 SIGNAL {}", e.signal),
            ParsedEvent::Status(e) => write!(
                f,
                "650 STATUS_{} {} {}",
                e.status_type, e.runlevel, e.action
            ),
            ParsedEvent::ConfChanged(e) => {
                let changes: Vec<String> = e
                    .changed
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v.join(",")))
                    .collect();
                write!(f, "650 CONF_CHANGED {}", changes.join(" "))
            }
            ParsedEvent::NetworkLiveness(e) => write!(f, "650 NETWORK_LIVENESS {}", e.status),
            ParsedEvent::CircuitBandwidth(e) => {
                write!(f, "650 CIRC_BW {} {} {}", e.id, e.read, e.written)
            }
            ParsedEvent::ConnectionBandwidth(e) => write!(
                f,
                "650 CONN_BW {} {} {} {}",
                e.id, e.conn_type, e.read, e.written
            ),
            ParsedEvent::HsDesc(e) => write!(f, "650 HS_DESC {} {}", e.action, e.address),
            ParsedEvent::Unknown {
                event_type,
                content,
            } => write!(f, "650 {} {}", event_type, content),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};

    #[test]
    fn test_bandwidth_event() {
        let event = BandwidthEvent::parse("15 25").unwrap();
        assert_eq!(event.read, 15);
        assert_eq!(event.written, 25);
    }

    #[test]
    fn test_bandwidth_event_zero() {
        let event = BandwidthEvent::parse("0 0").unwrap();
        assert_eq!(event.read, 0);
        assert_eq!(event.written, 0);
    }

    #[test]
    fn test_bandwidth_event_invalid_missing_values() {
        assert!(BandwidthEvent::parse("").is_err());
        assert!(BandwidthEvent::parse("15").is_err());
    }

    #[test]
    fn test_bandwidth_event_invalid_non_numeric() {
        assert!(BandwidthEvent::parse("x 25").is_err());
        assert!(BandwidthEvent::parse("15 y").is_err());
    }

    #[test]
    fn test_log_event() {
        let event = LogEvent::parse(Runlevel::Debug, "test message").unwrap();
        assert_eq!(event.runlevel, Runlevel::Debug);
        assert_eq!(event.message, "test message");
    }

    #[test]
    fn test_log_event_debug() {
        let event = LogEvent::parse(
            Runlevel::Debug,
            "connection_edge_process_relay_cell(): Got an extended cell! Yay.",
        )
        .unwrap();
        assert_eq!(event.runlevel, Runlevel::Debug);
        assert_eq!(
            event.message,
            "connection_edge_process_relay_cell(): Got an extended cell! Yay."
        );
    }

    #[test]
    fn test_log_event_info() {
        let event = LogEvent::parse(
            Runlevel::Info,
            "circuit_finish_handshake(): Finished building circuit hop:",
        )
        .unwrap();
        assert_eq!(event.runlevel, Runlevel::Info);
    }

    #[test]
    fn test_log_event_warn() {
        let event = LogEvent::parse(Runlevel::Warn, "a multi-line\nwarning message").unwrap();
        assert_eq!(event.runlevel, Runlevel::Warn);
        assert_eq!(event.message, "a multi-line\nwarning message");
    }

    #[test]
    fn test_circuit_event_launched() {
        let content = "7 LAUNCHED BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2012-11-08T16:48:38.417238";
        let event = CircuitEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "7");
        assert_eq!(event.status, CircStatus::Launched);
        assert!(event.path.is_empty());
        assert_eq!(event.build_flags, Some(vec![CircBuildFlag::NeedCapacity]));
        assert_eq!(event.purpose, Some(CircPurpose::General));
        assert!(event.created.is_some());
        assert_eq!(event.reason, None);
        assert_eq!(event.remote_reason, None);
        assert_eq!(event.socks_username, None);
        assert_eq!(event.socks_password, None);
    }

    #[test]
    fn test_circuit_event_extended() {
        let content = "7 EXTENDED $999A226EBED397F331B612FE1E4CFAE5C1F201BA=piyaz BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL";
        let event = CircuitEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "7");
        assert_eq!(event.status, CircStatus::Extended);
        assert_eq!(event.path.len(), 1);
        assert_eq!(event.path[0].0, "999A226EBED397F331B612FE1E4CFAE5C1F201BA");
        assert_eq!(event.path[0].1, Some("piyaz".to_string()));
    }

    #[test]
    fn test_circuit_event_failed() {
        let content = "5 FAILED $E57A476CD4DFBD99B4EE52A100A58610AD6E80B9=ergebnisoffen BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL REASON=DESTROYED REMOTE_REASON=OR_CONN_CLOSED";
        let event = CircuitEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "5");
        assert_eq!(event.status, CircStatus::Failed);
        assert_eq!(event.reason, Some(CircClosureReason::Destroyed));
        assert_eq!(event.remote_reason, Some(CircClosureReason::OrConnClosed));
    }

    #[test]
    fn test_circuit_event_with_credentials() {
        let content = r#"7 LAUNCHED SOCKS_USERNAME="It's a me, Mario!" SOCKS_PASSWORD="your princess is in another castle""#;
        let event = CircuitEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "7");
        assert_eq!(event.status, CircStatus::Launched);
        assert_eq!(event.socks_username, Some("It's a me, Mario!".to_string()));
        assert_eq!(
            event.socks_password,
            Some("your princess is in another castle".to_string())
        );
    }

    #[test]
    fn test_circuit_event_launched_old_format() {
        let content = "4 LAUNCHED";
        let event = CircuitEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "4");
        assert_eq!(event.status, CircStatus::Launched);
        assert!(event.path.is_empty());
        assert_eq!(event.build_flags, None);
        assert_eq!(event.purpose, None);
    }

    #[test]
    fn test_circuit_event_extended_old_format() {
        let content = "$E57A476CD4DFBD99B4EE52A100A58610AD6E80B9,hamburgerphone";
        let event = CircuitEvent::parse(&format!("1 EXTENDED {}", content)).unwrap();
        assert_eq!(event.id.0, "1");
        assert_eq!(event.status, CircStatus::Extended);
    }

    #[test]
    fn test_circuit_event_built_old_format() {
        let content =
            "1 BUILT $E57A476CD4DFBD99B4EE52A100A58610AD6E80B9,hamburgerphone,PrivacyRepublic14";
        let event = CircuitEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "1");
        assert_eq!(event.status, CircStatus::Built);
    }

    #[test]
    fn test_stream_event_new() {
        let content = "18 NEW 0 encrypted.google.com:443 SOURCE_ADDR=127.0.0.1:47849 PURPOSE=USER";
        let event = StreamEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "18");
        assert_eq!(event.status, StreamStatus::New);
        assert_eq!(event.circuit_id, None);
        assert_eq!(event.target_host, "encrypted.google.com");
        assert_eq!(event.target_port, 443);
        assert_eq!(event.source_addr, Some("127.0.0.1:47849".to_string()));
        assert_eq!(event.purpose, Some(StreamPurpose::User));
    }

    #[test]
    fn test_stream_event_sentconnect() {
        let content = "18 SENTCONNECT 26 encrypted.google.com:443";
        let event = StreamEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "18");
        assert_eq!(event.status, StreamStatus::SentConnect);
        assert_eq!(event.circuit_id, Some(CircuitId::new("26")));
        assert_eq!(event.target_host, "encrypted.google.com");
        assert_eq!(event.target_port, 443);
        assert_eq!(event.source_addr, None);
        assert_eq!(event.purpose, None);
    }

    #[test]
    fn test_stream_event_remap() {
        let content = "18 REMAP 26 74.125.227.129:443 SOURCE=EXIT";
        let event = StreamEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "18");
        assert_eq!(event.status, StreamStatus::Remap);
        assert_eq!(event.circuit_id, Some(CircuitId::new("26")));
        assert_eq!(event.target_host, "74.125.227.129");
        assert_eq!(event.target_port, 443);
        assert_eq!(event.source, Some(StreamSource::Exit));
    }

    #[test]
    fn test_stream_event_succeeded() {
        let content = "18 SUCCEEDED 26 74.125.227.129:443";
        let event = StreamEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "18");
        assert_eq!(event.status, StreamStatus::Succeeded);
        assert_eq!(event.circuit_id, Some(CircuitId::new("26")));
        assert_eq!(event.target_host, "74.125.227.129");
        assert_eq!(event.target_port, 443);
    }

    #[test]
    fn test_stream_event_closed() {
        let content = "21 CLOSED 26 74.125.227.129:443 REASON=CONNRESET";
        let event = StreamEvent::parse(content).unwrap();
        assert_eq!(event.status, StreamStatus::Closed);
        assert_eq!(event.reason, Some(StreamClosureReason::ConnReset));
    }

    #[test]
    fn test_stream_event_closed_done() {
        let content = "25 CLOSED 26 199.7.52.72:80 REASON=DONE";
        let event = StreamEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "25");
        assert_eq!(event.status, StreamStatus::Closed);
        assert_eq!(event.reason, Some(StreamClosureReason::Done));
    }

    #[test]
    fn test_stream_event_dir_fetch() {
        let content = "14 NEW 0 176.28.51.238.$649F2D0ACF418F7CFC6539AB2257EB2D5297BAFA.exit:443 SOURCE_ADDR=(Tor_internal):0 PURPOSE=DIR_FETCH";
        let event = StreamEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "14");
        assert_eq!(event.status, StreamStatus::New);
        assert_eq!(event.circuit_id, None);
        assert_eq!(
            event.target_host,
            "176.28.51.238.$649F2D0ACF418F7CFC6539AB2257EB2D5297BAFA.exit"
        );
        assert_eq!(event.target_port, 443);
        assert_eq!(event.source_addr, Some("(Tor_internal):0".to_string()));
        assert_eq!(event.purpose, Some(StreamPurpose::DirFetch));
    }

    #[test]
    fn test_stream_event_dns_request() {
        let content = "1113 NEW 0 www.google.com:0 SOURCE_ADDR=127.0.0.1:15297 PURPOSE=DNS_REQUEST";
        let event = StreamEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "1113");
        assert_eq!(event.status, StreamStatus::New);
        assert_eq!(event.target_host, "www.google.com");
        assert_eq!(event.target_port, 0);
        assert_eq!(event.purpose, Some(StreamPurpose::DnsRequest));
    }

    #[test]
    fn test_orconn_event_closed() {
        let content = "$A1130635A0CDA6F60C276FBF6994EFBD4ECADAB1~tama CLOSED REASON=DONE";
        let event = OrConnEvent::parse(content).unwrap();
        assert_eq!(
            event.target,
            "$A1130635A0CDA6F60C276FBF6994EFBD4ECADAB1~tama"
        );
        assert_eq!(event.status, OrStatus::Closed);
        assert_eq!(event.reason, Some(OrClosureReason::Done));
        assert_eq!(event.num_circuits, None);
        assert_eq!(event.id, None);
    }

    #[test]
    fn test_orconn_event_connected() {
        let content = "127.0.0.1:9000 CONNECTED NCIRCS=20 ID=18";
        let event = OrConnEvent::parse(content).unwrap();
        assert_eq!(event.target, "127.0.0.1:9000");
        assert_eq!(event.status, OrStatus::Connected);
        assert_eq!(event.num_circuits, Some(20));
        assert_eq!(event.id, Some("18".to_string()));
        assert_eq!(event.reason, None);
    }

    #[test]
    fn test_orconn_event_launched() {
        let content = "$7ED90E2833EE38A75795BA9237B0A4560E51E1A0=GreenDragon LAUNCHED";
        let event = OrConnEvent::parse(content).unwrap();
        assert_eq!(
            event.target,
            "$7ED90E2833EE38A75795BA9237B0A4560E51E1A0=GreenDragon"
        );
        assert_eq!(event.status, OrStatus::Launched);
        assert_eq!(event.reason, None);
        assert_eq!(event.num_circuits, None);
    }

    #[test]
    fn test_addrmap_event() {
        let content =
            r#"www.atagar.com 75.119.206.243 "2012-11-19 00:50:13" EXPIRES="2012-11-19 08:50:13""#;
        let event = AddrMapEvent::parse(content).unwrap();
        assert_eq!(event.hostname, "www.atagar.com");
        assert_eq!(event.destination, Some("75.119.206.243".to_string()));
        assert!(event.expiry.is_some());
        assert_eq!(event.error, None);
        assert!(event.utc_expiry.is_some());
    }

    #[test]
    fn test_addrmap_event_no_expiration() {
        let content = "www.atagar.com 75.119.206.243 NEVER";
        let event = AddrMapEvent::parse(content).unwrap();
        assert_eq!(event.hostname, "www.atagar.com");
        assert_eq!(event.destination, Some("75.119.206.243".to_string()));
        assert_eq!(event.expiry, None);
        assert_eq!(event.utc_expiry, None);
    }

    #[test]
    fn test_addrmap_event_error() {
        let content = r#"www.atagar.com <error> "2012-11-19 00:50:13" error=yes EXPIRES="2012-11-19 08:50:13""#;
        let event = AddrMapEvent::parse(content).unwrap();
        assert_eq!(event.hostname, "www.atagar.com");
        assert_eq!(event.destination, None);
        assert_eq!(event.error, Some("yes".to_string()));
    }

    #[test]
    fn test_addrmap_event_cached_yes() {
        let content = r#"example.com 192.0.43.10 "2013-04-03 22:31:22" EXPIRES="2013-04-03 20:31:22" CACHED="YES""#;
        let event = AddrMapEvent::parse(content).unwrap();
        assert_eq!(event.hostname, "example.com");
        assert_eq!(event.cached, Some(true));
    }

    #[test]
    fn test_addrmap_event_cached_no() {
        let content = r#"example.com 192.0.43.10 "2013-04-03 22:29:11" EXPIRES="2013-04-03 20:29:11" CACHED="NO""#;
        let event = AddrMapEvent::parse(content).unwrap();
        assert_eq!(event.hostname, "example.com");
        assert_eq!(event.cached, Some(false));
    }

    #[test]
    fn test_build_timeout_set_event() {
        let content = "COMPUTED TOTAL_TIMES=124 TIMEOUT_MS=9019 XM=1375 ALPHA=0.855662 CUTOFF_QUANTILE=0.800000 TIMEOUT_RATE=0.137097 CLOSE_MS=21850 CLOSE_RATE=0.072581";
        let event = BuildTimeoutSetEvent::parse(content).unwrap();
        assert_eq!(event.set_type, TimeoutSetType::Computed);
        assert_eq!(event.total_times, Some(124));
        assert_eq!(event.timeout, Some(9019));
        assert_eq!(event.xm, Some(1375));
        assert!((event.alpha.unwrap() - 0.855662).abs() < 0.0001);
        assert!((event.quantile.unwrap() - 0.8).abs() < 0.0001);
        assert!((event.timeout_rate.unwrap() - 0.137097).abs() < 0.0001);
        assert_eq!(event.close_timeout, Some(21850));
        assert!((event.close_rate.unwrap() - 0.072581).abs() < 0.0001);
    }

    #[test]
    fn test_build_timeout_set_event_invalid_total_times() {
        let content = "COMPUTED TOTAL_TIMES=one_twenty_four TIMEOUT_MS=9019";
        assert!(BuildTimeoutSetEvent::parse(content).is_err());
    }

    #[test]
    fn test_build_timeout_set_event_invalid_quantile() {
        let content = "COMPUTED TOTAL_TIMES=124 CUTOFF_QUANTILE=zero_point_eight";
        assert!(BuildTimeoutSetEvent::parse(content).is_err());
    }

    #[test]
    fn test_guard_event_new() {
        let content = "ENTRY $36B5DBA788246E8369DBAF58577C6BC044A9A374 NEW";
        let event = GuardEvent::parse(content).unwrap();
        assert_eq!(event.guard_type, GuardType::Entry);
        assert_eq!(event.endpoint, "$36B5DBA788246E8369DBAF58577C6BC044A9A374");
        assert_eq!(
            event.endpoint_fingerprint,
            "36B5DBA788246E8369DBAF58577C6BC044A9A374"
        );
        assert_eq!(event.endpoint_nickname, None);
        assert_eq!(event.status, GuardStatus::New);
    }

    #[test]
    fn test_guard_event_good() {
        let content = "ENTRY $5D0034A368E0ABAF663D21847E1C9B6CFA09752A GOOD";
        let event = GuardEvent::parse(content).unwrap();
        assert_eq!(event.guard_type, GuardType::Entry);
        assert_eq!(
            event.endpoint_fingerprint,
            "5D0034A368E0ABAF663D21847E1C9B6CFA09752A"
        );
        assert_eq!(event.endpoint_nickname, None);
        assert_eq!(event.status, GuardStatus::Good);
    }

    #[test]
    fn test_guard_event_bad() {
        let content = "ENTRY $5D0034A368E0ABAF663D21847E1C9B6CFA09752A=caerSidi BAD";
        let event = GuardEvent::parse(content).unwrap();
        assert_eq!(
            event.endpoint_fingerprint,
            "5D0034A368E0ABAF663D21847E1C9B6CFA09752A"
        );
        assert_eq!(event.endpoint_nickname, Some("caerSidi".to_string()));
        assert_eq!(event.status, GuardStatus::Bad);
    }

    #[test]
    fn test_newdesc_event_single() {
        let content = "$B3FA3110CC6F42443F039220C134CBD2FC4F0493=Sakura";
        let event = NewDescEvent::parse(content).unwrap();
        assert_eq!(event.relays.len(), 1);
        assert_eq!(
            event.relays[0].0,
            "B3FA3110CC6F42443F039220C134CBD2FC4F0493"
        );
        assert_eq!(event.relays[0].1, Some("Sakura".to_string()));
    }

    #[test]
    fn test_newdesc_event_multiple() {
        let content = "$BE938957B2CA5F804B3AFC2C1EE6673170CDBBF8=Moonshine $B4BE08B22D4D2923EDC3970FD1B93D0448C6D8FF~Unnamed";
        let event = NewDescEvent::parse(content).unwrap();
        assert_eq!(event.relays.len(), 2);
        assert_eq!(
            event.relays[0].0,
            "BE938957B2CA5F804B3AFC2C1EE6673170CDBBF8"
        );
        assert_eq!(event.relays[0].1, Some("Moonshine".to_string()));
        assert_eq!(
            event.relays[1].0,
            "B4BE08B22D4D2923EDC3970FD1B93D0448C6D8FF"
        );
        assert_eq!(event.relays[1].1, Some("Unnamed".to_string()));
    }

    #[test]
    fn test_signal_event() {
        let event = SignalEvent::parse("DEBUG").unwrap();
        assert_eq!(event.signal, Signal::Debug);

        let event = SignalEvent::parse("DUMP").unwrap();
        assert_eq!(event.signal, Signal::Dump);
    }

    #[test]
    fn test_signal_event_all_signals() {
        assert_eq!(SignalEvent::parse("RELOAD").unwrap().signal, Signal::Reload);
        assert_eq!(SignalEvent::parse("HUP").unwrap().signal, Signal::Reload);
        assert_eq!(
            SignalEvent::parse("SHUTDOWN").unwrap().signal,
            Signal::Shutdown
        );
        assert_eq!(SignalEvent::parse("INT").unwrap().signal, Signal::Shutdown);
        assert_eq!(SignalEvent::parse("DUMP").unwrap().signal, Signal::Dump);
        assert_eq!(SignalEvent::parse("USR1").unwrap().signal, Signal::Dump);
        assert_eq!(SignalEvent::parse("DEBUG").unwrap().signal, Signal::Debug);
        assert_eq!(SignalEvent::parse("USR2").unwrap().signal, Signal::Debug);
        assert_eq!(SignalEvent::parse("HALT").unwrap().signal, Signal::Halt);
        assert_eq!(SignalEvent::parse("TERM").unwrap().signal, Signal::Halt);
        assert_eq!(SignalEvent::parse("NEWNYM").unwrap().signal, Signal::Newnym);
        assert_eq!(
            SignalEvent::parse("CLEARDNSCACHE").unwrap().signal,
            Signal::ClearDnsCache
        );
        assert_eq!(
            SignalEvent::parse("HEARTBEAT").unwrap().signal,
            Signal::Heartbeat
        );
        assert_eq!(SignalEvent::parse("ACTIVE").unwrap().signal, Signal::Active);
        assert_eq!(
            SignalEvent::parse("DORMANT").unwrap().signal,
            Signal::Dormant
        );
    }

    #[test]
    fn test_status_event() {
        let content = "NOTICE CONSENSUS_ARRIVED";
        let event = StatusEvent::parse(StatusType::General, content).unwrap();
        assert_eq!(event.status_type, StatusType::General);
        assert_eq!(event.runlevel, Runlevel::Notice);
        assert_eq!(event.action, "CONSENSUS_ARRIVED");
    }

    #[test]
    fn test_status_event_enough_dir_info() {
        let content = "NOTICE ENOUGH_DIR_INFO";
        let event = StatusEvent::parse(StatusType::Client, content).unwrap();
        assert_eq!(event.status_type, StatusType::Client);
        assert_eq!(event.runlevel, Runlevel::Notice);
        assert_eq!(event.action, "ENOUGH_DIR_INFO");
    }

    #[test]
    fn test_status_event_circuit_established() {
        let content = "NOTICE CIRCUIT_ESTABLISHED";
        let event = StatusEvent::parse(StatusType::Client, content).unwrap();
        assert_eq!(event.status_type, StatusType::Client);
        assert_eq!(event.runlevel, Runlevel::Notice);
        assert_eq!(event.action, "CIRCUIT_ESTABLISHED");
    }

    #[test]
    fn test_status_event_with_args() {
        let content = "NOTICE BOOTSTRAP PROGRESS=53 TAG=loading_descriptors SUMMARY=\"Loading relay descriptors\"";
        let event = StatusEvent::parse(StatusType::Client, content).unwrap();
        assert_eq!(event.status_type, StatusType::Client);
        assert_eq!(event.action, "BOOTSTRAP");
        assert_eq!(event.arguments.get("PROGRESS"), Some(&"53".to_string()));
        assert_eq!(
            event.arguments.get("TAG"),
            Some(&"loading_descriptors".to_string())
        );
        assert_eq!(
            event.arguments.get("SUMMARY"),
            Some(&"Loading relay descriptors".to_string())
        );
    }

    #[test]
    fn test_status_event_bootstrap_stuck() {
        let content = "WARN BOOTSTRAP PROGRESS=80 TAG=conn_or SUMMARY=\"Connecting to the Tor network\" WARNING=\"Network is unreachable\" REASON=NOROUTE COUNT=5 RECOMMENDATION=warn";
        let event = StatusEvent::parse(StatusType::Client, content).unwrap();
        assert_eq!(event.status_type, StatusType::Client);
        assert_eq!(event.runlevel, Runlevel::Warn);
        assert_eq!(event.action, "BOOTSTRAP");
        assert_eq!(event.arguments.get("PROGRESS"), Some(&"80".to_string()));
        assert_eq!(event.arguments.get("TAG"), Some(&"conn_or".to_string()));
        assert_eq!(
            event.arguments.get("WARNING"),
            Some(&"Network is unreachable".to_string())
        );
        assert_eq!(event.arguments.get("REASON"), Some(&"NOROUTE".to_string()));
        assert_eq!(event.arguments.get("COUNT"), Some(&"5".to_string()));
        assert_eq!(
            event.arguments.get("RECOMMENDATION"),
            Some(&"warn".to_string())
        );
    }

    #[test]
    fn test_status_event_bootstrap_done() {
        let content = "NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"";
        let event = StatusEvent::parse(StatusType::Client, content).unwrap();
        assert_eq!(event.arguments.get("PROGRESS"), Some(&"100".to_string()));
        assert_eq!(event.arguments.get("TAG"), Some(&"done".to_string()));
        assert_eq!(event.arguments.get("SUMMARY"), Some(&"Done".to_string()));
    }

    #[test]
    fn test_status_event_server_check_reachability() {
        let content = "NOTICE CHECKING_REACHABILITY ORADDRESS=71.35.143.230:9050";
        let event = StatusEvent::parse(StatusType::Server, content).unwrap();
        assert_eq!(event.status_type, StatusType::Server);
        assert_eq!(event.runlevel, Runlevel::Notice);
        assert_eq!(event.action, "CHECKING_REACHABILITY");
        assert_eq!(
            event.arguments.get("ORADDRESS"),
            Some(&"71.35.143.230:9050".to_string())
        );
    }

    #[test]
    fn test_status_event_dns_timeout() {
        let content =
            "NOTICE NAMESERVER_STATUS NS=205.171.3.25 STATUS=DOWN ERR=\"request timed out.\"";
        let event = StatusEvent::parse(StatusType::Server, content).unwrap();
        assert_eq!(event.action, "NAMESERVER_STATUS");
        assert_eq!(event.arguments.get("NS"), Some(&"205.171.3.25".to_string()));
        assert_eq!(event.arguments.get("STATUS"), Some(&"DOWN".to_string()));
        assert_eq!(
            event.arguments.get("ERR"),
            Some(&"request timed out.".to_string())
        );
    }

    #[test]
    fn test_status_event_dns_down() {
        let content = "WARN NAMESERVER_ALL_DOWN";
        let event = StatusEvent::parse(StatusType::Server, content).unwrap();
        assert_eq!(event.status_type, StatusType::Server);
        assert_eq!(event.runlevel, Runlevel::Warn);
        assert_eq!(event.action, "NAMESERVER_ALL_DOWN");
    }

    #[test]
    fn test_status_event_dns_up() {
        let content = "NOTICE NAMESERVER_STATUS NS=205.171.3.25 STATUS=UP";
        let event = StatusEvent::parse(StatusType::Server, content).unwrap();
        assert_eq!(event.action, "NAMESERVER_STATUS");
        assert_eq!(event.arguments.get("STATUS"), Some(&"UP".to_string()));
    }

    #[test]
    fn test_conf_changed_event() {
        let lines = vec![
            "ExitNodes=caerSidi".to_string(),
            "ExitPolicy".to_string(),
            "MaxCircuitDirtiness=20".to_string(),
        ];
        let event = ConfChangedEvent::parse(&lines).unwrap();
        assert_eq!(
            event.changed.get("ExitNodes"),
            Some(&vec!["caerSidi".to_string()])
        );
        assert_eq!(
            event.changed.get("MaxCircuitDirtiness"),
            Some(&vec!["20".to_string()])
        );
        assert_eq!(event.unset, vec!["ExitPolicy".to_string()]);
    }

    #[test]
    fn test_conf_changed_event_multiple_values() {
        let lines = vec![
            "ExitPolicy=accept 34.3.4.5".to_string(),
            "ExitPolicy=accept 3.4.53.3".to_string(),
            "MaxCircuitDirtiness=20".to_string(),
        ];
        let event = ConfChangedEvent::parse(&lines).unwrap();
        assert_eq!(
            event.changed.get("ExitPolicy"),
            Some(&vec![
                "accept 34.3.4.5".to_string(),
                "accept 3.4.53.3".to_string()
            ])
        );
        assert_eq!(
            event.changed.get("MaxCircuitDirtiness"),
            Some(&vec!["20".to_string()])
        );
        assert!(event.unset.is_empty());
    }

    #[test]
    fn test_network_liveness_event() {
        let event = NetworkLivenessEvent::parse("UP").unwrap();
        assert_eq!(event.status, "UP");

        let event = NetworkLivenessEvent::parse("DOWN").unwrap();
        assert_eq!(event.status, "DOWN");
    }

    #[test]
    fn test_network_liveness_event_other_status() {
        let event = NetworkLivenessEvent::parse("OTHER_STATUS key=value").unwrap();
        assert_eq!(event.status, "OTHER_STATUS");
    }

    #[test]
    fn test_circuit_bandwidth_event() {
        let content = "ID=11 READ=272 WRITTEN=817";
        let event = CircuitBandwidthEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "11");
        assert_eq!(event.read, 272);
        assert_eq!(event.written, 817);
        assert_eq!(event.time, None);
    }

    #[test]
    fn test_circuit_bandwidth_event_with_time() {
        let content = "ID=11 READ=272 WRITTEN=817 TIME=2012-12-06T13:51:11.433755";
        let event = CircuitBandwidthEvent::parse(content).unwrap();
        assert_eq!(event.id.0, "11");
        assert!(event.time.is_some());
    }

    #[test]
    fn test_circuit_bandwidth_event_invalid_written() {
        let content = "ID=11 READ=272 WRITTEN=817.7";
        assert!(CircuitBandwidthEvent::parse(content).is_err());
    }

    #[test]
    fn test_circuit_bandwidth_event_missing_id() {
        let content = "READ=272 WRITTEN=817";
        assert!(CircuitBandwidthEvent::parse(content).is_err());
    }

    #[test]
    fn test_connection_bandwidth_event() {
        let content = "ID=11 TYPE=DIR READ=272 WRITTEN=817";
        let event = ConnectionBandwidthEvent::parse(content).unwrap();
        assert_eq!(event.id, "11");
        assert_eq!(event.conn_type, ConnectionType::Dir);
        assert_eq!(event.read, 272);
        assert_eq!(event.written, 817);
    }

    #[test]
    fn test_connection_bandwidth_event_invalid_written() {
        let content = "ID=11 TYPE=DIR READ=272 WRITTEN=817.7";
        assert!(ConnectionBandwidthEvent::parse(content).is_err());
    }

    #[test]
    fn test_connection_bandwidth_event_missing_id() {
        let content = "TYPE=DIR READ=272 WRITTEN=817";
        assert!(ConnectionBandwidthEvent::parse(content).is_err());
    }

    #[test]
    fn test_hs_desc_event() {
        let content = "REQUESTED ajhb7kljbiru65qo NO_AUTH $67B2BDA4264D8A189D9270E28B1D30A262838243=europa1 b3oeducbhjmbqmgw2i3jtz4fekkrinwj";
        let event = HsDescEvent::parse(content).unwrap();
        assert_eq!(event.action, HsDescAction::Requested);
        assert_eq!(event.address, "ajhb7kljbiru65qo");
        assert_eq!(event.authentication, Some(HsAuth::NoAuth));
        assert_eq!(
            event.directory,
            Some("$67B2BDA4264D8A189D9270E28B1D30A262838243=europa1".to_string())
        );
        assert_eq!(
            event.directory_fingerprint,
            Some("67B2BDA4264D8A189D9270E28B1D30A262838243".to_string())
        );
        assert_eq!(event.directory_nickname, Some("europa1".to_string()));
        assert_eq!(
            event.descriptor_id,
            Some("b3oeducbhjmbqmgw2i3jtz4fekkrinwj".to_string())
        );
        assert_eq!(event.reason, None);
    }

    #[test]
    fn test_hs_desc_event_no_desc_id() {
        let content =
            "REQUESTED ajhb7kljbiru65qo NO_AUTH $67B2BDA4264D8A189D9270E28B1D30A262838243";
        let event = HsDescEvent::parse(content).unwrap();
        assert_eq!(
            event.directory,
            Some("$67B2BDA4264D8A189D9270E28B1D30A262838243".to_string())
        );
        assert_eq!(
            event.directory_fingerprint,
            Some("67B2BDA4264D8A189D9270E28B1D30A262838243".to_string())
        );
        assert_eq!(event.directory_nickname, None);
        assert_eq!(event.descriptor_id, None);
        assert_eq!(event.reason, None);
    }

    #[test]
    fn test_hs_desc_event_not_found() {
        let content = "REQUESTED ajhb7kljbiru65qo NO_AUTH UNKNOWN";
        let event = HsDescEvent::parse(content).unwrap();
        assert_eq!(event.directory, None);
        assert_eq!(event.directory_fingerprint, None);
        assert_eq!(event.directory_nickname, None);
        assert_eq!(event.descriptor_id, None);
        assert_eq!(event.reason, None);
    }

    #[test]
    fn test_hs_desc_event_failed() {
        let content = "FAILED ajhb7kljbiru65qo NO_AUTH $67B2BDA4264D8A189D9270E28B1D30A262838243 b3oeducbhjmbqmgw2i3jtz4fekkrinwj REASON=NOT_FOUND";
        let event = HsDescEvent::parse(content).unwrap();
        assert_eq!(event.action, HsDescAction::Failed);
        assert_eq!(event.address, "ajhb7kljbiru65qo");
        assert_eq!(event.authentication, Some(HsAuth::NoAuth));
        assert_eq!(
            event.directory,
            Some("$67B2BDA4264D8A189D9270E28B1D30A262838243".to_string())
        );
        assert_eq!(
            event.directory_fingerprint,
            Some("67B2BDA4264D8A189D9270E28B1D30A262838243".to_string())
        );
        assert_eq!(event.directory_nickname, None);
        assert_eq!(
            event.descriptor_id,
            Some("b3oeducbhjmbqmgw2i3jtz4fekkrinwj".to_string())
        );
        assert_eq!(event.reason, Some(HsDescReason::NotFound));
    }

    #[test]
    fn test_parsed_event_dispatch() {
        let event = ParsedEvent::parse("BW", "100 200", None).unwrap();
        match event {
            ParsedEvent::Bandwidth(bw) => {
                assert_eq!(bw.read, 100);
                assert_eq!(bw.written, 200);
            }
            _ => panic!("expected bandwidth event"),
        }

        let event = ParsedEvent::parse("CIRC", "1 BUILT", None).unwrap();
        match event {
            ParsedEvent::Circuit(circ) => {
                assert_eq!(circ.id.0, "1");
                assert_eq!(circ.status, CircStatus::Built);
            }
            _ => panic!("expected circuit event"),
        }
    }

    #[test]
    fn test_parsed_event_log_events() {
        let event = ParsedEvent::parse("DEBUG", "test debug message", None).unwrap();
        match event {
            ParsedEvent::Log(log) => {
                assert_eq!(log.runlevel, Runlevel::Debug);
                assert_eq!(log.message, "test debug message");
            }
            _ => panic!("expected log event"),
        }

        let event = ParsedEvent::parse("INFO", "test info message", None).unwrap();
        match event {
            ParsedEvent::Log(log) => {
                assert_eq!(log.runlevel, Runlevel::Info);
            }
            _ => panic!("expected log event"),
        }

        let event = ParsedEvent::parse("NOTICE", "test notice message", None).unwrap();
        match event {
            ParsedEvent::Log(log) => {
                assert_eq!(log.runlevel, Runlevel::Notice);
            }
            _ => panic!("expected log event"),
        }

        let event = ParsedEvent::parse("WARN", "test warn message", None).unwrap();
        match event {
            ParsedEvent::Log(log) => {
                assert_eq!(log.runlevel, Runlevel::Warn);
            }
            _ => panic!("expected log event"),
        }

        let event = ParsedEvent::parse("ERR", "test error message", None).unwrap();
        match event {
            ParsedEvent::Log(log) => {
                assert_eq!(log.runlevel, Runlevel::Err);
            }
            _ => panic!("expected log event"),
        }
    }

    #[test]
    fn test_parsed_event_status_events() {
        let event = ParsedEvent::parse("STATUS_GENERAL", "NOTICE CONSENSUS_ARRIVED", None).unwrap();
        match event {
            ParsedEvent::Status(status) => {
                assert_eq!(status.status_type, StatusType::General);
                assert_eq!(status.action, "CONSENSUS_ARRIVED");
            }
            _ => panic!("expected status event"),
        }

        let event = ParsedEvent::parse("STATUS_CLIENT", "NOTICE ENOUGH_DIR_INFO", None).unwrap();
        match event {
            ParsedEvent::Status(status) => {
                assert_eq!(status.status_type, StatusType::Client);
            }
            _ => panic!("expected status event"),
        }

        let event = ParsedEvent::parse(
            "STATUS_SERVER",
            "NOTICE CHECKING_REACHABILITY ORADDRESS=127.0.0.1:9050",
            None,
        )
        .unwrap();
        match event {
            ParsedEvent::Status(status) => {
                assert_eq!(status.status_type, StatusType::Server);
            }
            _ => panic!("expected status event"),
        }
    }

    #[test]
    fn test_parsed_event_unknown() {
        let event = ParsedEvent::parse("UNKNOWN_EVENT", "some content", None).unwrap();
        match event {
            ParsedEvent::Unknown {
                event_type,
                content,
            } => {
                assert_eq!(event_type, "UNKNOWN_EVENT");
                assert_eq!(content, "some content");
            }
            _ => panic!("expected unknown event"),
        }
    }

    #[test]
    fn test_parse_circuit_path() {
        let path = parse_circuit_path("$999A226EBED397F331B612FE1E4CFAE5C1F201BA=piyaz");
        assert_eq!(path.len(), 1);
        assert_eq!(path[0].0, "999A226EBED397F331B612FE1E4CFAE5C1F201BA");
        assert_eq!(path[0].1, Some("piyaz".to_string()));

        let path = parse_circuit_path(
            "$E57A476CD4DFBD99B4EE52A100A58610AD6E80B9,hamburgerphone,PrivacyRepublic14",
        );
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn test_parse_relay_endpoint() {
        let (fp, nick) = parse_relay_endpoint("$36B5DBA788246E8369DBAF58577C6BC044A9A374");
        assert_eq!(fp, "36B5DBA788246E8369DBAF58577C6BC044A9A374");
        assert_eq!(nick, None);

        let (fp, nick) = parse_relay_endpoint("$5D0034A368E0ABAF663D21847E1C9B6CFA09752A=caerSidi");
        assert_eq!(fp, "5D0034A368E0ABAF663D21847E1C9B6CFA09752A");
        assert_eq!(nick, Some("caerSidi".to_string()));

        let (fp, nick) = parse_relay_endpoint("$B4BE08B22D4D2923EDC3970FD1B93D0448C6D8FF~Unnamed");
        assert_eq!(fp, "B4BE08B22D4D2923EDC3970FD1B93D0448C6D8FF");
        assert_eq!(nick, Some("Unnamed".to_string()));
    }

    #[test]
    fn test_parse_target() {
        let (host, port) = parse_target("encrypted.google.com:443").unwrap();
        assert_eq!(host, "encrypted.google.com");
        assert_eq!(port, 443);

        let (host, port) = parse_target("74.125.227.129:443").unwrap();
        assert_eq!(host, "74.125.227.129");
        assert_eq!(port, 443);

        let (host, port) = parse_target("www.google.com:0").unwrap();
        assert_eq!(host, "www.google.com");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_parse_iso_timestamp() {
        let dt = parse_iso_timestamp("2012-11-08T16:48:38.417238").unwrap();
        assert_eq!(dt.year(), 2012);
        assert_eq!(dt.month(), 11);
        assert_eq!(dt.day(), 8);
        assert_eq!(dt.hour(), 16);
        assert_eq!(dt.minute(), 48);
        assert_eq!(dt.second(), 38);

        let dt = parse_iso_timestamp("2012-12-06T13:51:11.433755").unwrap();
        assert_eq!(dt.year(), 2012);
        assert_eq!(dt.month(), 12);
        assert_eq!(dt.day(), 6);
    }

    #[test]
    fn test_parse_build_flags() {
        let flags = parse_build_flags("NEED_CAPACITY");
        assert_eq!(flags, vec![CircBuildFlag::NeedCapacity]);

        let flags = parse_build_flags("IS_INTERNAL,NEED_CAPACITY");
        assert_eq!(
            flags,
            vec![CircBuildFlag::IsInternal, CircBuildFlag::NeedCapacity]
        );

        let flags = parse_build_flags("ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME");
        assert_eq!(
            flags,
            vec![
                CircBuildFlag::OneHopTunnel,
                CircBuildFlag::IsInternal,
                CircBuildFlag::NeedCapacity,
                CircBuildFlag::NeedUptime
            ]
        );
    }
}
