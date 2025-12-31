//! High-level controller API for Tor control protocol interaction.
//!
//! This module provides the primary interface for interacting with Tor's control
//! protocol. The [`Controller`] type wraps a [`ControlSocket`](crate::socket::ControlSocket)
//! and provides high-level methods for common operations like authentication,
//! circuit management, stream handling, and event subscription.
//!
//! # Overview
//!
//! The Controller is the main entry point for most stem-rs users. It handles:
//!
//! - **Connection Management**: Connect via TCP port or Unix domain socket
//! - **Authentication**: Automatic method detection and credential handling
//! - **Information Queries**: GETINFO commands for version, PID, circuit status, etc.
//! - **Configuration**: GETCONF/SETCONF/RESETCONF for Tor configuration
//! - **Circuit Control**: Create, extend, and close circuits
//! - **Stream Control**: Attach and close streams
//! - **Event Handling**: Subscribe to and receive asynchronous events
//! - **Hidden Services**: Create and manage ephemeral hidden services
//! - **Address Mapping**: Map addresses for custom routing
//!
//! # Conceptual Role
//!
//! The Controller sits between your application and Tor's control socket:
//!
//! ```text
//! ┌─────────────┐     ┌────────────┐     ┌─────────────┐
//! │ Application │ ──▶│ Controller │ ──▶│ Tor Process │
//! └─────────────┘     └────────────┘     └─────────────┘
//!                           │
//!                     Handles:
//!                     • Protocol formatting
//!                     • Response parsing
//!                     • Event buffering
//!                     • Error handling
//! ```
//!
//! # What This Module Does NOT Do
//!
//! - **Direct relay communication**: Use [`client::Relay`](crate::client::Relay) for ORPort connections
//! - **Descriptor parsing**: Use the [`descriptor`](crate::descriptor) module
//! - **Exit policy evaluation**: Use [`ExitPolicy`](crate::exit_policy::ExitPolicy)
//!
//! # Thread Safety
//!
//! [`Controller`] is `Send` but not `Sync`. The controller maintains internal
//! state (socket, event buffer) that requires exclusive access. For concurrent
//! access from multiple tasks, wrap in `Arc<Mutex<Controller>>`:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::sync::Mutex;
//! use stem_rs::controller::Controller;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! let shared = Arc::new(Mutex::new(controller));
//!
//! // Clone Arc for each task
//! let c1 = shared.clone();
//! tokio::spawn(async move {
//!     let mut ctrl = c1.lock().await;
//!     // Use controller...
//! });
//! # Ok(())
//! # }
//! ```
//!
//! # Example
//!
//! Basic usage pattern:
//!
//! ```rust,no_run
//! use stem_rs::controller::Controller;
//! use stem_rs::Signal;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! // Connect to Tor's control port
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//!
//! // Authenticate (auto-detects method)
//! controller.authenticate(None).await?;
//!
//! // Query information
//! let version = controller.get_version().await?;
//! println!("Connected to Tor {}", version);
//!
//! // Get active circuits
//! let circuits = controller.get_circuits().await?;
//! for circuit in circuits {
//!     println!("Circuit {}: {:?}", circuit.id, circuit.status);
//! }
//!
//! // Request new identity
//! controller.signal(Signal::Newnym).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! - Passwords are not stored after authentication
//! - Cookie files are read with minimal permissions
//! - SAFECOOKIE authentication uses secure random nonces
//! - Input is validated to prevent protocol injection attacks
//!
//! # See Also
//!
//! - [`socket`](crate::socket): Low-level socket communication
//! - [`auth`](crate::auth): Authentication implementation details
//! - [`events`](crate::events): Event types for subscription
//! - Python Stem's `Controller` class for equivalent functionality

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

use crate::auth;
use crate::events::ParsedEvent;
use crate::protocol::ControlLine;
use crate::socket::{ControlMessage, ControlSocket};
use crate::version::Version;
use crate::{CircStatus, Error, EventType, Signal, StreamStatus};

/// A unique identifier for a Tor circuit.
///
/// Circuit IDs are assigned by Tor when circuits are created and are used
/// to reference specific circuits in control protocol commands. The ID is
/// a string representation of a numeric identifier.
///
/// # Invariants
///
/// - Circuit IDs are unique within a Tor session
/// - IDs are assigned sequentially by Tor
/// - An ID remains valid until the circuit is closed
///
/// # Example
///
/// ```rust
/// use stem_rs::controller::CircuitId;
///
/// let id = CircuitId::new("42");
/// assert_eq!(id.to_string(), "42");
///
/// // CircuitIds can be compared for equality
/// let id2 = CircuitId::new("42");
/// assert_eq!(id, id2);
/// ```
///
/// # See Also
///
/// - [`Controller::get_circuits`]: Retrieve active circuits
/// - [`Controller::new_circuit`]: Create a new circuit
/// - [`Controller::close_circuit`]: Close a circuit by ID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CircuitId(pub String);

impl CircuitId {
    /// Creates a new circuit ID from any string-like value.
    ///
    /// # Arguments
    ///
    /// * `id` - The circuit identifier, typically a numeric string
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::controller::CircuitId;
    ///
    /// let id = CircuitId::new("123");
    /// let id_from_string = CircuitId::new(String::from("123"));
    /// assert_eq!(id, id_from_string);
    /// ```
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for CircuitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A unique identifier for a Tor stream.
///
/// Stream IDs are assigned by Tor when streams are created and are used
/// to reference specific streams in control protocol commands. Streams
/// represent individual TCP connections being routed through Tor circuits.
///
/// # Invariants
///
/// - Stream IDs are unique within a Tor session
/// - IDs are assigned sequentially by Tor
/// - An ID remains valid until the stream is closed
///
/// # Example
///
/// ```rust
/// use stem_rs::controller::StreamId;
///
/// let id = StreamId::new("99");
/// assert_eq!(id.to_string(), "99");
///
/// // StreamIds can be compared for equality
/// let id2 = StreamId::new("99");
/// assert_eq!(id, id2);
/// ```
///
/// # See Also
///
/// - [`Controller::get_streams`]: Retrieve active streams
/// - [`Controller::attach_stream`]: Attach a stream to a circuit
/// - [`Controller::close_stream`]: Close a stream by ID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamId(pub String);

impl StreamId {
    /// Creates a new stream ID from any string-like value.
    ///
    /// # Arguments
    ///
    /// * `id` - The stream identifier, typically a numeric string
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::controller::StreamId;
    ///
    /// let id = StreamId::new("456");
    /// let id_from_string = StreamId::new(String::from("456"));
    /// assert_eq!(id, id_from_string);
    /// ```
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Information about a relay in a circuit path.
///
/// Each hop in a Tor circuit is represented by a `RelayInfo` containing
/// the relay's fingerprint and optionally its nickname. The fingerprint
/// is a 40-character hexadecimal string representing the SHA-1 hash of
/// the relay's identity key.
///
/// # Fields
///
/// - `fingerprint`: The relay's identity fingerprint (40 hex characters)
/// - `nickname`: The relay's optional human-readable nickname
///
/// # Example
///
/// ```rust
/// use stem_rs::controller::RelayInfo;
///
/// let relay = RelayInfo {
///     fingerprint: "9695DFC35FFEB861329B9F1AB04C46397020CE31".to_string(),
///     nickname: Some("MyRelay".to_string()),
/// };
///
/// println!("Relay: {} ({:?})", relay.fingerprint, relay.nickname);
/// ```
///
/// # See Also
///
/// - [`Circuit`]: Contains a path of `RelayInfo` entries
/// - [`util::is_valid_fingerprint`](crate::util::is_valid_fingerprint): Validate fingerprint format
#[derive(Debug, Clone)]
pub struct RelayInfo {
    /// The relay's identity fingerprint (40 hexadecimal characters).
    ///
    /// This is the SHA-1 hash of the relay's identity key, used to uniquely
    /// identify relays across the Tor network.
    pub fingerprint: String,

    /// The relay's optional human-readable nickname.
    ///
    /// Nicknames are chosen by relay operators and are not guaranteed to be
    /// unique. May be `None` if the nickname was not provided in the circuit
    /// status response.
    pub nickname: Option<String>,
}

/// Information about an active Tor circuit.
///
/// A circuit is a path through the Tor network consisting of multiple
/// relay hops. Circuits are used to route traffic anonymously by encrypting
/// data in layers that are peeled off at each hop.
///
/// # Circuit Lifecycle
///
/// Circuits progress through several states:
///
/// 1. **Launched**: Circuit creation has begun
/// 2. **Extended**: Circuit is being extended to additional hops
/// 3. **Built**: Circuit is fully constructed and ready for use
/// 4. **Failed**: Circuit construction failed
/// 5. **Closed**: Circuit has been closed
///
/// # Fields
///
/// - `id`: Unique identifier for this circuit
/// - `status`: Current state of the circuit
/// - `path`: Ordered list of relays in the circuit (guard → middle → exit)
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::controller::Controller;
/// use stem_rs::CircStatus;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
/// controller.authenticate(None).await?;
///
/// for circuit in controller.get_circuits().await? {
///     if circuit.status == CircStatus::Built {
///         println!("Circuit {} has {} hops:", circuit.id, circuit.path.len());
///         for (i, relay) in circuit.path.iter().enumerate() {
///             println!("  Hop {}: {} ({:?})", i + 1, relay.fingerprint, relay.nickname);
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`Controller::get_circuits`]: Retrieve all active circuits
/// - [`Controller::new_circuit`]: Create a new circuit
/// - [`CircStatus`](crate::CircStatus): Circuit status enumeration
#[derive(Debug, Clone)]
pub struct Circuit {
    /// Unique identifier for this circuit.
    pub id: CircuitId,

    /// Current status of the circuit.
    ///
    /// See [`CircStatus`](crate::CircStatus) for possible values.
    pub status: CircStatus,

    /// Ordered list of relays in the circuit path.
    ///
    /// The first relay is the guard (entry) node, and the last relay is
    /// typically the exit node. The path may be empty for newly launched
    /// circuits that haven't yet established any hops.
    pub path: Vec<RelayInfo>,
}

/// Information about an active Tor stream.
///
/// A stream represents a single TCP connection being routed through a Tor
/// circuit. Streams are created when applications connect through Tor's
/// SOCKS proxy and are attached to circuits for routing.
///
/// # Stream Lifecycle
///
/// Streams progress through several states:
///
/// 1. **New**: Stream created, awaiting circuit attachment
/// 2. **SentConnect**: CONNECT command sent to exit relay
/// 3. **Succeeded**: Connection established successfully
/// 4. **Failed**: Connection attempt failed
/// 5. **Closed**: Stream has been closed
///
/// # Fields
///
/// - `id`: Unique identifier for this stream
/// - `status`: Current state of the stream
/// - `circuit_id`: The circuit this stream is attached to (if any)
/// - `target_host`: Destination hostname or IP address
/// - `target_port`: Destination port number
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::controller::Controller;
/// use stem_rs::StreamStatus;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
/// controller.authenticate(None).await?;
///
/// for stream in controller.get_streams().await? {
///     println!("Stream {} -> {}:{} ({:?})",
///         stream.id,
///         stream.target_host,
///         stream.target_port,
///         stream.status
///     );
///     if let Some(ref circuit_id) = stream.circuit_id {
///         println!("  Attached to circuit {}", circuit_id);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`Controller::get_streams`]: Retrieve all active streams
/// - [`Controller::attach_stream`]: Attach a stream to a circuit
/// - [`StreamStatus`](crate::StreamStatus): Stream status enumeration
#[derive(Debug, Clone)]
pub struct Stream {
    /// Unique identifier for this stream.
    pub id: StreamId,

    /// Current status of the stream.
    ///
    /// See [`StreamStatus`](crate::StreamStatus) for possible values.
    pub status: StreamStatus,

    /// The circuit this stream is attached to, if any.
    ///
    /// Streams in the `New` or `Detached` state may not be attached to
    /// any circuit. Once attached, this field contains the circuit ID.
    pub circuit_id: Option<CircuitId>,

    /// Destination hostname or IP address.
    ///
    /// This is the target the stream is connecting to through Tor.
    pub target_host: String,

    /// Destination port number.
    ///
    /// The TCP port on the target host. May be 0 if not specified.
    pub target_port: u16,
}

/// A high-level interface for interacting with Tor's control protocol.
///
/// The `Controller` provides the primary API for controlling a Tor process.
/// It wraps a [`ControlSocket`](crate::socket::ControlSocket) and provides
/// typed methods for common operations like authentication, circuit management,
/// and event subscription.
///
/// # Conceptual Role
///
/// The Controller is the main entry point for most stem-rs users. It handles:
///
/// - Protocol message formatting and parsing
/// - Response validation and error handling
/// - Asynchronous event buffering
/// - Connection lifecycle management
///
/// # What This Type Does NOT Do
///
/// - Direct relay communication (use [`client::Relay`](crate::client::Relay))
/// - Descriptor parsing (use [`descriptor`](crate::descriptor) module)
/// - Exit policy evaluation (use [`ExitPolicy`](crate::exit_policy::ExitPolicy))
///
/// # Invariants
///
/// - The underlying socket connection is valid while the Controller exists
/// - After successful authentication, the controller is ready for commands
/// - Events received during command execution are buffered for later retrieval
///
/// # Thread Safety
///
/// `Controller` is `Send` but not `Sync`. For concurrent access from multiple
/// tasks, wrap in `Arc<Mutex<Controller>>`:
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use tokio::sync::Mutex;
/// use stem_rs::controller::Controller;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
/// let shared = Arc::new(Mutex::new(controller));
///
/// // Clone Arc for each task
/// let c1 = shared.clone();
/// tokio::spawn(async move {
///     let mut ctrl = c1.lock().await;
///     // Use controller...
/// });
/// # Ok(())
/// # }
/// ```
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::controller::Controller;
/// use stem_rs::Signal;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// // Connect and authenticate
/// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
/// controller.authenticate(Some("my_password")).await?;
///
/// // Query information
/// let version = controller.get_version().await?;
/// let circuits = controller.get_circuits().await?;
///
/// // Send signal
/// controller.signal(Signal::Newnym).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Passwords are not stored after authentication
/// - Cookie files are read with minimal permissions
/// - SAFECOOKIE uses secure random nonces
///
/// # See Also
///
/// - [`from_port`](Controller::from_port): Connect via TCP
/// - [`from_socket_file`](Controller::from_socket_file): Connect via Unix socket
/// - [`authenticate`](Controller::authenticate): Authenticate with Tor
pub struct Controller {
    /// The underlying control socket connection.
    socket: ControlSocket,
    /// Buffer for asynchronous events received during command execution.
    event_buffer: Vec<ControlMessage>,
}

impl Controller {
    /// Creates a new Controller connected to a TCP control port.
    ///
    /// Establishes a TCP connection to Tor's control port at the specified
    /// address. The connection is unauthenticated; call [`authenticate`](Self::authenticate)
    /// before issuing commands.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address of Tor's control port (e.g., `127.0.0.1:9051`)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Socket`](crate::Error::Socket) if:
    /// - The connection is refused (Tor not running or port incorrect)
    /// - Network is unreachable
    /// - Connection times out
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// // Connect to default control port
    /// let controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    ///
    /// // Connect to custom port
    /// let controller = Controller::from_port("127.0.0.1:9151".parse()?).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`from_socket_file`](Self::from_socket_file): Connect via Unix socket
    /// - [`authenticate`](Self::authenticate): Authenticate after connecting
    pub async fn from_port(addr: SocketAddr) -> Result<Self, Error> {
        let socket = ControlSocket::connect_port(addr).await?;
        Ok(Self {
            socket,
            event_buffer: Vec::new(),
        })
    }

    /// Creates a new Controller connected to a Unix domain socket.
    ///
    /// Establishes a connection to Tor's control socket at the specified
    /// file path. This is typically more secure than TCP as it doesn't
    /// expose the control interface to the network.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to Tor's control socket file (e.g., `/var/run/tor/control`)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Socket`](crate::Error::Socket) if:
    /// - The socket file doesn't exist
    /// - Permission denied accessing the socket
    /// - The socket is not a valid Unix domain socket
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::path::Path;
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// // Connect to Tor's Unix control socket
    /// let controller = Controller::from_socket_file(
    ///     Path::new("/var/run/tor/control")
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Platform Support
    ///
    /// Unix domain sockets are only available on Unix-like systems (Linux, macOS, BSD).
    /// On Windows, use [`from_port`](Self::from_port) instead.
    ///
    /// # See Also
    ///
    /// - [`from_port`](Self::from_port): Connect via TCP
    /// - [`authenticate`](Self::authenticate): Authenticate after connecting
    pub async fn from_socket_file(path: &Path) -> Result<Self, Error> {
        let socket = ControlSocket::connect_unix(path).await?;
        Ok(Self {
            socket,
            event_buffer: Vec::new(),
        })
    }

    /// Receives a response, buffering any asynchronous events.
    ///
    /// This internal method reads responses from the socket, automatically
    /// buffering any asynchronous events (status code 650) that arrive
    /// while waiting for a command response.
    async fn recv_response(&mut self) -> Result<ControlMessage, Error> {
        loop {
            let response = self.socket.recv().await?;
            if response.status_code == 650 {
                self.event_buffer.push(response);
            } else {
                return Ok(response);
            }
        }
    }

    /// Authenticates with the Tor control interface.
    ///
    /// Attempts authentication using the best available method. If `password`
    /// is provided, PASSWORD authentication is attempted. Otherwise, the method
    /// is auto-detected from PROTOCOLINFO.
    ///
    /// # Authentication Methods
    ///
    /// Methods are tried in this order:
    /// 1. **NONE** - If control port is open (no auth required)
    /// 2. **SAFECOOKIE** - Preferred for local connections
    /// 3. **COOKIE** - Fallback for older Tor versions
    /// 4. **PASSWORD** - If password is provided
    ///
    /// # Arguments
    ///
    /// * `password` - Optional password for PASSWORD authentication
    ///
    /// # Preconditions
    ///
    /// - Socket must be connected (not closed)
    /// - No prior successful authentication on this connection
    ///
    /// # Postconditions
    ///
    /// - On success: Controller is authenticated and ready for commands
    /// - On failure: Connection state is undefined; reconnect recommended
    ///
    /// # Errors
    ///
    /// Returns [`Error::Authentication`](crate::Error::Authentication) with specific reason:
    ///
    /// - [`AuthError::NoMethods`](crate::AuthError::NoMethods) - No compatible auth methods available
    /// - [`AuthError::IncorrectPassword`](crate::AuthError::IncorrectPassword) - PASSWORD auth failed
    /// - [`AuthError::CookieUnreadable`](crate::AuthError::CookieUnreadable) - Cannot read cookie file
    /// - [`AuthError::IncorrectCookie`](crate::AuthError::IncorrectCookie) - COOKIE auth failed
    /// - [`AuthError::ChallengeFailed`](crate::AuthError::ChallengeFailed) - SAFECOOKIE challenge failed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    ///
    /// // Auto-detect authentication method
    /// controller.authenticate(None).await?;
    ///
    /// // Or use password authentication
    /// controller.authenticate(Some("my_password")).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security
    ///
    /// - Passwords are cleared from memory after use
    /// - Cookie comparison uses constant-time algorithm
    /// - SAFECOOKIE nonces are cryptographically random
    ///
    /// # See Also
    ///
    /// - [`auth`](crate::auth): Authentication implementation details
    /// - [`AuthError`](crate::AuthError): Authentication error types
    pub async fn authenticate(&mut self, password: Option<&str>) -> Result<(), Error> {
        auth::authenticate(&mut self.socket, password).await
    }

    /// Queries Tor for information using the GETINFO command.
    ///
    /// GETINFO retrieves various pieces of information from Tor. The available
    /// keys depend on Tor's version and configuration.
    ///
    /// # Arguments
    ///
    /// * `key` - The information key to query (e.g., "version", "circuit-status")
    ///
    /// # Common Keys
    ///
    /// | Key | Description |
    /// |-----|-------------|
    /// | `version` | Tor version string |
    /// | `process/pid` | Tor process ID |
    /// | `circuit-status` | Active circuit information |
    /// | `stream-status` | Active stream information |
    /// | `address` | Best guess at external IP address |
    /// | `fingerprint` | Relay fingerprint (if running as relay) |
    /// | `config-file` | Path to torrc file |
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - The key is unrecognized
    /// - The information is not available
    /// - Tor returns an error response
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Query Tor version
    /// let version = controller.get_info("version").await?;
    /// println!("Tor version: {}", version);
    ///
    /// // Query external IP address
    /// let address = controller.get_info("address").await?;
    /// println!("External IP: {}", address);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`get_version`](Self::get_version): Typed version query
    /// - [`get_pid`](Self::get_pid): Typed PID query
    pub async fn get_info(&mut self, key: &str) -> Result<String, Error> {
        let command = format!("GETINFO {}", key);
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if !response.is_ok() {
            return Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            });
        }

        for line in &response.lines {
            if let Some(rest) = line.strip_prefix(&format!("{}=", key)) {
                return Ok(rest.to_string());
            }
            if line.starts_with(&format!("{}\n", key)) {
                return Ok(line
                    .strip_prefix(&format!("{}\n", key))
                    .unwrap_or("")
                    .to_string());
            }
        }

        Ok(response.content().to_string())
    }

    /// Retrieves the Tor version as a parsed [`Version`] object.
    ///
    /// This is a convenience wrapper around [`get_info("version")`](Self::get_info)
    /// that parses the version string into a structured [`Version`] type.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The GETINFO command fails
    /// - The version string cannot be parsed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// let version = controller.get_version().await?;
    /// println!("Tor version: {}", version);
    ///
    /// // Version supports comparison
    /// // if version >= Version::parse("0.4.0.0")? { ... }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`Version`](crate::version::Version): Version type with comparison support
    pub async fn get_version(&mut self) -> Result<Version, Error> {
        let version_str = self.get_info("version").await?;
        Version::parse(&version_str)
    }

    /// Retrieves the process ID of the Tor process.
    ///
    /// This is a convenience wrapper around [`get_info("process/pid")`](Self::get_info)
    /// that parses the PID into a `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The GETINFO command fails
    /// - The PID string cannot be parsed as a number
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// let pid = controller.get_pid().await?;
    /// println!("Tor PID: {}", pid);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_pid(&mut self) -> Result<u32, Error> {
        let pid_str = self.get_info("process/pid").await?;
        pid_str.parse().map_err(|_| Error::Parse {
            location: "pid".to_string(),
            reason: format!("invalid pid: {}", pid_str),
        })
    }

    /// Retrieves the value(s) of a Tor configuration option.
    ///
    /// Uses the GETCONF command to query Tor's current configuration.
    /// Some options can have multiple values, so this returns a `Vec<String>`.
    ///
    /// # Arguments
    ///
    /// * `key` - The configuration option name (e.g., "SocksPort", "ExitPolicy")
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - The configuration option is unrecognized
    /// - Tor returns an error response
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Get SOCKS port configuration
    /// let socks_ports = controller.get_conf("SocksPort").await?;
    /// for port in socks_ports {
    ///     println!("SOCKS port: {}", port);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`set_conf`](Self::set_conf): Set a configuration option
    /// - [`reset_conf`](Self::reset_conf): Reset to default value
    pub async fn get_conf(&mut self, key: &str) -> Result<Vec<String>, Error> {
        let command = format!("GETCONF {}", key);
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if !response.is_ok() {
            return Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            });
        }

        let mut values = Vec::new();
        for line in &response.lines {
            if let Some(rest) = line.strip_prefix(&format!("{}=", key)) {
                values.push(rest.to_string());
            } else if line
                .to_lowercase()
                .starts_with(&format!("{}=", key.to_lowercase()))
            {
                let eq_pos = line.find('=').unwrap_or(line.len());
                values.push(line[eq_pos + 1..].to_string());
            }
        }

        if values.is_empty() && !response.lines.is_empty() {
            let first_line = &response.lines[0];
            if let Some(eq_pos) = first_line.find('=') {
                values.push(first_line[eq_pos + 1..].to_string());
            }
        }

        Ok(values)
    }

    /// Sets a Tor configuration option.
    ///
    /// Uses the SETCONF command to change Tor's configuration at runtime.
    /// The change takes effect immediately but is not persisted to the torrc
    /// file unless you call `save_conf`.
    ///
    /// # Arguments
    ///
    /// * `key` - The configuration option name
    /// * `value` - The new value for the option
    ///
    /// # Value Escaping
    ///
    /// Values containing spaces or quotes are automatically escaped. You don't
    /// need to handle quoting yourself.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - The configuration option is unrecognized
    /// - The value is invalid for this option
    /// - The option cannot be changed at runtime
    /// - Tor returns an error response
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Change bandwidth rate
    /// controller.set_conf("BandwidthRate", "1 MB").await?;
    ///
    /// // Enable a feature
    /// controller.set_conf("SafeLogging", "1").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`get_conf`](Self::get_conf): Get current configuration
    /// - [`reset_conf`](Self::reset_conf): Reset to default value
    pub async fn set_conf(&mut self, key: &str, value: &str) -> Result<(), Error> {
        let command = if value.contains(' ') || value.contains('"') {
            format!(
                "SETCONF {}=\"{}\"",
                key,
                value.replace('\\', "\\\\").replace('"', "\\\"")
            )
        } else {
            format!("SETCONF {}={}", key, value)
        };
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if response.is_ok() {
            Ok(())
        } else {
            Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            })
        }
    }

    /// Resets a Tor configuration option to its default value.
    ///
    /// Uses the RESETCONF command to restore a configuration option to its
    /// default value as if it were not set in the torrc file.
    ///
    /// # Arguments
    ///
    /// * `key` - The configuration option name to reset
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - The configuration option is unrecognized
    /// - The option cannot be reset at runtime
    /// - Tor returns an error response
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Reset bandwidth rate to default
    /// controller.reset_conf("BandwidthRate").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`get_conf`](Self::get_conf): Get current configuration
    /// - [`set_conf`](Self::set_conf): Set a configuration option
    pub async fn reset_conf(&mut self, key: &str) -> Result<(), Error> {
        let command = format!("RESETCONF {}", key);
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if response.is_ok() {
            Ok(())
        } else {
            Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            })
        }
    }

    /// Sends a signal to the Tor process.
    ///
    /// Signals control various aspects of Tor's behavior, from requesting
    /// new circuits to initiating shutdown.
    ///
    /// # Arguments
    ///
    /// * `signal` - The signal to send (see [`Signal`](crate::Signal))
    ///
    /// # Available Signals
    ///
    /// | Signal | Description |
    /// |--------|-------------|
    /// | [`Reload`](crate::Signal::Reload) | Reload configuration (SIGHUP) |
    /// | [`Shutdown`](crate::Signal::Shutdown) | Controlled shutdown |
    /// | [`Dump`](crate::Signal::Dump) | Write statistics to disk |
    /// | [`Debug`](crate::Signal::Debug) | Switch to debug logging |
    /// | [`Halt`](crate::Signal::Halt) | Immediate shutdown (SIGTERM) |
    /// | [`Newnym`](crate::Signal::Newnym) | Request new circuits |
    /// | [`ClearDnsCache`](crate::Signal::ClearDnsCache) | Clear DNS cache |
    /// | [`Heartbeat`](crate::Signal::Heartbeat) | Trigger heartbeat log |
    /// | [`Active`](crate::Signal::Active) | Wake from dormant mode |
    /// | [`Dormant`](crate::Signal::Dormant) | Enter dormant mode |
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - The signal is not recognized
    /// - The signal cannot be sent (e.g., rate-limited NEWNYM)
    /// - Tor returns an error response
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    /// use stem_rs::Signal;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Request new identity (new circuits)
    /// controller.signal(Signal::Newnym).await?;
    ///
    /// // Reload configuration
    /// controller.signal(Signal::Reload).await?;
    ///
    /// // Clear DNS cache
    /// controller.signal(Signal::ClearDnsCache).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Rate Limiting
    ///
    /// The `Newnym` signal is rate-limited by Tor to prevent abuse. If called
    /// too frequently, Tor may delay the signal or return an error.
    ///
    /// # See Also
    ///
    /// - [`Signal`](crate::Signal): Signal enumeration
    pub async fn signal(&mut self, signal: Signal) -> Result<(), Error> {
        let command = format!("SIGNAL {}", signal);
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if response.is_ok() {
            Ok(())
        } else {
            Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            })
        }
    }

    /// Retrieves information about all active circuits.
    ///
    /// Returns a list of all circuits currently known to Tor, including
    /// their status and path information.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The GETINFO command fails
    /// - The circuit status cannot be parsed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    /// use stem_rs::CircStatus;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// let circuits = controller.get_circuits().await?;
    /// for circuit in circuits {
    ///     if circuit.status == CircStatus::Built {
    ///         println!("Circuit {} is ready with {} hops",
    ///             circuit.id, circuit.path.len());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`Circuit`]: Circuit information structure
    /// - [`new_circuit`](Self::new_circuit): Create a new circuit
    /// - [`close_circuit`](Self::close_circuit): Close a circuit
    pub async fn get_circuits(&mut self) -> Result<Vec<Circuit>, Error> {
        let response_str = self.get_info("circuit-status").await?;
        parse_circuits(&response_str)
    }

    /// Creates a new circuit, optionally with a specified path.
    ///
    /// If no path is specified, Tor will select relays automatically based
    /// on its path selection algorithm. If a path is provided, Tor will
    /// attempt to build a circuit through those specific relays.
    ///
    /// # Arguments
    ///
    /// * `path` - Optional list of relay fingerprints or nicknames for the circuit path
    ///
    /// # Path Specification
    ///
    /// Relays can be specified by:
    /// - Fingerprint: `$9695DFC35FFEB861329B9F1AB04C46397020CE31`
    /// - Nickname: `MyRelay`
    /// - Fingerprint with nickname: `$9695DFC35FFEB861329B9F1AB04C46397020CE31~MyRelay`
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - A specified relay is unknown or unavailable
    /// - The path is invalid (e.g., too short)
    /// - Circuit creation fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Create circuit with automatic path selection
    /// let circuit_id = controller.new_circuit(None).await?;
    /// println!("Created circuit: {}", circuit_id);
    ///
    /// // Create circuit with specific path
    /// let path = &["$AAAA...", "$BBBB...", "$CCCC..."];
    /// let circuit_id = controller.new_circuit(Some(path)).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`extend_circuit`](Self::extend_circuit): Extend an existing circuit
    /// - [`close_circuit`](Self::close_circuit): Close a circuit
    /// - [`get_circuits`](Self::get_circuits): List active circuits
    pub async fn new_circuit(&mut self, path: Option<&[&str]>) -> Result<CircuitId, Error> {
        let command = match path {
            Some(relays) if !relays.is_empty() => {
                format!("EXTENDCIRCUIT 0 {}", relays.join(","))
            }
            _ => "EXTENDCIRCUIT 0".to_string(),
        };
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if !response.is_ok() {
            return Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            });
        }

        let content = response.content();
        let mut line = ControlLine::new(content);
        if line.is_next_mapping(Some("EXTENDED"), false) {
            let (_, circuit_id) = line.pop_mapping(false, false)?;
            return Ok(CircuitId::new(circuit_id));
        }

        let circuit_id = line.pop(false, false)?;
        Ok(CircuitId::new(circuit_id))
    }

    /// Extends an existing circuit by adding additional hops.
    ///
    /// Adds one or more relays to an existing circuit. The circuit must be
    /// in a state that allows extension (typically BUILT or EXTENDED).
    ///
    /// # Arguments
    ///
    /// * `id` - The circuit ID to extend
    /// * `path` - List of relay fingerprints or nicknames to add
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArguments`](crate::Error::InvalidArguments) if:
    /// - The path is empty
    ///
    /// Returns [`Error::CircuitExtensionFailed`](crate::Error::CircuitExtensionFailed) if:
    /// - The circuit doesn't exist
    /// - The circuit is in a state that doesn't allow extension
    /// - A specified relay is unknown or unavailable
    /// - The extension fails for any other reason
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Create a circuit and extend it
    /// let circuit_id = controller.new_circuit(None).await?;
    /// controller.extend_circuit(&circuit_id, &["$DDDD..."]).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`new_circuit`](Self::new_circuit): Create a new circuit
    /// - [`close_circuit`](Self::close_circuit): Close a circuit
    pub async fn extend_circuit(&mut self, id: &CircuitId, path: &[&str]) -> Result<(), Error> {
        if path.is_empty() {
            return Err(Error::InvalidArguments("path cannot be empty".to_string()));
        }
        let command = format!("EXTENDCIRCUIT {} {}", id.0, path.join(","));
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if response.is_ok() {
            Ok(())
        } else {
            Err(Error::CircuitExtensionFailed(
                response.content().to_string(),
            ))
        }
    }

    /// Closes an existing circuit.
    ///
    /// Tears down the specified circuit, closing all streams attached to it.
    ///
    /// # Arguments
    ///
    /// * `id` - The circuit ID to close
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - The circuit doesn't exist
    /// - The circuit is already closed
    /// - Tor returns an error response
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Create and then close a circuit
    /// let circuit_id = controller.new_circuit(None).await?;
    /// controller.close_circuit(&circuit_id).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`new_circuit`](Self::new_circuit): Create a new circuit
    /// - [`get_circuits`](Self::get_circuits): List active circuits
    pub async fn close_circuit(&mut self, id: &CircuitId) -> Result<(), Error> {
        let command = format!("CLOSECIRCUIT {}", id.0);
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if response.is_ok() {
            Ok(())
        } else {
            Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            })
        }
    }

    /// Retrieves information about all active streams.
    ///
    /// Returns a list of all streams currently known to Tor, including
    /// their status, target, and circuit attachment.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The GETINFO command fails
    /// - The stream status cannot be parsed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    /// use stem_rs::StreamStatus;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// let streams = controller.get_streams().await?;
    /// for stream in streams {
    ///     println!("Stream {} -> {}:{} ({:?})",
    ///         stream.id, stream.target_host, stream.target_port, stream.status);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`Stream`]: Stream information structure
    /// - [`attach_stream`](Self::attach_stream): Attach a stream to a circuit
    /// - [`close_stream`](Self::close_stream): Close a stream
    pub async fn get_streams(&mut self) -> Result<Vec<Stream>, Error> {
        let response_str = self.get_info("stream-status").await?;
        parse_streams(&response_str)
    }

    /// Attaches a stream to a specific circuit.
    ///
    /// Manually attaches a stream to a circuit. This is typically used when
    /// you want to control which circuit a stream uses, rather than letting
    /// Tor choose automatically.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream to attach
    /// * `circuit_id` - The circuit to attach the stream to
    ///
    /// # Preconditions
    ///
    /// - The stream must be in a state that allows attachment (typically NEW)
    /// - The circuit must be BUILT
    /// - The circuit's exit policy must allow the stream's target
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - The stream doesn't exist
    /// - The circuit doesn't exist
    /// - The stream is not in an attachable state
    /// - The circuit cannot handle the stream's target
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::{Controller, CircuitId, StreamId};
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Attach stream 1 to circuit 5
    /// let stream_id = StreamId::new("1");
    /// let circuit_id = CircuitId::new("5");
    /// controller.attach_stream(&stream_id, &circuit_id).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`get_streams`](Self::get_streams): List active streams
    /// - [`close_stream`](Self::close_stream): Close a stream
    pub async fn attach_stream(
        &mut self,
        stream_id: &StreamId,
        circuit_id: &CircuitId,
    ) -> Result<(), Error> {
        let command = format!("ATTACHSTREAM {} {}", stream_id.0, circuit_id.0);
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if response.is_ok() {
            Ok(())
        } else {
            Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            })
        }
    }

    /// Closes an existing stream.
    ///
    /// Terminates the specified stream with an optional reason code.
    ///
    /// # Arguments
    ///
    /// * `id` - The stream ID to close
    /// * `reason` - Optional reason code (defaults to 1 = MISC if not specified)
    ///
    /// # Reason Codes
    ///
    /// Common reason codes include:
    /// - 1: MISC (miscellaneous)
    /// - 2: RESOLVEFAILED (DNS resolution failed)
    /// - 3: CONNECTREFUSED (connection refused)
    /// - 4: EXITPOLICY (exit policy violation)
    /// - 5: DESTROY (circuit destroyed)
    /// - 6: DONE (stream finished normally)
    /// - 7: TIMEOUT (connection timeout)
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - The stream doesn't exist
    /// - The stream is already closed
    /// - Tor returns an error response
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::{Controller, StreamId};
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Close stream with default reason
    /// let stream_id = StreamId::new("1");
    /// controller.close_stream(&stream_id, None).await?;
    ///
    /// // Close stream with specific reason (DONE)
    /// controller.close_stream(&stream_id, Some(6)).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`get_streams`](Self::get_streams): List active streams
    /// - [`attach_stream`](Self::attach_stream): Attach a stream to a circuit
    pub async fn close_stream(&mut self, id: &StreamId, reason: Option<u8>) -> Result<(), Error> {
        let command = match reason {
            Some(r) => format!("CLOSESTREAM {} {}", id.0, r),
            None => format!("CLOSESTREAM {} 1", id.0),
        };
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if response.is_ok() {
            Ok(())
        } else {
            Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            })
        }
    }

    /// Maps one address to another for Tor connections.
    ///
    /// Creates an address mapping so that connections to the `from` address
    /// are redirected to the `to` address. This is useful for creating
    /// virtual addresses or redirecting traffic.
    ///
    /// # Arguments
    ///
    /// * `from` - The source address to map from
    /// * `to` - The destination address to map to
    ///
    /// # Returns
    ///
    /// Returns a `HashMap` containing the established mappings. The keys are
    /// the source addresses and values are the destination addresses.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - The address format is invalid
    /// - The mapping cannot be created
    /// - Tor returns an error response
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Map a hostname to a .onion address
    /// let mappings = controller.map_address(
    ///     "www.example.com",
    ///     "exampleonion.onion"
    /// ).await?;
    ///
    /// for (from, to) in mappings {
    ///     println!("{} -> {}", from, to);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn map_address(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<HashMap<String, String>, Error> {
        let command = format!("MAPADDRESS {}={}", from, to);
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if !response.is_ok() {
            return Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            });
        }

        let mut mappings = HashMap::new();
        for line in &response.lines {
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].to_string();
                let value = line[eq_pos + 1..].to_string();
                mappings.insert(key, value);
            }
        }
        Ok(mappings)
    }

    /// Subscribes to asynchronous events from Tor.
    ///
    /// Configures which event types Tor should send to this controller.
    /// Events are received via [`recv_event`](Self::recv_event).
    ///
    /// # Arguments
    ///
    /// * `events` - List of event types to subscribe to
    ///
    /// # Event Types
    ///
    /// Common event types include:
    /// - [`EventType::Circ`](crate::EventType::Circ) - Circuit status changes
    /// - [`EventType::Stream`](crate::EventType::Stream) - Stream status changes
    /// - [`EventType::Bw`](crate::EventType::Bw) - Bandwidth usage
    /// - [`EventType::Notice`](crate::EventType::Notice) - Notice-level log messages
    /// - [`EventType::Warn`](crate::EventType::Warn) - Warning-level log messages
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - An event type is not recognized
    /// - Tor returns an error response
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    /// use stem_rs::EventType;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Subscribe to circuit and bandwidth events
    /// controller.set_events(&[EventType::Circ, EventType::Bw]).await?;
    ///
    /// // Receive events
    /// loop {
    ///     let event = controller.recv_event().await?;
    ///     println!("Received event: {:?}", event);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Clearing Subscriptions
    ///
    /// To stop receiving events, call with an empty slice:
    ///
    /// ```rust,no_run
    /// # use stem_rs::controller::Controller;
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// # let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.set_events(&[]).await?; // Clear all subscriptions
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`recv_event`](Self::recv_event): Receive subscribed events
    /// - [`EventType`](crate::EventType): Available event types
    /// - [`events`](crate::events): Event parsing module
    pub async fn set_events(&mut self, events: &[EventType]) -> Result<(), Error> {
        let event_names: Vec<String> = events.iter().map(|e| e.to_string()).collect();
        let command = if event_names.is_empty() {
            "SETEVENTS".to_string()
        } else {
            format!("SETEVENTS {}", event_names.join(" "))
        };
        self.socket.send(&command).await?;
        let response = self.recv_response().await?;

        if response.is_ok() {
            Ok(())
        } else {
            Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            })
        }
    }

    /// Receives the next asynchronous event from Tor.
    ///
    /// Blocks until an event is available. Events must first be subscribed
    /// to using [`set_events`](Self::set_events).
    ///
    /// # Event Buffering
    ///
    /// Events that arrive while waiting for command responses are automatically
    /// buffered and returned by subsequent calls to this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`](crate::Error::Protocol) if:
    /// - The received message is not an event (status code != 650)
    ///
    /// Returns [`Error::Socket`](crate::Error::Socket) if:
    /// - The connection is closed
    /// - A network error occurs
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    /// use stem_rs::EventType;
    /// use stem_rs::events::ParsedEvent;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Subscribe to bandwidth events
    /// controller.set_events(&[EventType::Bw]).await?;
    ///
    /// // Receive and process events
    /// loop {
    ///     match controller.recv_event().await? {
    ///         ParsedEvent::Bandwidth(bw) => {
    ///             println!("Bandwidth: {} read, {} written", bw.read, bw.written);
    ///         }
    ///         other => println!("Other event: {:?}", other),
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`set_events`](Self::set_events): Subscribe to events
    /// - [`ParsedEvent`](crate::events::ParsedEvent): Event types
    pub async fn recv_event(&mut self) -> Result<ParsedEvent, Error> {
        let response = if let Some(buffered) = self.event_buffer.pop() {
            buffered
        } else {
            self.socket.recv().await?
        };

        if response.status_code != 650 {
            return Err(Error::Protocol(format!(
                "expected async event (650), got {}",
                response.status_code
            )));
        }

        let content = response.content();
        let (event_type, event_content) = content.split_once(' ').unwrap_or((content, ""));

        let lines: Vec<String> = response
            .lines
            .iter()
            .skip(1)
            .filter(|l| !l.is_empty() && *l != "OK")
            .cloned()
            .collect();

        ParsedEvent::parse(event_type, event_content, Some(&lines))
    }

    /// Sends a raw command to Tor and returns the response.
    ///
    /// This is a low-level method for sending arbitrary control protocol
    /// commands. For most use cases, prefer the typed methods like
    /// [`get_info`](Self::get_info), [`signal`](Self::signal), etc.
    ///
    /// # Arguments
    ///
    /// * `command` - The raw command string to send
    ///
    /// # Errors
    ///
    /// Returns [`Error::OperationFailed`](crate::Error::OperationFailed) if:
    /// - Tor returns an error response
    ///
    /// Returns [`Error::Socket`](crate::Error::Socket) if:
    /// - The connection is closed
    /// - A network error occurs
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Send a raw GETINFO command
    /// let response = controller.msg("GETINFO version").await?;
    /// println!("Raw response: {}", response);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`get_info`](Self::get_info): Typed GETINFO wrapper
    /// - [`signal`](Self::signal): Typed SIGNAL wrapper
    pub async fn msg(&mut self, command: &str) -> Result<String, Error> {
        self.socket.send(command).await?;
        let response = self.recv_response().await?;

        if !response.is_ok() {
            return Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            });
        }

        Ok(response.raw_content())
    }

    /// Creates an ephemeral hidden service.
    ///
    /// Unlike file-based hidden services, ephemeral services don't touch disk
    /// and are the recommended way to create hidden services programmatically.
    ///
    /// # Arguments
    ///
    /// * `ports` - Mapping of virtual ports to local targets (e.g., `[(80, "127.0.0.1:8080")]`)
    /// * `key_type` - Type of key: `"NEW"` to generate, `"RSA1024"`, or `"ED25519-V3"`
    /// * `key_content` - Key content or type to generate (`"BEST"`, `"RSA1024"`, `"ED25519-V3"`)
    /// * `flags` - Optional flags like `"Detach"`, `"DiscardPK"`, `"BasicAuth"`, `"MaxStreamsCloseCircuit"`
    ///
    /// # Returns
    ///
    /// Returns an [`AddOnionResponse`] containing:
    /// - `service_id`: The onion address (without `.onion` suffix)
    /// - `private_key`: The private key (unless `DiscardPK` flag was set)
    /// - `private_key_type`: The key type (e.g., `"ED25519-V3"`)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Create a v3 hidden service mapping port 80 to local port 8080
    /// let response = controller.create_ephemeral_hidden_service(
    ///     &[(80, "127.0.0.1:8080")],
    ///     "NEW",
    ///     "ED25519-V3",
    ///     &[],
    /// ).await?;
    ///
    /// println!("Hidden service: {}.onion", response.service_id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    ///
    /// - [`remove_ephemeral_hidden_service`](Self::remove_ephemeral_hidden_service): Remove the service
    pub async fn create_ephemeral_hidden_service(
        &mut self,
        ports: &[(u16, &str)],
        key_type: &str,
        key_content: &str,
        flags: &[&str],
    ) -> Result<AddOnionResponse, Error> {
        let mut request = format!("ADD_ONION {}:{}", key_type, key_content);

        if !flags.is_empty() {
            request.push_str(&format!(" Flags={}", flags.join(",")));
        }

        for (virt_port, target) in ports {
            request.push_str(&format!(" Port={},{}", virt_port, target));
        }

        self.socket.send(&request).await?;
        let response = self.recv_response().await?;

        if !response.is_ok() {
            return Err(Error::OperationFailed {
                code: response.status_code.to_string(),
                message: response.content().to_string(),
            });
        }

        parse_add_onion_response(&response.all_content())
    }

    /// Removes an ephemeral hidden service.
    ///
    /// Discontinues a hidden service that was created with
    /// [`create_ephemeral_hidden_service`](Self::create_ephemeral_hidden_service).
    ///
    /// # Arguments
    ///
    /// * `service_id` - The onion address without the `.onion` suffix
    ///
    /// # Returns
    ///
    /// Returns `true` if the service was removed, `false` if it wasn't running.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::controller::Controller;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// // Create and then remove a hidden service
    /// let response = controller.create_ephemeral_hidden_service(
    ///     &[(80, "127.0.0.1:8080")],
    ///     "NEW",
    ///     "BEST",
    ///     &[],
    /// ).await?;
    ///
    /// controller.remove_ephemeral_hidden_service(&response.service_id).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn remove_ephemeral_hidden_service(&mut self, service_id: &str) -> Result<bool, Error> {
        let command = format!("DEL_ONION {}", service_id);
        match self.msg(&command).await {
            Ok(_) => Ok(true),
            Err(Error::OperationFailed { code, message }) => {
                if message.contains("Unknown Onion Service") {
                    Ok(false)
                } else {
                    Err(Error::OperationFailed { code, message })
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// Response from ADD_ONION command.
///
/// Contains the service ID and optionally the private key for the hidden service.
#[derive(Debug, Clone)]
pub struct AddOnionResponse {
    /// The onion address without the `.onion` suffix.
    pub service_id: String,
    /// The private key (base64 encoded), if not discarded.
    pub private_key: Option<String>,
    /// The type of private key (e.g., `"ED25519-V3"`, `"RSA1024"`).
    pub private_key_type: Option<String>,
}

/// Parses the response from an ADD_ONION command.
fn parse_add_onion_response(content: &str) -> Result<AddOnionResponse, Error> {
    let mut service_id = None;
    let mut private_key = None;
    let mut private_key_type = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("ServiceID=") {
            service_id = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("PrivateKey=") {
            if let Some((key_type, key_content)) = value.split_once(':') {
                private_key_type = Some(key_type.to_string());
                private_key = Some(key_content.to_string());
            }
        }
    }

    let service_id = service_id.ok_or_else(|| Error::Parse {
        location: "ADD_ONION response".to_string(),
        reason: "missing ServiceID".to_string(),
    })?;

    Ok(AddOnionResponse {
        service_id,
        private_key,
        private_key_type,
    })
}

/// Parses circuit status output from GETINFO circuit-status.
///
/// Converts the multi-line circuit status response into a vector of [`Circuit`] structs.
fn parse_circuits(content: &str) -> Result<Vec<Circuit>, Error> {
    let mut circuits = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let id = parts.next().ok_or_else(|| Error::Parse {
            location: "circuit".to_string(),
            reason: "missing circuit id".to_string(),
        })?;

        let status_str = parts.next().ok_or_else(|| Error::Parse {
            location: "circuit".to_string(),
            reason: "missing circuit status".to_string(),
        })?;

        let status = parse_circ_status(status_str)?;

        let mut path = Vec::new();
        if let Some(path_str) = parts.next() {
            if !path_str.starts_with("BUILD_FLAGS=")
                && !path_str.starts_with("PURPOSE=")
                && !path_str.starts_with("TIME_CREATED=")
            {
                for relay in path_str.split(',') {
                    let relay_info = parse_relay_info(relay);
                    path.push(relay_info);
                }
            }
        }

        circuits.push(Circuit {
            id: CircuitId::new(id),
            status,
            path,
        });
    }

    Ok(circuits)
}

/// Parses a circuit status string into a [`CircStatus`] enum.
fn parse_circ_status(s: &str) -> Result<CircStatus, Error> {
    match s.to_uppercase().as_str() {
        "LAUNCHED" => Ok(CircStatus::Launched),
        "BUILT" => Ok(CircStatus::Built),
        "GUARD_WAIT" => Ok(CircStatus::GuardWait),
        "EXTENDED" => Ok(CircStatus::Extended),
        "FAILED" => Ok(CircStatus::Failed),
        "CLOSED" => Ok(CircStatus::Closed),
        _ => Err(Error::Parse {
            location: "circuit status".to_string(),
            reason: format!("unknown status: {}", s),
        }),
    }
}

/// Parses a relay specification string into a [`RelayInfo`] struct.
///
/// Handles formats like `$FINGERPRINT~Nickname` or just `$FINGERPRINT`.
fn parse_relay_info(s: &str) -> RelayInfo {
    if let Some((fingerprint, nickname)) = s.split_once('~') {
        RelayInfo {
            fingerprint: fingerprint.trim_start_matches('$').to_string(),
            nickname: Some(nickname.to_string()),
        }
    } else {
        RelayInfo {
            fingerprint: s.trim_start_matches('$').to_string(),
            nickname: None,
        }
    }
}

/// Parses stream status output from GETINFO stream-status.
///
/// Converts the multi-line stream status response into a vector of [`Stream`] structs.
fn parse_streams(content: &str) -> Result<Vec<Stream>, Error> {
    let mut streams = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let id = parts.next().ok_or_else(|| Error::Parse {
            location: "stream".to_string(),
            reason: "missing stream id".to_string(),
        })?;

        let status_str = parts.next().ok_or_else(|| Error::Parse {
            location: "stream".to_string(),
            reason: "missing stream status".to_string(),
        })?;

        let status = parse_stream_status(status_str)?;

        let circuit_id_str = parts.next().ok_or_else(|| Error::Parse {
            location: "stream".to_string(),
            reason: "missing circuit id".to_string(),
        })?;

        let circuit_id = if circuit_id_str == "0" {
            None
        } else {
            Some(CircuitId::new(circuit_id_str))
        };

        let target = parts.next().ok_or_else(|| Error::Parse {
            location: "stream".to_string(),
            reason: "missing target".to_string(),
        })?;

        let (target_host, target_port) = parse_target(target)?;

        streams.push(Stream {
            id: StreamId::new(id),
            status,
            circuit_id,
            target_host,
            target_port,
        });
    }

    Ok(streams)
}

/// Parses a stream status string into a [`StreamStatus`] enum.
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
        _ => Err(Error::Parse {
            location: "stream status".to_string(),
            reason: format!("unknown status: {}", s),
        }),
    }
}

/// Parses a target address string into host and port components.
///
/// Handles formats like `host:port` or just `host` (port defaults to 0).
fn parse_target(target: &str) -> Result<(String, u16), Error> {
    if let Some(colon_pos) = target.rfind(':') {
        let host = target[..colon_pos].to_string();
        let port_str = &target[colon_pos + 1..];
        let port: u16 = port_str.parse().map_err(|_| Error::Parse {
            location: "stream target".to_string(),
            reason: format!("invalid port: {}", port_str),
        })?;
        Ok((host, port))
    } else {
        Ok((target.to_string(), 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_id_display() {
        let id = CircuitId::new("123");
        assert_eq!(id.to_string(), "123");
    }

    #[test]
    fn test_stream_id_display() {
        let id = StreamId::new("456");
        assert_eq!(id.to_string(), "456");
    }

    #[test]
    fn test_parse_circ_status() {
        assert_eq!(parse_circ_status("LAUNCHED").unwrap(), CircStatus::Launched);
        assert_eq!(parse_circ_status("BUILT").unwrap(), CircStatus::Built);
        assert_eq!(
            parse_circ_status("GUARD_WAIT").unwrap(),
            CircStatus::GuardWait
        );
        assert_eq!(parse_circ_status("EXTENDED").unwrap(), CircStatus::Extended);
        assert_eq!(parse_circ_status("FAILED").unwrap(), CircStatus::Failed);
        assert_eq!(parse_circ_status("CLOSED").unwrap(), CircStatus::Closed);
        assert_eq!(parse_circ_status("launched").unwrap(), CircStatus::Launched);
        assert!(parse_circ_status("UNKNOWN").is_err());
    }

    #[test]
    fn test_parse_stream_status() {
        assert_eq!(parse_stream_status("NEW").unwrap(), StreamStatus::New);
        assert_eq!(
            parse_stream_status("NEWRESOLVE").unwrap(),
            StreamStatus::NewResolve
        );
        assert_eq!(parse_stream_status("REMAP").unwrap(), StreamStatus::Remap);
        assert_eq!(
            parse_stream_status("SENTCONNECT").unwrap(),
            StreamStatus::SentConnect
        );
        assert_eq!(
            parse_stream_status("SENTRESOLVE").unwrap(),
            StreamStatus::SentResolve
        );
        assert_eq!(
            parse_stream_status("SUCCEEDED").unwrap(),
            StreamStatus::Succeeded
        );
        assert_eq!(parse_stream_status("FAILED").unwrap(), StreamStatus::Failed);
        assert_eq!(
            parse_stream_status("DETACHED").unwrap(),
            StreamStatus::Detached
        );
        assert_eq!(
            parse_stream_status("CONTROLLER_WAIT").unwrap(),
            StreamStatus::ControllerWait
        );
        assert_eq!(parse_stream_status("CLOSED").unwrap(), StreamStatus::Closed);
        assert!(parse_stream_status("UNKNOWN").is_err());
    }

    #[test]
    fn test_parse_relay_info_with_nickname() {
        let info = parse_relay_info("$ABCD1234~MyRelay");
        assert_eq!(info.fingerprint, "ABCD1234");
        assert_eq!(info.nickname, Some("MyRelay".to_string()));
    }

    #[test]
    fn test_parse_relay_info_without_nickname() {
        let info = parse_relay_info("$ABCD1234");
        assert_eq!(info.fingerprint, "ABCD1234");
        assert_eq!(info.nickname, None);
    }

    #[test]
    fn test_parse_relay_info_no_dollar() {
        let info = parse_relay_info("ABCD1234~MyRelay");
        assert_eq!(info.fingerprint, "ABCD1234");
        assert_eq!(info.nickname, Some("MyRelay".to_string()));
    }

    #[test]
    fn test_parse_target_with_port() {
        let (host, port) = parse_target("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_target_ipv4_with_port() {
        let (host, port) = parse_target("192.168.1.1:80").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_target_without_port() {
        let (host, port) = parse_target("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_parse_circuits_empty() {
        let circuits = parse_circuits("").unwrap();
        assert!(circuits.is_empty());
    }

    #[test]
    fn test_parse_circuits_single() {
        let content = "1 BUILT $AAAA~Guard,$BBBB~Middle,$CCCC~Exit";
        let circuits = parse_circuits(content).unwrap();
        assert_eq!(circuits.len(), 1);
        assert_eq!(circuits[0].id.0, "1");
        assert_eq!(circuits[0].status, CircStatus::Built);
        assert_eq!(circuits[0].path.len(), 3);
        assert_eq!(circuits[0].path[0].fingerprint, "AAAA");
        assert_eq!(circuits[0].path[0].nickname, Some("Guard".to_string()));
    }

    #[test]
    fn test_parse_circuits_multiple() {
        let content = "1 BUILT $AAAA~Guard,$BBBB~Exit\n2 LAUNCHED\n3 EXTENDED $CCCC~Relay";
        let circuits = parse_circuits(content).unwrap();
        assert_eq!(circuits.len(), 3);
        assert_eq!(circuits[0].status, CircStatus::Built);
        assert_eq!(circuits[1].status, CircStatus::Launched);
        assert_eq!(circuits[2].status, CircStatus::Extended);
    }

    #[test]
    fn test_parse_circuits_with_flags() {
        let content = "1 BUILT $AAAA~Guard BUILD_FLAGS=IS_INTERNAL PURPOSE=GENERAL";
        let circuits = parse_circuits(content).unwrap();
        assert_eq!(circuits.len(), 1);
        assert_eq!(circuits[0].path.len(), 1);
    }

    #[test]
    fn test_parse_streams_empty() {
        let streams = parse_streams("").unwrap();
        assert!(streams.is_empty());
    }

    #[test]
    fn test_parse_streams_single() {
        let content = "1 SUCCEEDED 5 www.example.com:443";
        let streams = parse_streams(content).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].id.0, "1");
        assert_eq!(streams[0].status, StreamStatus::Succeeded);
        assert_eq!(streams[0].circuit_id, Some(CircuitId::new("5")));
        assert_eq!(streams[0].target_host, "www.example.com");
        assert_eq!(streams[0].target_port, 443);
    }

    #[test]
    fn test_parse_streams_no_circuit() {
        let content = "1 NEW 0 www.example.com:80";
        let streams = parse_streams(content).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].circuit_id, None);
    }

    #[test]
    fn test_parse_streams_multiple() {
        let content = "1 SUCCEEDED 5 www.example.com:443\n2 NEW 0 api.example.com:80";
        let streams = parse_streams(content).unwrap();
        assert_eq!(streams.len(), 2);
    }

    #[test]
    fn test_circuit_id_equality() {
        let id1 = CircuitId::new("123");
        let id2 = CircuitId::new("123");
        let id3 = CircuitId::new("456");
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_stream_id_equality() {
        let id1 = StreamId::new("123");
        let id2 = StreamId::new("123");
        let id3 = StreamId::new("456");
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }
}

#[cfg(test)]
mod stem_tests {
    use super::*;

    #[test]
    fn test_parse_circ_path_empty() {
        let circuits = parse_circuits("").unwrap();
        assert!(circuits.is_empty());
    }

    #[test]
    fn test_parse_circ_path_with_fingerprint_and_nickname() {
        let content = "1 BUILT $999A226EBED397F331B612FE1E4CFAE5C1F201BA~piyaz";
        let circuits = parse_circuits(content).unwrap();
        assert_eq!(circuits.len(), 1);
        assert_eq!(circuits[0].path.len(), 1);
        assert_eq!(
            circuits[0].path[0].fingerprint,
            "999A226EBED397F331B612FE1E4CFAE5C1F201BA"
        );
        assert_eq!(circuits[0].path[0].nickname, Some("piyaz".to_string()));
    }

    #[test]
    fn test_parse_circ_path_multiple_relays() {
        let content =
            "1 BUILT $E57A476CD4DFBD99B4EE52A100A58610AD6E80B9,$AAAA,$BBBB~PrivacyRepublic14";
        let circuits = parse_circuits(content).unwrap();
        assert_eq!(circuits.len(), 1);
        assert_eq!(circuits[0].path.len(), 3);
        assert_eq!(
            circuits[0].path[0].fingerprint,
            "E57A476CD4DFBD99B4EE52A100A58610AD6E80B9"
        );
        assert_eq!(circuits[0].path[0].nickname, None);
        assert_eq!(circuits[0].path[2].fingerprint, "BBBB");
        assert_eq!(
            circuits[0].path[2].nickname,
            Some("PrivacyRepublic14".to_string())
        );
    }

    #[test]
    fn test_get_streams_parsing() {
        let content =
            "1 NEW 4 10.10.10.1:80\n2 SUCCEEDED 4 10.10.10.1:80\n3 SUCCEEDED 4 10.10.10.1:80";
        let streams = parse_streams(content).unwrap();
        assert_eq!(streams.len(), 3);

        assert_eq!(streams[0].id.0, "1");
        assert_eq!(streams[0].status, StreamStatus::New);
        assert_eq!(streams[0].circuit_id, Some(CircuitId::new("4")));
        assert_eq!(streams[0].target_host, "10.10.10.1");
        assert_eq!(streams[0].target_port, 80);

        assert_eq!(streams[1].id.0, "2");
        assert_eq!(streams[1].status, StreamStatus::Succeeded);

        assert_eq!(streams[2].id.0, "3");
        assert_eq!(streams[2].status, StreamStatus::Succeeded);
    }

    #[test]
    fn test_circuit_status_parsing() {
        let test_cases = [
            ("LAUNCHED", CircStatus::Launched),
            ("BUILT", CircStatus::Built),
            ("GUARD_WAIT", CircStatus::GuardWait),
            ("EXTENDED", CircStatus::Extended),
            ("FAILED", CircStatus::Failed),
            ("CLOSED", CircStatus::Closed),
        ];

        for (input, expected) in test_cases {
            assert_eq!(parse_circ_status(input).unwrap(), expected);
        }
    }

    #[test]
    fn test_stream_status_parsing() {
        let test_cases = [
            ("NEW", StreamStatus::New),
            ("NEWRESOLVE", StreamStatus::NewResolve),
            ("REMAP", StreamStatus::Remap),
            ("SENTCONNECT", StreamStatus::SentConnect),
            ("SENTRESOLVE", StreamStatus::SentResolve),
            ("SUCCEEDED", StreamStatus::Succeeded),
            ("FAILED", StreamStatus::Failed),
            ("DETACHED", StreamStatus::Detached),
            ("CONTROLLER_WAIT", StreamStatus::ControllerWait),
            ("CLOSED", StreamStatus::Closed),
        ];

        for (input, expected) in test_cases {
            assert_eq!(parse_stream_status(input).unwrap(), expected);
        }
    }

    #[test]
    fn test_parse_target_various() {
        let test_cases = [
            ("www.example.com:443", ("www.example.com", 443)),
            ("192.168.1.1:80", ("192.168.1.1", 80)),
            ("10.10.10.1:8080", ("10.10.10.1", 8080)),
            ("[::1]:443", ("[::1]", 443)),
        ];

        for (input, (expected_host, expected_port)) in test_cases {
            let (host, port) = parse_target(input).unwrap();
            assert_eq!(host, expected_host);
            assert_eq!(port, expected_port);
        }
    }

    #[test]
    fn test_parse_circuits_with_build_flags() {
        let content = "1 BUILT $AAAA~Guard,$BBBB~Exit BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2023-01-01T00:00:00";
        let circuits = parse_circuits(content).unwrap();
        assert_eq!(circuits.len(), 1);
        assert_eq!(circuits[0].status, CircStatus::Built);
        assert_eq!(circuits[0].path.len(), 2);
    }

    #[test]
    fn test_parse_circuits_launched_no_path() {
        let content = "1 LAUNCHED BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL";
        let circuits = parse_circuits(content).unwrap();
        assert_eq!(circuits.len(), 1);
        assert_eq!(circuits[0].status, CircStatus::Launched);
        assert!(circuits[0].path.is_empty());
    }

    #[test]
    fn test_parse_streams_detached() {
        let content = "1 DETACHED 0 www.example.com:443";
        let streams = parse_streams(content).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].status, StreamStatus::Detached);
        assert_eq!(streams[0].circuit_id, None);
    }

    #[test]
    fn test_relay_info_parsing_variations() {
        let test_cases = [
            ("$ABCD1234~MyRelay", "ABCD1234", Some("MyRelay")),
            ("$ABCD1234", "ABCD1234", None),
            ("ABCD1234~MyRelay", "ABCD1234", Some("MyRelay")),
            ("ABCD1234", "ABCD1234", None),
        ];

        for (input, expected_fp, expected_nick) in test_cases {
            let info = parse_relay_info(input);
            assert_eq!(info.fingerprint, expected_fp);
            assert_eq!(info.nickname, expected_nick.map(|s| s.to_string()));
        }
    }

    #[test]
    fn test_circuit_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CircuitId::new("1"));
        set.insert(CircuitId::new("2"));
        set.insert(CircuitId::new("1"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_stream_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(StreamId::new("1"));
        set.insert(StreamId::new("2"));
        set.insert(StreamId::new("1"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_parse_circuits_real_world_example() {
        let content = r#"7 BUILT $5CECC5C30ACC4B3DE462792323967087CC53D947~Quetzalcoatl,$51E1CF613FD6F9F11FE24743C91D6F9981807D82~DigiGesTor4e3,$B06F093A3D4DFAD3E923F4F28A74901BD4F74EB1~torserversNet BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_CLIENT_HSDIR HS_STATE=HSCI_CONNECTING TIME_CREATED=2023-06-15T10:30:45.123456"#;
        let circuits = parse_circuits(content).unwrap();
        assert_eq!(circuits.len(), 1);
        assert_eq!(circuits[0].id.0, "7");
        assert_eq!(circuits[0].status, CircStatus::Built);
        assert_eq!(circuits[0].path.len(), 3);
        assert_eq!(
            circuits[0].path[0].nickname,
            Some("Quetzalcoatl".to_string())
        );
        assert_eq!(
            circuits[0].path[1].nickname,
            Some("DigiGesTor4e3".to_string())
        );
        assert_eq!(
            circuits[0].path[2].nickname,
            Some("torserversNet".to_string())
        );
    }

    #[test]
    fn test_parse_streams_real_world_example() {
        let content =
            "42 SUCCEEDED 7 www.torproject.org:443 SOURCE_ADDR=127.0.0.1:12345 PURPOSE=USER";
        let streams = parse_streams(content).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].id.0, "42");
        assert_eq!(streams[0].status, StreamStatus::Succeeded);
        assert_eq!(streams[0].circuit_id, Some(CircuitId::new("7")));
        assert_eq!(streams[0].target_host, "www.torproject.org");
        assert_eq!(streams[0].target_port, 443);
    }

    #[test]
    fn test_parse_add_onion_response_v3() {
        let content = "ServiceID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nPrivateKey=ED25519-V3:base64keydata==";
        let response = parse_add_onion_response(content).unwrap();
        assert_eq!(response.service_id, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_eq!(response.private_key_type, Some("ED25519-V3".to_string()));
        assert_eq!(response.private_key, Some("base64keydata==".to_string()));
    }

    #[test]
    fn test_parse_add_onion_response_discarded_key() {
        let content = "ServiceID=abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv";
        let response = parse_add_onion_response(content).unwrap();
        assert_eq!(response.service_id, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv");
        assert!(response.private_key.is_none());
        assert!(response.private_key_type.is_none());
    }

    #[test]
    fn test_parse_add_onion_response_missing_service_id() {
        let content = "PrivateKey=ED25519-V3:base64keydata==";
        let result = parse_add_onion_response(content);
        assert!(result.is_err());
    }
}
