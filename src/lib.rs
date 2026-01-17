//! # stem-rs
//!
//! A Rust implementation of the Stem library for Tor control protocol interaction.
//!
//! # Overview
//!
//! stem-rs provides idiomatic Rust APIs for interacting with Tor's control protocol,
//! maintaining functional parity with Python Stem. The library enables:
//!
//! - Control socket communication (TCP and Unix domain sockets)
//! - All authentication methods (NONE, PASSWORD, COOKIE, SAFECOOKIE)
//! - High-level Controller API for Tor interaction
//! - Complete descriptor parsing (server, micro, consensus, extra-info, hidden service)
//! - Event subscription and handling
//! - Exit policy parsing and evaluation
//! - ORPort relay communication
//! - Version parsing and comparison
//!
//! # Feature Flags
//!
//! stem-rs uses feature flags to allow you to compile only what you need, reducing
//! compile time and binary size.
//!
//! ## Default Features
//!
//! By default, all features are enabled:
//!
//! ```toml
//! [dependencies]
//! stem-rs = "1.2"  # Includes all features
//! ```
//!
//! ## Minimal Build
//!
//! For a minimal build with just the core functionality:
//!
//! ```toml
//! [dependencies]
//! stem-rs = { version = "1.2", default-features = false }
//! ```
//!
//! This includes: socket communication, authentication, protocol parsing, utilities,
//! and version handling.
//!
//! ## Available Features
//!
//! | Feature | Description | Dependencies |
//! |---------|-------------|--------------|
//! | `full` | All features (default) | All features below |
//! | `controller` | High-level Controller API | `events` |
//! | `descriptors` | Tor descriptor parsing | `client`, `exit-policy` |
//! | `events` | Event subscription and handling | None |
//! | `exit-policy` | Exit policy parsing and evaluation | None |
//! | `client` | ORPort relay communication | None |
//! | `interpreter` | Interactive Tor control interpreter | `controller`, `events` |
//! | `compression` | Gzip decompression for descriptors | None |
//!
//! ## Custom Feature Combinations
//!
//! **Controller only** (no descriptor parsing):
//! ```toml
//! [dependencies]
//! stem-rs = { version = "1.2", default-features = false, features = ["controller"] }
//! ```
//!
//! **Descriptors only** (offline analysis):
//! ```toml
//! [dependencies]
//! stem-rs = { version = "1.2", default-features = false, features = ["descriptors"] }
//! ```
//!
//! **Controller + Descriptors** (most common):
//! ```toml
//! [dependencies]
//! stem-rs = { version = "1.2", default-features = false, features = ["controller", "descriptors"] }
//! ```
//!
//! ## Compile Time Improvements
//!
//! Approximate compile time reductions with feature flags:
//!
//! - **Minimal build**: ~40% faster (excludes descriptors, controller, events)
//! - **Controller-only**: ~30% faster (excludes descriptor parsing)
//! - **Descriptors-only**: ~20% faster (excludes controller, events)
//!
//! Binary size reductions follow similar patterns.
//!
//! # Choosing the Right Library: stem-rs vs tor-metrics-library
//!
//! ## Use stem-rs for:
//! Real-time Tor control, live network interaction (circuits, streams, hidden services),
//! event monitoring, configuration management, and interactive applications.
//!
//! ## Use tor-metrics-library for:
//! Historical analysis, batch processing of archived descriptors, metrics collection,
//! database export, network research, and async streaming of large archives.
//!
//! # Architecture
//!
//! The library is organized into these primary modules:
//!
//! - [`socket`]: Low-level control socket communication
//! - [`auth`]: Authentication methods and protocol info
//! - [`controller`]: High-level Controller API
//! - [`descriptor`]: Tor descriptor parsing
//! - [`events`]: Event types and handling
//! - [`exit_policy`]: Exit policy evaluation
//! - [`client`]: Direct ORPort relay communication
//! - [`response`]: Control protocol response parsing
//! - [`interpreter`]: Interactive Tor control interpreter
//! - [`version`]: Tor version parsing and comparison
//! - [`util`]: Validation utilities for fingerprints, nicknames, etc.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use stem_rs::{controller::Controller, Error};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     // Connect to Tor's control port
//!     let mut controller = Controller::from_port("127.0.0.1:9051".parse().unwrap()).await?;
//!     
//!     // Authenticate (auto-detects method)
//!     controller.authenticate(None).await?;
//!     
//!     // Query Tor version
//!     let version = controller.get_version().await?;
//!     println!("Connected to Tor {}", version);
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Using Descriptors with Controller
//!
//! The [`controller::Controller`] provides methods to retrieve and work with
//! Tor network descriptors. This enables intelligent circuit building, relay
//! selection, and network analysis.
//!
//! ## Retrieving Network Consensus
//!
//! The consensus document contains the current state of the Tor network:
//!
//! ```rust,no_run
//! use stem_rs::controller::Controller;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! let consensus = controller.get_consensus().await?;
//! println!("Network has {} authorities", consensus.authorities.len());
//! println!("Consensus valid from {} to {}",
//!          consensus.valid_after, consensus.valid_until);
//! # Ok(())
//! # }
//! ```
//!
//! ## Finding Relays by Flags
//!
//! Filter relays based on directory authority flags:
//!
//! ```rust,no_run
//! use stem_rs::{controller::Controller, Flag};
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! let guard_relays = controller.find_relays_by_flag(Flag::Guard).await?;
//! let exit_relays = controller.find_relays_by_flag(Flag::Exit).await?;
//! let fast_stable = controller.find_relays_by_flag(Flag::Fast).await?
//!     .into_iter()
//!     .filter(|r| r.flags.contains(&"Stable".to_string()))
//!     .collect::<Vec<_>>();
//!
//! println!("Found {} guards, {} exits, {} fast+stable relays",
//!          guard_relays.len(), exit_relays.len(), fast_stable.len());
//! # Ok(())
//! # }
//! ```
//!
//! ## Selecting High-Performance Relays
//!
//! Find the fastest relays for high-bandwidth circuits:
//!
//! ```rust,no_run
//! use stem_rs::controller::Controller;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! let top_10 = controller.find_fastest_relays(10).await?;
//! for (i, relay) in top_10.iter().enumerate() {
//!     println!("#{}: {} - {} KB/s",
//!              i + 1, relay.nickname, relay.bandwidth.unwrap_or(0));
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Bandwidth-Weighted Guard Selection
//!
//! Select guard relays using Tor's bandwidth-weighted algorithm:
//!
//! ```rust,no_run
//! use stem_rs::controller::Controller;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! if let Some(guard) = controller.select_guard_relay().await? {
//!     println!("Selected guard: {} ({})", guard.nickname, guard.fingerprint);
//!     println!("Bandwidth: {} KB/s", guard.bandwidth.unwrap_or(0));
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Building Circuits with Descriptor Data
//!
//! Use descriptor information to build circuits through specific relays:
//!
//! ```rust,no_run
//! use stem_rs::{controller::{Controller, CircuitId}, Flag};
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! let guard = controller.select_guard_relay().await?
//!     .ok_or_else(|| stem_rs::Error::Protocol("No guards available".into()))?;
//!
//! let middle_relays = controller.find_fastest_relays(100).await?;
//! let middle = middle_relays.get(0)
//!     .ok_or_else(|| stem_rs::Error::Protocol("No middle relays".into()))?;
//!
//! let exit_relays = controller.find_relays_by_flag(Flag::Exit).await?;
//! let exit = exit_relays.get(0)
//!     .ok_or_else(|| stem_rs::Error::Protocol("No exit relays".into()))?;
//!
//! let path = vec![
//!     guard.fingerprint.as_str(),
//!     middle.fingerprint.as_str(),
//!     exit.fingerprint.as_str(),
//! ];
//!
//! let circuit_id = CircuitId("0".to_string());
//! controller.extend_circuit(&circuit_id, &path).await?;
//! println!("Built circuit through {} -> {} -> {}",
//!          guard.nickname, middle.nickname, exit.nickname);
//! # Ok(())
//! # }
//! ```
//!
//! ## Filtering by Exit Policy
//!
//! Find exit relays that allow specific destinations:
//!
//! ```rust,no_run
//! use stem_rs::{controller::Controller, Flag};
//! use std::net::IpAddr;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! let exit_relays = controller.find_relays_by_flag(Flag::Exit).await?;
//!
//! let https_exits: Vec<_> = exit_relays.into_iter()
//!     .filter(|relay| {
//!         relay.exit_policy.as_ref()
//!             .map(|policy| policy.can_exit_to(443))
//!             .unwrap_or(false)
//!     })
//!     .collect();
//!
//! println!("Found {} exits allowing HTTPS", https_exits.len());
//! # Ok(())
//! # }
//! ```
//!
//! ## Retrieving Full Relay Descriptors
//!
//! Get detailed information about specific relays:
//!
//! ```rust,no_run
//! use stem_rs::controller::Controller;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! let entries = controller.get_router_status_entries().await?;
//! if let Some(relay) = entries.first() {
//!     let descriptor = controller
//!         .get_server_descriptor(&relay.fingerprint)
//!         .await?;
//!     
//!     println!("Relay: {} at {}", descriptor.nickname, descriptor.address);
//!     let platform_str = descriptor.platform.as_ref()
//!         .and_then(|p| std::str::from_utf8(p).ok())
//!         .unwrap_or("unknown");
//!     println!("Platform: {}", platform_str);
//!     println!("Bandwidth: avg={}, burst={}, observed={}",
//!              descriptor.bandwidth_avg,
//!              descriptor.bandwidth_burst,
//!              descriptor.bandwidth_observed);
//!     println!("Exit policy: {}", descriptor.exit_policy);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Monitoring Network Changes
//!
//! Subscribe to descriptor events to track network changes:
//!
//! ```rust,no_run
//! use stem_rs::{controller::Controller, EventType};
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! controller.set_events(&[EventType::NewDesc]).await?;
//!
//! loop {
//!     let event = controller.recv_event().await?;
//!     match event {
//!         stem_rs::events::ParsedEvent::NewDesc(desc_event) => {
//!             println!("New descriptors: {} relays", desc_event.relays.len());
//!             
//!             for (fingerprint, _nickname) in &desc_event.relays {
//!                 if let Ok(desc) = controller.get_server_descriptor(fingerprint).await {
//!                     println!("Updated relay: {} at {}", desc.nickname, desc.address);
//!                 }
//!             }
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Best Practices
//!
//! - **Cache descriptors**: Consensus documents are valid for 3 hours, cache them
//! - **Validate descriptors**: Use `descriptor.validate()` to check for malformed data
//! - **Handle unavailable descriptors**: Not all relays have cached descriptors
//! - **Respect bandwidth weights**: Use bandwidth-weighted selection for fairness
//! - **Filter by flags**: Always check Guard/Exit/Fast/Stable flags for circuit building
//! - **Monitor events**: Subscribe to NEWDESC/NEWCONSENSUS to stay current
//!
//! # Thread Safety
//!
//! The [`controller::Controller`] type is `Send` but not `Sync`. For concurrent access,
//! wrap it in `Arc<Mutex<Controller>>` or use separate connections.
//!
//! # Security Considerations
//!
//! - Authentication tokens are cleared from memory after use
//! - Constant-time comparison is used for sensitive data (see [`util::secure_compare`])
//! - Input validation prevents protocol injection attacks
//!
//! # Error Handling
//!
//! All fallible operations return [`Result<T, Error>`]. The [`enum@Error`] enum provides
//! specific error variants for different failure modes:
//!
//! - [`Error::Socket`] - I/O and connection failures
//! - [`Error::Authentication`] - Authentication failures (see [`AuthError`])
//! - [`Error::OperationFailed`] - Tor rejected the operation
//! - [`Error::Descriptor`] - Descriptor parsing failures (see [`descriptor::DescriptorError`])
//! - [`Error::Parse`] - Legacy parse errors (deprecated, use [`Error::Descriptor`])
//!
//! See the [`enum@Error`] documentation for recovery guidance.

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

pub mod auth;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "controller")]
pub mod controller;
#[cfg(feature = "descriptors")]
pub mod descriptor;
#[cfg(feature = "events")]
pub mod events;
#[cfg(feature = "exit-policy")]
pub mod exit_policy;
#[cfg(feature = "interpreter")]
pub mod interpreter;
pub mod protocol;
pub mod response;
pub mod socket;
pub mod types;
pub mod util;
pub mod version;

// Re-export commonly used types at crate root
#[cfg(feature = "controller")]
pub use controller::Controller;
pub use socket::ControlSocket;
pub use version::Version;

use std::fmt;
use thiserror::Error;

/// Errors that can occur during stem-rs operations.
///
/// This enum represents all possible error conditions in the library.
/// Each variant provides specific information about the failure.
///
/// # Error Categories
///
/// - **I/O Errors**: [`Socket`](Error::Socket) - Connection and communication failures
/// - **Protocol Errors**: [`Protocol`](Error::Protocol) - Malformed control protocol data
/// - **Auth Errors**: [`Authentication`](Error::Authentication) - Authentication failures
/// - **Operation Errors**: [`OperationFailed`](Error::OperationFailed) - Tor rejected the request
/// - **Descriptor Errors**: [`Descriptor`](Error::Descriptor) - Descriptor parsing failures
/// - **Parse Errors**: [`Parse`](Error::Parse) - Legacy parse errors (deprecated)
///
/// # Recovery Guide
///
/// | Error | Recoverable | Retry Meaningful |
/// |-------|-------------|------------------|
/// | [`Socket`](Error::Socket) | Sometimes | Yes, with backoff |
/// | [`Protocol`](Error::Protocol) | No | No |
/// | [`Authentication`](Error::Authentication) | Sometimes | Yes, with different credentials |
/// | [`OperationFailed`](Error::OperationFailed) | Depends on code | Check error code |
/// | [`Descriptor`](Error::Descriptor) | No | No |
/// | [`Parse`](Error::Parse) | No | No |
/// | [`Timeout`](Error::Timeout) | Yes | Yes, with longer timeout |
/// | [`SocketClosed`](Error::SocketClosed) | Yes | Yes, reconnect first |
/// | [`Download`](Error::Download) | Sometimes | Yes, with backoff |
/// | [`DownloadTimeout`](Error::DownloadTimeout) | Yes | Yes, with longer timeout |
///
/// # Example
///
/// ```rust
/// use stem_rs::Error;
///
/// fn handle_error(err: Error) {
///     match err {
///         Error::Socket(io_err) => {
///             eprintln!("Connection failed: {}", io_err);
///             // Retry with exponential backoff
///         }
///         Error::Authentication(auth_err) => {
///             eprintln!("Auth failed: {}", auth_err);
///             // Check credentials or try different auth method
///         }
///         Error::Descriptor(desc_err) => {
///             eprintln!("Descriptor parse error: {}", desc_err);
///             // Log and skip this descriptor
///         }
///         Error::Parse { location, reason } => {
///             eprintln!("Parse error at {}: {}", location, reason);
///             // Log and skip this descriptor (legacy error)
///         }
///         Error::OperationFailed { code, message } => {
///             eprintln!("Tor rejected request: {} - {}", code, message);
///             // Check if operation can be retried
///         }
///         _ => eprintln!("Error: {}", err),
///     }
/// }
/// ```
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error during socket communication.
    ///
    /// This error wraps standard I/O errors that occur during socket operations.
    /// Common causes include connection refused, connection reset, and network
    /// unreachable errors.
    ///
    /// # Recovery
    ///
    /// - Check if Tor is running and the control port is accessible
    /// - Retry with exponential backoff for transient network issues
    /// - Verify firewall rules allow the connection
    #[error("socket error: {0}")]
    Socket(#[from] std::io::Error),

    /// Malformed data received from the control protocol.
    ///
    /// This indicates the data received from Tor doesn't conform to the
    /// expected control protocol format. This typically indicates a bug
    /// in either Tor or this library.
    ///
    /// # Recovery
    ///
    /// This error is not recoverable. Report the issue with the malformed data.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Authentication with Tor failed.
    ///
    /// See [`AuthError`] for specific authentication failure reasons.
    ///
    /// # Recovery
    ///
    /// - Check credentials (password, cookie file path)
    /// - Verify Tor's authentication configuration
    /// - Try a different authentication method
    #[error("authentication failed: {0}")]
    Authentication(#[from] AuthError),

    /// Tor was unable to complete the requested operation.
    ///
    /// This error is returned when Tor understands the request but cannot
    /// fulfill it. The error code and message provide details about why.
    ///
    /// # Fields
    ///
    /// - `code`: The numeric error code from Tor (e.g., "552")
    /// - `message`: Human-readable error description from Tor
    ///
    /// # Recovery
    ///
    /// Check the error code to determine if retry is meaningful:
    /// - 4xx codes: Client error, fix the request
    /// - 5xx codes: Server error, may be transient
    #[error("operation failed: {code} {message}")]
    OperationFailed {
        /// The error code returned by Tor.
        code: String,
        /// The error message returned by Tor.
        message: String,
    },

    /// The request cannot be satisfied with current Tor state.
    ///
    /// This error indicates a valid request that Tor cannot fulfill due to
    /// its current state (e.g., requesting a circuit when Tor is not connected).
    ///
    /// # Recovery
    ///
    /// Wait for Tor to reach the required state, then retry.
    #[error("unsatisfiable request: {0}")]
    UnsatisfiableRequest(String),

    /// The request was malformed or invalid.
    ///
    /// This indicates a programming error - the request doesn't conform
    /// to the control protocol specification.
    ///
    /// # Recovery
    ///
    /// Fix the request format. This is not a transient error.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The request contained invalid arguments.
    ///
    /// Similar to [`InvalidRequest`](Error::InvalidRequest), but specifically
    /// for argument validation failures.
    ///
    /// # Recovery
    ///
    /// Fix the arguments. This is not a transient error.
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),

    /// Failed to parse a descriptor or other structured data.
    ///
    /// This error occurs when parsing Tor descriptors (server descriptors,
    /// consensus documents, etc.) and the data doesn't match the expected format.
    ///
    /// See [`descriptor::DescriptorError`] for specific descriptor error types.
    ///
    /// # Recovery
    ///
    /// This error is not recoverable for the specific descriptor. Log the
    /// error and skip to the next descriptor if processing multiple.
    #[cfg(feature = "descriptors")]
    #[error("descriptor parse error: {0}")]
    Descriptor(#[from] crate::descriptor::DescriptorError),

    /// Failed to parse a descriptor or other structured data (legacy).
    ///
    /// This error occurs when parsing Tor descriptors (server descriptors,
    /// consensus documents, etc.) and the data doesn't match the expected format.
    ///
    /// # Fields
    ///
    /// - `location`: Where in the data the parse error occurred
    /// - `reason`: Description of what was expected vs. found
    ///
    /// # Recovery
    ///
    /// This error is not recoverable for the specific descriptor. Log the
    /// error and skip to the next descriptor if processing multiple.
    ///
    /// # Note
    ///
    /// This variant is deprecated in favor of [`Error::Descriptor`] which provides
    /// more specific error information. It is kept for backward compatibility.
    #[error("parse error at {location}: {reason}")]
    Parse {
        /// Location in the data where parsing failed.
        location: String,
        /// Description of the parse failure.
        reason: String,
    },

    /// Failed to download a resource from the network.
    ///
    /// This error occurs when downloading descriptors or other data from
    /// directory authorities or mirrors.
    ///
    /// # Fields
    ///
    /// - `url`: The URL that failed to download
    /// - `reason`: Description of the failure
    ///
    /// # Recovery
    ///
    /// - Retry with exponential backoff
    /// - Try a different directory authority or mirror
    #[error("download failed: {url} - {reason}")]
    Download {
        /// The URL that failed to download.
        url: String,
        /// The reason for the download failure.
        reason: String,
    },

    /// Download timed out before completing.
    ///
    /// The configured timeout was reached before the download completed.
    ///
    /// # Recovery
    ///
    /// - Increase the timeout value
    /// - Try a different server
    /// - Check network connectivity
    #[error("download timeout: {url}")]
    DownloadTimeout {
        /// The URL that timed out.
        url: String,
    },

    /// A general operation timeout occurred.
    ///
    /// The operation did not complete within the expected time.
    ///
    /// # Recovery
    ///
    /// - Increase timeout if configurable
    /// - Check if Tor is responsive
    /// - Retry the operation
    #[error("timeout")]
    Timeout,

    /// The control socket was closed unexpectedly.
    ///
    /// This indicates the connection to Tor was lost. This can happen if
    /// Tor exits, the network connection is interrupted, or the socket
    /// is closed from the other end.
    ///
    /// # Recovery
    ///
    /// Reconnect to Tor and re-authenticate.
    #[error("socket closed")]
    SocketClosed,

    /// The requested descriptor is not available.
    ///
    /// Tor doesn't have the requested descriptor cached and cannot
    /// retrieve it.
    ///
    /// # Recovery
    ///
    /// - Wait and retry (descriptor may become available)
    /// - Try downloading from a different source
    #[error("descriptor unavailable: {0}")]
    DescriptorUnavailable(String),

    /// Failed to extend or create a circuit.
    ///
    /// The circuit could not be built through the requested relays.
    ///
    /// # Recovery
    ///
    /// - Try different relays
    /// - Wait for network conditions to improve
    /// - Check if the target relay is online
    #[error("circuit extension failed: {0}")]
    CircuitExtensionFailed(String),

    /// Failed to parse a socket address.
    ///
    /// This error occurs when parsing a string into a socket address fails.
    ///
    /// # Recovery
    ///
    /// Verify the address format is correct (e.g., "127.0.0.1:9051").
    #[error("address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
}

/// Authentication-specific errors.
///
/// These errors provide detailed information about why authentication
/// with Tor's control port failed.
///
/// # Authentication Methods
///
/// Tor supports several authentication methods:
///
/// - **NONE**: No authentication required (open control port)
/// - **PASSWORD**: Password-based authentication (HashedControlPassword)
/// - **COOKIE**: Cookie file authentication (CookieAuthentication)
/// - **SAFECOOKIE**: Challenge-response cookie authentication (recommended)
///
/// # Recovery Guide
///
/// | Error | Recovery Action |
/// |-------|-----------------|
/// | [`NoMethods`](AuthError::NoMethods) | Configure authentication in torrc |
/// | [`IncorrectPassword`](AuthError::IncorrectPassword) | Verify password matches HashedControlPassword |
/// | [`CookieUnreadable`](AuthError::CookieUnreadable) | Check file permissions and path |
/// | [`IncorrectCookie`](AuthError::IncorrectCookie) | Cookie file may be stale; restart Tor |
/// | [`ChallengeFailed`](AuthError::ChallengeFailed) | SAFECOOKIE protocol error; try COOKIE |
/// | [`MissingPassword`](AuthError::MissingPassword) | Provide password for PASSWORD auth |
///
/// # Example
///
/// ```rust
/// use stem_rs::AuthError;
///
/// fn handle_auth_error(err: AuthError) {
///     match err {
///         AuthError::IncorrectPassword => {
///             eprintln!("Wrong password - check your torrc HashedControlPassword");
///         }
///         AuthError::CookieUnreadable(path) => {
///             eprintln!("Cannot read cookie file: {}", path);
///             eprintln!("Check file permissions and that Tor is running");
///         }
///         AuthError::NoMethods => {
///             eprintln!("No compatible auth methods - configure torrc");
///         }
///         _ => eprintln!("Authentication error: {}", err),
///     }
/// }
/// ```
#[derive(Debug, Error)]
pub enum AuthError {
    /// No compatible authentication methods are available.
    ///
    /// Tor's PROTOCOLINFO response didn't include any authentication
    /// methods that this library supports.
    ///
    /// # Recovery
    ///
    /// Configure at least one of: CookieAuthentication, HashedControlPassword,
    /// or disable authentication entirely in torrc.
    #[error("no authentication methods available")]
    NoMethods,

    /// The provided password was incorrect.
    ///
    /// PASSWORD authentication failed because the password doesn't match
    /// the HashedControlPassword in torrc.
    ///
    /// # Recovery
    ///
    /// Verify the password matches what was used to generate HashedControlPassword.
    /// Use `tor --hash-password` to generate a new hash if needed.
    #[error("incorrect password")]
    IncorrectPassword,

    /// The cookie file could not be read.
    ///
    /// COOKIE or SAFECOOKIE authentication requires reading a cookie file,
    /// but the file couldn't be accessed.
    ///
    /// # Recovery
    ///
    /// - Verify the cookie file path is correct
    /// - Check file permissions (must be readable by your process)
    /// - Ensure Tor is running (cookie file is created on startup)
    #[error("cookie file unreadable: {0}")]
    CookieUnreadable(String),

    /// The cookie value was incorrect.
    ///
    /// The cookie file was read successfully, but Tor rejected the value.
    /// This can happen if the cookie file is stale (from a previous Tor run).
    ///
    /// # Recovery
    ///
    /// Restart Tor to generate a fresh cookie file, then retry authentication.
    #[error("incorrect cookie value")]
    IncorrectCookie,

    /// The cookie file has an incorrect size.
    ///
    /// Tor's cookie file should be exactly 32 bytes. A different size
    /// indicates file corruption or an incorrect file.
    ///
    /// # Recovery
    ///
    /// Verify you're reading the correct cookie file. Restart Tor if needed.
    #[error("incorrect cookie size")]
    IncorrectCookieSize,

    /// SAFECOOKIE challenge-response failed.
    ///
    /// The SAFECOOKIE authentication protocol failed during the
    /// challenge-response exchange.
    ///
    /// # Recovery
    ///
    /// - Fall back to COOKIE authentication if available
    /// - Verify the cookie file is current
    /// - Check for network issues between client and Tor
    #[error("safecookie challenge failed")]
    ChallengeFailed,

    /// SAFECOOKIE authentication is not supported.
    ///
    /// The Tor version doesn't support SAFECOOKIE, or it's disabled.
    ///
    /// # Recovery
    ///
    /// Use COOKIE or PASSWORD authentication instead.
    #[error("safecookie challenge unsupported")]
    ChallengeUnsupported,

    /// A security check failed during authentication.
    ///
    /// This indicates a potential security issue, such as a mismatch
    /// in expected vs. received authentication data.
    ///
    /// # Recovery
    ///
    /// This may indicate a man-in-the-middle attack. Verify your
    /// connection to Tor is secure.
    #[error("auth security failure")]
    SecurityFailure,

    /// PASSWORD authentication was requested but no password provided.
    ///
    /// The authenticate method was called without a password, but
    /// PASSWORD is the only available authentication method.
    ///
    /// # Recovery
    ///
    /// Provide a password to the authenticate method.
    #[error("missing password")]
    MissingPassword,

    /// Tor advertised unrecognized authentication methods.
    ///
    /// PROTOCOLINFO returned authentication methods this library
    /// doesn't recognize. This may indicate a newer Tor version.
    ///
    /// # Recovery
    ///
    /// Update stem-rs to a newer version that supports these methods.
    #[error("unrecognized auth methods: {0:?}")]
    UnrecognizedMethods(Vec<String>),

    /// Wrong socket type for the requested authentication.
    ///
    /// Some authentication methods are only valid for certain socket types
    /// (e.g., Unix domain sockets vs. TCP sockets).
    ///
    /// # Recovery
    ///
    /// Use a different authentication method appropriate for your socket type.
    #[error("incorrect socket type")]
    IncorrectSocketType,
}

/// Logging severity levels for Tor events.
///
/// These levels correspond to Tor's internal logging runlevels and are used
/// in log events received via the control protocol.
///
/// # Severity Order
///
/// From most to least severe: [`Err`](Runlevel::Err) > [`Warn`](Runlevel::Warn) >
/// [`Notice`](Runlevel::Notice) > [`Info`](Runlevel::Info) > [`Debug`](Runlevel::Debug)
///
/// # Example
///
/// ```rust
/// use stem_rs::Runlevel;
///
/// let level = Runlevel::Notice;
/// println!("Log level: {}", level); // Prints "NOTICE"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Runlevel {
    /// Low-level runtime information for debugging.
    ///
    /// Very verbose output useful for development and troubleshooting.
    Debug,
    /// High-level runtime information.
    ///
    /// General operational information about Tor's activities.
    Info,
    /// Information that may be helpful to the user.
    ///
    /// Normal operational messages that users might want to see.
    Notice,
    /// Non-critical issues the user should be aware of.
    ///
    /// Problems that don't prevent operation but may need attention.
    Warn,
    /// Critical issues that impair Tor's ability to function.
    ///
    /// Serious errors that may prevent normal operation.
    Err,
}

impl fmt::Display for Runlevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Runlevel::Debug => write!(f, "DEBUG"),
            Runlevel::Info => write!(f, "INFO"),
            Runlevel::Notice => write!(f, "NOTICE"),
            Runlevel::Warn => write!(f, "WARN"),
            Runlevel::Err => write!(f, "ERR"),
        }
    }
}

/// Signals that can be sent to the Tor process.
///
/// These signals control Tor's behavior and can be sent via
/// [`controller::Controller::signal`].
///
/// # Signal Pairs
///
/// Some signals have Unix signal equivalents:
/// - [`Reload`](Signal::Reload) / [`Hup`](Signal::Hup) - Reload configuration (SIGHUP)
/// - [`Shutdown`](Signal::Shutdown) / [`Int`](Signal::Int) - Graceful shutdown (SIGINT)
/// - [`Dump`](Signal::Dump) / [`Usr1`](Signal::Usr1) - Dump stats (SIGUSR1)
/// - [`Debug`](Signal::Debug) / [`Usr2`](Signal::Usr2) - Debug logging (SIGUSR2)
/// - [`Halt`](Signal::Halt) / [`Term`](Signal::Term) - Immediate exit (SIGTERM)
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::{controller::Controller, Signal};
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// # let mut controller = Controller::from_port("127.0.0.1:9051".parse().unwrap()).await?;
/// // Request new circuits for privacy
/// controller.signal(Signal::Newnym).await?;
///
/// // Clear DNS cache
/// controller.signal(Signal::ClearDnsCache).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    /// Reload configuration files.
    ///
    /// Tor will reload torrc and apply changes that can be changed at runtime.
    /// Equivalent to sending SIGHUP.
    Reload,
    /// Alias for [`Reload`](Signal::Reload).
    ///
    /// Unix SIGHUP signal equivalent.
    Hup,
    /// Controlled shutdown.
    ///
    /// Tor will close listeners and exit cleanly after current connections
    /// complete, waiting ShutdownWaitLength if configured as a relay.
    Shutdown,
    /// Alias for [`Shutdown`](Signal::Shutdown).
    ///
    /// Unix SIGINT signal equivalent.
    Int,
    /// Dump information about open connections and circuits to the log.
    ///
    /// Useful for debugging connection issues.
    Dump,
    /// Alias for [`Dump`](Signal::Dump).
    ///
    /// Unix SIGUSR1 signal equivalent.
    Usr1,
    /// Switch logging to DEBUG level.
    ///
    /// Temporarily enables debug-level logging until the next RELOAD.
    Debug,
    /// Alias for [`Debug`](Signal::Debug).
    ///
    /// Unix SIGUSR2 signal equivalent.
    Usr2,
    /// Immediate shutdown.
    ///
    /// Tor exits immediately without waiting for connections to close.
    Halt,
    /// Alias for [`Halt`](Signal::Halt).
    ///
    /// Unix SIGTERM signal equivalent.
    Term,
    /// Request new circuits for future connections.
    ///
    /// Clears the current circuit cache and builds new circuits.
    /// Also clears the DNS cache. Rate-limited to prevent abuse.
    /// Use this for privacy when you want to appear as a "new" user.
    Newnym,
    /// Clear cached DNS results.
    ///
    /// Forces Tor to re-resolve all hostnames on subsequent requests.
    ClearDnsCache,
    /// Trigger a heartbeat log message.
    ///
    /// Useful for monitoring that Tor is responsive.
    Heartbeat,
    /// Wake from dormant mode.
    ///
    /// Resumes normal operation if Tor was in dormant mode.
    /// Disables dormant mode.
    Active,
    /// Enter dormant mode.
    ///
    /// Reduces resource usage (CPU and network) when Tor is not actively needed.
    /// Tor will avoid building circuits and making network connections.
    Dormant,
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signal::Reload => write!(f, "RELOAD"),
            Signal::Hup => write!(f, "HUP"),
            Signal::Shutdown => write!(f, "SHUTDOWN"),
            Signal::Int => write!(f, "INT"),
            Signal::Dump => write!(f, "DUMP"),
            Signal::Usr1 => write!(f, "USR1"),
            Signal::Debug => write!(f, "DEBUG"),
            Signal::Usr2 => write!(f, "USR2"),
            Signal::Halt => write!(f, "HALT"),
            Signal::Term => write!(f, "TERM"),
            Signal::Newnym => write!(f, "NEWNYM"),
            Signal::ClearDnsCache => write!(f, "CLEARDNSCACHE"),
            Signal::Heartbeat => write!(f, "HEARTBEAT"),
            Signal::Active => write!(f, "ACTIVE"),
            Signal::Dormant => write!(f, "DORMANT"),
        }
    }
}

/// Flags assigned to Tor relays by directory authorities.
///
/// These flags indicate various characteristics of relays and are used
/// for path selection and relay classification.
///
/// # Flag Meanings
///
/// Flags are assigned based on relay behavior and capabilities:
/// - Performance flags: [`Fast`](Flag::Fast), [`Stable`](Flag::Stable)
/// - Role flags: [`Guard`](Flag::Guard), [`Exit`](Flag::Exit), [`Authority`](Flag::Authority)
/// - Status flags: [`Running`](Flag::Running), [`Valid`](Flag::Valid)
/// - Warning flags: [`BadExit`](Flag::BadExit), [`BadDirectory`](Flag::BadDirectory)
///
/// # Example
///
/// ```rust
/// use stem_rs::Flag;
///
/// let flag = Flag::Guard;
/// println!("Relay flag: {}", flag); // Prints "Guard"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    /// Relay is a directory authority.
    ///
    /// This relay is one of the trusted directory authorities that
    /// vote on the network consensus.
    Authority,
    /// Relay shouldn't be used as an exit due to being problematic or malicious.
    ///
    /// The relay has been flagged for bad behavior when used as an exit node.
    BadExit,
    /// Relay shouldn't be used for directory information.
    ///
    /// Note: This flag was removed from Tor but may appear in older descriptors.
    BadDirectory,
    /// Relay's exit policy makes it useful as an exit node.
    ///
    /// The relay allows exiting to a reasonable number of ports.
    Exit,
    /// Relay is suitable for high-bandwidth circuits.
    ///
    /// The relay has sufficient bandwidth for performance-sensitive traffic.
    Fast,
    /// Relay is suitable for being an entry guard (first hop).
    ///
    /// The relay is stable and fast enough to be used as a guard node.
    Guard,
    /// Relay is being used as a hidden service directory.
    ///
    /// The relay stores and serves hidden service descriptors.
    HsDir,
    /// Relay can be referred to by its nickname.
    ///
    /// The nickname is unique and verified.
    Named,
    /// Relay's Ed25519 key doesn't match the consensus.
    ///
    /// There's a mismatch in the relay's Ed25519 identity.
    NoEdConsensus,
    /// Relay is currently usable.
    ///
    /// The relay is online and responding to connections.
    Running,
    /// Relay is suitable for long-lived circuits.
    ///
    /// The relay has good uptime and is reliable for persistent connections.
    Stable,
    /// Relay descriptor is outdated and should be re-uploaded.
    ///
    /// The relay's descriptor is stale and needs to be refreshed.
    StaleDesc,
    /// Relay isn't currently bound to a nickname.
    ///
    /// The nickname is not verified or is shared with other relays.
    Unnamed,
    /// Relay supports the v2 directory protocol.
    ///
    /// The relay can serve directory information via the v2 protocol.
    V2Dir,
    /// Relay supports the v3 directory protocol.
    ///
    /// The relay can serve directory information via the v3 protocol.
    V3Dir,
    /// Relay has been validated.
    ///
    /// The relay's identity has been verified by the directory authorities.
    Valid,
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Flag::Authority => write!(f, "Authority"),
            Flag::BadExit => write!(f, "BadExit"),
            Flag::BadDirectory => write!(f, "BadDirectory"),
            Flag::Exit => write!(f, "Exit"),
            Flag::Fast => write!(f, "Fast"),
            Flag::Guard => write!(f, "Guard"),
            Flag::HsDir => write!(f, "HSDir"),
            Flag::Named => write!(f, "Named"),
            Flag::NoEdConsensus => write!(f, "NoEdConsensus"),
            Flag::Running => write!(f, "Running"),
            Flag::Stable => write!(f, "Stable"),
            Flag::StaleDesc => write!(f, "StaleDesc"),
            Flag::Unnamed => write!(f, "Unnamed"),
            Flag::V2Dir => write!(f, "V2Dir"),
            Flag::V3Dir => write!(f, "V3Dir"),
            Flag::Valid => write!(f, "Valid"),
        }
    }
}

/// Status of a circuit in the Tor network.
///
/// Circuits progress through these states during their lifecycle.
/// Tor may provide statuses not in this enum.
///
/// # Circuit Lifecycle
///
/// ```text
/// LAUNCHED -> EXTENDED -> BUILT -> CLOSED
///     |          |
///     v          v
///   FAILED    FAILED
/// ```
///
/// # Example
///
/// ```rust
/// use stem_rs::CircStatus;
///
/// let status = CircStatus::Built;
/// println!("Circuit status: {}", status); // Prints "BUILT"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircStatus {
    /// New circuit was created.
    ///
    /// The circuit has been initiated but not yet extended to any relays.
    Launched,
    /// Circuit finished being created and can accept traffic.
    ///
    /// The circuit is fully built and ready for use.
    Built,
    /// Waiting to see if there's a circuit with a better guard.
    ///
    /// Tor is evaluating whether to use this circuit or wait for a better one.
    GuardWait,
    /// Circuit has been extended by a hop.
    ///
    /// The circuit is being built and has added another relay.
    Extended,
    /// Circuit construction failed.
    ///
    /// The circuit could not be completed. See [`CircClosureReason`] for details.
    Failed,
    /// Circuit has been closed.
    ///
    /// The circuit is no longer usable. See [`CircClosureReason`] for details.
    Closed,
}

impl fmt::Display for CircStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircStatus::Launched => write!(f, "LAUNCHED"),
            CircStatus::Built => write!(f, "BUILT"),
            CircStatus::GuardWait => write!(f, "GUARD_WAIT"),
            CircStatus::Extended => write!(f, "EXTENDED"),
            CircStatus::Failed => write!(f, "FAILED"),
            CircStatus::Closed => write!(f, "CLOSED"),
        }
    }
}

/// Attributes about how a circuit is built.
///
/// These flags describe special properties of circuit construction.
/// Introduced in Tor version 0.2.3.11.
///
/// # Example
///
/// ```rust
/// use stem_rs::CircBuildFlag;
///
/// let flag = CircBuildFlag::IsInternal;
/// println!("Build flag: {}", flag); // Prints "IS_INTERNAL"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircBuildFlag {
    /// Single hop circuit to fetch directory information.
    ///
    /// A one-hop tunnel used for directory fetches, not for user traffic.
    OneHopTunnel,
    /// Circuit that won't be used for client traffic.
    ///
    /// Internal circuits are used for Tor's own operations.
    IsInternal,
    /// Circuit only includes high capacity relays.
    ///
    /// Built for bandwidth-intensive operations.
    NeedCapacity,
    /// Circuit only includes relays with high uptime.
    ///
    /// Built for long-lived connections that need stability.
    NeedUptime,
}

impl fmt::Display for CircBuildFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircBuildFlag::OneHopTunnel => write!(f, "ONEHOP_TUNNEL"),
            CircBuildFlag::IsInternal => write!(f, "IS_INTERNAL"),
            CircBuildFlag::NeedCapacity => write!(f, "NEED_CAPACITY"),
            CircBuildFlag::NeedUptime => write!(f, "NEED_UPTIME"),
        }
    }
}

/// Purpose of a circuit.
///
/// Describes what a circuit is intended for. Introduced in Tor version 0.2.1.6.
///
/// # Example
///
/// ```rust
/// use stem_rs::CircPurpose;
///
/// let purpose = CircPurpose::General;
/// println!("Circuit purpose: {}", purpose); // Prints "GENERAL"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircPurpose {
    /// General client traffic or fetching directory information.
    ///
    /// Standard circuits used for normal Tor operations.
    General,
    /// Client-side introduction point for a hidden service circuit.
    ///
    /// Used when connecting to a hidden service's introduction point.
    HsClientIntro,
    /// Client-side hidden service rendezvous circuit.
    ///
    /// Used for the rendezvous connection when accessing a hidden service.
    HsClientRend,
    /// Server-side introduction point for a hidden service circuit.
    ///
    /// Used by hidden services to establish introduction points.
    HsServiceIntro,
    /// Server-side hidden service rendezvous circuit.
    ///
    /// Used by hidden services for rendezvous connections.
    HsServiceRend,
    /// Testing to see if we're reachable as a relay.
    ///
    /// Self-test circuits to verify relay reachability.
    Testing,
    /// Circuit that was built by a controller.
    ///
    /// Explicitly created via the control protocol.
    Controller,
    /// Circuit being kept around to measure timeout.
    ///
    /// Used for circuit build time measurement.
    MeasureTimeout,
    /// Constructed in advance for hidden service vanguards.
    ///
    /// Pre-built circuits for vanguard protection.
    HsVanguards,
    /// Probing if circuits are being maliciously closed.
    ///
    /// Used to detect path bias attacks.
    PathBiasTesting,
    /// Circuit is unused but remains open to disguise closure time.
    ///
    /// Padding circuits to prevent traffic analysis.
    CircuitPadding,
}

impl fmt::Display for CircPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircPurpose::General => write!(f, "GENERAL"),
            CircPurpose::HsClientIntro => write!(f, "HS_CLIENT_INTRO"),
            CircPurpose::HsClientRend => write!(f, "HS_CLIENT_REND"),
            CircPurpose::HsServiceIntro => write!(f, "HS_SERVICE_INTRO"),
            CircPurpose::HsServiceRend => write!(f, "HS_SERVICE_REND"),
            CircPurpose::Testing => write!(f, "TESTING"),
            CircPurpose::Controller => write!(f, "CONTROLLER"),
            CircPurpose::MeasureTimeout => write!(f, "MEASURE_TIMEOUT"),
            CircPurpose::HsVanguards => write!(f, "HS_VANGUARDS"),
            CircPurpose::PathBiasTesting => write!(f, "PATH_BIAS_TESTING"),
            CircPurpose::CircuitPadding => write!(f, "CIRCUIT_PADDING"),
        }
    }
}

/// Reason that a circuit is being closed or failed to be established.
///
/// Provides detailed information about why a circuit ended.
///
/// # Example
///
/// ```rust
/// use stem_rs::CircClosureReason;
///
/// let reason = CircClosureReason::Timeout;
/// println!("Closure reason: {}", reason); // Prints "TIMEOUT"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircClosureReason {
    /// No reason given.
    None,
    /// Violation in the Tor protocol.
    ///
    /// A relay sent malformed or unexpected data.
    TorProtocol,
    /// Internal error.
    ///
    /// An internal error occurred in Tor.
    Internal,
    /// Requested by the client via a TRUNCATE command.
    ///
    /// The circuit was explicitly closed by the client.
    Requested,
    /// Relay is currently hibernating.
    ///
    /// The relay is in low-power mode and not accepting circuits.
    Hibernating,
    /// Relay is out of memory, sockets, or circuit IDs.
    ///
    /// The relay has exhausted resources.
    ResourceLimit,
    /// Unable to contact the relay.
    ///
    /// Network connectivity issue to the next hop.
    ConnectFailed,
    /// Relay had the wrong OR identification.
    ///
    /// The relay's identity key didn't match what was expected.
    OrIdentity,
    /// Connection failed after being established.
    ///
    /// The OR connection was closed unexpectedly.
    OrConnClosed,
    /// Circuit has expired.
    ///
    /// The circuit exceeded MaxCircuitDirtiness lifetime.
    Finished,
    /// Circuit construction timed out.
    ///
    /// The circuit took too long to build.
    Timeout,
    /// Circuit unexpectedly closed.
    ///
    /// The circuit was destroyed by a relay.
    Destroyed,
    /// Not enough relays to make a circuit.
    ///
    /// Insufficient relays available for path selection.
    NoPath,
    /// Requested hidden service does not exist.
    ///
    /// The onion address is invalid or the service is offline.
    NoSuchService,
    /// Same as Timeout but left open for measurement.
    ///
    /// Circuit timed out but was kept for build time measurement.
    MeasurementExpired,
    /// Introduction point is redundant with another circuit.
    ///
    /// Another circuit already serves this introduction point.
    IpNowRedundant,
}

impl fmt::Display for CircClosureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircClosureReason::None => write!(f, "NONE"),
            CircClosureReason::TorProtocol => write!(f, "TORPROTOCOL"),
            CircClosureReason::Internal => write!(f, "INTERNAL"),
            CircClosureReason::Requested => write!(f, "REQUESTED"),
            CircClosureReason::Hibernating => write!(f, "HIBERNATING"),
            CircClosureReason::ResourceLimit => write!(f, "RESOURCELIMIT"),
            CircClosureReason::ConnectFailed => write!(f, "CONNECTFAILED"),
            CircClosureReason::OrIdentity => write!(f, "OR_IDENTITY"),
            CircClosureReason::OrConnClosed => write!(f, "OR_CONN_CLOSED"),
            CircClosureReason::Finished => write!(f, "FINISHED"),
            CircClosureReason::Timeout => write!(f, "TIMEOUT"),
            CircClosureReason::Destroyed => write!(f, "DESTROYED"),
            CircClosureReason::NoPath => write!(f, "NOPATH"),
            CircClosureReason::NoSuchService => write!(f, "NOSUCHSERVICE"),
            CircClosureReason::MeasurementExpired => write!(f, "MEASUREMENT_EXPIRED"),
            CircClosureReason::IpNowRedundant => write!(f, "IP_NOW_REDUNDANT"),
        }
    }
}

/// Type of change reflected in a circuit by a CIRC_MINOR event.
///
/// These events indicate minor changes to circuits that don't affect
/// their overall status.
///
/// # Example
///
/// ```rust
/// use stem_rs::CircEvent;
///
/// let event = CircEvent::PurposeChanged;
/// println!("Circuit event: {}", event); // Prints "PURPOSE_CHANGED"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircEvent {
    /// Circuit purpose or hidden service state has changed.
    ///
    /// The circuit's intended use has been modified.
    PurposeChanged,
    /// Circuit connections are being reused for a different circuit.
    ///
    /// An existing circuit is being repurposed.
    Cannibalized,
}

impl fmt::Display for CircEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircEvent::PurposeChanged => write!(f, "PURPOSE_CHANGED"),
            CircEvent::Cannibalized => write!(f, "CANNIBALIZED"),
        }
    }
}

/// State of a hidden service circuit.
///
/// These states track the progress of hidden service connections.
/// Introduced in Tor version 0.2.3.11.
///
/// # State Prefixes
///
/// - `HSCI_*` - Client-side introduction point
/// - `HSCR_*` - Client-side rendezvous point
/// - `HSSI_*` - Service-side introduction point
/// - `HSSR_*` - Service-side rendezvous point
///
/// # Example
///
/// ```rust
/// use stem_rs::HiddenServiceState;
///
/// let state = HiddenServiceState::HscrJoined;
/// println!("HS state: {}", state); // Prints "HSCR_JOINED"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HiddenServiceState {
    /// Client connecting to the introduction point.
    HsciConnecting,
    /// Client sent INTRODUCE1 and awaiting reply.
    HsciIntroSent,
    /// Client received reply, circuit is closing.
    HsciDone,
    /// Client connecting to rendezvous point.
    HscrConnecting,
    /// Rendezvous point established, awaiting introduction.
    HscrEstablishedIdle,
    /// Introduction received, awaiting rendezvous.
    HscrEstablishedWaiting,
    /// Client connected to the hidden service.
    HscrJoined,
    /// Service connecting to introduction point.
    HssiConnecting,
    /// Service established introduction point.
    HssiEstablished,
    /// Service connecting to rendezvous point.
    HssrConnecting,
    /// Service connected to rendezvous point.
    HssrJoined,
}

impl fmt::Display for HiddenServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HiddenServiceState::HsciConnecting => write!(f, "HSCI_CONNECTING"),
            HiddenServiceState::HsciIntroSent => write!(f, "HSCI_INTRO_SENT"),
            HiddenServiceState::HsciDone => write!(f, "HSCI_DONE"),
            HiddenServiceState::HscrConnecting => write!(f, "HSCR_CONNECTING"),
            HiddenServiceState::HscrEstablishedIdle => write!(f, "HSCR_ESTABLISHED_IDLE"),
            HiddenServiceState::HscrEstablishedWaiting => write!(f, "HSCR_ESTABLISHED_WAITING"),
            HiddenServiceState::HscrJoined => write!(f, "HSCR_JOINED"),
            HiddenServiceState::HssiConnecting => write!(f, "HSSI_CONNECTING"),
            HiddenServiceState::HssiEstablished => write!(f, "HSSI_ESTABLISHED"),
            HiddenServiceState::HssrConnecting => write!(f, "HSSR_CONNECTING"),
            HiddenServiceState::HssrJoined => write!(f, "HSSR_JOINED"),
        }
    }
}

/// Status of a stream going through Tor.
///
/// Streams represent individual TCP connections tunneled through circuits.
///
/// # Example
///
/// ```rust
/// use stem_rs::StreamStatus;
///
/// let status = StreamStatus::Succeeded;
/// println!("Stream status: {}", status); // Prints "SUCCEEDED"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamStatus {
    /// Request for a new connection.
    New,
    /// Request to resolve an address.
    NewResolve,
    /// Address is being re-mapped to another.
    Remap,
    /// Sent a connect cell along a circuit.
    SentConnect,
    /// Sent a resolve cell along a circuit.
    SentResolve,
    /// Stream has been established.
    Succeeded,
    /// Stream is detached and won't be re-established.
    Failed,
    /// Stream is detached but might be re-established.
    Detached,
    /// Awaiting a controller's ATTACHSTREAM request.
    ControllerWait,
    /// Stream has closed.
    Closed,
}

impl fmt::Display for StreamStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamStatus::New => write!(f, "NEW"),
            StreamStatus::NewResolve => write!(f, "NEWRESOLVE"),
            StreamStatus::Remap => write!(f, "REMAP"),
            StreamStatus::SentConnect => write!(f, "SENTCONNECT"),
            StreamStatus::SentResolve => write!(f, "SENTRESOLVE"),
            StreamStatus::Succeeded => write!(f, "SUCCEEDED"),
            StreamStatus::Failed => write!(f, "FAILED"),
            StreamStatus::Detached => write!(f, "DETACHED"),
            StreamStatus::ControllerWait => write!(f, "CONTROLLER_WAIT"),
            StreamStatus::Closed => write!(f, "CLOSED"),
        }
    }
}

/// Reason that a stream is being closed or failed to be established.
///
/// Provides detailed information about why a stream ended.
///
/// # Example
///
/// ```rust
/// use stem_rs::StreamClosureReason;
///
/// let reason = StreamClosureReason::Done;
/// println!("Closure reason: {}", reason); // Prints "DONE"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamClosureReason {
    /// None of the other reasons apply.
    Misc,
    /// Unable to resolve the hostname.
    ResolveFailed,
    /// Remote host refused the connection.
    ConnectRefused,
    /// OR refuses to connect due to exit policy.
    ExitPolicy,
    /// Circuit is being shut down.
    Destroy,
    /// Connection has been closed normally.
    Done,
    /// Connection timed out.
    Timeout,
    /// Routing error while contacting the destination.
    NoRoute,
    /// Relay is temporarily hibernating.
    Hibernating,
    /// Internal error at the relay.
    Internal,
    /// Relay has insufficient resources.
    ResourceLimit,
    /// Connection was unexpectedly reset.
    ConnReset,
    /// Violation in the Tor protocol.
    TorProtocol,
    /// Directory info requested from non-directory relay.
    NotDirectory,
    /// Endpoint has sent a RELAY_END cell.
    End,
    /// Endpoint was a private address (127.0.0.1, 10.0.0.1, etc).
    PrivateAddr,
}

impl fmt::Display for StreamClosureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamClosureReason::Misc => write!(f, "MISC"),
            StreamClosureReason::ResolveFailed => write!(f, "RESOLVEFAILED"),
            StreamClosureReason::ConnectRefused => write!(f, "CONNECTREFUSED"),
            StreamClosureReason::ExitPolicy => write!(f, "EXITPOLICY"),
            StreamClosureReason::Destroy => write!(f, "DESTROY"),
            StreamClosureReason::Done => write!(f, "DONE"),
            StreamClosureReason::Timeout => write!(f, "TIMEOUT"),
            StreamClosureReason::NoRoute => write!(f, "NOROUTE"),
            StreamClosureReason::Hibernating => write!(f, "HIBERNATING"),
            StreamClosureReason::Internal => write!(f, "INTERNAL"),
            StreamClosureReason::ResourceLimit => write!(f, "RESOURCELIMIT"),
            StreamClosureReason::ConnReset => write!(f, "CONNRESET"),
            StreamClosureReason::TorProtocol => write!(f, "TORPROTOCOL"),
            StreamClosureReason::NotDirectory => write!(f, "NOTDIRECTORY"),
            StreamClosureReason::End => write!(f, "END"),
            StreamClosureReason::PrivateAddr => write!(f, "PRIVATE_ADDR"),
        }
    }
}

/// Cause of a stream being remapped to another address.
///
/// # Example
///
/// ```rust
/// use stem_rs::StreamSource;
///
/// let source = StreamSource::Cache;
/// println!("Stream source: {}", source); // Prints "CACHE"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamSource {
    /// Tor is remapping because of a cached answer.
    Cache,
    /// Exit relay requested the remap.
    Exit,
}

impl fmt::Display for StreamSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamSource::Cache => write!(f, "CACHE"),
            StreamSource::Exit => write!(f, "EXIT"),
        }
    }
}

/// Purpose of a stream.
///
/// Describes what the stream is being used for. Only provided with new streams.
///
/// # Example
///
/// ```rust
/// use stem_rs::StreamPurpose;
///
/// let purpose = StreamPurpose::User;
/// println!("Stream purpose: {}", purpose); // Prints "USER"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamPurpose {
    /// Fetching directory information (descriptors, consensus, etc).
    DirFetch,
    /// Uploading our descriptor to an authority.
    DirUpload,
    /// User initiated DNS request.
    DnsRequest,
    /// Checking that our directory port is reachable externally.
    DirportTest,
    /// Either relaying user traffic or not one of the above categories.
    User,
}

impl fmt::Display for StreamPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamPurpose::DirFetch => write!(f, "DIR_FETCH"),
            StreamPurpose::DirUpload => write!(f, "DIR_UPLOAD"),
            StreamPurpose::DnsRequest => write!(f, "DNS_REQUEST"),
            StreamPurpose::DirportTest => write!(f, "DIRPORT_TEST"),
            StreamPurpose::User => write!(f, "USER"),
        }
    }
}

/// Status of an OR (Onion Router) connection.
///
/// OR connections are the TLS connections between Tor relays.
///
/// # Example
///
/// ```rust
/// use stem_rs::OrStatus;
///
/// let status = OrStatus::Connected;
/// println!("OR status: {}", status); // Prints "CONNECTED"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrStatus {
    /// Received OR connection, starting server-side handshake.
    New,
    /// Launched outbound OR connection, starting client-side handshake.
    Launched,
    /// OR connection has been established.
    Connected,
    /// Attempt to establish OR connection failed.
    Failed,
    /// OR connection has been closed.
    Closed,
}

impl fmt::Display for OrStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrStatus::New => write!(f, "NEW"),
            OrStatus::Launched => write!(f, "LAUNCHED"),
            OrStatus::Connected => write!(f, "CONNECTED"),
            OrStatus::Failed => write!(f, "FAILED"),
            OrStatus::Closed => write!(f, "CLOSED"),
        }
    }
}

/// Reason that an OR connection is being closed or failed.
///
/// # Example
///
/// ```rust
/// use stem_rs::OrClosureReason;
///
/// let reason = OrClosureReason::Done;
/// println!("OR closure reason: {}", reason); // Prints "DONE"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrClosureReason {
    /// OR connection shut down cleanly.
    Done,
    /// Got ECONNREFUSED when connecting to the relay.
    ConnectRefused,
    /// Identity of the relay wasn't what we expected.
    Identity,
    /// Got ECONNRESET or similar error from relay.
    ConnectReset,
    /// Got ETIMEOUT or similar error from relay.
    Timeout,
    /// Got ENOTCONN, ENETUNREACH, ENETDOWN, EHOSTUNREACH, or similar.
    NoRoute,
    /// Got a different kind of I/O error from relay.
    IoError,
    /// Relay has insufficient resources.
    ResourceLimit,
    /// Connection refused for another reason.
    Misc,
    /// No pluggable transport was available.
    PtMissing,
}

impl fmt::Display for OrClosureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrClosureReason::Done => write!(f, "DONE"),
            OrClosureReason::ConnectRefused => write!(f, "CONNECTREFUSED"),
            OrClosureReason::Identity => write!(f, "IDENTITY"),
            OrClosureReason::ConnectReset => write!(f, "CONNECTRESET"),
            OrClosureReason::Timeout => write!(f, "TIMEOUT"),
            OrClosureReason::NoRoute => write!(f, "NOROUTE"),
            OrClosureReason::IoError => write!(f, "IOERROR"),
            OrClosureReason::ResourceLimit => write!(f, "RESOURCELIMIT"),
            OrClosureReason::Misc => write!(f, "MISC"),
            OrClosureReason::PtMissing => write!(f, "PT_MISSING"),
        }
    }
}

/// Type of guard relay usage.
///
/// # Example
///
/// ```rust
/// use stem_rs::GuardType;
///
/// let guard_type = GuardType::Entry;
/// println!("Guard type: {}", guard_type); // Prints "ENTRY"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardType {
    /// Used to connect to the Tor network (entry guard).
    Entry,
}

impl fmt::Display for GuardType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardType::Entry => write!(f, "ENTRY"),
        }
    }
}

/// Status of a guard relay.
///
/// # Example
///
/// ```rust
/// use stem_rs::GuardStatus;
///
/// let status = GuardStatus::Up;
/// println!("Guard status: {}", status); // Prints "UP"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardStatus {
    /// New guard that we weren't previously using.
    New,
    /// Removed from use as one of our guards.
    Dropped,
    /// Guard is now reachable.
    Up,
    /// Guard is now unreachable.
    Down,
    /// Consensus or relay considers this relay unusable as a guard.
    Bad,
    /// Consensus or relay considers this relay usable as a guard.
    Good,
}

impl fmt::Display for GuardStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardStatus::New => write!(f, "NEW"),
            GuardStatus::Dropped => write!(f, "DROPPED"),
            GuardStatus::Up => write!(f, "UP"),
            GuardStatus::Down => write!(f, "DOWN"),
            GuardStatus::Bad => write!(f, "BAD"),
            GuardStatus::Good => write!(f, "GOOD"),
        }
    }
}

/// Way in which the timeout value of a circuit is changing.
///
/// # Example
///
/// ```rust
/// use stem_rs::TimeoutSetType;
///
/// let timeout_type = TimeoutSetType::Computed;
/// println!("Timeout type: {}", timeout_type); // Prints "COMPUTED"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeoutSetType {
    /// Tor has computed a new timeout based on prior circuits.
    Computed,
    /// Timeout reverted to its default.
    Reset,
    /// Timeout reverted to default until network connectivity recovers.
    Suspended,
    /// Throwing out timeout value from when the network was down.
    Discard,
    /// Resumed calculations to determine the proper timeout.
    Resume,
}

impl fmt::Display for TimeoutSetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeoutSetType::Computed => write!(f, "COMPUTED"),
            TimeoutSetType::Reset => write!(f, "RESET"),
            TimeoutSetType::Suspended => write!(f, "SUSPENDED"),
            TimeoutSetType::Discard => write!(f, "DISCARD"),
            TimeoutSetType::Resume => write!(f, "RESUME"),
        }
    }
}

/// Action being taken in a HS_DESC event.
///
/// # Example
///
/// ```rust
/// use stem_rs::HsDescAction;
///
/// let action = HsDescAction::Received;
/// println!("HS_DESC action: {}", action); // Prints "RECEIVED"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HsDescAction {
    /// Uncached hidden service descriptor is being requested.
    Requested,
    /// Descriptor is being uploaded with HSPOST.
    Upload,
    /// Hidden service descriptor has been retrieved.
    Received,
    /// Descriptor was uploaded with HSPOST.
    Uploaded,
    /// Fetched descriptor was ignored (already have v0 descriptor).
    Ignore,
    /// We were unable to retrieve the descriptor.
    Failed,
    /// Hidden service descriptor was just created.
    Created,
}

impl fmt::Display for HsDescAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HsDescAction::Requested => write!(f, "REQUESTED"),
            HsDescAction::Upload => write!(f, "UPLOAD"),
            HsDescAction::Received => write!(f, "RECEIVED"),
            HsDescAction::Uploaded => write!(f, "UPLOADED"),
            HsDescAction::Ignore => write!(f, "IGNORE"),
            HsDescAction::Failed => write!(f, "FAILED"),
            HsDescAction::Created => write!(f, "CREATED"),
        }
    }
}

/// Reason for a hidden service descriptor fetch to fail.
///
/// # Example
///
/// ```rust
/// use stem_rs::HsDescReason;
///
/// let reason = HsDescReason::NotFound;
/// println!("HS_DESC reason: {}", reason); // Prints "NOT_FOUND"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HsDescReason {
    /// Descriptor was unparseable.
    BadDesc,
    /// Hidden service directory refused to provide the descriptor.
    QueryRejected,
    /// Descriptor was rejected by the hidden service directory.
    UploadRejected,
    /// Descriptor with the given identifier wasn't found.
    NotFound,
    /// No hidden service directory was found.
    QueryNoHsDir,
    /// Request was throttled (rate limited).
    QueryRateLimited,
    /// Failure type is unknown.
    Unexpected,
}

impl fmt::Display for HsDescReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HsDescReason::BadDesc => write!(f, "BAD_DESC"),
            HsDescReason::QueryRejected => write!(f, "QUERY_REJECTED"),
            HsDescReason::UploadRejected => write!(f, "UPLOAD_REJECTED"),
            HsDescReason::NotFound => write!(f, "NOT_FOUND"),
            HsDescReason::QueryNoHsDir => write!(f, "QUERY_NO_HSDIR"),
            HsDescReason::QueryRateLimited => write!(f, "QUERY_RATE_LIMITED"),
            HsDescReason::Unexpected => write!(f, "UNEXPECTED"),
        }
    }
}

/// Type of authentication for a HS_DESC event.
///
/// # Example
///
/// ```rust
/// use stem_rs::HsAuth;
///
/// let auth = HsAuth::NoAuth;
/// println!("HS auth: {}", auth); // Prints "NO_AUTH"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HsAuth {
    /// No authentication required.
    NoAuth,
    /// General hidden service authentication.
    BasicAuth,
    /// Authentication that hides service activity from unauthorized clients.
    StealthAuth,
    /// Unrecognized method of authentication.
    Unknown,
}

impl fmt::Display for HsAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HsAuth::NoAuth => write!(f, "NO_AUTH"),
            HsAuth::BasicAuth => write!(f, "BASIC_AUTH"),
            HsAuth::StealthAuth => write!(f, "STEALTH_AUTH"),
            HsAuth::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Types of events that can be subscribed to via the control protocol.
///
/// Use with [`controller::Controller::set_events`] to subscribe to events.
///
/// # Example
///
/// ```rust
/// use stem_rs::EventType;
///
/// let event = EventType::Circ;
/// println!("Event type: {}", event); // Prints "CIRC"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    /// Circuit status changed.
    Circ,
    /// Stream status changed.
    Stream,
    /// OR connection status changed.
    OrConn,
    /// Bandwidth used in the last second.
    Bw,
    /// Debug-level log message.
    Debug,
    /// Info-level log message.
    Info,
    /// Notice-level log message.
    Notice,
    /// Warning-level log message.
    Warn,
    /// Error-level log message.
    Err,
    /// New descriptors available.
    NewDesc,
    /// Address mapping changed.
    AddrMap,
    /// New descriptors uploaded to us as an authority.
    AuthDir,
    /// Our descriptor changed.
    DescChanged,
    /// General status event.
    Status,
    /// Guard status changed.
    Guard,
    /// Network status changed.
    Ns,
    /// Per-stream bandwidth.
    StreamBw,
    /// Periodic client summary (bridge/relay only).
    ClientsSeen,
    /// New consensus available.
    NewConsensus,
    /// Circuit build timeout changed.
    BuildTimeoutSet,
    /// Signal received.
    Signal,
    /// Configuration changed.
    ConfChanged,
    /// Minor circuit event.
    CircMinor,
    /// Pluggable transport launched.
    TransportLaunched,
    /// Per-connection bandwidth.
    ConnBw,
    /// Per-circuit bandwidth.
    CircBw,
    /// Cell statistics.
    CellStats,
    /// Hidden service descriptor event.
    HsDesc,
    /// Hidden service descriptor content.
    HsDescContent,
    /// Network liveness changed.
    NetworkLiveness,
    /// Pluggable transport log message.
    PtLog,
    /// Pluggable transport status.
    PtStatus,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::Circ => write!(f, "CIRC"),
            EventType::Stream => write!(f, "STREAM"),
            EventType::OrConn => write!(f, "ORCONN"),
            EventType::Bw => write!(f, "BW"),
            EventType::Debug => write!(f, "DEBUG"),
            EventType::Info => write!(f, "INFO"),
            EventType::Notice => write!(f, "NOTICE"),
            EventType::Warn => write!(f, "WARN"),
            EventType::Err => write!(f, "ERR"),
            EventType::NewDesc => write!(f, "NEWDESC"),
            EventType::AddrMap => write!(f, "ADDRMAP"),
            EventType::AuthDir => write!(f, "AUTHDIR_NEWDESCS"),
            EventType::DescChanged => write!(f, "DESCCHANGED"),
            EventType::Status => write!(f, "STATUS_GENERAL"),
            EventType::Guard => write!(f, "GUARD"),
            EventType::Ns => write!(f, "NS"),
            EventType::StreamBw => write!(f, "STREAM_BW"),
            EventType::ClientsSeen => write!(f, "CLIENTS_SEEN"),
            EventType::NewConsensus => write!(f, "NEWCONSENSUS"),
            EventType::BuildTimeoutSet => write!(f, "BUILDTIMEOUT_SET"),
            EventType::Signal => write!(f, "SIGNAL"),
            EventType::ConfChanged => write!(f, "CONF_CHANGED"),
            EventType::CircMinor => write!(f, "CIRC_MINOR"),
            EventType::TransportLaunched => write!(f, "TRANSPORT_LAUNCHED"),
            EventType::ConnBw => write!(f, "CONN_BW"),
            EventType::CircBw => write!(f, "CIRC_BW"),
            EventType::CellStats => write!(f, "CELL_STATS"),
            EventType::HsDesc => write!(f, "HS_DESC"),
            EventType::HsDescContent => write!(f, "HS_DESC_CONTENT"),
            EventType::NetworkLiveness => write!(f, "NETWORK_LIVENESS"),
            EventType::PtLog => write!(f, "PT_LOG"),
            EventType::PtStatus => write!(f, "PT_STATUS"),
        }
    }
}

/// Source of a status event.
///
/// # Example
///
/// ```rust
/// use stem_rs::StatusType;
///
/// let status = StatusType::General;
/// println!("Status type: {}", status); // Prints "GENERAL"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusType {
    /// General Tor activity, not specifically as a client or relay.
    General,
    /// Related to our activity as a Tor client.
    Client,
    /// Related to our activity as a Tor relay.
    Server,
}

impl fmt::Display for StatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatusType::General => write!(f, "GENERAL"),
            StatusType::Client => write!(f, "CLIENT"),
            StatusType::Server => write!(f, "SERVER"),
        }
    }
}

/// Purpose for a Tor connection.
///
/// # Example
///
/// ```rust
/// use stem_rs::ConnectionType;
///
/// let conn_type = ConnectionType::Or;
/// println!("Connection type: {}", conn_type); // Prints "OR"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionType {
    /// Carrying traffic within the Tor network.
    Or,
    /// Fetching or sending Tor descriptor data.
    Dir,
    /// Carrying traffic between Tor network and external destination.
    Exit,
}

impl fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionType::Or => write!(f, "OR"),
            ConnectionType::Dir => write!(f, "DIR"),
            ConnectionType::Exit => write!(f, "EXIT"),
        }
    }
}

/// Bucket categories for TB_EMPTY events.
///
/// Token buckets are used for rate limiting in Tor.
///
/// # Example
///
/// ```rust
/// use stem_rs::TokenBucket;
///
/// let bucket = TokenBucket::Global;
/// println!("Token bucket: {}", bucket); // Prints "GLOBAL"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenBucket {
    /// Global token bucket for overall bandwidth.
    Global,
    /// Relay token bucket for relay traffic.
    Relay,
    /// Bucket used for OR connections.
    OrConn,
}

impl fmt::Display for TokenBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenBucket::Global => write!(f, "GLOBAL"),
            TokenBucket::Relay => write!(f, "RELAY"),
            TokenBucket::OrConn => write!(f, "ORCONN"),
        }
    }
}

/// Actions that directory authorities take with relay descriptors.
///
/// # Example
///
/// ```rust
/// use stem_rs::AuthDescriptorAction;
///
/// let action = AuthDescriptorAction::Accepted;
/// println!("Auth action: {}", action); // Prints "ACCEPTED"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthDescriptorAction {
    /// Accepting the descriptor as the newest version.
    Accepted,
    /// Descriptor rejected without notifying the relay.
    Dropped,
    /// Relay notified that its descriptor has been rejected.
    Rejected,
}

impl fmt::Display for AuthDescriptorAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthDescriptorAction::Accepted => write!(f, "ACCEPTED"),
            AuthDescriptorAction::Dropped => write!(f, "DROPPED"),
            AuthDescriptorAction::Rejected => write!(f, "REJECTED"),
        }
    }
}

/// Bridge distribution methods.
///
/// Specifies how a bridge relay should be distributed to users.
///
/// # Example
///
/// ```rust
/// use stem_rs::BridgeDistribution;
///
/// let dist = BridgeDistribution::Https;
/// println!("Distribution: {}", dist); // Prints "https"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BridgeDistribution {
    /// Distribute via any method.
    Any,
    /// Distribute via HTTPS (bridges.torproject.org).
    Https,
    /// Distribute via email.
    Email,
    /// Distribute via Moat (built into Tor Browser).
    Moat,
    /// Distribute via Hyphae.
    Hyphae,
}

impl fmt::Display for BridgeDistribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeDistribution::Any => write!(f, "any"),
            BridgeDistribution::Https => write!(f, "https"),
            BridgeDistribution::Email => write!(f, "email"),
            BridgeDistribution::Moat => write!(f, "moat"),
            BridgeDistribution::Hyphae => write!(f, "hyphae"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runlevel_display() {
        assert_eq!(format!("{}", Runlevel::Debug), "DEBUG");
        assert_eq!(format!("{}", Runlevel::Info), "INFO");
        assert_eq!(format!("{}", Runlevel::Notice), "NOTICE");
        assert_eq!(format!("{}", Runlevel::Warn), "WARN");
        assert_eq!(format!("{}", Runlevel::Err), "ERR");
    }

    #[test]
    fn test_signal_display() {
        assert_eq!(format!("{}", Signal::Reload), "RELOAD");
        assert_eq!(format!("{}", Signal::Hup), "HUP");
        assert_eq!(format!("{}", Signal::Shutdown), "SHUTDOWN");
        assert_eq!(format!("{}", Signal::Int), "INT");
        assert_eq!(format!("{}", Signal::Dump), "DUMP");
        assert_eq!(format!("{}", Signal::Usr1), "USR1");
        assert_eq!(format!("{}", Signal::Debug), "DEBUG");
        assert_eq!(format!("{}", Signal::Usr2), "USR2");
        assert_eq!(format!("{}", Signal::Halt), "HALT");
        assert_eq!(format!("{}", Signal::Term), "TERM");
        assert_eq!(format!("{}", Signal::Newnym), "NEWNYM");
        assert_eq!(format!("{}", Signal::ClearDnsCache), "CLEARDNSCACHE");
        assert_eq!(format!("{}", Signal::Heartbeat), "HEARTBEAT");
        assert_eq!(format!("{}", Signal::Active), "ACTIVE");
        assert_eq!(format!("{}", Signal::Dormant), "DORMANT");
    }

    #[test]
    fn test_flag_display() {
        assert_eq!(format!("{}", Flag::Authority), "Authority");
        assert_eq!(format!("{}", Flag::BadExit), "BadExit");
        assert_eq!(format!("{}", Flag::BadDirectory), "BadDirectory");
        assert_eq!(format!("{}", Flag::Exit), "Exit");
        assert_eq!(format!("{}", Flag::Fast), "Fast");
        assert_eq!(format!("{}", Flag::Guard), "Guard");
        assert_eq!(format!("{}", Flag::HsDir), "HSDir");
        assert_eq!(format!("{}", Flag::Named), "Named");
        assert_eq!(format!("{}", Flag::NoEdConsensus), "NoEdConsensus");
        assert_eq!(format!("{}", Flag::Running), "Running");
        assert_eq!(format!("{}", Flag::Stable), "Stable");
        assert_eq!(format!("{}", Flag::StaleDesc), "StaleDesc");
        assert_eq!(format!("{}", Flag::Unnamed), "Unnamed");
        assert_eq!(format!("{}", Flag::V2Dir), "V2Dir");
        assert_eq!(format!("{}", Flag::V3Dir), "V3Dir");
        assert_eq!(format!("{}", Flag::Valid), "Valid");
    }

    #[test]
    fn test_circ_status_display() {
        assert_eq!(format!("{}", CircStatus::Launched), "LAUNCHED");
        assert_eq!(format!("{}", CircStatus::Built), "BUILT");
        assert_eq!(format!("{}", CircStatus::GuardWait), "GUARD_WAIT");
        assert_eq!(format!("{}", CircStatus::Extended), "EXTENDED");
        assert_eq!(format!("{}", CircStatus::Failed), "FAILED");
        assert_eq!(format!("{}", CircStatus::Closed), "CLOSED");
    }

    #[test]
    fn test_circ_build_flag_display() {
        assert_eq!(format!("{}", CircBuildFlag::OneHopTunnel), "ONEHOP_TUNNEL");
        assert_eq!(format!("{}", CircBuildFlag::IsInternal), "IS_INTERNAL");
        assert_eq!(format!("{}", CircBuildFlag::NeedCapacity), "NEED_CAPACITY");
        assert_eq!(format!("{}", CircBuildFlag::NeedUptime), "NEED_UPTIME");
    }

    #[test]
    fn test_circ_purpose_display() {
        assert_eq!(format!("{}", CircPurpose::General), "GENERAL");
        assert_eq!(format!("{}", CircPurpose::HsClientIntro), "HS_CLIENT_INTRO");
        assert_eq!(format!("{}", CircPurpose::HsClientRend), "HS_CLIENT_REND");
        assert_eq!(
            format!("{}", CircPurpose::HsServiceIntro),
            "HS_SERVICE_INTRO"
        );
        assert_eq!(format!("{}", CircPurpose::HsServiceRend), "HS_SERVICE_REND");
        assert_eq!(format!("{}", CircPurpose::Testing), "TESTING");
        assert_eq!(format!("{}", CircPurpose::Controller), "CONTROLLER");
        assert_eq!(
            format!("{}", CircPurpose::MeasureTimeout),
            "MEASURE_TIMEOUT"
        );
        assert_eq!(format!("{}", CircPurpose::HsVanguards), "HS_VANGUARDS");
        assert_eq!(
            format!("{}", CircPurpose::PathBiasTesting),
            "PATH_BIAS_TESTING"
        );
        assert_eq!(
            format!("{}", CircPurpose::CircuitPadding),
            "CIRCUIT_PADDING"
        );
    }

    #[test]
    fn test_circ_closure_reason_display() {
        assert_eq!(format!("{}", CircClosureReason::None), "NONE");
        assert_eq!(format!("{}", CircClosureReason::TorProtocol), "TORPROTOCOL");
        assert_eq!(format!("{}", CircClosureReason::Internal), "INTERNAL");
        assert_eq!(format!("{}", CircClosureReason::Requested), "REQUESTED");
        assert_eq!(format!("{}", CircClosureReason::Hibernating), "HIBERNATING");
        assert_eq!(
            format!("{}", CircClosureReason::ResourceLimit),
            "RESOURCELIMIT"
        );
        assert_eq!(
            format!("{}", CircClosureReason::ConnectFailed),
            "CONNECTFAILED"
        );
        assert_eq!(format!("{}", CircClosureReason::OrIdentity), "OR_IDENTITY");
        assert_eq!(
            format!("{}", CircClosureReason::OrConnClosed),
            "OR_CONN_CLOSED"
        );
        assert_eq!(format!("{}", CircClosureReason::Finished), "FINISHED");
        assert_eq!(format!("{}", CircClosureReason::Timeout), "TIMEOUT");
        assert_eq!(format!("{}", CircClosureReason::Destroyed), "DESTROYED");
        assert_eq!(format!("{}", CircClosureReason::NoPath), "NOPATH");
        assert_eq!(
            format!("{}", CircClosureReason::NoSuchService),
            "NOSUCHSERVICE"
        );
        assert_eq!(
            format!("{}", CircClosureReason::MeasurementExpired),
            "MEASUREMENT_EXPIRED"
        );
        assert_eq!(
            format!("{}", CircClosureReason::IpNowRedundant),
            "IP_NOW_REDUNDANT"
        );
    }

    #[test]
    fn test_circ_event_display() {
        assert_eq!(format!("{}", CircEvent::PurposeChanged), "PURPOSE_CHANGED");
        assert_eq!(format!("{}", CircEvent::Cannibalized), "CANNIBALIZED");
    }

    #[test]
    fn test_hidden_service_state_display() {
        assert_eq!(
            format!("{}", HiddenServiceState::HsciConnecting),
            "HSCI_CONNECTING"
        );
        assert_eq!(
            format!("{}", HiddenServiceState::HsciIntroSent),
            "HSCI_INTRO_SENT"
        );
        assert_eq!(format!("{}", HiddenServiceState::HsciDone), "HSCI_DONE");
        assert_eq!(
            format!("{}", HiddenServiceState::HscrConnecting),
            "HSCR_CONNECTING"
        );
        assert_eq!(
            format!("{}", HiddenServiceState::HscrEstablishedIdle),
            "HSCR_ESTABLISHED_IDLE"
        );
        assert_eq!(
            format!("{}", HiddenServiceState::HscrEstablishedWaiting),
            "HSCR_ESTABLISHED_WAITING"
        );
        assert_eq!(format!("{}", HiddenServiceState::HscrJoined), "HSCR_JOINED");
        assert_eq!(
            format!("{}", HiddenServiceState::HssiConnecting),
            "HSSI_CONNECTING"
        );
        assert_eq!(
            format!("{}", HiddenServiceState::HssiEstablished),
            "HSSI_ESTABLISHED"
        );
        assert_eq!(
            format!("{}", HiddenServiceState::HssrConnecting),
            "HSSR_CONNECTING"
        );
        assert_eq!(format!("{}", HiddenServiceState::HssrJoined), "HSSR_JOINED");
    }

    #[test]
    fn test_stream_status_display() {
        assert_eq!(format!("{}", StreamStatus::New), "NEW");
        assert_eq!(format!("{}", StreamStatus::NewResolve), "NEWRESOLVE");
        assert_eq!(format!("{}", StreamStatus::Remap), "REMAP");
        assert_eq!(format!("{}", StreamStatus::SentConnect), "SENTCONNECT");
        assert_eq!(format!("{}", StreamStatus::SentResolve), "SENTRESOLVE");
        assert_eq!(format!("{}", StreamStatus::Succeeded), "SUCCEEDED");
        assert_eq!(format!("{}", StreamStatus::Failed), "FAILED");
        assert_eq!(format!("{}", StreamStatus::Detached), "DETACHED");
        assert_eq!(
            format!("{}", StreamStatus::ControllerWait),
            "CONTROLLER_WAIT"
        );
        assert_eq!(format!("{}", StreamStatus::Closed), "CLOSED");
    }

    #[test]
    fn test_stream_closure_reason_display() {
        assert_eq!(format!("{}", StreamClosureReason::Misc), "MISC");
        assert_eq!(
            format!("{}", StreamClosureReason::ResolveFailed),
            "RESOLVEFAILED"
        );
        assert_eq!(
            format!("{}", StreamClosureReason::ConnectRefused),
            "CONNECTREFUSED"
        );
        assert_eq!(format!("{}", StreamClosureReason::ExitPolicy), "EXITPOLICY");
        assert_eq!(format!("{}", StreamClosureReason::Destroy), "DESTROY");
        assert_eq!(format!("{}", StreamClosureReason::Done), "DONE");
        assert_eq!(format!("{}", StreamClosureReason::Timeout), "TIMEOUT");
        assert_eq!(format!("{}", StreamClosureReason::NoRoute), "NOROUTE");
        assert_eq!(
            format!("{}", StreamClosureReason::Hibernating),
            "HIBERNATING"
        );
        assert_eq!(format!("{}", StreamClosureReason::Internal), "INTERNAL");
        assert_eq!(
            format!("{}", StreamClosureReason::ResourceLimit),
            "RESOURCELIMIT"
        );
        assert_eq!(format!("{}", StreamClosureReason::ConnReset), "CONNRESET");
        assert_eq!(
            format!("{}", StreamClosureReason::TorProtocol),
            "TORPROTOCOL"
        );
        assert_eq!(
            format!("{}", StreamClosureReason::NotDirectory),
            "NOTDIRECTORY"
        );
        assert_eq!(format!("{}", StreamClosureReason::End), "END");
        assert_eq!(
            format!("{}", StreamClosureReason::PrivateAddr),
            "PRIVATE_ADDR"
        );
    }

    #[test]
    fn test_stream_source_display() {
        assert_eq!(format!("{}", StreamSource::Cache), "CACHE");
        assert_eq!(format!("{}", StreamSource::Exit), "EXIT");
    }

    #[test]
    fn test_stream_purpose_display() {
        assert_eq!(format!("{}", StreamPurpose::DirFetch), "DIR_FETCH");
        assert_eq!(format!("{}", StreamPurpose::DirUpload), "DIR_UPLOAD");
        assert_eq!(format!("{}", StreamPurpose::DnsRequest), "DNS_REQUEST");
        assert_eq!(format!("{}", StreamPurpose::DirportTest), "DIRPORT_TEST");
        assert_eq!(format!("{}", StreamPurpose::User), "USER");
    }

    #[test]
    fn test_or_status_display() {
        assert_eq!(format!("{}", OrStatus::New), "NEW");
        assert_eq!(format!("{}", OrStatus::Launched), "LAUNCHED");
        assert_eq!(format!("{}", OrStatus::Connected), "CONNECTED");
        assert_eq!(format!("{}", OrStatus::Failed), "FAILED");
        assert_eq!(format!("{}", OrStatus::Closed), "CLOSED");
    }

    #[test]
    fn test_or_closure_reason_display() {
        assert_eq!(format!("{}", OrClosureReason::Done), "DONE");
        assert_eq!(
            format!("{}", OrClosureReason::ConnectRefused),
            "CONNECTREFUSED"
        );
        assert_eq!(format!("{}", OrClosureReason::Identity), "IDENTITY");
        assert_eq!(format!("{}", OrClosureReason::ConnectReset), "CONNECTRESET");
        assert_eq!(format!("{}", OrClosureReason::Timeout), "TIMEOUT");
        assert_eq!(format!("{}", OrClosureReason::NoRoute), "NOROUTE");
        assert_eq!(format!("{}", OrClosureReason::IoError), "IOERROR");
        assert_eq!(
            format!("{}", OrClosureReason::ResourceLimit),
            "RESOURCELIMIT"
        );
        assert_eq!(format!("{}", OrClosureReason::Misc), "MISC");
        assert_eq!(format!("{}", OrClosureReason::PtMissing), "PT_MISSING");
    }

    #[test]
    fn test_guard_type_display() {
        assert_eq!(format!("{}", GuardType::Entry), "ENTRY");
    }

    #[test]
    fn test_guard_status_display() {
        assert_eq!(format!("{}", GuardStatus::New), "NEW");
        assert_eq!(format!("{}", GuardStatus::Dropped), "DROPPED");
        assert_eq!(format!("{}", GuardStatus::Up), "UP");
        assert_eq!(format!("{}", GuardStatus::Down), "DOWN");
        assert_eq!(format!("{}", GuardStatus::Bad), "BAD");
        assert_eq!(format!("{}", GuardStatus::Good), "GOOD");
    }

    #[test]
    fn test_timeout_set_type_display() {
        assert_eq!(format!("{}", TimeoutSetType::Computed), "COMPUTED");
        assert_eq!(format!("{}", TimeoutSetType::Reset), "RESET");
        assert_eq!(format!("{}", TimeoutSetType::Suspended), "SUSPENDED");
        assert_eq!(format!("{}", TimeoutSetType::Discard), "DISCARD");
        assert_eq!(format!("{}", TimeoutSetType::Resume), "RESUME");
    }

    #[test]
    fn test_hs_desc_action_display() {
        assert_eq!(format!("{}", HsDescAction::Requested), "REQUESTED");
        assert_eq!(format!("{}", HsDescAction::Upload), "UPLOAD");
        assert_eq!(format!("{}", HsDescAction::Received), "RECEIVED");
        assert_eq!(format!("{}", HsDescAction::Uploaded), "UPLOADED");
        assert_eq!(format!("{}", HsDescAction::Ignore), "IGNORE");
        assert_eq!(format!("{}", HsDescAction::Failed), "FAILED");
        assert_eq!(format!("{}", HsDescAction::Created), "CREATED");
    }

    #[test]
    fn test_hs_desc_reason_display() {
        assert_eq!(format!("{}", HsDescReason::BadDesc), "BAD_DESC");
        assert_eq!(format!("{}", HsDescReason::QueryRejected), "QUERY_REJECTED");
        assert_eq!(
            format!("{}", HsDescReason::UploadRejected),
            "UPLOAD_REJECTED"
        );
        assert_eq!(format!("{}", HsDescReason::NotFound), "NOT_FOUND");
        assert_eq!(format!("{}", HsDescReason::QueryNoHsDir), "QUERY_NO_HSDIR");
        assert_eq!(
            format!("{}", HsDescReason::QueryRateLimited),
            "QUERY_RATE_LIMITED"
        );
        assert_eq!(format!("{}", HsDescReason::Unexpected), "UNEXPECTED");
    }

    #[test]
    fn test_hs_auth_display() {
        assert_eq!(format!("{}", HsAuth::NoAuth), "NO_AUTH");
        assert_eq!(format!("{}", HsAuth::BasicAuth), "BASIC_AUTH");
        assert_eq!(format!("{}", HsAuth::StealthAuth), "STEALTH_AUTH");
        assert_eq!(format!("{}", HsAuth::Unknown), "UNKNOWN");
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(format!("{}", EventType::Circ), "CIRC");
        assert_eq!(format!("{}", EventType::Stream), "STREAM");
        assert_eq!(format!("{}", EventType::OrConn), "ORCONN");
        assert_eq!(format!("{}", EventType::Bw), "BW");
        assert_eq!(format!("{}", EventType::Debug), "DEBUG");
        assert_eq!(format!("{}", EventType::Info), "INFO");
        assert_eq!(format!("{}", EventType::Notice), "NOTICE");
        assert_eq!(format!("{}", EventType::Warn), "WARN");
        assert_eq!(format!("{}", EventType::Err), "ERR");
        assert_eq!(format!("{}", EventType::NewDesc), "NEWDESC");
        assert_eq!(format!("{}", EventType::AddrMap), "ADDRMAP");
        assert_eq!(format!("{}", EventType::AuthDir), "AUTHDIR_NEWDESCS");
        assert_eq!(format!("{}", EventType::DescChanged), "DESCCHANGED");
        assert_eq!(format!("{}", EventType::Status), "STATUS_GENERAL");
        assert_eq!(format!("{}", EventType::Guard), "GUARD");
        assert_eq!(format!("{}", EventType::Ns), "NS");
        assert_eq!(format!("{}", EventType::StreamBw), "STREAM_BW");
        assert_eq!(format!("{}", EventType::ClientsSeen), "CLIENTS_SEEN");
        assert_eq!(format!("{}", EventType::NewConsensus), "NEWCONSENSUS");
        assert_eq!(
            format!("{}", EventType::BuildTimeoutSet),
            "BUILDTIMEOUT_SET"
        );
        assert_eq!(format!("{}", EventType::Signal), "SIGNAL");
        assert_eq!(format!("{}", EventType::ConfChanged), "CONF_CHANGED");
        assert_eq!(format!("{}", EventType::CircMinor), "CIRC_MINOR");
        assert_eq!(
            format!("{}", EventType::TransportLaunched),
            "TRANSPORT_LAUNCHED"
        );
        assert_eq!(format!("{}", EventType::ConnBw), "CONN_BW");
        assert_eq!(format!("{}", EventType::CircBw), "CIRC_BW");
        assert_eq!(format!("{}", EventType::CellStats), "CELL_STATS");
        assert_eq!(format!("{}", EventType::HsDesc), "HS_DESC");
        assert_eq!(format!("{}", EventType::HsDescContent), "HS_DESC_CONTENT");
        assert_eq!(
            format!("{}", EventType::NetworkLiveness),
            "NETWORK_LIVENESS"
        );
        assert_eq!(format!("{}", EventType::PtLog), "PT_LOG");
        assert_eq!(format!("{}", EventType::PtStatus), "PT_STATUS");
    }

    #[test]
    fn test_status_type_display() {
        assert_eq!(format!("{}", StatusType::General), "GENERAL");
        assert_eq!(format!("{}", StatusType::Client), "CLIENT");
        assert_eq!(format!("{}", StatusType::Server), "SERVER");
    }

    #[test]
    fn test_connection_type_display() {
        assert_eq!(format!("{}", ConnectionType::Or), "OR");
        assert_eq!(format!("{}", ConnectionType::Dir), "DIR");
        assert_eq!(format!("{}", ConnectionType::Exit), "EXIT");
    }

    #[test]
    fn test_token_bucket_display() {
        assert_eq!(format!("{}", TokenBucket::Global), "GLOBAL");
        assert_eq!(format!("{}", TokenBucket::Relay), "RELAY");
        assert_eq!(format!("{}", TokenBucket::OrConn), "ORCONN");
    }

    #[test]
    fn test_auth_descriptor_action_display() {
        assert_eq!(format!("{}", AuthDescriptorAction::Accepted), "ACCEPTED");
        assert_eq!(format!("{}", AuthDescriptorAction::Dropped), "DROPPED");
        assert_eq!(format!("{}", AuthDescriptorAction::Rejected), "REJECTED");
    }

    #[test]
    fn test_bridge_distribution_display() {
        assert_eq!(format!("{}", BridgeDistribution::Any), "any");
        assert_eq!(format!("{}", BridgeDistribution::Https), "https");
        assert_eq!(format!("{}", BridgeDistribution::Email), "email");
        assert_eq!(format!("{}", BridgeDistribution::Moat), "moat");
        assert_eq!(format!("{}", BridgeDistribution::Hyphae), "hyphae");
    }

    #[test]
    fn test_error_display() {
        let err = Error::Protocol("test error".to_string());
        assert!(format!("{}", err).contains("test error"));

        let err = Error::OperationFailed {
            code: "500".to_string(),
            message: "failed".to_string(),
        };
        assert!(format!("{}", err).contains("500"));
        assert!(format!("{}", err).contains("failed"));

        let err = Error::Parse {
            location: "line 1".to_string(),
            reason: "invalid".to_string(),
        };
        assert!(format!("{}", err).contains("line 1"));
        assert!(format!("{}", err).contains("invalid"));

        let err = Error::Download {
            url: "http://example.com".to_string(),
            reason: "timeout".to_string(),
        };
        assert!(format!("{}", err).contains("example.com"));

        let err = Error::DownloadTimeout {
            url: "http://example.com".to_string(),
        };
        assert!(format!("{}", err).contains("example.com"));

        let err = Error::Timeout;
        assert!(format!("{}", err).contains("timeout"));

        let err = Error::SocketClosed;
        assert!(format!("{}", err).contains("closed"));

        let err = Error::DescriptorUnavailable("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = Error::CircuitExtensionFailed("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = Error::UnsatisfiableRequest("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = Error::InvalidRequest("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = Error::InvalidArguments("test".to_string());
        assert!(format!("{}", err).contains("test"));
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::NoMethods;
        assert!(format!("{}", err).contains("no authentication"));

        let err = AuthError::IncorrectPassword;
        assert!(format!("{}", err).contains("password"));

        let err = AuthError::CookieUnreadable("path".to_string());
        assert!(format!("{}", err).contains("path"));

        let err = AuthError::IncorrectCookie;
        assert!(format!("{}", err).contains("cookie"));

        let err = AuthError::IncorrectCookieSize;
        assert!(format!("{}", err).contains("cookie"));

        let err = AuthError::ChallengeFailed;
        assert!(format!("{}", err).contains("challenge"));

        let err = AuthError::ChallengeUnsupported;
        assert!(format!("{}", err).contains("challenge"));

        let err = AuthError::SecurityFailure;
        assert!(format!("{}", err).contains("security"));

        let err = AuthError::MissingPassword;
        assert!(format!("{}", err).contains("password"));

        let err = AuthError::UnrecognizedMethods(vec!["test".to_string()]);
        assert!(format!("{}", err).contains("test"));

        let err = AuthError::IncorrectSocketType;
        assert!(format!("{}", err).contains("socket"));
    }

    #[test]
    fn test_enum_equality() {
        assert_eq!(Runlevel::Debug, Runlevel::Debug);
        assert_ne!(Runlevel::Debug, Runlevel::Info);

        assert_eq!(Signal::Reload, Signal::Reload);
        assert_ne!(Signal::Reload, Signal::Shutdown);

        assert_eq!(Flag::Exit, Flag::Exit);
        assert_ne!(Flag::Exit, Flag::Guard);
    }

    #[test]
    fn test_enum_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(Runlevel::Debug);
        set.insert(Runlevel::Info);
        assert!(set.contains(&Runlevel::Debug));
        assert!(!set.contains(&Runlevel::Warn));

        let mut set = HashSet::new();
        set.insert(Signal::Newnym);
        assert!(set.contains(&Signal::Newnym));
    }

    #[test]
    fn test_enum_clone() {
        let r = Runlevel::Debug;
        let r2 = r;
        assert_eq!(r, r2);

        let s = Signal::Newnym;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn test_enum_debug() {
        assert!(format!("{:?}", Runlevel::Debug).contains("Debug"));
        assert!(format!("{:?}", Signal::Newnym).contains("Newnym"));
        assert!(format!("{:?}", Flag::Exit).contains("Exit"));
    }
}
