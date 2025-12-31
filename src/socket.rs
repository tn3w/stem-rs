//! Control socket communication with Tor's control interface.
//!
//! This module provides low-level async socket communication with Tor's control
//! interface. It handles both TCP and Unix domain socket connections, with proper
//! message framing according to the Tor control protocol specification.
//!
//! # Conceptual Role
//!
//! The [`ControlSocket`] is the transport layer for the Tor control protocol. It
//! handles:
//!
//! - Establishing TCP connections to Tor's ControlPort (typically port 9051)
//! - Establishing Unix domain socket connections to Tor's ControlSocket
//! - Sending formatted control protocol messages with proper CRLF termination
//! - Receiving and parsing control protocol responses (single-line, multi-line, and data)
//! - Connection lifecycle management and status tracking
//!
//! Most users should use the high-level [`Controller`](crate::Controller) API instead
//! of this module directly. This module is primarily useful for:
//!
//! - Implementing custom control protocol extensions
//! - Low-level debugging of control protocol communication
//! - Building alternative high-level abstractions
//!
//! # Protocol Format
//!
//! The Tor control protocol uses a text-based format with CRLF line endings:
//!
//! - **Requests**: `COMMAND [ARGS]\r\n`
//! - **Single-line responses**: `STATUS MESSAGE\r\n` (space divider)
//! - **Multi-line responses**: `STATUS-LINE1\r\n STATUS-LINE2\r\n ... STATUS FINAL\r\n` (hyphen divider)
//! - **Data responses**: `STATUS+KEYWORD\r\n DATA...\r\n .\r\n` (plus divider, dot terminator)
//!
//! Status codes follow HTTP conventions:
//! - 2xx: Success
//! - 4xx: Client error (bad request)
//! - 5xx: Server error (Tor rejected the command)
//! - 6xx: Asynchronous event notification
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::ControlSocket;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! // Connect to Tor's control port
//! let addr: SocketAddr = "127.0.0.1:9051".parse().unwrap();
//! let mut socket = ControlSocket::connect_port(addr).await?;
//!
//! // Query protocol info (no authentication required)
//! socket.send("PROTOCOLINFO 1").await?;
//! let response = socket.recv().await?;
//!
//! if response.is_ok() {
//!     println!("Protocol info: {}", response.content());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! [`ControlSocket`] is `Send` but not `Sync`. The socket maintains internal
//! read/write buffers that require exclusive access. For concurrent access from
//! multiple tasks, wrap in `Arc<Mutex<ControlSocket>>` or use separate connections.
//!
//! # Platform Support
//!
//! - **TCP sockets**: Supported on all platforms
//! - **Unix domain sockets**: Supported on Unix-like systems only (Linux, macOS, BSD)
//!
//! On non-Unix platforms, [`connect_unix`](ControlSocket::connect_unix) returns
//! [`Error::Socket`](crate::Error::Socket) with `ErrorKind::Unsupported`.
//!
//! # See Also
//!
//! - [`crate::Controller`]: High-level API built on top of this socket
//! - [`crate::auth`]: Authentication methods for the control connection
//! - [`crate::protocol`]: Protocol message parsing utilities

use std::net::SocketAddr;
use std::path::Path;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::Error;

#[cfg(unix)]
use tokio::net::UnixStream;

/// A connection to Tor's control interface.
///
/// `ControlSocket` provides async communication with Tor's control port using
/// either TCP or Unix domain sockets. It handles the low-level details of the
/// control protocol including message framing and response parsing.
///
/// # Conceptual Role
///
/// This is the transport layer for all control protocol communication. It:
///
/// - Manages the underlying TCP or Unix socket connection
/// - Formats outgoing messages with proper CRLF termination
/// - Parses incoming responses according to the control protocol spec
/// - Tracks connection state and timing
///
/// # What This Type Does NOT Do
///
/// - Authentication (see [`crate::auth`])
/// - High-level command abstractions (see [`crate::Controller`])
/// - Event handling or subscription management
/// - Connection pooling or automatic reconnection
///
/// # Invariants
///
/// - After successful construction, the socket is connected and ready for I/O
/// - The socket remains valid until explicitly dropped or an I/O error occurs
/// - Messages sent are automatically terminated with CRLF if not already present
///
/// # Thread Safety
///
/// `ControlSocket` is `Send` but not `Sync`. The internal buffers require
/// exclusive access for reading and writing. For concurrent access:
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use tokio::sync::Mutex;
/// use stem_rs::ControlSocket;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
/// let shared = Arc::new(Mutex::new(socket));
///
/// // Clone Arc for each task
/// let s1 = shared.clone();
/// tokio::spawn(async move {
///     let mut sock = s1.lock().await;
///     // Use socket exclusively
/// });
/// # Ok(())
/// # }
/// ```
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::ControlSocket;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
///
/// // Send a command
/// socket.send("GETINFO version").await?;
///
/// // Receive the response
/// let response = socket.recv().await?;
/// if response.is_ok() {
///     println!("Tor version: {}", response.content());
/// }
/// # Ok(())
/// # }
/// ```
pub struct ControlSocket {
    reader: SocketReader,
    writer: SocketWriter,
    connection_time: Instant,
}

enum SocketReader {
    Tcp(BufReader<OwnedReadHalf>),
    #[cfg(unix)]
    Unix(BufReader<tokio::net::unix::OwnedReadHalf>),
}

enum SocketWriter {
    Tcp(OwnedWriteHalf),
    #[cfg(unix)]
    Unix(tokio::net::unix::OwnedWriteHalf),
}

impl ControlSocket {
    /// Connects to Tor's control port via TCP.
    ///
    /// Establishes a TCP connection to the specified address, which should be
    /// Tor's ControlPort (typically `127.0.0.1:9051` or as configured in torrc).
    ///
    /// # Preconditions
    ///
    /// - Tor must be running with a ControlPort configured
    /// - The address must be reachable from this host
    /// - No firewall rules blocking the connection
    ///
    /// # Postconditions
    ///
    /// - On success: Returns a connected socket ready for I/O
    /// - The connection time is recorded for later retrieval
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to connect to (IP and port)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Socket`](crate::Error::Socket) if:
    ///
    /// - The connection is refused (Tor not running or wrong port)
    /// - The address is unreachable (network error)
    /// - The connection times out
    /// - Any other I/O error occurs
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::ControlSocket;
    /// use std::net::SocketAddr;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// // Connect to default control port
    /// let addr: SocketAddr = "127.0.0.1:9051".parse().unwrap();
    /// let socket = ControlSocket::connect_port(addr).await?;
    ///
    /// // Or parse directly
    /// let socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_port(addr: SocketAddr) -> Result<Self, Error> {
        let stream = TcpStream::connect(addr).await?;
        let (read_half, write_half) = stream.into_split();
        Ok(Self {
            reader: SocketReader::Tcp(BufReader::new(read_half)),
            writer: SocketWriter::Tcp(write_half),
            connection_time: Instant::now(),
        })
    }

    /// Connects to Tor's control socket via Unix domain socket.
    ///
    /// Establishes a Unix domain socket connection to the specified path, which
    /// should be Tor's ControlSocket (typically `/var/run/tor/control` or as
    /// configured in torrc).
    ///
    /// # Platform Support
    ///
    /// This method is only available on Unix-like systems (Linux, macOS, BSD).
    /// On other platforms, it returns [`Error::Socket`](crate::Error::Socket)
    /// with `ErrorKind::Unsupported`.
    ///
    /// # Preconditions
    ///
    /// - Tor must be running with a ControlSocket configured
    /// - The socket file must exist and be accessible
    /// - The current process must have permission to connect to the socket
    ///
    /// # Postconditions
    ///
    /// - On success: Returns a connected socket ready for I/O
    /// - The connection time is recorded for later retrieval
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the Unix domain socket file
    ///
    /// # Errors
    ///
    /// Returns [`Error::Socket`](crate::Error::Socket) if:
    ///
    /// - The socket file does not exist
    /// - Permission denied (insufficient privileges)
    /// - The path is not a socket
    /// - Platform does not support Unix sockets
    /// - Any other I/O error occurs
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::ControlSocket;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// // Connect to default control socket
    /// let socket = ControlSocket::connect_unix(Path::new("/var/run/tor/control")).await?;
    ///
    /// // Or a custom path
    /// let socket = ControlSocket::connect_unix(Path::new("/tmp/tor/control")).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(unix)]
    pub async fn connect_unix(path: &Path) -> Result<Self, Error> {
        let stream = UnixStream::connect(path).await?;
        let (read_half, write_half) = stream.into_split();
        Ok(Self {
            reader: SocketReader::Unix(BufReader::new(read_half)),
            writer: SocketWriter::Unix(write_half),
            connection_time: Instant::now(),
        })
    }

    /// Connects to Tor's control socket via Unix domain socket (non-Unix stub).
    ///
    /// This is a stub implementation for non-Unix platforms that always returns
    /// an error indicating Unix sockets are not supported.
    ///
    /// # Errors
    ///
    /// Always returns [`Error::Socket`](crate::Error::Socket) with
    /// `ErrorKind::Unsupported` on non-Unix platforms.
    #[cfg(not(unix))]
    pub async fn connect_unix(_path: &Path) -> Result<Self, Error> {
        Err(Error::Socket(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unix sockets not supported on this platform",
        )))
    }

    /// Sends a message to the control socket.
    ///
    /// Formats and sends a control protocol message to Tor. The message is
    /// automatically terminated with CRLF (`\r\n`) if not already present.
    ///
    /// # Protocol Format
    ///
    /// Messages are sent as: `MESSAGE\r\n`
    ///
    /// For multi-line data, use the `+` prefix format manually or use the
    /// higher-level [`Controller`](crate::Controller) API.
    ///
    /// # Preconditions
    ///
    /// - The socket must be connected (not closed)
    /// - For authenticated commands, authentication must have succeeded
    ///
    /// # Postconditions
    ///
    /// - On success: The message has been written and flushed to the socket
    /// - The socket remains ready for subsequent operations
    ///
    /// # Arguments
    ///
    /// * `message` - The control protocol message to send (without CRLF)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Socket`](crate::Error::Socket) if:
    ///
    /// - The socket has been closed or disconnected
    /// - A write error occurs
    /// - The flush operation fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::ControlSocket;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
    ///
    /// // Send PROTOCOLINFO (no auth required)
    /// socket.send("PROTOCOLINFO 1").await?;
    ///
    /// // Send GETINFO (requires auth)
    /// socket.send("GETINFO version").await?;
    ///
    /// // CRLF is added automatically, but explicit is also fine
    /// socket.send("GETINFO config-file\r\n").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send(&mut self, message: &str) -> Result<(), Error> {
        let formatted = if message.ends_with("\r\n") {
            message.to_string()
        } else {
            format!("{}\r\n", message)
        };

        match &mut self.writer {
            SocketWriter::Tcp(w) => {
                w.write_all(formatted.as_bytes()).await?;
                w.flush().await?;
            }
            #[cfg(unix)]
            SocketWriter::Unix(w) => {
                w.write_all(formatted.as_bytes()).await?;
                w.flush().await?;
            }
        }
        Ok(())
    }

    /// Receives a message from the control socket.
    ///
    /// Reads and parses a complete control protocol response from Tor. This method
    /// blocks until a complete message is received, handling single-line, multi-line,
    /// and data responses according to the protocol specification.
    ///
    /// # Protocol Format
    ///
    /// Responses follow the format: `STATUS[DIVIDER]CONTENT\r\n`
    ///
    /// Where DIVIDER indicates the response type:
    /// - ` ` (space): Final line of response
    /// - `-` (hyphen): Continuation line (more lines follow)
    /// - `+` (plus): Data block follows, terminated by `.\r\n`
    ///
    /// # Response Types
    ///
    /// **Single-line response:**
    /// ```text
    /// 250 OK\r\n
    /// ```
    ///
    /// **Multi-line response:**
    /// ```text
    /// 250-version=0.4.7.1\r\n
    /// 250-config-file=/etc/tor/torrc\r\n
    /// 250 OK\r\n
    /// ```
    ///
    /// **Data response:**
    /// ```text
    /// 250+getinfo/names=\r\n
    /// accounting/bytes -- Number of bytes...\r\n
    /// accounting/enabled -- Is accounting enabled?\r\n
    /// .\r\n
    /// 250 OK\r\n
    /// ```
    ///
    /// # Postconditions
    ///
    /// - On success: Returns a complete [`ControlMessage`] with all response lines
    /// - The socket remains ready for subsequent operations
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - [`Error::SocketClosed`](crate::Error::SocketClosed): The socket was closed
    ///   before a complete message was received
    /// - [`Error::Protocol`](crate::Error::Protocol): The response is malformed:
    ///   - Line too short (less than 4 characters)
    ///   - Invalid status code (not a 3-digit number)
    ///   - Inconsistent status codes across lines
    ///   - Invalid divider character
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::ControlSocket;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
    ///
    /// socket.send("PROTOCOLINFO 1").await?;
    /// let response = socket.recv().await?;
    ///
    /// if response.is_ok() {
    ///     // Single-line content
    ///     println!("First line: {}", response.content());
    ///     
    ///     // All lines joined
    ///     println!("Full response: {}", response.all_content());
    /// } else {
    ///     println!("Error {}: {}", response.status_code, response.content());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn recv(&mut self) -> Result<ControlMessage, Error> {
        let mut lines = Vec::new();
        let mut status_code: Option<u16> = None;

        loop {
            let mut line = String::new();
            let bytes_read = match &mut self.reader {
                SocketReader::Tcp(r) => r.read_line(&mut line).await?,
                #[cfg(unix)]
                SocketReader::Unix(r) => r.read_line(&mut line).await?,
            };

            if bytes_read == 0 {
                return Err(Error::SocketClosed);
            }

            let line = line.trim_end_matches(['\r', '\n']);
            if line.len() < 4 {
                return Err(Error::Protocol(format!(
                    "response line too short: {}",
                    line
                )));
            }

            let code: u16 = line[..3]
                .parse()
                .map_err(|_| Error::Protocol(format!("invalid status code: {}", &line[..3])))?;

            match status_code {
                None => status_code = Some(code),
                Some(existing) if existing != code => {
                    return Err(Error::Protocol(format!(
                        "inconsistent status codes: {} vs {}",
                        existing, code
                    )));
                }
                _ => {}
            }

            let divider = line.chars().nth(3).unwrap_or(' ');
            let content = &line[4..];

            match divider {
                ' ' => {
                    lines.push(content.to_string());
                    break;
                }
                '-' => {
                    lines.push(content.to_string());
                }
                '+' => {
                    let mut multi_line_content = content.to_string();
                    loop {
                        let mut data_line = String::new();
                        let bytes = match &mut self.reader {
                            SocketReader::Tcp(r) => r.read_line(&mut data_line).await?,
                            #[cfg(unix)]
                            SocketReader::Unix(r) => r.read_line(&mut data_line).await?,
                        };
                        if bytes == 0 {
                            return Err(Error::SocketClosed);
                        }
                        let data_line = data_line.trim_end_matches(['\r', '\n']);
                        if data_line == "." {
                            break;
                        }
                        let unescaped = data_line.strip_prefix('.').unwrap_or(data_line);
                        if !multi_line_content.is_empty() {
                            multi_line_content.push('\n');
                        }
                        multi_line_content.push_str(unescaped);
                    }
                    lines.push(multi_line_content);
                }
                _ => {
                    return Err(Error::Protocol(format!("invalid divider: {}", divider)));
                }
            }
        }

        Ok(ControlMessage {
            status_code: status_code.unwrap_or(0),
            lines,
        })
    }

    /// Checks if the socket connection is alive.
    ///
    /// Returns whether the socket is believed to be connected. Note that this
    /// is a best-effort check and may not detect all disconnection scenarios
    /// until an actual I/O operation is attempted.
    ///
    /// # Limitations
    ///
    /// This method currently always returns `true` as the underlying socket
    /// state is not actively monitored. A disconnection will only be detected
    /// when [`send`](Self::send) or [`recv`](Self::recv) fails.
    ///
    /// For reliable disconnection detection, continuously poll with
    /// [`recv`](Self::recv) or use the higher-level
    /// [`Controller`](crate::Controller) which handles this automatically.
    ///
    /// # Returns
    ///
    /// `true` if the socket is believed to be connected, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::ControlSocket;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
    ///
    /// if socket.is_alive() {
    ///     println!("Socket is connected");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_alive(&self) -> bool {
        true
    }

    /// Returns the time when the socket connection was established.
    ///
    /// This returns the [`Instant`] when the socket was successfully connected,
    /// which can be used to calculate connection duration or implement
    /// connection timeouts.
    ///
    /// # Returns
    ///
    /// The [`Instant`] when [`connect_port`](Self::connect_port) or
    /// [`connect_unix`](Self::connect_unix) successfully completed.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::ControlSocket;
    /// use std::time::Duration;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
    ///
    /// // ... do some work ...
    ///
    /// let connected_for = socket.connection_time().elapsed();
    /// println!("Connected for {:?}", connected_for);
    ///
    /// // Implement a connection timeout
    /// if socket.connection_time().elapsed() > Duration::from_secs(3600) {
    ///     println!("Connection has been open for over an hour");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn connection_time(&self) -> Instant {
        self.connection_time
    }
}

/// A parsed control protocol response message.
///
/// `ControlMessage` represents a complete response from Tor's control interface,
/// containing the status code and all response lines. It provides methods to
/// check success/failure and access the response content.
///
/// # Protocol Format
///
/// Control protocol responses consist of:
/// - A 3-digit status code (similar to HTTP)
/// - One or more content lines
///
/// Status code ranges:
/// - **2xx**: Success (command accepted)
/// - **4xx**: Temporary failure (try again later)
/// - **5xx**: Permanent failure (command rejected)
/// - **6xx**: Asynchronous event notification
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::ControlSocket;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
///
/// socket.send("GETINFO version").await?;
/// let msg = socket.recv().await?;
///
/// // Check if successful
/// if msg.is_ok() {
///     // Get first line content
///     println!("Version: {}", msg.content());
/// } else {
///     // Handle error
///     println!("Error {}: {}", msg.status_code, msg.content());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ControlMessage {
    /// The 3-digit status code from the response.
    ///
    /// Common status codes:
    /// - `250`: Command successful
    /// - `251`: Resource exhausted
    /// - `451`: Resource temporarily unavailable
    /// - `500`: Syntax error
    /// - `510`: Unrecognized command
    /// - `515`: Authentication required/failed
    /// - `550`: Unspecified error
    /// - `650`: Asynchronous event
    pub status_code: u16,

    /// The content lines from the response.
    ///
    /// For single-line responses, this contains one element.
    /// For multi-line responses, each line is a separate element.
    /// For data responses, the data block content is included.
    pub lines: Vec<String>,
}

impl ControlMessage {
    /// Checks if the response indicates success.
    ///
    /// Returns `true` if the status code is in the 2xx range (200-299),
    /// indicating the command was accepted and executed successfully.
    ///
    /// # Returns
    ///
    /// `true` if `status_code` is between 200 and 299 inclusive.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::socket::ControlMessage;
    ///
    /// let success = ControlMessage {
    ///     status_code: 250,
    ///     lines: vec!["OK".to_string()],
    /// };
    /// assert!(success.is_ok());
    ///
    /// let error = ControlMessage {
    ///     status_code: 515,
    ///     lines: vec!["Authentication failed".to_string()],
    /// };
    /// assert!(!error.is_ok());
    /// ```
    pub fn is_ok(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }

    /// Returns the first line of response content.
    ///
    /// For most responses, this is the primary content. For multi-line
    /// responses, use [`all_content`](Self::all_content) to get all lines.
    ///
    /// # Returns
    ///
    /// The first line of content, or an empty string if there are no lines.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::socket::ControlMessage;
    ///
    /// let msg = ControlMessage {
    ///     status_code: 250,
    ///     lines: vec!["version=0.4.7.1".to_string()],
    /// };
    /// assert_eq!(msg.content(), "version=0.4.7.1");
    ///
    /// let empty = ControlMessage {
    ///     status_code: 250,
    ///     lines: vec![],
    /// };
    /// assert_eq!(empty.content(), "");
    /// ```
    pub fn content(&self) -> &str {
        self.lines.first().map(|s| s.as_str()).unwrap_or("")
    }

    /// Returns all response lines joined with newlines.
    ///
    /// Combines all content lines into a single string, separated by
    /// newline characters (`\n`). Useful for multi-line responses.
    ///
    /// # Returns
    ///
    /// All lines joined with `\n` separators.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::socket::ControlMessage;
    ///
    /// let msg = ControlMessage {
    ///     status_code: 250,
    ///     lines: vec![
    ///         "version=0.4.7.1".to_string(),
    ///         "config-file=/etc/tor/torrc".to_string(),
    ///         "OK".to_string(),
    ///     ],
    /// };
    /// assert_eq!(
    ///     msg.all_content(),
    ///     "version=0.4.7.1\nconfig-file=/etc/tor/torrc\nOK"
    /// );
    /// ```
    pub fn all_content(&self) -> String {
        self.lines.join("\n")
    }

    /// Returns the raw protocol representation of the response.
    ///
    /// Reconstructs the response in control protocol format with status
    /// codes and CRLF line endings. Useful for debugging or logging.
    ///
    /// # Returns
    ///
    /// The response formatted as it would appear on the wire.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::socket::ControlMessage;
    ///
    /// let msg = ControlMessage {
    ///     status_code: 250,
    ///     lines: vec![
    ///         "version=0.4.7.1".to_string(),
    ///         "OK".to_string(),
    ///     ],
    /// };
    /// assert_eq!(msg.raw_content(), "250-version=0.4.7.1\r\n250 OK\r\n");
    /// ```
    pub fn raw_content(&self) -> String {
        let mut result = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            if i == self.lines.len() - 1 {
                result.push_str(&format!("{} {}\r\n", self.status_code, line));
            } else {
                result.push_str(&format!("{}-{}\r\n", self.status_code, line));
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_message_is_ok() {
        let msg = ControlMessage {
            status_code: 250,
            lines: vec!["OK".to_string()],
        };
        assert!(msg.is_ok());

        let msg = ControlMessage {
            status_code: 200,
            lines: vec!["OK".to_string()],
        };
        assert!(msg.is_ok());

        let msg = ControlMessage {
            status_code: 299,
            lines: vec!["OK".to_string()],
        };
        assert!(msg.is_ok());
    }

    #[test]
    fn test_control_message_not_ok() {
        let msg = ControlMessage {
            status_code: 500,
            lines: vec!["Error".to_string()],
        };
        assert!(!msg.is_ok());

        let msg = ControlMessage {
            status_code: 515,
            lines: vec!["Authentication failed".to_string()],
        };
        assert!(!msg.is_ok());
    }

    #[test]
    fn test_control_message_content() {
        let msg = ControlMessage {
            status_code: 250,
            lines: vec!["version=0.4.7.1".to_string()],
        };
        assert_eq!(msg.content(), "version=0.4.7.1");
    }

    #[test]
    fn test_control_message_empty_content() {
        let msg = ControlMessage {
            status_code: 250,
            lines: vec![],
        };
        assert_eq!(msg.content(), "");
    }

    #[test]
    fn test_control_message_all_content() {
        let msg = ControlMessage {
            status_code: 250,
            lines: vec![
                "line1".to_string(),
                "line2".to_string(),
                "line3".to_string(),
            ],
        };
        assert_eq!(msg.all_content(), "line1\nline2\nline3");
    }

    #[test]
    fn test_control_message_status_code_ranges() {
        for code in [200, 250, 251, 299] {
            let msg = ControlMessage {
                status_code: code,
                lines: vec!["OK".to_string()],
            };
            assert!(msg.is_ok(), "Status code {} should be OK", code);
        }

        for code in [400, 450, 499] {
            let msg = ControlMessage {
                status_code: code,
                lines: vec!["Error".to_string()],
            };
            assert!(!msg.is_ok(), "Status code {} should not be OK", code);
        }

        for code in [500, 510, 515, 550, 599] {
            let msg = ControlMessage {
                status_code: code,
                lines: vec!["Error".to_string()],
            };
            assert!(!msg.is_ok(), "Status code {} should not be OK", code);
        }

        for code in [650, 651] {
            let msg = ControlMessage {
                status_code: code,
                lines: vec!["Event".to_string()],
            };
            assert!(!msg.is_ok(), "Status code {} should not be OK", code);
        }
    }

    #[test]
    fn test_control_message_multiline_content() {
        let msg = ControlMessage {
            status_code: 250,
            lines: vec![
                "First line".to_string(),
                "Second line with data".to_string(),
                "Third line".to_string(),
            ],
        };
        assert_eq!(msg.content(), "First line");
        assert_eq!(
            msg.all_content(),
            "First line\nSecond line with data\nThird line"
        );
    }

    #[test]
    fn test_control_message_single_line() {
        let msg = ControlMessage {
            status_code: 250,
            lines: vec!["Single line response".to_string()],
        };
        assert_eq!(msg.content(), "Single line response");
        assert_eq!(msg.all_content(), "Single line response");
    }

    #[test]
    fn test_control_message_clone() {
        let msg = ControlMessage {
            status_code: 250,
            lines: vec!["Test".to_string()],
        };
        let cloned = msg.clone();
        assert_eq!(msg.status_code, cloned.status_code);
        assert_eq!(msg.lines, cloned.lines);
    }

    #[test]
    fn test_control_message_debug() {
        let msg = ControlMessage {
            status_code: 250,
            lines: vec!["OK".to_string()],
        };
        let debug_str = format!("{:?}", msg);
        assert!(debug_str.contains("250"));
        assert!(debug_str.contains("OK"));
    }
}
