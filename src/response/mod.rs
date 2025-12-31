//! Response parsing for Tor control protocol messages.
//!
//! This module provides types for parsing and handling responses from Tor's control
//! protocol. The control protocol uses a text-based format where responses consist
//! of status codes, dividers, and content.
//!
//! # Overview
//!
//! The Tor control protocol response format follows this structure:
//!
//! - Single-line responses: `STATUS DIVIDER CONTENT\r\n`
//! - Multi-line responses: Multiple lines with `-` or `+` dividers, ending with ` `
//!
//! Where:
//! - `STATUS` is a 3-digit code (e.g., `250` for success, `5xx` for errors)
//! - `DIVIDER` is one of:
//!   - ` ` (space): End of response
//!   - `-`: More lines follow
//!   - `+`: Data section follows (terminated by `.\r\n`)
//! - `CONTENT` is the payload of the line
//!
//! # Primary Types
//!
//! - [`ControlMessage`]: Represents a complete control protocol response
//! - [`ControlLine`]: A single line with parsing utilities for extracting values
//! - [`SingleLineResponse`]: A simple response containing only one line
//!
//! # Response-Specific Types
//!
//! Each submodule provides specialized parsing for specific command responses:
//!
//! - [`add_onion`]: ADD_ONION response parsing
//! - [`authchallenge`]: AUTHCHALLENGE response for SAFECOOKIE authentication
//! - [`events`]: Asynchronous event parsing
//! - [`getconf`]: GETCONF response parsing
//! - [`getinfo`]: GETINFO response parsing
//! - [`mapaddress`]: MAPADDRESS response parsing
//! - [`onion_client_auth`]: ONION_CLIENT_AUTH_VIEW response parsing
//! - [`protocolinfo`]: PROTOCOLINFO response parsing
//!
//! # Example
//!
//! ```rust
//! use stem_rs::response::{ControlMessage, ControlLine};
//!
//! // Parse a simple OK response
//! let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
//! assert!(msg.is_ok());
//!
//! // Parse a multi-line GETINFO response
//! let response = "250-version=0.4.7.8\r\n250 OK\r\n";
//! let msg = ControlMessage::from_str(response, None, false).unwrap();
//! assert_eq!(msg.len(), 2);
//!
//! // Iterate over response lines
//! for line in msg.iter() {
//!     println!("Line: {}", line);
//! }
//! ```
//!
//! # Thread Safety
//!
//! [`ControlMessage`] is `Send` and `Sync`. [`ControlLine`] uses internal
//! synchronization for its mutable parsing state, making it safe to share
//! across threads.
//!
//! # See Also
//!
//! - [`crate::Controller`]: High-level API that uses these response types
//! - [`crate::socket::ControlSocket`]: Low-level socket that produces these messages
//! - [Tor Control Protocol Specification](https://spec.torproject.org/control-spec)

pub mod add_onion;
pub mod authchallenge;
pub mod events;
pub mod getconf;
pub mod getinfo;
pub mod mapaddress;
pub mod onion_client_auth;
pub mod protocolinfo;

use std::hash::{Hash, Hasher};
use std::sync::Mutex;

use crate::Error;

pub use add_onion::AddOnionResponse;
pub use authchallenge::AuthChallengeResponse;
pub use getconf::GetConfResponse;
pub use getinfo::GetInfoResponse;
pub use mapaddress::MapAddressResponse;
pub use onion_client_auth::OnionClientAuthViewResponse;
pub use protocolinfo::{AuthMethod, ProtocolInfoResponse};

/// A parsed control protocol message from Tor.
///
/// `ControlMessage` represents a complete response from Tor's control interface.
/// It handles both single-line and multi-line responses, parsing the status codes,
/// dividers, and content according to the control protocol specification.
///
/// # Response Format
///
/// Each line in a control message has the format:
/// ```text
/// STATUS DIVIDER CONTENT
/// ```
///
/// Where STATUS is a 3-digit code, DIVIDER indicates continuation, and CONTENT
/// is the payload. The parsed content is stored as tuples of `(status_code, divider, content)`.
///
/// # Status Codes
///
/// - `2xx`: Success (e.g., `250 OK`)
/// - `4xx`: Temporary failure
/// - `5xx`: Permanent failure (e.g., `552 Unrecognized key`)
/// - `6xx`: Asynchronous event notification
///
/// # Invariants
///
/// - A `ControlMessage` is never empty; construction fails if no valid lines exist
/// - The `arrived_at` timestamp is set at construction time
/// - Raw content preserves the original bytes for hashing and equality
///
/// # Thread Safety
///
/// `ControlMessage` is `Send` and `Sync`. It is immutable after construction.
///
/// # Example
///
/// ```rust
/// use stem_rs::response::ControlMessage;
///
/// // Parse a GETINFO response
/// let response = "250-version=0.4.7.8\r\n250 OK\r\n";
/// let msg = ControlMessage::from_str(response, None, false).unwrap();
///
/// // Check if successful
/// assert!(msg.is_ok());
///
/// // Access parsed content
/// let content = msg.content();
/// assert_eq!(content[0].0, "250"); // status code
/// assert_eq!(content[0].1, '-');   // divider (more lines follow)
///
/// // Iterate over lines
/// for line in msg.iter() {
///     if let Ok((key, value)) = line.clone().pop_mapping(false, false) {
///         println!("{} = {}", key, value);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ControlMessage {
    /// Parsed content as tuples of (status_code, divider, content_bytes).
    parsed_content: Vec<(String, char, Vec<u8>)>,
    /// Original raw bytes received from the socket.
    raw_content: Vec<u8>,
    /// Unix timestamp (seconds since epoch) when this message arrived.
    pub arrived_at: i64,
}

impl ControlMessage {
    /// Creates a new `ControlMessage` from pre-parsed content.
    ///
    /// This is a low-level constructor typically used internally. Most users
    /// should use [`from_str`](Self::from_str) instead.
    ///
    /// # Arguments
    ///
    /// * `parsed_content` - Vector of (status_code, divider, content) tuples
    /// * `raw_content` - Original raw bytes of the message
    /// * `arrived_at` - Optional Unix timestamp; defaults to current time if `None`
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`](crate::Error::Protocol) if `parsed_content` is empty,
    /// as control messages must contain at least one line.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlMessage;
    ///
    /// let parsed = vec![("250".to_string(), ' ', b"OK".to_vec())];
    /// let raw = b"250 OK\r\n".to_vec();
    /// let msg = ControlMessage::new(parsed, raw, None).unwrap();
    /// assert!(msg.is_ok());
    /// ```
    pub fn new(
        parsed_content: Vec<(String, char, Vec<u8>)>,
        raw_content: Vec<u8>,
        arrived_at: Option<i64>,
    ) -> Result<Self, Error> {
        if parsed_content.is_empty() {
            return Err(Error::Protocol(
                "ControlMessages can't be empty".to_string(),
            ));
        }
        Ok(Self {
            parsed_content,
            raw_content,
            arrived_at: arrived_at.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            }),
        })
    }

    /// Parses a control message from a string.
    ///
    /// This is the primary way to create a `ControlMessage` from raw protocol data.
    /// It handles both single-line and multi-line responses, including data sections.
    ///
    /// # Arguments
    ///
    /// * `content` - The raw message string to parse
    /// * `msg_type` - Optional response type for validation (e.g., "SINGLELINE", "GETINFO")
    /// * `normalize` - If `true`, ensures proper `\r\n` line endings
    ///
    /// # Normalization
    ///
    /// When `normalize` is `true`:
    /// - Adds a trailing newline if missing
    /// - Converts `\n` to `\r\n` (CRLF) as required by the protocol
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`](crate::Error::Protocol) if:
    /// - The content contains no valid control protocol lines
    /// - The specified `msg_type` validation fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlMessage;
    ///
    /// // Parse without normalization (content already has \r\n)
    /// let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
    ///
    /// // Parse with normalization (adds \r\n if needed)
    /// let msg = ControlMessage::from_str("250 OK", None, true).unwrap();
    ///
    /// // Parse and validate as single-line response
    /// let msg = ControlMessage::from_str("250 OK\r\n", Some("SINGLELINE"), false).unwrap();
    /// ```
    pub fn from_str(content: &str, msg_type: Option<&str>, normalize: bool) -> Result<Self, Error> {
        let mut content_bytes = content.as_bytes().to_vec();

        if normalize {
            if !content_bytes.ends_with(b"\n") {
                content_bytes.push(b'\n');
            }
            let mut normalized = Vec::with_capacity(content_bytes.len() * 2);
            let mut i = 0;
            while i < content_bytes.len() {
                if content_bytes[i] == b'\n' {
                    if i == 0 || content_bytes[i - 1] != b'\r' {
                        normalized.push(b'\r');
                    }
                    normalized.push(b'\n');
                } else {
                    normalized.push(content_bytes[i]);
                }
                i += 1;
            }
            content_bytes = normalized;
        }

        let raw_content = content_bytes.clone();
        let parsed_content = Self::parse_content(&content_bytes)?;

        let mut msg = Self::new(parsed_content, raw_content, None)?;

        if let Some(response_type) = msg_type {
            msg = convert(response_type, msg)?;
        }

        Ok(msg)
    }

    fn parse_content(content: &[u8]) -> Result<Vec<(String, char, Vec<u8>)>, Error> {
        let mut result = Vec::new();
        let content_str = String::from_utf8_lossy(content);

        for line in content_str.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.len() < 3 {
                continue;
            }

            let status_code = &line[..3];
            let divider = line.chars().nth(3).unwrap_or(' ');
            let line_content = if line.len() > 4 { &line[4..] } else { "" };

            if divider == '+' {
                let mut data_content = Vec::new();
                let mut in_data = false;
                let mut data_lines = Vec::new();

                for data_line in content_str
                    .lines()
                    .skip_while(|l| !l.starts_with(&format!("{}+", status_code)))
                {
                    if data_line.starts_with(&format!("{}+", status_code)) {
                        in_data = true;
                        let key = if data_line.len() > 4 {
                            &data_line[4..]
                        } else {
                            ""
                        };
                        if let Some(eq_pos) = key.find('=') {
                            data_content.extend_from_slice(&key.as_bytes()[..=eq_pos]);
                            data_content.push(b'\n');
                        }
                        continue;
                    }
                    if in_data {
                        if data_line == "." {
                            break;
                        }
                        let unescaped = data_line.strip_prefix('.').unwrap_or(data_line);
                        data_lines.push(unescaped.to_string());
                    }
                }

                if !data_lines.is_empty() {
                    data_content.extend_from_slice(data_lines.join("\n").as_bytes());
                }

                result.push((status_code.to_string(), divider, data_content));
            } else {
                result.push((
                    status_code.to_string(),
                    divider,
                    line_content.as_bytes().to_vec(),
                ));
            }
        }

        if result.is_empty() {
            return Err(Error::Protocol(
                "No valid lines in control message".to_string(),
            ));
        }

        Ok(result)
    }

    /// Checks if the response indicates success.
    ///
    /// A response is considered successful if any of its lines has a status code
    /// in the 2xx range (200-299). This is the standard success range in the
    /// Tor control protocol.
    ///
    /// # Returns
    ///
    /// `true` if at least one line has a 2xx status code, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlMessage;
    ///
    /// let ok = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
    /// assert!(ok.is_ok());
    ///
    /// let err = ControlMessage::from_str("552 Unrecognized key\r\n", None, false).unwrap();
    /// assert!(!err.is_ok());
    /// ```
    pub fn is_ok(&self) -> bool {
        for (code, _, _) in &self.parsed_content {
            if let Ok(code_num) = code.parse::<u16>() {
                if (200..300).contains(&code_num) {
                    return true;
                }
            }
        }
        false
    }

    /// Returns the parsed content as string tuples.
    ///
    /// Each tuple contains:
    /// - Status code (e.g., "250", "552", "650")
    /// - Divider character (` `, `-`, or `+`)
    /// - Content as a UTF-8 string (lossy conversion from bytes)
    ///
    /// # Returns
    ///
    /// A vector of `(status_code, divider, content)` tuples.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlMessage;
    ///
    /// let msg = ControlMessage::from_str("250-version=0.4.7.8\r\n250 OK\r\n", None, false).unwrap();
    /// let content = msg.content();
    ///
    /// assert_eq!(content[0].0, "250");
    /// assert_eq!(content[0].1, '-');
    /// assert!(content[0].2.starts_with("version="));
    ///
    /// assert_eq!(content[1].0, "250");
    /// assert_eq!(content[1].1, ' ');
    /// assert_eq!(content[1].2, "OK");
    /// ```
    pub fn content(&self) -> Vec<(String, char, String)> {
        self.parsed_content
            .iter()
            .map(|(code, div, content)| {
                (
                    code.clone(),
                    *div,
                    String::from_utf8_lossy(content).to_string(),
                )
            })
            .collect()
    }

    /// Returns the parsed content with raw bytes.
    ///
    /// Similar to [`content`](Self::content), but preserves the original bytes
    /// without UTF-8 conversion. Useful when handling binary data or when
    /// exact byte preservation is required.
    ///
    /// # Returns
    ///
    /// A slice of `(status_code, divider, content_bytes)` tuples.
    pub fn content_bytes(&self) -> &[(String, char, Vec<u8>)] {
        &self.parsed_content
    }

    /// Returns the original raw bytes of the message.
    ///
    /// This is the unmodified data as received from the control socket,
    /// including all protocol formatting (`\r\n`, status codes, etc.).
    ///
    /// # Returns
    ///
    /// A byte slice of the original message data.
    pub fn raw_content(&self) -> &[u8] {
        &self.raw_content
    }

    /// Returns the raw content as a UTF-8 string.
    ///
    /// Performs lossy UTF-8 conversion, replacing invalid sequences with
    /// the Unicode replacement character (U+FFFD).
    ///
    /// # Returns
    ///
    /// The raw message content as a string.
    pub fn raw_content_str(&self) -> String {
        String::from_utf8_lossy(&self.raw_content).to_string()
    }

    /// Returns an iterator over the message lines as [`ControlLine`] instances.
    ///
    /// Each [`ControlLine`] provides parsing utilities for extracting values,
    /// key-value mappings, and quoted strings from the line content.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlMessage;
    ///
    /// let msg = ControlMessage::from_str(
    ///     "250-version=0.4.7.8\r\n250 OK\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    ///
    /// for line in msg.iter() {
    ///     println!("Line: {}", line);
    /// }
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = ControlLine> + '_ {
        self.parsed_content
            .iter()
            .map(|(_, _, content)| ControlLine::new(&String::from_utf8_lossy(content)))
    }

    /// Returns the number of lines in the message.
    ///
    /// # Returns
    ///
    /// The count of parsed lines. Always at least 1 for valid messages.
    pub fn len(&self) -> usize {
        self.parsed_content.len()
    }

    /// Checks if the message has no lines.
    ///
    /// # Returns
    ///
    /// `true` if the message is empty, `false` otherwise.
    ///
    /// # Note
    ///
    /// Valid `ControlMessage` instances are never empty; this method exists
    /// for API completeness with `len()`.
    pub fn is_empty(&self) -> bool {
        self.parsed_content.is_empty()
    }

    /// Returns the line at the specified index as a [`ControlLine`].
    ///
    /// # Arguments
    ///
    /// * `index` - Zero-based index of the line to retrieve
    ///
    /// # Returns
    ///
    /// `Some(ControlLine)` if the index is valid, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlMessage;
    ///
    /// let msg = ControlMessage::from_str("250-first\r\n250 second\r\n", None, false).unwrap();
    ///
    /// assert!(msg.get(0).is_some());
    /// assert!(msg.get(1).is_some());
    /// assert!(msg.get(2).is_none());
    /// ```
    pub fn get(&self, index: usize) -> Option<ControlLine> {
        self.parsed_content
            .get(index)
            .map(|(_, _, content)| ControlLine::new(&String::from_utf8_lossy(content)))
    }
}

impl PartialEq for ControlMessage {
    fn eq(&self, other: &Self) -> bool {
        self.raw_content == other.raw_content
    }
}

impl Eq for ControlMessage {}

impl Hash for ControlMessage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw_content.hash(state);
    }
}

impl std::fmt::Display for ControlMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lines: Vec<String> = self.iter().map(|line| line.to_string()).collect();
        write!(f, "{}", lines.join("\n"))
    }
}

impl std::ops::Index<usize> for ControlMessage {
    type Output = str;

    fn index(&self, _index: usize) -> &Self::Output {
        panic!("Use get() method instead for safe access")
    }
}

/// A single line from a control protocol response with parsing utilities.
///
/// `ControlLine` provides methods for parsing space-delimited entries from
/// control protocol response lines. It maintains internal state to track
/// the unparsed remainder, allowing sequential extraction of values.
///
/// # Parsing Model
///
/// The line is treated as a sequence of space-separated entries that can be
/// "popped" from left to right. Each pop operation:
/// 1. Extracts the next entry (optionally handling quotes and escapes)
/// 2. Updates the internal remainder to exclude the extracted entry
/// 3. Returns the extracted value
///
/// # Entry Types
///
/// - **Simple values**: Space-separated tokens (e.g., `PROTOCOLINFO 1`)
/// - **Quoted values**: Values enclosed in double quotes (e.g., `"hello world"`)
/// - **Key-value mappings**: `KEY=VALUE` pairs (e.g., `Tor="0.4.7.8"`)
/// - **Escaped values**: Values with backslash escapes (e.g., `"path\\to\\file"`)
///
/// # Thread Safety
///
/// `ControlLine` uses internal synchronization (`Mutex`) for its mutable
/// parsing state, making it safe to share across threads. However, concurrent
/// pops from multiple threads will produce unpredictable results.
///
/// # Example
///
/// ```rust
/// use stem_rs::response::ControlLine;
///
/// let mut line = ControlLine::new("AUTH METHODS=COOKIE,PASSWORD VERSION=\"1.0\"");
///
/// // Pop simple value
/// assert_eq!(line.pop(false, false).unwrap(), "AUTH");
///
/// // Pop key-value mapping
/// let (key, value) = line.pop_mapping(false, false).unwrap();
/// assert_eq!(key, "METHODS");
/// assert_eq!(value, "COOKIE,PASSWORD");
///
/// // Pop quoted key-value mapping
/// let (key, value) = line.pop_mapping(true, false).unwrap();
/// assert_eq!(key, "VERSION");
/// assert_eq!(value, "1.0");
///
/// assert!(line.is_empty());
/// ```
#[derive(Debug)]
pub struct ControlLine {
    /// The original content of the line (immutable).
    content: String,
    /// The unparsed remainder (mutable via Mutex).
    remainder: Mutex<String>,
}

impl Clone for ControlLine {
    fn clone(&self) -> Self {
        Self {
            content: self.content.clone(),
            remainder: Mutex::new(self.remainder.lock().unwrap().clone()),
        }
    }
}

impl ControlLine {
    /// Creates a new `ControlLine` from the given content.
    ///
    /// The entire content is initially available as the remainder for parsing.
    ///
    /// # Arguments
    ///
    /// * `content` - The line content to parse
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlLine;
    ///
    /// let line = ControlLine::new("KEY=value more data");
    /// assert_eq!(line.remainder(), "KEY=value more data");
    /// ```
    pub fn new(content: &str) -> Self {
        Self {
            content: content.to_string(),
            remainder: Mutex::new(content.to_string()),
        }
    }

    /// Returns the unparsed remainder of the line.
    ///
    /// This is the portion of the line that hasn't been consumed by
    /// [`pop`](Self::pop) or [`pop_mapping`](Self::pop_mapping) calls.
    ///
    /// # Returns
    ///
    /// The remaining unparsed content as a string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlLine;
    ///
    /// let mut line = ControlLine::new("first second third");
    /// assert_eq!(line.remainder(), "first second third");
    ///
    /// line.pop(false, false).unwrap();
    /// assert_eq!(line.remainder(), "second third");
    /// ```
    pub fn remainder(&self) -> String {
        self.remainder.lock().unwrap().clone()
    }

    /// Checks if there is no remaining content to parse.
    ///
    /// # Returns
    ///
    /// `true` if the remainder is empty, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlLine;
    ///
    /// let mut line = ControlLine::new("single");
    /// assert!(!line.is_empty());
    ///
    /// line.pop(false, false).unwrap();
    /// assert!(line.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.remainder.lock().unwrap().is_empty()
    }

    /// Checks if the next entry is a quoted value.
    ///
    /// A quoted value starts with a double quote (`"`) and has a matching
    /// closing quote.
    ///
    /// # Arguments
    ///
    /// * `escaped` - If `true`, handles backslash-escaped quotes within the value
    ///
    /// # Returns
    ///
    /// `true` if the next entry can be parsed as a quoted value, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlLine;
    ///
    /// let line = ControlLine::new("\"quoted value\" unquoted");
    /// assert!(line.is_next_quoted(false));
    ///
    /// let line = ControlLine::new("unquoted \"quoted\"");
    /// assert!(!line.is_next_quoted(false));
    /// ```
    pub fn is_next_quoted(&self, escaped: bool) -> bool {
        let remainder = self.remainder.lock().unwrap();
        let trimmed = remainder.trim_start();
        if !trimmed.starts_with('"') {
            return false;
        }
        let (start, end) = get_quote_indices(trimmed, escaped);
        start == 0 && end != -1
    }

    /// Checks if the next entry is a KEY=VALUE mapping.
    ///
    /// # Arguments
    ///
    /// * `key` - If `Some`, checks that the key matches this specific value
    /// * `quoted` - If `true`, checks that the value is quoted
    /// * `escaped` - If `true`, handles backslash escapes in quoted values
    ///
    /// # Returns
    ///
    /// `true` if the next entry is a valid KEY=VALUE mapping matching the criteria.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlLine;
    ///
    /// let line = ControlLine::new("KEY=value OTHER=stuff");
    ///
    /// // Check for any mapping
    /// assert!(line.is_next_mapping(None, false, false));
    ///
    /// // Check for specific key
    /// assert!(line.is_next_mapping(Some("KEY"), false, false));
    /// assert!(!line.is_next_mapping(Some("OTHER"), false, false));
    ///
    /// // Check for quoted value
    /// let line = ControlLine::new("KEY=\"quoted\"");
    /// assert!(line.is_next_mapping(Some("KEY"), true, false));
    /// ```
    pub fn is_next_mapping(&self, key: Option<&str>, quoted: bool, escaped: bool) -> bool {
        let remainder = self.remainder.lock().unwrap();
        let trimmed = remainder.trim_start();

        if let Some(eq_pos) = trimmed.find('=') {
            let actual_key = &trimmed[..eq_pos];
            if let Some(expected_key) = key {
                if actual_key != expected_key {
                    return false;
                }
            }
            if quoted {
                let after_eq = &trimmed[eq_pos + 1..];
                let (start, end) = get_quote_indices(after_eq, escaped);
                start == 0 && end != -1
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Returns the key of the next entry without consuming it.
    ///
    /// If the next entry is a KEY=VALUE mapping, returns the key portion.
    /// Otherwise returns `None`.
    ///
    /// # Returns
    ///
    /// `Some(key)` if the next entry is a mapping, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlLine;
    ///
    /// let line = ControlLine::new("MYKEY=myvalue");
    /// assert_eq!(line.peek_key(), Some("MYKEY".to_string()));
    ///
    /// let line = ControlLine::new("no_equals_here");
    /// assert!(line.peek_key().is_none());
    /// ```
    pub fn peek_key(&self) -> Option<String> {
        let remainder = self.remainder.lock().unwrap();
        let trimmed = remainder.trim_start();
        trimmed.find('=').map(|pos| trimmed[..pos].to_string())
    }

    /// Removes and returns the next space-separated entry.
    ///
    /// This method extracts the next entry from the remainder, handling
    /// optional quoting and escape sequences.
    ///
    /// # Arguments
    ///
    /// * `quoted` - If `true`, parses the entry as a quoted value (removes quotes)
    /// * `escaped` - If `true`, processes backslash escape sequences
    ///
    /// # Escape Sequences
    ///
    /// When `escaped` is `true`, the following sequences are processed:
    /// - `\\n` → newline
    /// - `\\r` → carriage return
    /// - `\\t` → tab
    /// - `\\\\` → backslash
    /// - `\\"` → double quote
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`](crate::Error::Protocol) if:
    /// - No remaining content to parse
    /// - `quoted` is `true` but the next entry isn't quoted
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlLine;
    ///
    /// let mut line = ControlLine::new("\"We're all mad here.\" says the cat.");
    ///
    /// // Pop quoted value
    /// assert_eq!(line.pop(true, false).unwrap(), "We're all mad here.");
    ///
    /// // Pop unquoted value
    /// assert_eq!(line.pop(false, false).unwrap(), "says");
    ///
    /// // Check remainder
    /// assert_eq!(line.remainder(), "the cat.");
    /// ```
    pub fn pop(&mut self, quoted: bool, escaped: bool) -> Result<String, Error> {
        let mut remainder = self.remainder.lock().unwrap();
        let trimmed = remainder.trim_start();

        if trimmed.is_empty() {
            return Err(Error::Protocol("no remaining content to parse".to_string()));
        }

        let (entry, new_remainder) = parse_entry(trimmed, quoted, escaped, false)?;
        *remainder = new_remainder;
        Ok(entry)
    }

    /// Removes and returns the next entry as a KEY=VALUE mapping.
    ///
    /// Parses the next entry expecting a `KEY=VALUE` format and returns
    /// both the key and value as separate strings.
    ///
    /// # Arguments
    ///
    /// * `quoted` - If `true`, the value is expected to be quoted
    /// * `escaped` - If `true`, processes backslash escape sequences in the value
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`](crate::Error::Protocol) if:
    /// - No remaining content to parse
    /// - The next entry isn't a KEY=VALUE mapping
    /// - `quoted` is `true` but the value isn't quoted
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlLine;
    ///
    /// let mut line = ControlLine::new("Tor=\"0.4.7.8\" other=value");
    ///
    /// // Pop quoted mapping
    /// let (key, value) = line.pop_mapping(true, false).unwrap();
    /// assert_eq!(key, "Tor");
    /// assert_eq!(value, "0.4.7.8");
    ///
    /// // Pop unquoted mapping
    /// let (key, value) = line.pop_mapping(false, false).unwrap();
    /// assert_eq!(key, "other");
    /// assert_eq!(value, "value");
    /// ```
    pub fn pop_mapping(&mut self, quoted: bool, escaped: bool) -> Result<(String, String), Error> {
        self.pop_mapping_impl(quoted, escaped, false)
    }

    /// Removes and returns the next entry as a KEY=VALUE mapping with raw bytes.
    ///
    /// Similar to [`pop_mapping`](Self::pop_mapping), but returns the value as
    /// raw bytes instead of a string. Useful when the value may contain binary
    /// data or when exact byte preservation is required.
    ///
    /// # Arguments
    ///
    /// * `quoted` - If `true`, the value is expected to be quoted
    /// * `escaped` - If `true`, processes backslash escape sequences in the value
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`](crate::Error::Protocol) if:
    /// - No remaining content to parse
    /// - The next entry isn't a KEY=VALUE mapping
    /// - `quoted` is `true` but the value isn't quoted
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::ControlLine;
    ///
    /// let mut line = ControlLine::new("DATA=binary_content");
    /// let (key, value_bytes) = line.pop_mapping_bytes(false, false).unwrap();
    /// assert_eq!(key, "DATA");
    /// assert_eq!(value_bytes, b"binary_content");
    /// ```
    pub fn pop_mapping_bytes(
        &mut self,
        quoted: bool,
        escaped: bool,
    ) -> Result<(String, Vec<u8>), Error> {
        let mut remainder = self.remainder.lock().unwrap();
        let trimmed = remainder.trim_start();

        if trimmed.is_empty() {
            return Err(Error::Protocol("no remaining content to parse".to_string()));
        }

        let eq_pos = trimmed.find('=').ok_or_else(|| {
            Error::Protocol(format!(
                "the next entry isn't a KEY=VALUE mapping: {}",
                trimmed
            ))
        })?;

        let key = trimmed[..eq_pos].to_string();
        let after_eq = &trimmed[eq_pos + 1..];

        let (entry, new_remainder) = parse_entry(after_eq, quoted, escaped, true)?;
        *remainder = new_remainder;
        Ok((key, entry.into_bytes()))
    }

    /// Internal implementation for pop_mapping variants.
    fn pop_mapping_impl(
        &mut self,
        quoted: bool,
        escaped: bool,
        get_bytes: bool,
    ) -> Result<(String, String), Error> {
        let mut remainder = self.remainder.lock().unwrap();
        let trimmed = remainder.trim_start();

        if trimmed.is_empty() {
            return Err(Error::Protocol("no remaining content to parse".to_string()));
        }

        let eq_pos = trimmed.find('=').ok_or_else(|| {
            Error::Protocol(format!(
                "the next entry isn't a KEY=VALUE mapping: {}",
                trimmed
            ))
        })?;

        let key = trimmed[..eq_pos].to_string();
        let after_eq = &trimmed[eq_pos + 1..];

        let (entry, new_remainder) = parse_entry(after_eq, quoted, escaped, get_bytes)?;
        *remainder = new_remainder;
        Ok((key, entry))
    }
}

impl std::fmt::Display for ControlLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.content)
    }
}

impl AsRef<str> for ControlLine {
    fn as_ref(&self) -> &str {
        &self.content
    }
}

/// Parses an entry from a line, handling quoting and escaping.
fn parse_entry(
    line: &str,
    quoted: bool,
    escaped: bool,
    _get_bytes: bool,
) -> Result<(String, String), Error> {
    if line.is_empty() {
        return Err(Error::Protocol("no remaining content to parse".to_string()));
    }

    let (next_entry, remainder) = if quoted {
        let (start, end) = get_quote_indices(line, escaped);
        if start != 0 || end == -1 {
            return Err(Error::Protocol(format!(
                "the next entry isn't a quoted value: {}",
                line
            )));
        }
        let end = end as usize;
        let entry = &line[1..end];
        let rest = &line[end + 1..];
        (entry.to_string(), rest.trim_start().to_string())
    } else if let Some(space_pos) = line.find(' ') {
        (
            line[..space_pos].to_string(),
            line[space_pos + 1..].to_string(),
        )
    } else {
        (line.to_string(), String::new())
    };

    let result = if escaped {
        unescape_string(&next_entry)
    } else {
        next_entry
    };

    Ok((result, remainder))
}

/// Finds the indices of the next two quote characters in a line.
///
/// Returns (-1, -1) if quotes are not found. When `escaped` is true,
/// skips over backslash-escaped quotes.
fn get_quote_indices(line: &str, escaped: bool) -> (i32, i32) {
    let bytes = line.as_bytes();
    let mut indices = [-1i32, -1i32];
    let mut quote_index: i32 = -1;

    for index in indices.iter_mut().take(2) {
        let start = (quote_index + 1) as usize;
        if start >= bytes.len() {
            break;
        }

        let mut pos = start;
        while pos < bytes.len() {
            if bytes[pos] == b'"' {
                if escaped && pos > 0 && bytes[pos - 1] == b'\\' {
                    pos += 1;
                    continue;
                }
                quote_index = pos as i32;
                break;
            }
            pos += 1;
        }

        if pos >= bytes.len() {
            break;
        }

        *index = quote_index;
    }

    (indices[0], indices[1])
}

/// Processes backslash escape sequences in a string.
///
/// Handles: `\n`, `\r`, `\t`, `\\`, `\"`
fn unescape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                chars.next();
                match next {
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    '\\' => result.push('\\'),
                    '"' => result.push('"'),
                    _ => {
                        result.push('\\');
                        result.push(next);
                    }
                }
            } else {
                result.push('\\');
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// A simple single-line response from Tor.
///
/// `SingleLineResponse` represents responses that contain exactly one line,
/// typically used for commands that perform actions rather than query data.
/// These responses are usually "250 OK" on success or an error code with
/// a description on failure.
///
/// # Response Format
///
/// Single-line responses have the format:
/// ```text
/// STATUS CONTENT
/// ```
///
/// For example:
/// - `250 OK` - Success
/// - `552 Unrecognized key "foo"` - Error
///
/// # Example
///
/// ```rust
/// use stem_rs::response::{ControlMessage, SingleLineResponse};
///
/// let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
/// let response = SingleLineResponse::from_message(msg).unwrap();
///
/// assert!(response.is_ok(false));
/// assert!(response.is_ok(true)); // Strict check for "250 OK"
/// assert_eq!(response.code, "250");
/// assert_eq!(response.message_text, "OK");
/// ```
#[derive(Debug, Clone)]
pub struct SingleLineResponse {
    /// The underlying control message.
    pub message: ControlMessage,
    /// The 3-digit status code (e.g., "250", "552").
    pub code: String,
    /// The message content after the status code.
    pub message_text: String,
}

impl SingleLineResponse {
    /// Creates a `SingleLineResponse` from a control message.
    ///
    /// Validates that the message contains exactly one line and extracts
    /// the status code and message text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`](crate::Error::Protocol) if:
    /// - The message contains more than one line
    /// - The message is empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::{ControlMessage, SingleLineResponse};
    ///
    /// // Valid single-line response
    /// let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
    /// let response = SingleLineResponse::from_message(msg).unwrap();
    ///
    /// // Multi-line response fails
    /// let msg = ControlMessage::from_str("250-line1\r\n250 line2\r\n", None, false).unwrap();
    /// assert!(SingleLineResponse::from_message(msg).is_err());
    /// ```
    pub fn from_message(message: ControlMessage) -> Result<Self, Error> {
        let content = message.content();

        if content.len() > 1 {
            return Err(Error::Protocol("Received multi-line response".to_string()));
        }
        if content.is_empty() {
            return Err(Error::Protocol("Received empty response".to_string()));
        }

        let (code, _, msg) = &content[0];

        Ok(Self {
            code: code.clone(),
            message_text: msg.clone(),
            message,
        })
    }

    /// Checks if the response indicates success.
    ///
    /// # Arguments
    ///
    /// * `strict` - If `true`, requires exactly "250 OK"; if `false`, only checks
    ///   for status code "250"
    ///
    /// # Returns
    ///
    /// - Non-strict: `true` if status code is "250"
    /// - Strict: `true` if response is exactly "250 OK"
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::{ControlMessage, SingleLineResponse};
    ///
    /// let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
    /// let response = SingleLineResponse::from_message(msg).unwrap();
    /// assert!(response.is_ok(false)); // Non-strict
    /// assert!(response.is_ok(true));  // Strict
    ///
    /// let msg = ControlMessage::from_str("250 Done\r\n", None, false).unwrap();
    /// let response = SingleLineResponse::from_message(msg).unwrap();
    /// assert!(response.is_ok(false));  // Non-strict passes
    /// assert!(!response.is_ok(true));  // Strict fails (not "OK")
    /// ```
    pub fn is_ok(&self, strict: bool) -> bool {
        if strict {
            let content = self.message.content();
            if let Some((code, div, msg)) = content.first() {
                return code == "250" && *div == ' ' && msg == "OK";
            }
            false
        } else {
            self.code == "250"
        }
    }
}

/// Converts a control message to a specific response type.
///
/// This function validates that a [`ControlMessage`] conforms to the expected
/// format for a specific response type. It performs type-specific validation
/// without modifying the message.
///
/// # Supported Response Types
///
/// | Type | Description |
/// |------|-------------|
/// | `SINGLELINE` | Simple single-line response |
/// | `ADD_ONION` | ADD_ONION command response |
/// | `AUTHCHALLENGE` | SAFECOOKIE authentication challenge |
/// | `EVENT` | Asynchronous event notification |
/// | `GETCONF` | GETCONF command response |
/// | `GETINFO` | GETINFO command response |
/// | `MAPADDRESS` | MAPADDRESS command response |
/// | `ONION_CLIENT_AUTH_VIEW` | Onion client auth view response |
/// | `PROTOCOLINFO` | PROTOCOLINFO command response |
///
/// # Arguments
///
/// * `response_type` - The type of response to validate (case-insensitive)
/// * `message` - The control message to validate
///
/// # Errors
///
/// Returns [`Error::Protocol`](crate::Error::Protocol) if:
/// - The response type is not supported
/// - The message doesn't conform to the expected format (for `SINGLELINE`)
///
/// # Example
///
/// ```rust
/// use stem_rs::response::{ControlMessage, convert};
///
/// let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
///
/// // Validate as single-line response
/// let validated = convert("SINGLELINE", msg.clone()).unwrap();
///
/// // Multi-line fails SINGLELINE validation
/// let multi = ControlMessage::from_str("250-line1\r\n250 line2\r\n", None, false).unwrap();
/// assert!(convert("SINGLELINE", multi).is_err());
/// ```
pub fn convert(response_type: &str, message: ControlMessage) -> Result<ControlMessage, Error> {
    match response_type.to_uppercase().as_str() {
        "SINGLELINE" => {
            SingleLineResponse::from_message(message.clone())?;
            Ok(message)
        }
        "ADD_ONION"
        | "AUTHCHALLENGE"
        | "EVENT"
        | "GETCONF"
        | "GETINFO"
        | "MAPADDRESS"
        | "ONION_CLIENT_AUTH_VIEW"
        | "PROTOCOLINFO" => Ok(message),
        _ => Err(Error::Protocol(format!(
            "Unsupported response type: {}",
            response_type
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    const OK_REPLY: &str = "250 OK\r\n";
    const EVENT_BW: &str = "650 BW 32326 2856\r\n";
    const EVENT_CIRC_TIMEOUT: &str = "650 CIRC 5 FAILED PURPOSE=GENERAL REASON=TIMEOUT\r\n";
    const EVENT_CIRC_LAUNCHED: &str = "650 CIRC 9 LAUNCHED PURPOSE=GENERAL\r\n";

    const GETINFO_VERSION: &str = "250-version=0.2.2.23-alpha (git-b85eb949b528f4d7)\r\n250 OK\r\n";

    #[test]
    fn test_from_str_basic() {
        let msg = ControlMessage::from_str(GETINFO_VERSION, None, false).unwrap();
        assert!(msg.is_ok());
        assert_eq!(msg.len(), 2);
    }

    #[test]
    fn test_from_str_with_normalize() {
        let msg = ControlMessage::from_str("250 OK", None, true).unwrap();
        assert!(msg.is_ok());
    }

    #[test]
    fn test_ok_response() {
        let msg = ControlMessage::from_str(OK_REPLY, None, false).unwrap();
        assert!(msg.is_ok());
        let content = msg.content();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0], ("250".to_string(), ' ', "OK".to_string()));
    }

    #[test]
    fn test_event_response_bw() {
        let msg = ControlMessage::from_str(EVENT_BW, None, false).unwrap();
        let content = msg.content();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0].0, "650");
        assert_eq!(content[0].1, ' ');
        assert!(content[0].2.contains("BW 32326 2856"));
    }

    #[test]
    fn test_event_response_circ() {
        for circ_content in [EVENT_CIRC_TIMEOUT, EVENT_CIRC_LAUNCHED] {
            let msg = ControlMessage::from_str(circ_content, None, false).unwrap();
            let content = msg.content();
            assert_eq!(content.len(), 1);
            assert_eq!(content[0].0, "650");
        }
    }

    #[test]
    fn test_getinfo_response_version() {
        let msg = ControlMessage::from_str(GETINFO_VERSION, None, false).unwrap();
        assert_eq!(msg.len(), 2);
        let content = msg.content();
        assert_eq!(content[0].0, "250");
        assert_eq!(content[0].1, '-');
        assert!(content[0].2.starts_with("version="));
        assert_eq!(content[1], ("250".to_string(), ' ', "OK".to_string()));
    }

    #[test]
    fn test_is_ok_various_codes() {
        let msg_250 = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
        assert!(msg_250.is_ok());

        let msg_552 = ControlMessage::from_str("552 Unrecognized key\r\n", None, false).unwrap();
        assert!(!msg_552.is_ok());

        let msg_451 = ControlMessage::from_str("451 Resource exhausted\r\n", None, false).unwrap();
        assert!(!msg_451.is_ok());
    }

    #[test]
    fn test_raw_content() {
        let msg = ControlMessage::from_str(OK_REPLY, None, false).unwrap();
        assert_eq!(msg.raw_content(), OK_REPLY.as_bytes());
    }

    #[test]
    fn test_iteration() {
        let msg = ControlMessage::from_str(GETINFO_VERSION, None, false).unwrap();
        let lines: Vec<_> = msg.iter().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_indexing_get() {
        let msg = ControlMessage::from_str(GETINFO_VERSION, None, false).unwrap();
        let line = msg.get(0).unwrap();
        assert!(line.to_string().starts_with("version="));
        assert!(msg.get(10).is_none());
    }

    #[test]
    fn test_equality() {
        let msg1 = ControlMessage::from_str(EVENT_BW, None, false).unwrap();
        let msg2 = ControlMessage::from_str(EVENT_BW, None, false).unwrap();
        let msg3 = ControlMessage::from_str(EVENT_CIRC_TIMEOUT, None, false).unwrap();

        assert_eq!(msg1, msg2);
        assert_ne!(msg1, msg3);
    }

    #[test]
    fn test_hashing() {
        let msg1 = ControlMessage::from_str(EVENT_BW, None, false).unwrap();
        let msg2 = ControlMessage::from_str(EVENT_BW, None, false).unwrap();

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        msg1.hash(&mut hasher1);
        msg2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_empty_message_error() {
        let result = ControlMessage::new(vec![], vec![], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_control_line_pop_examples() {
        let mut line = ControlLine::new("\"We're all mad here.\" says the grinning cat.");
        assert_eq!(line.pop(true, false).unwrap(), "We're all mad here.");
        assert_eq!(line.pop(false, false).unwrap(), "says");
        assert_eq!(line.remainder(), "the grinning cat.");
    }

    #[test]
    fn test_control_line_pop_escaped() {
        let mut line = ControlLine::new("\"this has a \\\" and \\\\ in it\" foo=bar more_data");
        assert_eq!(line.pop(true, true).unwrap(), "this has a \" and \\ in it");
    }

    #[test]
    fn test_control_line_string_behavior() {
        let mut line = ControlLine::new("PROTOCOLINFO 1");
        assert_eq!(line.to_string(), "PROTOCOLINFO 1");
        assert!(line.to_string().starts_with("PROTOCOLINFO "));

        line.pop(false, false).unwrap();
        assert_eq!(line.to_string(), "PROTOCOLINFO 1");
    }

    #[test]
    fn test_control_line_general_usage() {
        let mut line = ControlLine::new("PROTOCOLINFO 1");
        assert_eq!(line.remainder(), "PROTOCOLINFO 1");
        assert!(!line.is_empty());
        assert!(!line.is_next_quoted(false));
        assert!(!line.is_next_mapping(None, false, false));
        assert!(line.peek_key().is_none());

        assert!(line.pop_mapping(false, false).is_err());
        assert_eq!(line.pop(false, false).unwrap(), "PROTOCOLINFO");
        assert_eq!(line.remainder(), "1");
        assert!(!line.is_empty());

        assert!(line.pop_mapping(false, false).is_err());
        assert_eq!(line.pop(false, false).unwrap(), "1");
        assert_eq!(line.remainder(), "");
        assert!(line.is_empty());

        assert!(line.pop_mapping(false, false).is_err());
        assert!(line.pop(false, false).is_err());
    }

    #[test]
    fn test_control_line_pop_mapping() {
        let version_entry = "Tor=\"0.2.1.30 (0a083b0188cacd2f07838ff0446113bd5211a024)\"";

        let mut line = ControlLine::new(version_entry);
        assert_eq!(line.remainder(), version_entry);
        assert!(!line.is_empty());
        assert!(!line.is_next_quoted(false));
        assert!(line.is_next_mapping(None, false, false));
        assert!(line.is_next_mapping(Some("Tor"), false, false));
        assert!(line.is_next_mapping(Some("Tor"), true, false));
        assert!(line.is_next_mapping(None, true, false));
        assert_eq!(line.peek_key(), Some("Tor".to_string()));

        let (key, value) = line.pop_mapping(false, false).unwrap();
        assert_eq!(key, "Tor");
        assert_eq!(value, "\"0.2.1.30");

        let mut line = ControlLine::new(version_entry);
        let (key, value) = line.pop_mapping(true, false).unwrap();
        assert_eq!(key, "Tor");
        assert_eq!(value, "0.2.1.30 (0a083b0188cacd2f07838ff0446113bd5211a024)");
        assert!(line.is_empty());
    }

    #[test]
    fn test_control_line_escapes() {
        let auth_line =
            r#"AUTH METHODS=COOKIE COOKIEFILE="/tmp/my data\\\"dir//control_auth_cookie""#;
        let mut line = ControlLine::new(auth_line);

        assert_eq!(line.pop(false, false).unwrap(), "AUTH");
        let (key, value) = line.pop_mapping(false, false).unwrap();
        assert_eq!(key, "METHODS");
        assert_eq!(value, "COOKIE");

        let cookie_entry = r#"COOKIEFILE="/tmp/my data\\\"dir//control_auth_cookie""#;
        let mut line = ControlLine::new(cookie_entry);
        let (key, value) = line.pop_mapping(true, true).unwrap();
        assert_eq!(key, "COOKIEFILE");
        assert_eq!(value, r#"/tmp/my data\"dir//control_auth_cookie"#);
        assert!(line.is_empty());
    }

    #[test]
    fn test_control_line_windows_path_escapes() {
        let mut line = ControlLine::new(
            r#"COOKIEFILE="C:\\Users\\Atagar\\AppData\\tor\\control_auth_cookie""#,
        );
        let (key, value) = line.pop_mapping(true, true).unwrap();
        assert_eq!(key, "COOKIEFILE");
        assert_eq!(value, r#"C:\Users\Atagar\AppData\tor\control_auth_cookie"#);
        assert!(line.is_empty());
    }

    #[test]
    fn test_is_next_quoted() {
        let line = ControlLine::new("\"quoted value\" unquoted");
        assert!(line.is_next_quoted(false));

        let line = ControlLine::new("unquoted \"quoted\"");
        assert!(!line.is_next_quoted(false));
    }

    #[test]
    fn test_is_next_mapping_with_key() {
        let line = ControlLine::new("KEY=value OTHER=stuff");
        assert!(line.is_next_mapping(Some("KEY"), false, false));
        assert!(!line.is_next_mapping(Some("OTHER"), false, false));
        assert!(line.is_next_mapping(None, false, false));
    }

    #[test]
    fn test_peek_key() {
        let line = ControlLine::new("MYKEY=myvalue");
        assert_eq!(line.peek_key(), Some("MYKEY".to_string()));

        let line = ControlLine::new("no_equals_here");
        assert!(line.peek_key().is_none());
    }

    #[test]
    fn test_single_line_response_not_ok() {
        let msg = ControlMessage::from_str("552 NOTOK\r\n", None, false).unwrap();
        let response = SingleLineResponse::from_message(msg).unwrap();
        assert!(!response.is_ok(false));
    }

    #[test]
    fn test_single_line_response_ok_non_strict() {
        let msg = ControlMessage::from_str("250 KK\r\n", None, false).unwrap();
        let response = SingleLineResponse::from_message(msg).unwrap();
        assert!(response.is_ok(false));
    }

    #[test]
    fn test_single_line_response_ok_strict() {
        let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
        let response = SingleLineResponse::from_message(msg).unwrap();
        assert!(response.is_ok(true));
    }

    #[test]
    fn test_single_line_response_ok_strict_fails() {
        let msg = ControlMessage::from_str("250 HMM\r\n", None, false).unwrap();
        let response = SingleLineResponse::from_message(msg).unwrap();
        assert!(!response.is_ok(true));
    }

    #[test]
    fn test_single_line_response_multi_line_error() {
        let msg = ControlMessage::from_str("250-MULTI\r\n250 LINE\r\n", None, false).unwrap();
        let result = SingleLineResponse::from_message(msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_singleline() {
        let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
        let result = convert("SINGLELINE", msg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_convert_singleline_multi_line_error() {
        let msg = ControlMessage::from_str("250-MULTI\r\n250 LINE\r\n", None, false).unwrap();
        let result = convert("SINGLELINE", msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_unsupported_type() {
        let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
        let result = convert("UNKNOWN_TYPE", msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_known_types() {
        let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
        for response_type in [
            "ADD_ONION",
            "AUTHCHALLENGE",
            "EVENT",
            "GETCONF",
            "GETINFO",
            "MAPADDRESS",
            "PROTOCOLINFO",
        ] {
            let result = convert(response_type, msg.clone());
            assert!(result.is_ok(), "Failed for type: {}", response_type);
        }
    }

    #[test]
    fn test_unescape_string() {
        assert_eq!(unescape_string(r#"hello\nworld"#), "hello\nworld");
        assert_eq!(unescape_string(r#"tab\there"#), "tab\there");
        assert_eq!(unescape_string(r#"quote\"here"#), "quote\"here");
        assert_eq!(unescape_string(r#"backslash\\here"#), "backslash\\here");
        assert_eq!(unescape_string(r#"carriage\rreturn"#), "carriage\rreturn");
        assert_eq!(unescape_string(r#"unknown\xescape"#), "unknown\\xescape");
    }

    #[test]
    fn test_get_quote_indices() {
        assert_eq!(get_quote_indices("\"hello\"", false), (0, 6));
        assert_eq!(get_quote_indices("no quotes", false), (-1, -1));
        assert_eq!(get_quote_indices("\"only one", false), (0, -1));
        assert_eq!(get_quote_indices("\"escaped\\\"quote\"", true), (0, 15));
    }
}
