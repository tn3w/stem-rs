//! Control protocol message parsing for Tor control protocol.
//!
//! This module provides parsing utilities for control protocol responses,
//! including single-line, multi-line, and data responses. It implements
//! the message format defined in section 2.3 of the Tor control protocol
//! specification.
//!
//! # Conceptual Role
//!
//! The protocol module handles the low-level parsing of control protocol
//! messages. It sits between the raw socket communication ([`crate::socket`])
//! and the high-level response types ([`crate::response`]).
//!
//! # Protocol Format
//!
//! The Tor control protocol uses a text-based format with the following structure:
//!
//! ## Request Format
//!
//! ```text
//! COMMAND [ARGS]\r\n
//! ```
//!
//! ## Response Format
//!
//! Each response line has the format:
//!
//! ```text
//! STATUS DIVIDER MESSAGE\r\n
//! ```
//!
//! Where:
//! - `STATUS` is a 3-digit status code (e.g., 250 for success, 5xx for errors)
//! - `DIVIDER` indicates the line type:
//!   - ` ` (space): Final line of the response
//!   - `-`: Continuation line (more lines follow)
//!   - `+`: Data line (multi-line data block follows)
//! - `MESSAGE` is the response content
//!
//! ## Status Codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 250  | Success |
//! | 251  | Operation unnecessary |
//! | 5xx  | Error (various types) |
//! | 650  | Asynchronous event |
//!
//! # Single-Line Response Example
//!
//! ```text
//! 250 OK
//! ```
//!
//! # Multi-Line Response Example
//!
//! ```text
//! 250-version=0.4.7.1
//! 250-config-file=/etc/tor/torrc
//! 250 OK
//! ```
//!
//! # Data Response Example
//!
//! ```text
//! 250+info/names=
//! desc/id/* -- Router descriptors by ID.
//! desc/name/* -- Router descriptors by nickname.
//! .
//! 250 OK
//! ```
//!
//! # Example
//!
//! ```rust
//! use stem_rs::protocol::{ParsedLine, ControlLine, format_command};
//!
//! // Parse a response line
//! let line = ParsedLine::parse("250 OK").unwrap();
//! assert_eq!(line.status_code, 250);
//! assert!(line.is_final());
//!
//! // Parse key=value content
//! let mut ctrl = ControlLine::new("key1=value1 key2=\"quoted value\"");
//! let (k, v) = ctrl.pop_mapping(false, false).unwrap();
//! assert_eq!(k, "key1");
//! assert_eq!(v, "value1");
//!
//! // Format a command
//! let cmd = format_command("GETINFO", &["version"]);
//! assert_eq!(cmd, "GETINFO version\r\n");
//! ```
//!
//! # Thread Safety
//!
//! [`ParsedLine`] is `Send` and `Sync` as it contains only owned data.
//! [`ControlLine`] is `Send` but not `Sync` due to internal mutable state
//! for tracking parse position.
//!
//! # See Also
//!
//! - [`crate::socket`]: Low-level socket communication
//! - [`crate::response`]: High-level response parsing
//! - [`crate::controller`]: High-level controller API

use crate::Error;

/// A parsed line from a Tor control protocol response.
///
/// Represents a single line of a control protocol response, broken down into
/// its component parts: status code, divider character, and content.
///
/// # Protocol Format
///
/// Each response line has the format: `STATUS DIVIDER CONTENT`
///
/// - `status_code`: 3-digit numeric code indicating success/failure
/// - `divider`: Single character indicating line type
/// - `content`: The actual message content
///
/// # Divider Types
///
/// | Divider | Method | Meaning |
/// |---------|--------|---------|
/// | ` ` (space) | [`is_final()`](Self::is_final) | Final line of response |
/// | `-` | [`is_continuation()`](Self::is_continuation) | More lines follow |
/// | `+` | [`is_data()`](Self::is_data) | Multi-line data block follows |
///
/// # Example
///
/// ```rust
/// use stem_rs::protocol::ParsedLine;
///
/// // Parse a success response
/// let line = ParsedLine::parse("250 OK").unwrap();
/// assert_eq!(line.status_code, 250);
/// assert_eq!(line.divider, ' ');
/// assert_eq!(line.content, "OK");
/// assert!(line.is_final());
///
/// // Parse a continuation line
/// let cont = ParsedLine::parse("250-version=0.4.7.1").unwrap();
/// assert!(cont.is_continuation());
///
/// // Parse a data line
/// let data = ParsedLine::parse("250+getinfo").unwrap();
/// assert!(data.is_data());
///
/// // Parse an error response
/// let err = ParsedLine::parse("515 Authentication failed").unwrap();
/// assert_eq!(err.status_code, 515);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLine {
    /// The 3-digit status code from the response.
    ///
    /// Common codes:
    /// - `250`: Success
    /// - `251`: Operation unnecessary
    /// - `5xx`: Various error conditions
    /// - `650`: Asynchronous event notification
    pub status_code: u16,

    /// The divider character indicating the line type.
    ///
    /// - `' '` (space): Final line of the response
    /// - `'-'`: Continuation line (more lines follow)
    /// - `'+'`: Data line (multi-line data block follows)
    pub divider: char,

    /// The content of the response line after the status code and divider.
    ///
    /// For success responses, this is typically "OK".
    /// For error responses, this contains the error description.
    /// For data responses, this may contain key=value pairs or other data.
    pub content: String,
}

impl ParsedLine {
    /// Parses a raw control protocol response line into its components.
    ///
    /// Takes a line from the control socket and extracts the status code,
    /// divider character, and content. The line may optionally include
    /// trailing `\r\n` characters which are stripped.
    ///
    /// # Arguments
    ///
    /// * `line` - The raw line to parse, with or without trailing CRLF
    ///
    /// # Returns
    ///
    /// A `ParsedLine` containing the extracted components.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The line is shorter than 3 characters
    /// - The first 3 characters are not a valid numeric status code
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ParsedLine;
    ///
    /// // Parse with CRLF (as received from socket)
    /// let line = ParsedLine::parse("250 OK\r\n").unwrap();
    /// assert_eq!(line.status_code, 250);
    /// assert_eq!(line.content, "OK");
    ///
    /// // Parse without CRLF
    /// let line = ParsedLine::parse("250-version=0.4.7.1").unwrap();
    /// assert_eq!(line.content, "version=0.4.7.1");
    ///
    /// // Error: line too short
    /// assert!(ParsedLine::parse("25").is_err());
    ///
    /// // Error: invalid status code
    /// assert!(ParsedLine::parse("abc OK").is_err());
    /// ```
    pub fn parse(line: &str) -> Result<Self, Error> {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.len() < 3 {
            return Err(Error::Protocol(format!("line too short: {}", line)));
        }

        let status_code: u16 = line[..3]
            .parse()
            .map_err(|_| Error::Protocol(format!("invalid status code: {}", &line[..3])))?;

        let divider = if line.len() > 3 {
            line.chars().nth(3).unwrap_or(' ')
        } else {
            ' '
        };

        let content = if line.len() > 4 {
            line[4..].to_string()
        } else {
            String::new()
        };

        Ok(Self {
            status_code,
            divider,
            content,
        })
    }

    /// Returns `true` if this is the final line of a response.
    ///
    /// A final line has a space character as its divider, indicating
    /// no more lines follow in this response.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ParsedLine;
    ///
    /// let final_line = ParsedLine::parse("250 OK").unwrap();
    /// assert!(final_line.is_final());
    ///
    /// let cont_line = ParsedLine::parse("250-more data").unwrap();
    /// assert!(!cont_line.is_final());
    /// ```
    pub fn is_final(&self) -> bool {
        self.divider == ' '
    }

    /// Returns `true` if this is a continuation line.
    ///
    /// A continuation line has a `-` character as its divider, indicating
    /// more lines follow in this response.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ParsedLine;
    ///
    /// let cont_line = ParsedLine::parse("250-version=0.4.7.1").unwrap();
    /// assert!(cont_line.is_continuation());
    ///
    /// let final_line = ParsedLine::parse("250 OK").unwrap();
    /// assert!(!final_line.is_continuation());
    /// ```
    pub fn is_continuation(&self) -> bool {
        self.divider == '-'
    }

    /// Returns `true` if this is a data line.
    ///
    /// A data line has a `+` character as its divider, indicating a
    /// multi-line data block follows. The data block is terminated
    /// by a line containing only a period (`.`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ParsedLine;
    ///
    /// let data_line = ParsedLine::parse("250+getinfo").unwrap();
    /// assert!(data_line.is_data());
    ///
    /// let final_line = ParsedLine::parse("250 OK").unwrap();
    /// assert!(!data_line.is_final());
    /// ```
    pub fn is_data(&self) -> bool {
        self.divider == '+'
    }
}

/// A parser for space-delimited control protocol response content.
///
/// `ControlLine` provides methods for parsing the content portion of control
/// protocol responses, which often contain space-separated values and
/// `KEY=VALUE` mappings. It maintains an internal position to track parsing
/// progress.
///
/// # Conceptual Role
///
/// After extracting the content from a [`ParsedLine`], `ControlLine` is used
/// to parse individual entries from that content. It supports:
///
/// - Unquoted values: `value1 value2 value3`
/// - Quoted values: `"value with spaces"`
/// - Key-value mappings: `key=value` or `key="quoted value"`
/// - Escaped strings: `"value with \"quotes\" and \\backslashes"`
///
/// # What This Type Does NOT Do
///
/// - Parse the status code or divider (use [`ParsedLine`] for that)
/// - Handle multi-line data blocks
/// - Validate semantic correctness of values
///
/// # Thread Safety
///
/// `ControlLine` is `Send` but not `Sync` due to internal mutable state
/// for tracking the parse position. For concurrent access, create separate
/// `ControlLine` instances.
///
/// # Example
///
/// ```rust
/// use stem_rs::protocol::ControlLine;
///
/// // Parse space-separated values
/// let mut line = ControlLine::new("hello world test");
/// assert_eq!(line.pop(false, false).unwrap(), "hello");
/// assert_eq!(line.pop(false, false).unwrap(), "world");
/// assert_eq!(line.pop(false, false).unwrap(), "test");
/// assert!(line.is_empty());
///
/// // Parse quoted values
/// let mut line = ControlLine::new("\"hello world\" test");
/// assert_eq!(line.pop(true, false).unwrap(), "hello world");
/// assert_eq!(line.pop(false, false).unwrap(), "test");
///
/// // Parse key=value mappings
/// let mut line = ControlLine::new("key=value other=\"quoted\"");
/// let (k, v) = line.pop_mapping(false, false).unwrap();
/// assert_eq!(k, "key");
/// assert_eq!(v, "value");
/// let (k2, v2) = line.pop_mapping(true, false).unwrap();
/// assert_eq!(k2, "other");
/// assert_eq!(v2, "quoted");
/// ```
pub struct ControlLine {
    /// The full content string being parsed.
    content: String,
    /// Current position in the content string.
    position: usize,
}

impl ControlLine {
    /// Creates a new `ControlLine` parser for the given content.
    ///
    /// The parser starts at the beginning of the content string.
    ///
    /// # Arguments
    ///
    /// * `content` - The content string to parse
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ControlLine;
    ///
    /// let line = ControlLine::new("key=value other=data");
    /// assert!(!line.is_empty());
    /// ```
    pub fn new(content: &str) -> Self {
        Self {
            content: content.to_string(),
            position: 0,
        }
    }

    /// Returns the unparsed remainder of the content.
    ///
    /// Leading whitespace is trimmed from the returned string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ControlLine;
    ///
    /// let mut line = ControlLine::new("hello world");
    /// assert_eq!(line.remainder(), "hello world");
    /// line.pop(false, false).unwrap();
    /// assert_eq!(line.remainder(), "world");
    /// ```
    pub fn remainder(&self) -> &str {
        self.content[self.position..].trim_start()
    }

    /// Returns `true` if there is no more content to parse.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ControlLine;
    ///
    /// let mut line = ControlLine::new("hello");
    /// assert!(!line.is_empty());
    /// line.pop(false, false).unwrap();
    /// assert!(line.is_empty());
    ///
    /// let empty = ControlLine::new("");
    /// assert!(empty.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.remainder().is_empty()
    }

    /// Returns `true` if the next entry is a quoted value.
    ///
    /// Checks if the next non-whitespace character is a double quote (`"`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ControlLine;
    ///
    /// let line = ControlLine::new("\"quoted\" unquoted");
    /// assert!(line.is_next_quoted());
    ///
    /// let line2 = ControlLine::new("unquoted \"quoted\"");
    /// assert!(!line2.is_next_quoted());
    /// ```
    pub fn is_next_quoted(&self) -> bool {
        self.remainder().starts_with('"')
    }

    /// Returns `true` if the next entry is a `KEY=VALUE` mapping.
    ///
    /// Optionally checks that the key matches a specific value and/or
    /// that the value is quoted.
    ///
    /// # Arguments
    ///
    /// * `key` - If `Some`, checks that the key matches this value
    /// * `quoted` - If `true`, checks that the value is quoted
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ControlLine;
    ///
    /// let line = ControlLine::new("key=value");
    /// assert!(line.is_next_mapping(None, false));
    /// assert!(line.is_next_mapping(Some("key"), false));
    /// assert!(!line.is_next_mapping(Some("other"), false));
    ///
    /// let quoted = ControlLine::new("key=\"value\"");
    /// assert!(quoted.is_next_mapping(None, true));
    /// assert!(quoted.is_next_mapping(Some("key"), true));
    /// ```
    pub fn is_next_mapping(&self, key: Option<&str>, quoted: bool) -> bool {
        let rest = self.remainder();
        if let Some(eq_pos) = rest.find('=') {
            if let Some(expected_key) = key {
                let actual_key = &rest[..eq_pos];
                if actual_key != expected_key {
                    return false;
                }
            }
            if quoted {
                rest.get(eq_pos + 1..).is_some_and(|s| s.starts_with('"'))
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Returns the key of the next entry if it's a `KEY=VALUE` mapping.
    ///
    /// Returns `None` if the next entry is not a mapping.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ControlLine;
    ///
    /// let line = ControlLine::new("mykey=myvalue");
    /// assert_eq!(line.peek_key(), Some("mykey"));
    ///
    /// let no_mapping = ControlLine::new("just a value");
    /// assert_eq!(no_mapping.peek_key(), None);
    /// ```
    pub fn peek_key(&self) -> Option<&str> {
        let rest = self.remainder();
        rest.find('=').map(|pos| &rest[..pos])
    }

    /// Removes and returns the next space-separated entry.
    ///
    /// Advances the internal position past the extracted entry.
    ///
    /// # Arguments
    ///
    /// * `quoted` - If `true`, expects and removes surrounding quotes
    /// * `escaped` - If `true`, processes escape sequences in the value
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
    /// Returns [`Error::Protocol`] if:
    /// - No more content to parse
    /// - `quoted` is `true` but the next entry doesn't start with a quote
    /// - A quoted string is not properly terminated
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ControlLine;
    ///
    /// // Unquoted values
    /// let mut line = ControlLine::new("hello world");
    /// assert_eq!(line.pop(false, false).unwrap(), "hello");
    /// assert_eq!(line.pop(false, false).unwrap(), "world");
    ///
    /// // Quoted values
    /// let mut line = ControlLine::new("\"hello world\" test");
    /// assert_eq!(line.pop(true, false).unwrap(), "hello world");
    ///
    /// // Escaped values
    /// let mut line = ControlLine::new("\"hello\\nworld\"");
    /// assert_eq!(line.pop(true, true).unwrap(), "hello\nworld");
    /// ```
    pub fn pop(&mut self, quoted: bool, escaped: bool) -> Result<String, Error> {
        let rest = self.remainder();
        if rest.is_empty() {
            return Err(Error::Protocol("no more content to pop".to_string()));
        }

        if quoted {
            if !rest.starts_with('"') {
                return Err(Error::Protocol("expected quoted string".to_string()));
            }
            let after_quote = &rest[1..];
            let end_pos = find_closing_quote(after_quote, escaped)?;
            let value = if escaped {
                unescape_string(&after_quote[..end_pos])
            } else {
                after_quote[..end_pos].to_string()
            };
            self.position = self.content.len() - rest.len() + 2 + end_pos;
            if self.position < self.content.len() && self.content.as_bytes()[self.position] == b' '
            {
                self.position += 1;
            }
            Ok(value)
        } else {
            let end_pos = rest.find(' ').unwrap_or(rest.len());
            let value = rest[..end_pos].to_string();
            self.position = self.content.len() - rest.len() + end_pos;
            if self.position < self.content.len() {
                self.position += 1;
            }
            Ok(value)
        }
    }

    /// Removes and returns the next `KEY=VALUE` mapping.
    ///
    /// Parses the next entry as a key-value pair separated by `=`.
    /// Advances the internal position past the extracted mapping.
    ///
    /// # Arguments
    ///
    /// * `quoted` - If `true`, expects the value to be quoted
    /// * `escaped` - If `true`, processes escape sequences in the value
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The next entry is not a `KEY=VALUE` mapping
    /// - `quoted` is `true` but the value is not quoted
    /// - A quoted string is not properly terminated
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::protocol::ControlLine;
    ///
    /// // Simple mapping
    /// let mut line = ControlLine::new("key=value other=data");
    /// let (k, v) = line.pop_mapping(false, false).unwrap();
    /// assert_eq!(k, "key");
    /// assert_eq!(v, "value");
    ///
    /// // Quoted mapping
    /// let mut line = ControlLine::new("key=\"hello world\"");
    /// let (k, v) = line.pop_mapping(true, false).unwrap();
    /// assert_eq!(k, "key");
    /// assert_eq!(v, "hello world");
    ///
    /// // Error: not a mapping
    /// let mut line = ControlLine::new("not_a_mapping");
    /// assert!(line.pop_mapping(false, false).is_err());
    /// ```
    pub fn pop_mapping(&mut self, quoted: bool, escaped: bool) -> Result<(String, String), Error> {
        let rest = self.remainder();
        let eq_pos = rest
            .find('=')
            .ok_or_else(|| Error::Protocol(format!("expected key=value mapping in: {}", rest)))?;

        let key = rest[..eq_pos].to_string();
        self.position = self.content.len() - rest.len() + eq_pos + 1;

        let value = self.pop(quoted, escaped)?;
        Ok((key, value))
    }
}

/// Finds the position of the closing quote in a string.
///
/// Searches for the closing `"` character, optionally handling escape
/// sequences where `\"` does not count as a closing quote.
///
/// # Arguments
///
/// * `s` - The string to search (should not include the opening quote)
/// * `escaped` - If `true`, `\"` sequences are skipped
///
/// # Errors
///
/// Returns [`Error::Protocol`] if no closing quote is found.
fn find_closing_quote(s: &str, escaped: bool) -> Result<usize, Error> {
    let mut pos = 0;
    let bytes = s.as_bytes();
    while pos < bytes.len() {
        if bytes[pos] == b'"' {
            return Ok(pos);
        }
        if escaped && bytes[pos] == b'\\' && pos + 1 < bytes.len() {
            pos += 2;
        } else {
            pos += 1;
        }
    }
    Err(Error::Protocol("unterminated quoted string".to_string()))
}

/// Processes escape sequences in a string.
///
/// Converts escape sequences to their actual characters:
/// - `\n` → newline
/// - `\r` → carriage return
/// - `\t` → tab
/// - `\\` → backslash
/// - `\"` → double quote
///
/// Unknown escape sequences are preserved as-is (e.g., `\x` → `\x`).
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

/// Formats a control protocol command with arguments.
///
/// Creates a properly formatted command string ready to send to the
/// control socket. The command is terminated with `\r\n` as required
/// by the protocol.
///
/// # Arguments
///
/// * `command` - The command name (e.g., "GETINFO", "SETCONF")
/// * `args` - Slice of argument strings to append to the command
///
/// # Returns
///
/// A formatted command string ending with `\r\n`.
///
/// # Example
///
/// ```rust
/// use stem_rs::protocol::format_command;
///
/// // Command without arguments
/// let cmd = format_command("AUTHENTICATE", &[]);
/// assert_eq!(cmd, "AUTHENTICATE\r\n");
///
/// // Command with single argument
/// let cmd = format_command("GETINFO", &["version"]);
/// assert_eq!(cmd, "GETINFO version\r\n");
///
/// // Command with multiple arguments
/// let cmd = format_command("SETCONF", &["key1=value1", "key2=value2"]);
/// assert_eq!(cmd, "SETCONF key1=value1 key2=value2\r\n");
/// ```
pub fn format_command(command: &str, args: &[&str]) -> String {
    if args.is_empty() {
        format!("{}\r\n", command)
    } else {
        format!("{} {}\r\n", command, args.join(" "))
    }
}

/// Quotes a string for use in control protocol commands.
///
/// Wraps the string in double quotes and escapes special characters:
/// - `"` → `\"`
/// - `\` → `\\`
/// - newline → `\n`
/// - carriage return → `\r`
/// - tab → `\t`
///
/// This is the inverse of the unescaping performed by [`ControlLine::pop`]
/// with `escaped = true`.
///
/// # Arguments
///
/// * `s` - The string to quote
///
/// # Returns
///
/// A quoted and escaped string.
///
/// # Example
///
/// ```rust
/// use stem_rs::protocol::quote_string;
///
/// // Simple string
/// assert_eq!(quote_string("hello"), "\"hello\"");
///
/// // String with special characters
/// assert_eq!(quote_string("hello\nworld"), "\"hello\\nworld\"");
/// assert_eq!(quote_string("say \"hi\""), "\"say \\\"hi\\\"\"");
/// assert_eq!(quote_string("path\\to\\file"), "\"path\\\\to\\\\file\"");
/// ```
///
/// # Round-Trip Property
///
/// For any string `s`, quoting and then unquoting should return the
/// original string:
///
/// ```rust
/// use stem_rs::protocol::{quote_string, ControlLine};
///
/// let original = "hello\nworld";
/// let quoted = quote_string(original);
/// let mut line = ControlLine::new(&quoted);
/// let unquoted = line.pop(true, true).unwrap();
/// assert_eq!(original, unquoted);
/// ```
pub fn quote_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }
    result.push('"');
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_simple() {
        let parsed = ParsedLine::parse("250 OK").unwrap();
        assert_eq!(parsed.status_code, 250);
        assert_eq!(parsed.divider, ' ');
        assert_eq!(parsed.content, "OK");
        assert!(parsed.is_final());
    }

    #[test]
    fn test_parse_line_continuation() {
        let parsed = ParsedLine::parse("250-version=0.4.7.1").unwrap();
        assert_eq!(parsed.status_code, 250);
        assert_eq!(parsed.divider, '-');
        assert_eq!(parsed.content, "version=0.4.7.1");
        assert!(parsed.is_continuation());
    }

    #[test]
    fn test_parse_line_data() {
        let parsed = ParsedLine::parse("250+getinfo").unwrap();
        assert_eq!(parsed.status_code, 250);
        assert_eq!(parsed.divider, '+');
        assert_eq!(parsed.content, "getinfo");
        assert!(parsed.is_data());
    }

    #[test]
    fn test_parse_line_error() {
        let parsed = ParsedLine::parse("515 Authentication failed").unwrap();
        assert_eq!(parsed.status_code, 515);
        assert_eq!(parsed.divider, ' ');
        assert_eq!(parsed.content, "Authentication failed");
    }

    #[test]
    fn test_parse_line_too_short() {
        assert!(ParsedLine::parse("25").is_err());
    }

    #[test]
    fn test_parse_line_invalid_code() {
        assert!(ParsedLine::parse("abc OK").is_err());
    }

    #[test]
    fn test_control_line_pop_unquoted() {
        let mut line = ControlLine::new("hello world test");
        assert_eq!(line.pop(false, false).unwrap(), "hello");
        assert_eq!(line.pop(false, false).unwrap(), "world");
        assert_eq!(line.pop(false, false).unwrap(), "test");
        assert!(line.is_empty());
    }

    #[test]
    fn test_control_line_pop_quoted() {
        let mut line = ControlLine::new("\"hello world\" test");
        assert_eq!(line.pop(true, false).unwrap(), "hello world");
        assert_eq!(line.pop(false, false).unwrap(), "test");
    }

    #[test]
    fn test_control_line_pop_escaped() {
        let mut line = ControlLine::new("\"hello\\nworld\" test");
        assert_eq!(line.pop(true, true).unwrap(), "hello\nworld");
    }

    #[test]
    fn test_control_line_pop_mapping() {
        let mut line = ControlLine::new("key=value other=data");
        let (k, v) = line.pop_mapping(false, false).unwrap();
        assert_eq!(k, "key");
        assert_eq!(v, "value");
        let (k2, v2) = line.pop_mapping(false, false).unwrap();
        assert_eq!(k2, "other");
        assert_eq!(v2, "data");
    }

    #[test]
    fn test_control_line_pop_mapping_quoted() {
        let mut line = ControlLine::new("key=\"hello world\"");
        let (k, v) = line.pop_mapping(true, false).unwrap();
        assert_eq!(k, "key");
        assert_eq!(v, "hello world");
    }

    #[test]
    fn test_control_line_is_next_mapping() {
        let line = ControlLine::new("key=value");
        assert!(line.is_next_mapping(None, false));
        assert!(line.is_next_mapping(Some("key"), false));
        assert!(!line.is_next_mapping(Some("other"), false));
    }

    #[test]
    fn test_control_line_peek_key() {
        let line = ControlLine::new("mykey=myvalue");
        assert_eq!(line.peek_key(), Some("mykey"));
    }

    #[test]
    fn test_format_command_no_args() {
        assert_eq!(format_command("AUTHENTICATE", &[]), "AUTHENTICATE\r\n");
    }

    #[test]
    fn test_format_command_with_args() {
        assert_eq!(
            format_command("GETINFO", &["version", "config-file"]),
            "GETINFO version config-file\r\n"
        );
    }

    #[test]
    fn test_quote_string_simple() {
        assert_eq!(quote_string("hello"), "\"hello\"");
    }

    #[test]
    fn test_quote_string_with_escapes() {
        assert_eq!(quote_string("hello\nworld"), "\"hello\\nworld\"");
        assert_eq!(quote_string("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(quote_string("path\\to\\file"), "\"path\\\\to\\\\file\"");
    }

    #[test]
    fn test_unescape_string() {
        assert_eq!(unescape_string("hello\\nworld"), "hello\nworld");
        assert_eq!(unescape_string("say \\\"hi\\\""), "say \"hi\"");
        assert_eq!(unescape_string("path\\\\to"), "path\\to");
        assert_eq!(unescape_string("tab\\there"), "tab\there");
    }

    #[test]
    fn test_parse_line_with_crlf() {
        let parsed = ParsedLine::parse("250 OK\r\n").unwrap();
        assert_eq!(parsed.status_code, 250);
        assert_eq!(parsed.content, "OK");
    }

    #[test]
    fn test_control_line_empty() {
        let line = ControlLine::new("");
        assert!(line.is_empty());
    }

    #[test]
    fn test_control_line_whitespace_handling() {
        let mut line = ControlLine::new("  hello   world  ");
        assert_eq!(line.pop(false, false).unwrap(), "hello");
        assert_eq!(line.pop(false, false).unwrap(), "world");
    }

    #[test]
    fn test_parse_line_status_codes() {
        let codes = [200, 250, 251, 500, 510, 515, 550, 650];
        for code in codes {
            let line = format!("{} Test message", code);
            let parsed = ParsedLine::parse(&line).unwrap();
            assert_eq!(parsed.status_code, code);
        }
    }

    #[test]
    fn test_control_line_complex_mapping() {
        let mut line = ControlLine::new("key1=value1 key2=\"quoted value\" key3=value3");

        let (k1, v1) = line.pop_mapping(false, false).unwrap();
        assert_eq!(k1, "key1");
        assert_eq!(v1, "value1");

        let (k2, v2) = line.pop_mapping(true, false).unwrap();
        assert_eq!(k2, "key2");
        assert_eq!(v2, "quoted value");

        let (k3, v3) = line.pop_mapping(false, false).unwrap();
        assert_eq!(k3, "key3");
        assert_eq!(v3, "value3");
    }

    #[test]
    fn test_control_line_escaped_quotes() {
        let mut line = ControlLine::new("\"hello \\\"world\\\"\"");
        let value = line.pop(true, true).unwrap();
        assert_eq!(value, "hello \"world\"");
    }

    #[test]
    fn test_control_line_escaped_backslash() {
        let mut line = ControlLine::new("\"path\\\\to\\\\file\"");
        let value = line.pop(true, true).unwrap();
        assert_eq!(value, "path\\to\\file");
    }

    #[test]
    fn test_control_line_all_escape_sequences() {
        let mut line = ControlLine::new("\"\\n\\r\\t\\\\\\\"\"");
        let value = line.pop(true, true).unwrap();
        assert_eq!(value, "\n\r\t\\\"");
    }

    #[test]
    fn test_quote_string_all_special_chars() {
        let input = "hello\nworld\r\ttab\\backslash\"quote";
        let quoted = quote_string(input);
        assert_eq!(quoted, "\"hello\\nworld\\r\\ttab\\\\backslash\\\"quote\"");
    }

    #[test]
    fn test_format_command_single_arg() {
        assert_eq!(
            format_command("GETINFO", &["version"]),
            "GETINFO version\r\n"
        );
    }

    #[test]
    fn test_format_command_multiple_args() {
        assert_eq!(
            format_command("SETCONF", &["key1=value1", "key2=value2"]),
            "SETCONF key1=value1 key2=value2\r\n"
        );
    }

    #[test]
    fn test_parsed_line_divider_types() {
        let final_line = ParsedLine::parse("250 OK").unwrap();
        assert!(final_line.is_final());
        assert!(!final_line.is_continuation());
        assert!(!final_line.is_data());

        let cont_line = ParsedLine::parse("250-More data").unwrap();
        assert!(!cont_line.is_final());
        assert!(cont_line.is_continuation());
        assert!(!cont_line.is_data());

        let data_line = ParsedLine::parse("250+Data block").unwrap();
        assert!(!data_line.is_final());
        assert!(!data_line.is_continuation());
        assert!(data_line.is_data());
    }

    #[test]
    fn test_control_line_is_next_quoted() {
        let line = ControlLine::new("\"quoted\" unquoted");
        assert!(line.is_next_quoted());

        let line2 = ControlLine::new("unquoted \"quoted\"");
        assert!(!line2.is_next_quoted());
    }

    #[test]
    fn test_control_line_pop_error_on_empty() {
        let mut line = ControlLine::new("");
        assert!(line.pop(false, false).is_err());
    }

    #[test]
    fn test_control_line_pop_error_on_missing_quote() {
        let mut line = ControlLine::new("unquoted");
        assert!(line.pop(true, false).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::char::range as char_range;
    use proptest::prelude::*;

    fn valid_status_code() -> impl Strategy<Value = u16> {
        prop_oneof![
            Just(200u16),
            Just(250u16),
            Just(251u16),
            Just(500u16),
            Just(510u16),
            Just(515u16),
            Just(550u16),
            Just(650u16),
        ]
    }

    fn safe_content_char() -> impl Strategy<Value = char> {
        prop_oneof![
            char_range('a', 'z'),
            char_range('A', 'Z'),
            char_range('0', '9'),
            Just(' '),
            Just('='),
            Just('-'),
            Just('_'),
            Just('.'),
            Just('/'),
        ]
    }

    fn safe_content_string() -> impl Strategy<Value = String> {
        proptest::collection::vec(safe_content_char(), 0..50)
            .prop_map(|chars| chars.into_iter().collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_parsed_line_roundtrip(
            status_code in valid_status_code(),
            content in safe_content_string()
        ) {
            let line = format!("{} {}", status_code, content);
            let parsed = ParsedLine::parse(&line).expect("should parse");
            prop_assert_eq!(parsed.status_code, status_code);
            prop_assert_eq!(parsed.divider, ' ');
            prop_assert_eq!(parsed.content, content);
        }

        #[test]
        fn prop_parsed_line_continuation_roundtrip(
            status_code in valid_status_code(),
            content in safe_content_string()
        ) {
            let line = format!("{}-{}", status_code, content);
            let parsed = ParsedLine::parse(&line).expect("should parse");
            prop_assert_eq!(parsed.status_code, status_code);
            prop_assert_eq!(parsed.divider, '-');
            prop_assert!(parsed.is_continuation());
        }

        #[test]
        fn prop_quote_unquote_roundtrip(content in safe_content_string()) {
            let quoted = quote_string(&content);
            prop_assert!(quoted.starts_with('"'));
            prop_assert!(quoted.ends_with('"'));
            let inner = &quoted[1..quoted.len()-1];
            let unquoted = unescape_string(inner);
            prop_assert_eq!(content, unquoted);
        }

        #[test]
        fn prop_format_command_ends_with_crlf(
            cmd in "[A-Z]{3,10}",
            args in proptest::collection::vec("[a-z0-9]{1,10}", 0..3)
        ) {
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let formatted = format_command(&cmd, &args_refs);
            prop_assert!(formatted.ends_with("\r\n"));
            prop_assert!(formatted.starts_with(&cmd));
        }

        #[test]
        fn prop_control_line_pop_preserves_content(
            word1 in "[a-z]{1,10}",
            word2 in "[a-z]{1,10}",
            word3 in "[a-z]{1,10}"
        ) {
            let content = format!("{} {} {}", word1, word2, word3);
            let mut line = ControlLine::new(&content);
            let popped1 = line.pop(false, false).expect("should pop");
            let popped2 = line.pop(false, false).expect("should pop");
            let popped3 = line.pop(false, false).expect("should pop");
            prop_assert_eq!(popped1, word1);
            prop_assert_eq!(popped2, word2);
            prop_assert_eq!(popped3, word3);
            prop_assert!(line.is_empty());
        }

        #[test]
        fn prop_control_line_mapping_roundtrip(
            key in "[a-z]{1,10}",
            value in "[a-z0-9]{1,10}"
        ) {
            let content = format!("{}={}", key, value);
            let mut line = ControlLine::new(&content);
            let (k, v) = line.pop_mapping(false, false).expect("should pop mapping");
            prop_assert_eq!(k, key);
            prop_assert_eq!(v, value);
        }
    }
}
