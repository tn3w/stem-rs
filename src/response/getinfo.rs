//! GETINFO response parsing.
//!
//! This module parses responses from the `GETINFO` command, which retrieves
//! runtime information from Tor. Unlike GETCONF (which gets configuration),
//! GETINFO retrieves dynamic state like version, address, and descriptors.
//!
//! # Response Format
//!
//! A successful GETINFO response contains key-value pairs:
//!
//! ```text
//! 250-version=0.4.7.1
//! 250-address=192.0.2.1
//! 250 OK
//! ```
//!
//! Multi-line values use the `+` divider:
//!
//! ```text
//! 250+config-text=
//! ControlPort 9051
//! DataDirectory /home/user/.tor
//! .
//! 250 OK
//! ```
//!
//! # Example
//!
//! ```rust
//! use stem_rs::response::{ControlMessage, GetInfoResponse};
//!
//! let response_text = "250-version=0.4.7.1\r\n\
//!                      250-address=192.0.2.1\r\n\
//!                      250 OK\r\n";
//! let msg = ControlMessage::from_str(response_text, None, false).unwrap();
//! let response = GetInfoResponse::from_message(&msg).unwrap();
//!
//! assert_eq!(response.get_str("version"), Some("0.4.7.1".to_string()));
//! assert_eq!(response.get_str("address"), Some("192.0.2.1".to_string()));
//! ```
//!
//! # Binary Data
//!
//! Values are stored as raw bytes to support binary data (like descriptors).
//! Use [`get_str`](GetInfoResponse::get_str) for string values or access
//! [`entries`](GetInfoResponse::entries) directly for binary data.
//!
//! # See Also
//!
//! - [`crate::Controller::get_info`]: High-level API for getting information
//! - [`GetConfResponse`](super::GetConfResponse): For querying configuration
//! - [Tor Control Protocol: GETINFO](https://spec.torproject.org/control-spec/commands.html#getinfo)

use std::collections::HashMap;
use std::collections::HashSet;

use super::ControlMessage;
use crate::Error;

/// Parsed response from the GETINFO command.
///
/// Contains a mapping of information keys to their byte values. Values are
/// stored as bytes to support binary data like descriptors.
///
/// # Example
///
/// ```rust
/// use stem_rs::response::{ControlMessage, GetInfoResponse};
///
/// let msg = ControlMessage::from_str(
///     "250-version=0.4.7.1\r\n\
///      250-fingerprint=ABCD1234\r\n\
///      250 OK\r\n",
///     None,
///     false
/// ).unwrap();
///
/// let response = GetInfoResponse::from_message(&msg).unwrap();
///
/// // Use get_str for string values
/// assert_eq!(response.get_str("version"), Some("0.4.7.1".to_string()));
///
/// // Or access raw bytes directly
/// assert_eq!(response.entries.get("fingerprint"), Some(&b"ABCD1234".to_vec()));
/// ```
#[derive(Debug, Clone)]
pub struct GetInfoResponse {
    /// Mapping of information keys to their byte values.
    ///
    /// Values are stored as raw bytes to support binary data. Use
    /// [`get_str`](Self::get_str) for convenient string access.
    pub entries: HashMap<String, Vec<u8>>,
}

impl GetInfoResponse {
    /// Parses a GETINFO response from a control message.
    ///
    /// Extracts information keys and their values from the response.
    /// Multi-line values (indicated by `+` divider) are handled automatically.
    ///
    /// # Arguments
    ///
    /// * `message` - The control message to parse
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`Error::InvalidArguments`]: One or more
    ///   requested keys were not recognized by Tor
    /// - [`Error::OperationFailed`]: Tor returned
    ///   an error code
    /// - [`Error::Protocol`]: The response format was
    ///   invalid (missing `=` separator, malformed multi-line value, etc.)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::{ControlMessage, GetInfoResponse};
    ///
    /// let msg = ControlMessage::from_str(
    ///     "250-version=0.4.7.1\r\n250 OK\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    /// let response = GetInfoResponse::from_message(&msg).unwrap();
    /// assert_eq!(response.get_str("version"), Some("0.4.7.1".to_string()));
    /// ```
    pub fn from_message(message: &ControlMessage) -> Result<Self, Error> {
        let mut entries: HashMap<String, Vec<u8>> = HashMap::new();

        let content_bytes = message.content_bytes();
        let mut remaining: Vec<&(String, char, Vec<u8>)> = content_bytes.iter().collect();

        if !message.is_ok() {
            let mut unrecognized_keywords = Vec::new();
            let mut error_code = None;
            let mut error_msg = None;

            for (code, _, line) in message.content() {
                if code != "250" {
                    error_code = Some(code.clone());
                    error_msg = Some(line.clone());
                }

                if code == "552" && line.starts_with("Unrecognized key \"") && line.ends_with('"') {
                    let keyword = &line[18..line.len() - 1];
                    unrecognized_keywords.push(keyword.to_string());
                }
            }

            if !unrecognized_keywords.is_empty() {
                return Err(Error::InvalidArguments(format!(
                    "GETINFO request contained unrecognized keywords: {}",
                    unrecognized_keywords.join(", ")
                )));
            }

            if let (Some(code), Some(msg)) = (error_code, error_msg) {
                return Err(Error::OperationFailed { code, message: msg });
            }

            return Err(Error::Protocol(format!(
                "GETINFO response didn't have an OK status:\n{}",
                message
            )));
        }

        if let Some(last) = remaining.last() {
            let last_content = String::from_utf8_lossy(&last.2);
            if last_content == "OK" {
                remaining.pop();
            }
        }

        for (_, divider, content) in remaining {
            let content_str = String::from_utf8_lossy(content);

            let eq_pos = content_str.find('=').ok_or_else(|| {
                Error::Protocol(format!(
                    "GETINFO replies should only contain parameter=value mappings:\n{}",
                    message
                ))
            })?;

            let key = content_str[..eq_pos].to_string();
            let mut value = content[eq_pos + 1..].to_vec();

            if *divider == '+' {
                if !value.starts_with(b"\n") && !value.is_empty() {
                    return Err(Error::Protocol(format!(
                        "GETINFO response contained a multi-line value that didn't start with a newline:\n{}",
                        message
                    )));
                }
                if value.starts_with(b"\n") {
                    value = value[1..].to_vec();
                }
            }

            entries.insert(key, value);
        }

        Ok(Self { entries })
    }

    /// Verifies that the response contains exactly the requested parameters.
    ///
    /// This is useful for ensuring the response matches what was requested,
    /// catching protocol errors where Tor returns different keys than expected.
    ///
    /// # Arguments
    ///
    /// * `params` - Set of parameter names that were requested
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if the response
    /// keys don't exactly match the requested parameters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::collections::HashSet;
    /// use stem_rs::response::{ControlMessage, GetInfoResponse};
    ///
    /// let msg = ControlMessage::from_str(
    ///     "250-version=0.4.7.1\r\n250 OK\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    /// let response = GetInfoResponse::from_message(&msg).unwrap();
    ///
    /// // Matches what we requested
    /// let mut expected = HashSet::new();
    /// expected.insert("version".to_string());
    /// assert!(response.assert_matches(&expected).is_ok());
    ///
    /// // Doesn't match
    /// let mut wrong = HashSet::new();
    /// wrong.insert("address".to_string());
    /// assert!(response.assert_matches(&wrong).is_err());
    /// ```
    pub fn assert_matches(&self, params: &HashSet<String>) -> Result<(), Error> {
        let reply_params: HashSet<String> = self.entries.keys().cloned().collect();

        if params != &reply_params {
            let requested_label = params.iter().cloned().collect::<Vec<_>>().join(", ");
            let reply_label = reply_params.iter().cloned().collect::<Vec<_>>().join(", ");

            return Err(Error::Protocol(format!(
                "GETINFO reply doesn't match the parameters that we requested. Queried '{}' but got '{}'.",
                requested_label, reply_label
            )));
        }

        Ok(())
    }

    /// Gets a value as a UTF-8 string.
    ///
    /// Convenience method for accessing string values. Invalid UTF-8 sequences
    /// are replaced with the Unicode replacement character (U+FFFD).
    ///
    /// # Arguments
    ///
    /// * `key` - The information key to retrieve
    ///
    /// # Returns
    ///
    /// `Some(String)` if the key exists, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::{ControlMessage, GetInfoResponse};
    ///
    /// let msg = ControlMessage::from_str(
    ///     "250-version=0.4.7.1\r\n250 OK\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    /// let response = GetInfoResponse::from_message(&msg).unwrap();
    ///
    /// assert_eq!(response.get_str("version"), Some("0.4.7.1".to_string()));
    /// assert_eq!(response.get_str("nonexistent"), None);
    /// ```
    pub fn get_str(&self, key: &str) -> Option<String> {
        self.entries
            .get(key)
            .map(|v| String::from_utf8_lossy(v).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_message(lines: Vec<(&str, char, &str)>) -> ControlMessage {
        let parsed: Vec<(String, char, Vec<u8>)> = lines
            .iter()
            .map(|(code, div, content)| (code.to_string(), *div, content.as_bytes().to_vec()))
            .collect();
        let raw = lines
            .iter()
            .map(|(_, _, c)| *c)
            .collect::<Vec<_>>()
            .join("\r\n");
        ControlMessage::new(parsed, raw.into_bytes(), None).unwrap()
    }

    fn create_simple_message(lines: Vec<&str>) -> ControlMessage {
        let parsed: Vec<(String, char, Vec<u8>)> = lines
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let divider = if i == lines.len() - 1 { ' ' } else { '-' };
                ("250".to_string(), divider, line.as_bytes().to_vec())
            })
            .collect();
        let raw = lines.join("\r\n");
        ControlMessage::new(parsed, raw.into_bytes(), None).unwrap()
    }

    #[test]
    fn test_getinfo_single_value() {
        let msg = create_simple_message(vec!["version=0.4.7.1", "OK"]);
        let response = GetInfoResponse::from_message(&msg).unwrap();
        assert_eq!(response.get_str("version"), Some("0.4.7.1".to_string()));
    }

    #[test]
    fn test_getinfo_multiple_values() {
        let msg =
            create_simple_message(vec!["version=0.4.7.1", "config-file=/etc/tor/torrc", "OK"]);
        let response = GetInfoResponse::from_message(&msg).unwrap();
        assert_eq!(response.get_str("version"), Some("0.4.7.1".to_string()));
        assert_eq!(
            response.get_str("config-file"),
            Some("/etc/tor/torrc".to_string())
        );
    }

    #[test]
    fn test_getinfo_multiline_value() {
        let msg = create_message(vec![
            (
                "250",
                '+',
                "config-text=\nControlPort 9051\nDataDirectory /home/.tor",
            ),
            ("250", ' ', "OK"),
        ]);
        let response = GetInfoResponse::from_message(&msg).unwrap();
        let config = response.get_str("config-text").unwrap();
        assert!(config.contains("ControlPort 9051"));
        assert!(config.contains("DataDirectory /home/.tor"));
    }

    #[test]
    fn test_getinfo_assert_matches() {
        let msg = create_simple_message(vec!["version=0.4.7.1", "OK"]);
        let response = GetInfoResponse::from_message(&msg).unwrap();

        let mut expected = HashSet::new();
        expected.insert("version".to_string());
        assert!(response.assert_matches(&expected).is_ok());

        let mut wrong = HashSet::new();
        wrong.insert("other".to_string());
        assert!(response.assert_matches(&wrong).is_err());
    }

    #[test]
    fn test_getinfo_unrecognized_key() {
        let msg = create_message(vec![("552", ' ', "Unrecognized key \"invalid-key\"")]);
        let result = GetInfoResponse::from_message(&msg);
        assert!(result.is_err());
        if let Err(Error::InvalidArguments(msg)) = result {
            assert!(msg.contains("invalid-key"));
        } else {
            panic!("Expected InvalidArguments error");
        }
    }

    #[test]
    fn test_getinfo_empty_value() {
        let msg = create_simple_message(vec!["some-key=", "OK"]);
        let response = GetInfoResponse::from_message(&msg).unwrap();
        assert_eq!(response.get_str("some-key"), Some("".to_string()));
    }

    #[test]
    fn test_getinfo_empty_response() {
        let msg = create_simple_message(vec!["OK"]);
        let response = GetInfoResponse::from_message(&msg).unwrap();
        assert!(response.entries.is_empty());
    }

    #[test]
    fn test_getinfo_batch_response() {
        let msg = create_simple_message(vec![
            "version=0.2.3.11-alpha-dev",
            "address=67.137.76.214",
            "fingerprint=5FDE0422045DF0E1879A3738D09099EB4A0C5BA0",
            "OK",
        ]);
        let response = GetInfoResponse::from_message(&msg).unwrap();
        assert_eq!(
            response.get_str("version"),
            Some("0.2.3.11-alpha-dev".to_string())
        );
        assert_eq!(
            response.get_str("address"),
            Some("67.137.76.214".to_string())
        );
        assert_eq!(
            response.get_str("fingerprint"),
            Some("5FDE0422045DF0E1879A3738D09099EB4A0C5BA0".to_string())
        );
    }

    #[test]
    fn test_getinfo_non_mapping_content() {
        let msg = create_simple_message(vec![
            "version=0.2.3.11-alpha-dev",
            "address 67.137.76.214",
            "OK",
        ]);
        let result = GetInfoResponse::from_message(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_getinfo_multiline_missing_newline() {
        let msg = create_message(vec![
            ("250", '+', "config-text=ControlPort 9051"),
            ("250", ' ', "OK"),
        ]);
        let result = GetInfoResponse::from_message(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_getinfo_bytes_access() {
        let msg = create_simple_message(vec!["version=0.4.7.1", "OK"]);
        let response = GetInfoResponse::from_message(&msg).unwrap();
        let bytes = response.entries.get("version").unwrap();
        assert_eq!(bytes, b"0.4.7.1");
    }
}
