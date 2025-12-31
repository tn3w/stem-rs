//! GETCONF response parsing.
//!
//! This module parses responses from the `GETCONF` command, which retrieves
//! Tor configuration values. Configuration options can have single values,
//! multiple values (like exit policies), or no value (unset options).
//!
//! # Response Format
//!
//! A successful GETCONF response contains key-value pairs:
//!
//! ```text
//! 250-CookieAuthentication=0
//! 250-ControlPort=9100
//! 250-DataDirectory=/home/user/.tor
//! 250 DirPort
//! ```
//!
//! Options without values (like `DirPort` above) indicate the option is unset
//! or using its default value.
//!
//! # Example
//!
//! ```rust
//! use stem_rs::response::{ControlMessage, GetConfResponse};
//!
//! let response_text = "250-CookieAuthentication=0\r\n\
//!                      250-ControlPort=9100\r\n\
//!                      250 OK\r\n";
//! let msg = ControlMessage::from_str(response_text, None, false).unwrap();
//! let response = GetConfResponse::from_message(&msg).unwrap();
//!
//! // Single-value options return a Vec with one element
//! assert_eq!(
//!     response.entries.get("CookieAuthentication"),
//!     Some(&vec!["0".to_string()])
//! );
//! ```
//!
//! # Multi-Value Options
//!
//! Some options like `ExitPolicy` can have multiple values:
//!
//! ```rust
//! use stem_rs::response::{ControlMessage, GetConfResponse};
//!
//! let response_text = "250-ExitPolicy=accept *:80\r\n\
//!                      250-ExitPolicy=accept *:443\r\n\
//!                      250-ExitPolicy=reject *:*\r\n\
//!                      250 OK\r\n";
//! let msg = ControlMessage::from_str(response_text, None, false).unwrap();
//! let response = GetConfResponse::from_message(&msg).unwrap();
//!
//! let policies = response.entries.get("ExitPolicy").unwrap();
//! assert_eq!(policies.len(), 3);
//! ```
//!
//! # See Also
//!
//! - [`crate::Controller::get_conf`]: High-level API for getting configuration
//! - [`GetInfoResponse`]: For querying runtime information
//! - [Tor Control Protocol: GETCONF](https://spec.torproject.org/control-spec/commands.html#getconf)

use std::collections::HashMap;

use super::ControlMessage;
use crate::Error;

/// Parsed response from the GETCONF command.
///
/// Contains a mapping of configuration option names to their values.
/// Options can have zero, one, or multiple values.
///
/// # Value Semantics
///
/// - **Empty Vec**: Option is unset or using default value
/// - **Single element**: Option has one value
/// - **Multiple elements**: Option has multiple values (e.g., ExitPolicy)
///
/// # Example
///
/// ```rust
/// use stem_rs::response::{ControlMessage, GetConfResponse};
///
/// let msg = ControlMessage::from_str(
///     "250-ControlPort=9051\r\n\
///      250-DirPort\r\n\
///      250 OK\r\n",
///     None,
///     false
/// ).unwrap();
///
/// let response = GetConfResponse::from_message(&msg).unwrap();
///
/// // ControlPort has a value
/// assert_eq!(
///     response.entries.get("ControlPort"),
///     Some(&vec!["9051".to_string()])
/// );
///
/// // DirPort is unset (empty Vec)
/// assert_eq!(response.entries.get("DirPort"), Some(&vec![]));
/// ```
#[derive(Debug, Clone)]
pub struct GetConfResponse {
    /// Mapping of configuration option names to their values.
    ///
    /// Each key is a configuration option name (e.g., "ControlPort").
    /// Each value is a Vec of strings:
    /// - Empty Vec: option is unset
    /// - Single element: option has one value
    /// - Multiple elements: option has multiple values
    pub entries: HashMap<String, Vec<String>>,
}

impl GetConfResponse {
    /// Parses a GETCONF response from a control message.
    ///
    /// Extracts configuration option names and their values from the response.
    ///
    /// # Arguments
    ///
    /// * `message` - The control message to parse
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`Error::InvalidArguments`](crate::Error::InvalidArguments): One or more
    ///   requested configuration options were not recognized by Tor
    /// - [`Error::Protocol`](crate::Error::Protocol): The response had a non-OK
    ///   status code for other reasons
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::{ControlMessage, GetConfResponse};
    ///
    /// // Successful response
    /// let msg = ControlMessage::from_str(
    ///     "250-SocksPort=9050\r\n250 OK\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    /// let response = GetConfResponse::from_message(&msg).unwrap();
    /// assert_eq!(
    ///     response.entries.get("SocksPort"),
    ///     Some(&vec!["9050".to_string()])
    /// );
    ///
    /// // Empty response (no options requested)
    /// let msg = ControlMessage::from_str("250 OK\r\n", None, false).unwrap();
    /// let response = GetConfResponse::from_message(&msg).unwrap();
    /// assert!(response.entries.is_empty());
    /// ```
    pub fn from_message(message: &ControlMessage) -> Result<Self, Error> {
        let mut entries: HashMap<String, Vec<String>> = HashMap::new();

        let content = message.content();

        if content == vec![("250".to_string(), ' ', "OK".to_string())] {
            return Ok(Self { entries });
        }

        if !message.is_ok() {
            let mut unrecognized_keywords = Vec::new();

            for (code, _, line) in &content {
                if code == "552"
                    && line.starts_with("Unrecognized configuration key \"")
                    && line.ends_with('"')
                {
                    let keyword = &line[32..line.len() - 1];
                    unrecognized_keywords.push(keyword.to_string());
                }
            }

            if !unrecognized_keywords.is_empty() {
                return Err(Error::InvalidArguments(format!(
                    "GETCONF request contained unrecognized keywords: {}",
                    unrecognized_keywords.join(", ")
                )));
            }

            return Err(Error::Protocol(format!(
                "GETCONF response contained a non-OK status code:\n{}",
                message
            )));
        }

        for line in message.iter() {
            let line_str = line.to_string();

            let (key, value) = if let Some(eq_pos) = line_str.find('=') {
                let k = line_str[..eq_pos].to_string();
                let v = line_str[eq_pos + 1..].to_string();
                let v = if v.is_empty() { None } else { Some(v) };
                (k, v)
            } else {
                (line_str.trim().to_string(), None)
            };

            if key.is_empty() || key == "OK" {
                continue;
            }

            let key_clone = key.clone();
            entries.entry(key).or_default();
            if let Some(v) = value {
                entries.get_mut(&key_clone).unwrap().push(v);
            }
        }

        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_message(lines: Vec<&str>) -> ControlMessage {
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

    fn create_error_message(code: &str, lines: Vec<&str>) -> ControlMessage {
        let parsed: Vec<(String, char, Vec<u8>)> = lines
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let divider = if i == lines.len() - 1 { ' ' } else { '-' };
                (code.to_string(), divider, line.as_bytes().to_vec())
            })
            .collect();
        let raw = lines.join("\r\n");
        ControlMessage::new(parsed, raw.into_bytes(), None).unwrap()
    }

    #[test]
    fn test_getconf_single_value() {
        let msg = create_message(vec!["CookieAuthentication=0", "OK"]);
        let response = GetConfResponse::from_message(&msg).unwrap();
        assert_eq!(
            response.entries.get("CookieAuthentication"),
            Some(&vec!["0".to_string()])
        );
    }

    #[test]
    fn test_getconf_multiple_values() {
        let msg = create_message(vec![
            "CookieAuthentication=0",
            "ControlPort=9100",
            "DataDirectory=/home/user/.tor",
            "OK",
        ]);
        let response = GetConfResponse::from_message(&msg).unwrap();
        assert_eq!(
            response.entries.get("CookieAuthentication"),
            Some(&vec!["0".to_string()])
        );
        assert_eq!(
            response.entries.get("ControlPort"),
            Some(&vec!["9100".to_string()])
        );
        assert_eq!(
            response.entries.get("DataDirectory"),
            Some(&vec!["/home/user/.tor".to_string()])
        );
    }

    #[test]
    fn test_getconf_key_without_value() {
        let msg = create_message(vec!["DirPort", "OK"]);
        let response = GetConfResponse::from_message(&msg).unwrap();
        assert_eq!(response.entries.get("DirPort"), Some(&vec![]));
    }

    #[test]
    fn test_getconf_multiple_values_same_key() {
        let msg = create_message(vec![
            "ExitPolicy=accept *:80",
            "ExitPolicy=accept *:443",
            "ExitPolicy=reject *:*",
            "OK",
        ]);
        let response = GetConfResponse::from_message(&msg).unwrap();
        let policies = response.entries.get("ExitPolicy").unwrap();
        assert_eq!(policies.len(), 3);
        assert_eq!(policies[0], "accept *:80");
        assert_eq!(policies[1], "accept *:443");
        assert_eq!(policies[2], "reject *:*");
    }

    #[test]
    fn test_getconf_empty_response() {
        let msg = create_message(vec!["OK"]);
        let response = GetConfResponse::from_message(&msg).unwrap();
        assert!(response.entries.is_empty());
    }

    #[test]
    fn test_getconf_unrecognized_key() {
        let msg =
            create_error_message("552", vec!["Unrecognized configuration key \"InvalidKey\""]);
        let result = GetConfResponse::from_message(&msg);
        assert!(result.is_err());
        if let Err(Error::InvalidArguments(msg)) = result {
            assert!(msg.contains("InvalidKey"));
        } else {
            panic!("Expected InvalidArguments error");
        }
    }

    #[test]
    fn test_getconf_empty_value_bug() {
        let msg = create_message(vec!["SomeOption=", "OK"]);
        let response = GetConfResponse::from_message(&msg).unwrap();
        assert_eq!(response.entries.get("SomeOption"), Some(&vec![]));
    }

    #[test]
    fn test_getconf_multiple_unrecognized_keys() {
        let parsed = vec![
            (
                "552".to_string(),
                '-',
                "Unrecognized configuration key \"brickroad\""
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "552".to_string(),
                ' ',
                "Unrecognized configuration key \"submarine\""
                    .as_bytes()
                    .to_vec(),
            ),
        ];
        let msg = ControlMessage::new(parsed, "552 error".into(), None).unwrap();
        let result = GetConfResponse::from_message(&msg);
        assert!(result.is_err());
        if let Err(Error::InvalidArguments(msg)) = result {
            assert!(msg.contains("brickroad"));
            assert!(msg.contains("submarine"));
        } else {
            panic!("Expected InvalidArguments error");
        }
    }

    #[test]
    fn test_getconf_value_with_spaces() {
        let msg = create_message(vec!["DataDirectory=/tmp/fake dir", "OK"]);
        let response = GetConfResponse::from_message(&msg).unwrap();
        assert_eq!(
            response.entries.get("DataDirectory"),
            Some(&vec!["/tmp/fake dir".to_string()])
        );
    }

    #[test]
    fn test_getconf_batch_response() {
        let msg = create_message(vec![
            "CookieAuthentication=0",
            "ControlPort=9100",
            "DataDirectory=/tmp/fake dir",
            "DirPort",
            "OK",
        ]);
        let response = GetConfResponse::from_message(&msg).unwrap();
        assert_eq!(
            response.entries.get("CookieAuthentication"),
            Some(&vec!["0".to_string()])
        );
        assert_eq!(
            response.entries.get("ControlPort"),
            Some(&vec!["9100".to_string()])
        );
        assert_eq!(
            response.entries.get("DataDirectory"),
            Some(&vec!["/tmp/fake dir".to_string()])
        );
        assert_eq!(response.entries.get("DirPort"), Some(&vec![]));
    }

    #[test]
    fn test_getconf_invalid_response_code() {
        let parsed = vec![
            ("123".to_string(), '-', "FOO".as_bytes().to_vec()),
            ("532".to_string(), ' ', "BAR".as_bytes().to_vec()),
        ];
        let msg = ControlMessage::new(parsed, "invalid".into(), None).unwrap();
        let result = GetConfResponse::from_message(&msg);
        assert!(result.is_err());
    }
}
