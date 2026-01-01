//! MAPADDRESS response parsing.
//!
//! This module parses responses from the `MAPADDRESS` command, which creates
//! address mappings in Tor. These mappings redirect connections from one
//! address to another, useful for hostname-to-IP mappings or virtual addresses.
//!
//! # Response Format
//!
//! A successful MAPADDRESS response contains address mappings:
//!
//! ```text
//! 250 1.2.3.4=tor.freehaven.net
//! ```
//!
//! Responses can contain a mixture of successes and failures:
//!
//! ```text
//! 512-syntax error: invalid address '@@@'
//! 250 1.2.3.4=tor.freehaven.net
//! ```
//!
//! # Example
//!
//! ```rust
//! use stem_rs::response::{ControlMessage, MapAddressResponse};
//!
//! // Single successful mapping
//! let msg = ControlMessage::from_str(
//!     "250 1.2.3.4=tor.freehaven.net\r\n",
//!     None,
//!     false
//! ).unwrap();
//! let response = MapAddressResponse::from_message(&msg).unwrap();
//!
//! assert_eq!(
//!     response.mapped.get("1.2.3.4"),
//!     Some(&"tor.freehaven.net".to_string())
//! );
//! assert!(response.failures.is_empty());
//! ```
//!
//! # Partial Failures
//!
//! The response can contain both successful mappings and failures. The
//! `from_message` method only returns an error if ALL mappings fail.
//!
//! # See Also
//!
//! - [`crate::Controller::map_address`]: High-level API for address mapping
//! - [Tor Control Protocol: MAPADDRESS](https://spec.torproject.org/control-spec/commands.html#mapaddress)

use std::collections::HashMap;

use super::ControlMessage;
use crate::Error;

/// Parsed response from the MAPADDRESS command.
///
/// Contains successful address mappings and any failure messages.
/// Responses can contain a mixture of successes and failures.
///
/// # Example
///
/// ```rust
/// use stem_rs::response::{ControlMessage, MapAddressResponse};
///
/// // Response with multiple mappings
/// let msg = ControlMessage::from_str(
///     "250-foo=bar\r\n\
///      250-baz=quux\r\n\
///      250 192.0.2.1=example.com\r\n",
///     None,
///     false
/// ).unwrap();
///
/// let response = MapAddressResponse::from_message(&msg).unwrap();
/// assert_eq!(response.mapped.len(), 3);
/// assert_eq!(response.mapped.get("foo"), Some(&"bar".to_string()));
/// ```
#[derive(Debug, Clone)]
pub struct MapAddressResponse {
    /// Successful address mappings.
    ///
    /// Maps the original address (key) to the replacement address (value).
    /// For example, `"1.2.3.4" => "tor.freehaven.net"` means connections
    /// to 1.2.3.4 will be redirected to tor.freehaven.net.
    pub mapped: HashMap<String, String>,

    /// Failure messages for mappings that could not be created.
    ///
    /// Each string contains the error message from Tor explaining why
    /// the mapping failed (e.g., "syntax error: invalid address '@@@'").
    pub failures: Vec<String>,
}

impl MapAddressResponse {
    /// Parses a MAPADDRESS response from a control message.
    ///
    /// Extracts successful mappings and failure messages from the response.
    /// This method only returns an error if ALL mappings fail or if the
    /// response format is invalid.
    ///
    /// # Arguments
    ///
    /// * `message` - The control message to parse
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`Error::InvalidRequest`]: All addresses
    ///   were invalid (512 error code)
    /// - [`Error::OperationFailed`]: Tor was
    ///   unable to satisfy the request (451 error code)
    /// - [`Error::Protocol`]: Response format was
    ///   invalid (missing `=` separator, unexpected status code)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::{ControlMessage, MapAddressResponse};
    ///
    /// // Successful mapping
    /// let msg = ControlMessage::from_str(
    ///     "250 192.0.2.1=example.com\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    /// let response = MapAddressResponse::from_message(&msg).unwrap();
    /// assert_eq!(
    ///     response.mapped.get("192.0.2.1"),
    ///     Some(&"example.com".to_string())
    /// );
    /// ```
    pub fn from_message(message: &ControlMessage) -> Result<Self, Error> {
        if !message.is_ok() {
            for (code, _, line) in message.content() {
                if code == "512" {
                    return Err(Error::InvalidRequest(line));
                } else if code == "451" {
                    return Err(Error::OperationFailed {
                        code,
                        message: line,
                    });
                } else if code != "250" {
                    return Err(Error::Protocol(format!(
                        "MAPADDRESS returned unexpected response code: {}",
                        code
                    )));
                }
            }
        }

        let mut mapped = HashMap::new();
        let mut failures = Vec::new();

        for (code, _, line) in message.content() {
            if code == "250" {
                if let Some(eq_pos) = line.find('=') {
                    let key = line[..eq_pos].to_string();
                    let value = line[eq_pos + 1..].to_string();
                    mapped.insert(key, value);
                } else {
                    return Err(Error::Protocol(format!(
                        "MAPADDRESS returned '{}', which isn't a mapping",
                        line
                    )));
                }
            } else {
                failures.push(line);
            }
        }

        Ok(Self { mapped, failures })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_message(lines: Vec<(&str, &str)>) -> ControlMessage {
        let parsed: Vec<(String, char, Vec<u8>)> = lines
            .iter()
            .enumerate()
            .map(|(i, (code, content))| {
                let divider = if i == lines.len() - 1 { ' ' } else { '-' };
                (code.to_string(), divider, content.as_bytes().to_vec())
            })
            .collect();
        let raw = lines
            .iter()
            .map(|(_, c)| *c)
            .collect::<Vec<_>>()
            .join("\r\n");
        ControlMessage::new(parsed, raw.into_bytes(), None).unwrap()
    }

    #[test]
    fn test_mapaddress_single_mapping() {
        let msg = create_message(vec![("250", "1.2.3.4=tor.freehaven.net")]);
        let response = MapAddressResponse::from_message(&msg).unwrap();
        assert_eq!(
            response.mapped.get("1.2.3.4"),
            Some(&"tor.freehaven.net".to_string())
        );
        assert!(response.failures.is_empty());
    }

    #[test]
    fn test_mapaddress_multiple_mappings() {
        let msg = create_message(vec![
            ("250", "1.2.3.4=example.com"),
            ("250", "5.6.7.8=another.com"),
        ]);
        let response = MapAddressResponse::from_message(&msg).unwrap();
        assert_eq!(response.mapped.len(), 2);
        assert_eq!(
            response.mapped.get("1.2.3.4"),
            Some(&"example.com".to_string())
        );
        assert_eq!(
            response.mapped.get("5.6.7.8"),
            Some(&"another.com".to_string())
        );
    }

    #[test]
    fn test_mapaddress_mixed_success_failure() {
        let msg = create_message(vec![
            ("512", "syntax error: invalid address '@@@'"),
            ("250", "1.2.3.4=tor.freehaven.net"),
        ]);
        let response = MapAddressResponse::from_message(&msg).unwrap();
        assert_eq!(
            response.mapped.get("1.2.3.4"),
            Some(&"tor.freehaven.net".to_string())
        );
        assert_eq!(response.failures.len(), 1);
        assert!(response.failures[0].contains("syntax error"));
    }

    #[test]
    fn test_mapaddress_512_error() {
        let msg = create_message(vec![("512", "syntax error: invalid address")]);
        let result = MapAddressResponse::from_message(&msg);
        assert!(matches!(result, Err(Error::InvalidRequest(_))));
    }

    #[test]
    fn test_mapaddress_451_error() {
        let msg = create_message(vec![("451", "Resource temporarily unavailable")]);
        let result = MapAddressResponse::from_message(&msg);
        assert!(matches!(result, Err(Error::OperationFailed { .. })));
    }

    #[test]
    fn test_mapaddress_batch_response() {
        let msg = create_message(vec![
            ("250", "foo=bar"),
            ("250", "baz=quux"),
            ("250", "gzzz=bzz"),
            ("250", "120.23.23.2=torproject.org"),
        ]);
        let response = MapAddressResponse::from_message(&msg).unwrap();
        assert_eq!(response.mapped.len(), 4);
        assert_eq!(response.mapped.get("foo"), Some(&"bar".to_string()));
        assert_eq!(response.mapped.get("baz"), Some(&"quux".to_string()));
        assert_eq!(response.mapped.get("gzzz"), Some(&"bzz".to_string()));
        assert_eq!(
            response.mapped.get("120.23.23.2"),
            Some(&"torproject.org".to_string())
        );
    }

    #[test]
    fn test_mapaddress_invalid_empty_response() {
        let msg = create_message(vec![("250", "OK")]);
        let result = MapAddressResponse::from_message(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_mapaddress_invalid_response_no_equals() {
        let msg = create_message(vec![("250", "foo is bar")]);
        let result = MapAddressResponse::from_message(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_mapaddress_partial_failure_response() {
        let msg = create_message(vec![
            (
                "512",
                "syntax error: mapping '2389' is not of expected form 'foo=bar'",
            ),
            (
                "512",
                "syntax error: mapping '23' is not of expected form 'foo=bar'.",
            ),
            ("250", "23=324"),
        ]);
        let response = MapAddressResponse::from_message(&msg).unwrap();
        assert_eq!(response.mapped.get("23"), Some(&"324".to_string()));
        assert_eq!(response.failures.len(), 2);
    }
}
