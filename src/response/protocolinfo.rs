//! PROTOCOLINFO response parsing.
//!
//! This module parses responses from the `PROTOCOLINFO` command, which provides
//! information about available authentication methods and the Tor version.
//! This is typically the first command sent after connecting to determine
//! how to authenticate.
//!
//! # Response Format
//!
//! A typical PROTOCOLINFO response:
//!
//! ```text
//! 250-PROTOCOLINFO 1
//! 250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/home/user/.tor/control_auth_cookie"
//! 250-VERSION Tor="0.4.7.1"
//! 250 OK
//! ```
//!
//! # Authentication Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `NULL` | No authentication required |
//! | `HASHEDPASSWORD` | Password authentication |
//! | `COOKIE` | Cookie file authentication |
//! | `SAFECOOKIE` | HMAC-based cookie authentication (most secure) |
//!
//! # Example
//!
//! ```rust
//! use stem_rs::response::{ControlMessage, ProtocolInfoResponse, AuthMethod};
//!
//! let response_text = "250-PROTOCOLINFO 1\r\n\
//!                      250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/tmp/cookie\"\r\n\
//!                      250-VERSION Tor=\"0.4.7.1\"\r\n\
//!                      250 OK\r\n";
//! let msg = ControlMessage::from_str(response_text, None, false).unwrap();
//! let response = ProtocolInfoResponse::from_message(&msg).unwrap();
//!
//! assert_eq!(response.protocol_version, 1);
//! assert!(response.auth_methods.contains(&AuthMethod::Cookie));
//! assert!(response.auth_methods.contains(&AuthMethod::SafeCookie));
//! ```
//!
//! # See Also
//!
//! - [`crate::auth::get_protocol_info`]: High-level API for getting protocol info
//! - [`crate::auth::authenticate`]: Uses this response to select auth method
//! - [Tor Control Protocol: PROTOCOLINFO](https://spec.torproject.org/control-spec/commands.html#protocolinfo)

use std::path::PathBuf;

use super::{ControlLine, ControlMessage};
use crate::version::Version;
use crate::Error;

/// Authentication methods supported by Tor's control protocol.
///
/// These correspond to the methods listed in the PROTOCOLINFO response's
/// AUTH METHODS field.
///
/// # Security Comparison
///
/// | Method | Security | Use Case |
/// |--------|----------|----------|
/// | [`None`](AuthMethod::None) | None | Testing only |
/// | [`Password`](AuthMethod::Password) | Low | Simple setups |
/// | [`Cookie`](AuthMethod::Cookie) | Medium | Local connections |
/// | [`SafeCookie`](AuthMethod::SafeCookie) | High | Recommended for local |
///
/// # Example
///
/// ```rust
/// use stem_rs::response::{ControlMessage, ProtocolInfoResponse, AuthMethod};
///
/// let msg = ControlMessage::from_str(
///     "250-PROTOCOLINFO 1\r\n\
///      250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/tmp/cookie\"\r\n\
///      250 OK\r\n",
///     None,
///     false
/// ).unwrap();
///
/// let response = ProtocolInfoResponse::from_message(&msg).unwrap();
///
/// // Check which methods are available
/// if response.auth_methods.contains(&AuthMethod::SafeCookie) {
///     println!("SafeCookie authentication available (recommended)");
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// No authentication required (`NULL` in protocol).
    ///
    /// The control port is open without any authentication. This is
    /// insecure and should only be used for testing.
    None,

    /// Password authentication (`HASHEDPASSWORD` in protocol).
    ///
    /// Requires the password configured via `HashedControlPassword` in torrc.
    /// The password is sent in cleartext, so this is less secure than
    /// cookie-based methods for local connections.
    Password,

    /// Cookie file authentication (`COOKIE` in protocol).
    ///
    /// Authenticates by proving access to a cookie file on disk.
    /// The cookie path is provided in the PROTOCOLINFO response.
    Cookie,

    /// HMAC-based cookie authentication (`SAFECOOKIE` in protocol).
    ///
    /// The most secure authentication method for local connections.
    /// Uses HMAC-SHA256 challenge-response to prove cookie knowledge
    /// without transmitting the cookie itself.
    SafeCookie,

    /// An unrecognized authentication method.
    ///
    /// This variant is used when Tor advertises an authentication method
    /// that this library doesn't recognize. The actual method name is
    /// stored in [`ProtocolInfoResponse::unknown_auth_methods`].
    Unknown,
}

impl AuthMethod {
    /// Parses an authentication method from its protocol string.
    fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "NULL" => AuthMethod::None,
            "HASHEDPASSWORD" => AuthMethod::Password,
            "COOKIE" => AuthMethod::Cookie,
            "SAFECOOKIE" => AuthMethod::SafeCookie,
            _ => AuthMethod::Unknown,
        }
    }
}

/// Parsed response from the PROTOCOLINFO command.
///
/// Contains information about the Tor version and available authentication
/// methods. This is typically used to determine how to authenticate with
/// the control port.
///
/// # Example
///
/// ```rust
/// use stem_rs::response::{ControlMessage, ProtocolInfoResponse, AuthMethod};
///
/// let msg = ControlMessage::from_str(
///     "250-PROTOCOLINFO 1\r\n\
///      250-AUTH METHODS=COOKIE COOKIEFILE=\"/home/user/.tor/control_auth_cookie\"\r\n\
///      250-VERSION Tor=\"0.4.7.1\"\r\n\
///      250 OK\r\n",
///     None,
///     false
/// ).unwrap();
///
/// let response = ProtocolInfoResponse::from_message(&msg).unwrap();
///
/// println!("Protocol version: {}", response.protocol_version);
/// if let Some(ref version) = response.tor_version {
///     println!("Tor version: {}", version);
/// }
/// println!("Auth methods: {:?}", response.auth_methods);
/// if let Some(ref path) = response.cookie_path {
///     println!("Cookie file: {}", path.display());
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ProtocolInfoResponse {
    /// The protocol version (typically 1).
    ///
    /// This indicates the version of the PROTOCOLINFO response format.
    /// Currently, version 1 is the only defined version.
    pub protocol_version: u32,

    /// The Tor version, if provided.
    ///
    /// Parsed from the VERSION line of the response. May be `None` if
    /// the VERSION line was not present.
    pub tor_version: Option<Version>,

    /// Available authentication methods.
    ///
    /// Lists all authentication methods that Tor will accept. Use this
    /// to determine which authentication method to use.
    pub auth_methods: Vec<AuthMethod>,

    /// Unrecognized authentication method names.
    ///
    /// Contains the raw strings of any authentication methods that
    /// weren't recognized. Useful for debugging or future compatibility.
    pub unknown_auth_methods: Vec<String>,

    /// Path to the authentication cookie file, if applicable.
    ///
    /// Present when COOKIE or SAFECOOKIE authentication is available.
    /// This file must be readable to authenticate using cookie methods.
    pub cookie_path: Option<PathBuf>,
}

impl ProtocolInfoResponse {
    /// Parses a PROTOCOLINFO response from a control message.
    ///
    /// Extracts the protocol version, Tor version, authentication methods,
    /// and cookie file path from the response.
    ///
    /// # Arguments
    ///
    /// * `message` - The control message to parse
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The response status is not OK
    /// - The response doesn't start with "PROTOCOLINFO"
    /// - The protocol version is missing or non-numeric
    /// - The AUTH line is missing the METHODS mapping
    /// - The VERSION line is missing the Tor version mapping
    /// - The Tor version string is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::{ControlMessage, ProtocolInfoResponse, AuthMethod};
    ///
    /// // Minimal response (just protocol version)
    /// let msg = ControlMessage::from_str(
    ///     "250-PROTOCOLINFO 1\r\n250 OK\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    /// let response = ProtocolInfoResponse::from_message(&msg).unwrap();
    /// assert_eq!(response.protocol_version, 1);
    /// assert!(response.auth_methods.is_empty());
    ///
    /// // Full response with all fields
    /// let msg = ControlMessage::from_str(
    ///     "250-PROTOCOLINFO 1\r\n\
    ///      250-AUTH METHODS=NULL,HASHEDPASSWORD,COOKIE,SAFECOOKIE COOKIEFILE=\"/tmp/cookie\"\r\n\
    ///      250-VERSION Tor=\"0.4.7.1\"\r\n\
    ///      250 OK\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    /// let response = ProtocolInfoResponse::from_message(&msg).unwrap();
    /// assert_eq!(response.auth_methods.len(), 4);
    /// ```
    pub fn from_message(message: &ControlMessage) -> Result<Self, Error> {
        let mut protocol_version = None;
        let mut tor_version = None;
        let mut auth_methods = Vec::new();
        let mut unknown_auth_methods = Vec::new();
        let mut cookie_path = None;

        let lines: Vec<String> = message.iter().map(|l| l.to_string()).collect();

        let last_line = lines.last().map(|s| s.as_str()).unwrap_or("");
        if !message.is_ok() || last_line != "OK" {
            return Err(Error::Protocol(format!(
                "PROTOCOLINFO response didn't have an OK status:\n{}",
                message
            )));
        }

        if lines.is_empty() || !lines[0].starts_with("PROTOCOLINFO") {
            return Err(Error::Protocol(format!(
                "Message is not a PROTOCOLINFO response:\n{}",
                message
            )));
        }

        for line_str in &lines {
            if line_str == "OK" {
                continue;
            }

            let mut line = ControlLine::new(line_str);
            let line_type = line.pop(false, false)?;

            match line_type.as_str() {
                "PROTOCOLINFO" => {
                    if line.is_empty() {
                        return Err(Error::Protocol(format!(
                            "PROTOCOLINFO response's initial line is missing the protocol version: {}",
                            line_str
                        )));
                    }

                    let version_str = line.pop(false, false)?;
                    protocol_version = Some(version_str.parse().map_err(|_| {
                        Error::Protocol(format!(
                            "PROTOCOLINFO response version is non-numeric: {}",
                            line_str
                        ))
                    })?);
                }
                "AUTH" => {
                    if !line.is_next_mapping(Some("METHODS"), false, false) {
                        return Err(Error::Protocol(format!(
                            "PROTOCOLINFO response's AUTH line is missing its mandatory 'METHODS' mapping: {}",
                            line_str
                        )));
                    }

                    let (_, methods_str) = line.pop_mapping(false, false)?;
                    for method in methods_str.split(',') {
                        let auth_method = AuthMethod::from_str(method);
                        if auth_method == AuthMethod::Unknown {
                            unknown_auth_methods.push(method.to_string());
                            if !auth_methods.contains(&AuthMethod::Unknown) {
                                auth_methods.push(AuthMethod::Unknown);
                            }
                        } else if !auth_methods.contains(&auth_method) {
                            auth_methods.push(auth_method);
                        }
                    }

                    if line.is_next_mapping(Some("COOKIEFILE"), true, true) {
                        let (_, path_bytes) = line.pop_mapping_bytes(true, true)?;
                        let path_str = String::from_utf8_lossy(&path_bytes);
                        cookie_path = Some(PathBuf::from(path_str.to_string()));
                    }
                }
                "VERSION" => {
                    if !line.is_next_mapping(Some("Tor"), true, false) {
                        return Err(Error::Protocol(format!(
                            "PROTOCOLINFO response's VERSION line is missing its mandatory tor version mapping: {}",
                            line_str
                        )));
                    }

                    let (_, version_str) = line.pop_mapping(true, false)?;
                    tor_version = Some(
                        Version::parse(&version_str)
                            .map_err(|e| Error::Protocol(format!("Invalid Tor version: {}", e)))?,
                    );
                }
                _ => {}
            }
        }

        Ok(Self {
            protocol_version: protocol_version.unwrap_or(1),
            tor_version,
            auth_methods,
            unknown_auth_methods,
            cookie_path,
        })
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

    #[test]
    fn test_protocolinfo_no_auth() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=NULL",
            "VERSION Tor=\"0.2.1.30\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert_eq!(response.protocol_version, 1);
        assert_eq!(
            response.tor_version,
            Some(Version::parse("0.2.1.30").unwrap())
        );
        assert_eq!(response.auth_methods, vec![AuthMethod::None]);
        assert!(response.cookie_path.is_none());
    }

    #[test]
    fn test_protocolinfo_password_auth() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=HASHEDPASSWORD",
            "VERSION Tor=\"0.2.1.30\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert_eq!(response.auth_methods, vec![AuthMethod::Password]);
    }

    #[test]
    fn test_protocolinfo_cookie_auth() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=COOKIE COOKIEFILE=\"/home/atagar/.tor/control_auth_cookie\"",
            "VERSION Tor=\"0.2.1.30\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert_eq!(response.auth_methods, vec![AuthMethod::Cookie]);
        assert_eq!(
            response.cookie_path,
            Some(PathBuf::from("/home/atagar/.tor/control_auth_cookie"))
        );
    }

    #[test]
    fn test_protocolinfo_cookie_auth_with_escape() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=COOKIE COOKIEFILE=\"/tmp/my data\\\\\\\"dir//control_auth_cookie\"",
            "VERSION Tor=\"0.2.1.30\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert_eq!(response.auth_methods, vec![AuthMethod::Cookie]);
        let path = response.cookie_path.unwrap();
        assert_eq!(
            path.to_str().unwrap(),
            "/tmp/my data\\\"dir//control_auth_cookie"
        );
    }

    #[test]
    fn test_protocolinfo_multiple_auth_methods() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=COOKIE,HASHEDPASSWORD COOKIEFILE=\"/home/atagar/.tor/control_auth_cookie\"",
            "VERSION Tor=\"0.2.1.30\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert!(response.auth_methods.contains(&AuthMethod::Cookie));
        assert!(response.auth_methods.contains(&AuthMethod::Password));
    }

    #[test]
    fn test_protocolinfo_safecookie_auth() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/var/run/tor/control.authcookie\"",
            "VERSION Tor=\"0.4.2.6\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert!(response.auth_methods.contains(&AuthMethod::Cookie));
        assert!(response.auth_methods.contains(&AuthMethod::SafeCookie));
    }

    #[test]
    fn test_protocolinfo_all_auth_methods() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=NULL,HASHEDPASSWORD,COOKIE,SAFECOOKIE COOKIEFILE=\"/tmp/cookie\"",
            "VERSION Tor=\"0.4.7.1\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert_eq!(response.auth_methods.len(), 4);
        assert!(response.auth_methods.contains(&AuthMethod::None));
        assert!(response.auth_methods.contains(&AuthMethod::Password));
        assert!(response.auth_methods.contains(&AuthMethod::Cookie));
        assert!(response.auth_methods.contains(&AuthMethod::SafeCookie));
    }

    #[test]
    fn test_protocolinfo_minimum_response() {
        let msg = create_message(vec!["PROTOCOLINFO 5", "OK"]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert_eq!(response.protocol_version, 5);
        assert!(response.tor_version.is_none());
        assert!(response.auth_methods.is_empty());
        assert!(response.cookie_path.is_none());
    }

    #[test]
    fn test_protocolinfo_unknown_auth_method() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=NULL,NEWMETHOD",
            "VERSION Tor=\"0.4.7.1\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert!(response.auth_methods.contains(&AuthMethod::None));
        assert!(response.auth_methods.contains(&AuthMethod::Unknown));
        assert!(response
            .unknown_auth_methods
            .contains(&"NEWMETHOD".to_string()));
    }

    #[test]
    fn test_protocolinfo_error_response() {
        let parsed = vec![(
            "515".to_string(),
            ' ',
            "Authentication required".as_bytes().to_vec(),
        )];
        let msg = ControlMessage::new(parsed, "515 Authentication required".into(), None).unwrap();
        assert!(ProtocolInfoResponse::from_message(&msg).is_err());
    }

    #[test]
    fn test_protocolinfo_missing_version() {
        let msg = create_message(vec!["PROTOCOLINFO", "OK"]);
        assert!(ProtocolInfoResponse::from_message(&msg).is_err());
    }

    #[test]
    fn test_protocolinfo_multiple_unknown_auth_methods() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=MAGIC,HASHEDPASSWORD,PIXIE_DUST",
            "VERSION Tor=\"0.2.1.30\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert!(response.auth_methods.contains(&AuthMethod::Unknown));
        assert!(response.auth_methods.contains(&AuthMethod::Password));
        assert!(response.unknown_auth_methods.contains(&"MAGIC".to_string()));
        assert!(response
            .unknown_auth_methods
            .contains(&"PIXIE_DUST".to_string()));
    }

    #[test]
    fn test_protocolinfo_relative_cookie_path() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH METHODS=COOKIE COOKIEFILE=\"./tor-browser_en-US/Data/control_auth_cookie\"",
            "VERSION Tor=\"0.2.1.30\"",
            "OK",
        ]);
        let response = ProtocolInfoResponse::from_message(&msg).unwrap();
        assert_eq!(
            response.cookie_path,
            Some(PathBuf::from(
                "./tor-browser_en-US/Data/control_auth_cookie"
            ))
        );
    }

    #[test]
    fn test_protocolinfo_not_protocolinfo_message() {
        let msg = create_message(vec!["BW 32326 2856", "OK"]);
        assert!(ProtocolInfoResponse::from_message(&msg).is_err());
    }

    #[test]
    fn test_protocolinfo_missing_auth_methods() {
        let msg = create_message(vec![
            "PROTOCOLINFO 1",
            "AUTH",
            "VERSION Tor=\"0.2.1.30\"",
            "OK",
        ]);
        assert!(ProtocolInfoResponse::from_message(&msg).is_err());
    }

    #[test]
    fn test_protocolinfo_missing_tor_version_mapping() {
        let msg = create_message(vec!["PROTOCOLINFO 1", "AUTH METHODS=NULL", "VERSION", "OK"]);
        assert!(ProtocolInfoResponse::from_message(&msg).is_err());
    }
}
