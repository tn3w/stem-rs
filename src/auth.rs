//! Authentication methods for Tor control protocol.
//!
//! This module provides functions for authenticating to Tor's control interface.
//! All control connections must authenticate before they can be used, even if
//! Tor hasn't been configured to require any authentication.
//!
//! # Overview
//!
//! Tor supports four authentication methods, tried in this order by [`authenticate`]:
//!
//! 1. **NONE** - No authentication required (open control port)
//! 2. **SAFECOOKIE** - Challenge-response authentication with HMAC (preferred for local connections)
//! 3. **COOKIE** - Cookie file authentication (fallback for older Tor versions)
//! 4. **PASSWORD** - Password authentication using `HashedControlPassword`
//!
//! # Conceptual Role
//!
//! The authentication module handles the security handshake between a client and
//! Tor's control interface. It queries Tor for supported authentication methods
//! via [`get_protocol_info`], then attempts authentication using the most secure
//! available method.
//!
//! # Security Considerations
//!
//! - **SAFECOOKIE** is preferred over **COOKIE** because it uses HMAC challenge-response,
//!   preventing replay attacks where an attacker captures and reuses the cookie value.
//! - Cookie files should have restrictive permissions (readable only by the Tor user).
//! - Passwords are hex-encoded before transmission but are not encrypted on the wire.
//! - The module uses constant-time comparison for cryptographic values to prevent
//!   timing attacks.
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::auth::{authenticate, get_protocol_info};
//! use stem_rs::ControlSocket;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
//!
//! // Query available authentication methods
//! let protocol_info = get_protocol_info(&mut socket).await?;
//! println!("Tor version: {}", protocol_info.tor_version);
//! println!("Auth methods: {:?}", protocol_info.auth_methods);
//!
//! // Authenticate (auto-detects best method)
//! authenticate(&mut socket, None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # This Compiles But Is Wrong
//!
//! ```rust,no_run
//! use stem_rs::auth::authenticate;
//! use stem_rs::ControlSocket;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
//!
//! // WRONG: Don't call authenticate twice on the same connection!
//! // Tor may reject or disconnect after the first successful authentication.
//! authenticate(&mut socket, None).await?;
//! // authenticate(&mut socket, None).await?; // This would fail!
//! # Ok(())
//! # }
//! ```
//!
//! # See Also
//!
//! - [`socket`](crate::socket): Low-level control socket communication
//! - [`controller`](crate::controller): High-level Controller API (handles auth automatically)

use std::path::{Path, PathBuf};

use crate::protocol::ControlLine;
use crate::socket::{ControlMessage, ControlSocket};
use crate::version::Version;
use crate::{AuthError, Error};

/// HMAC key for server-to-controller hash in SAFECOOKIE authentication.
const SAFECOOKIE_SERVER_TO_CONTROLLER: &[u8] =
    b"Tor safe cookie authentication server-to-controller hash";

/// HMAC key for controller-to-server hash in SAFECOOKIE authentication.
const SAFECOOKIE_CONTROLLER_TO_SERVER: &[u8] =
    b"Tor safe cookie authentication controller-to-server hash";

/// Authentication methods supported by Tor's control protocol.
///
/// These methods are reported by Tor in response to a `PROTOCOLINFO` query.
/// The [`authenticate`] function tries methods in order of security preference:
/// NONE → SAFECOOKIE → COOKIE → PASSWORD.
///
/// # Security Comparison
///
/// | Method | Security Level | Use Case |
/// |--------|---------------|----------|
/// | [`None`](AuthMethod::None) | Lowest | Testing only, never in production |
/// | [`Password`](AuthMethod::Password) | Medium | Remote access with strong password |
/// | [`Cookie`](AuthMethod::Cookie) | High | Local access, older Tor versions |
/// | [`SafeCookie`](AuthMethod::SafeCookie) | Highest | Local access, Tor 0.2.3+ |
///
/// # Example
///
/// ```rust
/// use stem_rs::auth::AuthMethod;
///
/// let methods = vec![AuthMethod::Cookie, AuthMethod::SafeCookie];
/// assert!(methods.contains(&AuthMethod::SafeCookie));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// No authentication required.
    ///
    /// This method is available when Tor's control port is open without any
    /// authentication configured. This is insecure and should only be used
    /// for testing or when the control port is bound to localhost and the
    /// system is trusted.
    ///
    /// Corresponds to `NULL` in the PROTOCOLINFO response.
    None,

    /// Password authentication using `HashedControlPassword`.
    ///
    /// Requires a password that matches the hash configured in Tor's
    /// `HashedControlPassword` torrc option. The password is hex-encoded
    /// before transmission.
    ///
    /// Corresponds to `HASHEDPASSWORD` in the PROTOCOLINFO response.
    Password,

    /// Cookie file authentication using `CookieAuthentication`.
    ///
    /// Authenticates by presenting the contents of Tor's authentication
    /// cookie file (typically 32 bytes). The cookie path is provided in
    /// the PROTOCOLINFO response.
    ///
    /// Corresponds to `COOKIE` in the PROTOCOLINFO response.
    Cookie,

    /// HMAC challenge-response authentication (Tor 0.2.3+).
    ///
    /// A more secure variant of cookie authentication that uses HMAC-SHA256
    /// challenge-response to prevent replay attacks. The client sends a
    /// random nonce, receives a server nonce and hash, verifies the server's
    /// response, then sends its own hash.
    ///
    /// Corresponds to `SAFECOOKIE` in the PROTOCOLINFO response.
    SafeCookie,
}

impl AuthMethod {
    /// Parses an authentication method from its PROTOCOLINFO string representation.
    ///
    /// # Arguments
    ///
    /// * `s` - The method string from PROTOCOLINFO (case-insensitive)
    ///
    /// # Returns
    ///
    /// `Some(AuthMethod)` if recognized, `None` for unknown methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use stem_rs::auth::AuthMethod;
    ///
    /// assert_eq!(AuthMethod::parse("NULL"), Some(AuthMethod::None));
    /// assert_eq!(AuthMethod::parse("HASHEDPASSWORD"), Some(AuthMethod::Password));
    /// assert_eq!(AuthMethod::parse("cookie"), Some(AuthMethod::Cookie));
    /// assert_eq!(AuthMethod::parse("UNKNOWN"), None);
    /// ```
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "NULL" => Some(AuthMethod::None),
            "HASHEDPASSWORD" => Some(AuthMethod::Password),
            "COOKIE" => Some(AuthMethod::Cookie),
            "SAFECOOKIE" => Some(AuthMethod::SafeCookie),
            _ => None,
        }
    }
}

/// Information about Tor's control protocol and authentication requirements.
///
/// This struct contains the response from a `PROTOCOLINFO` query, which must
/// be issued before authentication. It provides:
///
/// - The protocol version supported by Tor
/// - The Tor software version
/// - Available authentication methods
/// - The path to the authentication cookie (if cookie auth is available)
///
/// # Invariants
///
/// - `protocol_version` is typically 1 for all current Tor versions
/// - `cookie_path` is `Some` only when [`AuthMethod::Cookie`] or
///   [`AuthMethod::SafeCookie`] is in `auth_methods`
/// - `auth_methods` may be empty if Tor is misconfigured
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::auth::{get_protocol_info, AuthMethod};
/// use stem_rs::ControlSocket;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
/// let info = get_protocol_info(&mut socket).await?;
///
/// println!("Protocol version: {}", info.protocol_version);
/// println!("Tor version: {}", info.tor_version);
///
/// if info.auth_methods.contains(&AuthMethod::SafeCookie) {
///     println!("SafeCookie auth available at: {:?}", info.cookie_path);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    /// The control protocol version (typically 1).
    ///
    /// This indicates the version of the control protocol that Tor speaks.
    /// Currently, only version 1 is defined.
    pub protocol_version: u32,

    /// The version of the Tor software.
    ///
    /// This can be used to check for feature availability or known bugs
    /// in specific Tor versions.
    pub tor_version: Version,

    /// Authentication methods accepted by this Tor instance.
    ///
    /// The methods are listed in the order they appear in the PROTOCOLINFO
    /// response. Use [`authenticate`] to automatically select the best method.
    pub auth_methods: Vec<AuthMethod>,

    /// Path to the authentication cookie file, if available.
    ///
    /// This is `Some` when cookie-based authentication ([`AuthMethod::Cookie`]
    /// or [`AuthMethod::SafeCookie`]) is available. The path may be absolute
    /// or relative to Tor's data directory.
    ///
    /// # Security Note
    ///
    /// The cookie file should be readable only by the user running Tor.
    /// If you're in a chroot environment, you may need to adjust this path.
    pub cookie_path: Option<PathBuf>,
}

impl ProtocolInfo {
    /// Parses a PROTOCOLINFO response from Tor.
    ///
    /// This function extracts authentication information from a raw control
    /// protocol response. It handles the multi-line PROTOCOLINFO format and
    /// extracts all relevant fields.
    ///
    /// # Arguments
    ///
    /// * `message` - The control message containing the PROTOCOLINFO response
    ///
    /// # Returns
    ///
    /// A `ProtocolInfo` struct with the parsed information.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The response status code indicates failure
    /// - The response format is malformed
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::auth::{ProtocolInfo, AuthMethod};
    /// use stem_rs::socket::ControlMessage;
    ///
    /// let message = ControlMessage {
    ///     status_code: 250,
    ///     lines: vec![
    ///         "PROTOCOLINFO 1".to_string(),
    ///         "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/var/run/tor/control.authcookie\"".to_string(),
    ///         "VERSION Tor=\"0.4.7.1\"".to_string(),
    ///         "OK".to_string(),
    ///     ],
    /// };
    ///
    /// let info = ProtocolInfo::parse(&message).unwrap();
    /// assert_eq!(info.protocol_version, 1);
    /// assert!(info.auth_methods.contains(&AuthMethod::Cookie));
    /// ```
    pub fn parse(message: &ControlMessage) -> Result<Self, Error> {
        if !message.is_ok() {
            return Err(Error::Protocol(format!(
                "PROTOCOLINFO failed: {} {}",
                message.status_code,
                message.content()
            )));
        }

        let mut protocol_version: Option<u32> = None;
        let mut tor_version: Option<Version> = None;
        let mut auth_methods: Vec<AuthMethod> = Vec::new();
        let mut cookie_path: Option<PathBuf> = None;

        for line_content in &message.lines {
            let line = ControlLine::new(line_content);
            if line.is_empty() {
                continue;
            }

            if line_content.starts_with("PROTOCOLINFO ") {
                let version_str = line_content.strip_prefix("PROTOCOLINFO ").unwrap_or("1");
                protocol_version = version_str.trim().parse().ok();
            } else if line_content.starts_with("AUTH ") {
                let auth_part = line_content.strip_prefix("AUTH ").unwrap_or("");
                let mut auth_line = ControlLine::new(auth_part);

                while !auth_line.is_empty() {
                    if auth_line.is_next_mapping(Some("METHODS"), false) {
                        let (_, methods_str) = auth_line.pop_mapping(false, false)?;
                        for method in methods_str.split(',') {
                            if let Some(m) = AuthMethod::parse(method.trim()) {
                                if !auth_methods.contains(&m) {
                                    auth_methods.push(m);
                                }
                            }
                        }
                    } else if auth_line.is_next_mapping(Some("COOKIEFILE"), false) {
                        let (_, path_str) = auth_line.pop_mapping(true, true)?;
                        cookie_path = Some(PathBuf::from(path_str));
                    } else {
                        let _ = auth_line.pop(false, false);
                    }
                }
            } else if line_content.starts_with("VERSION ") {
                let version_part = line_content.strip_prefix("VERSION ").unwrap_or("");
                let mut version_line = ControlLine::new(version_part);

                while !version_line.is_empty() {
                    if version_line.is_next_mapping(Some("Tor"), false) {
                        let (_, ver_str) = version_line.pop_mapping(true, true)?;
                        tor_version = Version::parse(&ver_str).ok();
                    } else {
                        let _ = version_line.pop(false, false);
                    }
                }
            }
        }

        Ok(ProtocolInfo {
            protocol_version: protocol_version.unwrap_or(1),
            tor_version: tor_version.unwrap_or_else(|| Version::new(0, 0, 0)),
            auth_methods,
            cookie_path,
        })
    }
}

/// Queries Tor for protocol and authentication information.
///
/// Issues a `PROTOCOLINFO 1` command to the control socket and parses the
/// response. This must be called before authentication to determine which
/// authentication methods are available.
///
/// # Preconditions
///
/// - The socket must be connected but not yet authenticated
/// - No prior commands should have been sent on this connection
///
/// # Postconditions
///
/// - On success: Returns protocol information including available auth methods
/// - On failure: The socket state is undefined; reconnection may be required
///
/// # Arguments
///
/// * `socket` - A connected control socket
///
/// # Errors
///
/// Returns an error if:
/// - [`Error::Socket`]: Connection failed or was closed
/// - [`Error::Protocol`]: Response was malformed or indicated failure
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::auth::get_protocol_info;
/// use stem_rs::ControlSocket;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
/// let info = get_protocol_info(&mut socket).await?;
///
/// println!("Connected to Tor {}", info.tor_version);
/// for method in &info.auth_methods {
///     println!("  Auth method: {:?}", method);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Protocol Details
///
/// The PROTOCOLINFO command returns a multi-line response:
/// ```text
/// 250-PROTOCOLINFO 1
/// 250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/path/to/cookie"
/// 250-VERSION Tor="0.4.7.1"
/// 250 OK
/// ```
pub async fn get_protocol_info(socket: &mut ControlSocket) -> Result<ProtocolInfo, Error> {
    socket.send("PROTOCOLINFO 1").await?;
    let response = socket.recv().await?;
    ProtocolInfo::parse(&response)
}

/// Authenticates to Tor using the best available method.
///
/// This function queries Tor for supported authentication methods via
/// [`get_protocol_info`], then attempts authentication using the most secure
/// available method in this order:
///
/// 1. **NONE** - If no authentication is required
/// 2. **SAFECOOKIE** - HMAC challenge-response (most secure)
/// 3. **COOKIE** - Cookie file contents
/// 4. **PASSWORD** - If a password is provided
///
/// # Preconditions
///
/// - The socket must be connected but not yet authenticated
/// - For password authentication, `password` must be `Some`
///
/// # Postconditions
///
/// - On success: The socket is authenticated and ready for commands
/// - On failure: The socket state is undefined; reconnection is recommended
///
/// # Arguments
///
/// * `socket` - A connected control socket
/// * `password` - Optional password for PASSWORD authentication
///
/// # Errors
///
/// Returns [`Error::Authentication`] with specific [`AuthError`] variants:
///
/// - [`AuthError::NoMethods`]: No compatible auth methods available
/// - [`AuthError::MissingPassword`]: PASSWORD auth required but no password provided
/// - [`AuthError::IncorrectPassword`]: PASSWORD auth failed
/// - [`AuthError::CookieUnreadable`]: Cannot read cookie file
/// - [`AuthError::IncorrectCookie`]: COOKIE auth failed
/// - [`AuthError::ChallengeFailed`]: SAFECOOKIE challenge failed
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::auth::authenticate;
/// use stem_rs::ControlSocket;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
///
/// // Auto-detect authentication method (no password)
/// authenticate(&mut socket, None).await?;
///
/// // Or with a password
/// // authenticate(&mut socket, Some("my_password")).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Passwords are hex-encoded before transmission but not encrypted
/// - Cookie comparison uses constant-time algorithm to prevent timing attacks
/// - SAFECOOKIE nonces are cryptographically random (32 bytes)
pub async fn authenticate(socket: &mut ControlSocket, password: Option<&str>) -> Result<(), Error> {
    let protocol_info = get_protocol_info(socket).await?;

    if protocol_info.auth_methods.is_empty() {
        return Err(Error::Authentication(AuthError::NoMethods));
    }

    if protocol_info.auth_methods.contains(&AuthMethod::None) {
        return authenticate_none(socket).await;
    }

    if protocol_info.auth_methods.contains(&AuthMethod::SafeCookie) {
        if let Some(ref cookie_path) = protocol_info.cookie_path {
            if authenticate_safecookie(socket, cookie_path).await.is_ok() {
                return Ok(());
            }
        }
    }

    if protocol_info.auth_methods.contains(&AuthMethod::Cookie) {
        if let Some(ref cookie_path) = protocol_info.cookie_path {
            if authenticate_cookie(socket, cookie_path).await.is_ok() {
                return Ok(());
            }
        }
    }

    if protocol_info.auth_methods.contains(&AuthMethod::Password) {
        if let Some(pw) = password {
            return authenticate_password(socket, pw).await;
        }
        return Err(Error::Authentication(AuthError::MissingPassword));
    }

    Err(Error::Authentication(AuthError::NoMethods))
}

/// Authenticates to an open control socket (no credentials required).
///
/// This function sends an empty `AUTHENTICATE` command, which succeeds when
/// Tor's control port is configured without any authentication requirements.
///
/// # Preconditions
///
/// - The socket must be connected
/// - Tor must be configured with no authentication (NULL method)
///
/// # Postconditions
///
/// - On success: The socket is authenticated
/// - On failure: The socket may be disconnected by Tor
///
/// # Arguments
///
/// * `socket` - A connected control socket
///
/// # Errors
///
/// Returns [`Error::Authentication`] with [`AuthError::SecurityFailure`] if
/// Tor rejects the authentication attempt.
///
/// # Security Warning
///
/// Using NONE authentication is insecure and should only be used for:
/// - Local testing environments
/// - Trusted localhost connections
/// - Development purposes
///
/// Never use NONE authentication in production or when the control port
/// is accessible from untrusted networks.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::auth::authenticate_none;
/// use stem_rs::ControlSocket;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
/// authenticate_none(&mut socket).await?;
/// // Socket is now authenticated
/// # Ok(())
/// # }
/// ```
pub async fn authenticate_none(socket: &mut ControlSocket) -> Result<(), Error> {
    socket.send("AUTHENTICATE").await?;
    let response = socket.recv().await?;

    if response.is_ok() {
        Ok(())
    } else {
        Err(Error::Authentication(AuthError::SecurityFailure))
    }
}

/// Authenticates using a password.
///
/// Sends an `AUTHENTICATE` command with the password hex-encoded. The password
/// must match the hash configured in Tor's `HashedControlPassword` torrc option.
///
/// # Preconditions
///
/// - The socket must be connected
/// - Tor must be configured with `HashedControlPassword`
/// - The password must match the configured hash
///
/// # Postconditions
///
/// - On success: The socket is authenticated
/// - On failure: Tor may disconnect the socket
///
/// # Arguments
///
/// * `socket` - A connected control socket
/// * `password` - The plaintext password to authenticate with
///
/// # Errors
///
/// Returns [`Error::Authentication`] with [`AuthError::IncorrectPassword`] if
/// the password doesn't match the configured hash.
///
/// # Security Considerations
///
/// - The password is hex-encoded but transmitted in cleartext over the socket
/// - For TCP connections, consider using a secure tunnel or localhost only
/// - Unix domain sockets provide better security for local connections
/// - The password is not stored after the function returns
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::auth::authenticate_password;
/// use stem_rs::ControlSocket;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
/// authenticate_password(&mut socket, "my_secure_password").await?;
/// # Ok(())
/// # }
/// ```
///
/// # Protocol Details
///
/// The password is hex-encoded before sending:
/// ```text
/// AUTHENTICATE 6D795F7061737377 (hex of "my_passw")
/// ```
pub async fn authenticate_password(
    socket: &mut ControlSocket,
    password: &str,
) -> Result<(), Error> {
    let hex_password = hex_encode(password.as_bytes());
    let command = format!("AUTHENTICATE {}", hex_password);
    socket.send(&command).await?;
    let response = socket.recv().await?;

    if response.is_ok() {
        Ok(())
    } else {
        Err(Error::Authentication(AuthError::IncorrectPassword))
    }
}

/// Authenticates using a cookie file.
///
/// Reads the authentication cookie from the specified path and sends its
/// contents (hex-encoded) to Tor. The cookie file is typically 32 bytes
/// and is created by Tor when `CookieAuthentication` is enabled.
///
/// # Preconditions
///
/// - The socket must be connected
/// - Tor must be configured with `CookieAuthentication 1`
/// - The cookie file must exist and be readable
/// - The cookie file must be exactly 32 bytes
///
/// # Postconditions
///
/// - On success: The socket is authenticated
/// - On failure: Tor may disconnect the socket
///
/// # Arguments
///
/// * `socket` - A connected control socket
/// * `path` - Path to the authentication cookie file
///
/// # Errors
///
/// Returns [`Error::Authentication`] with:
/// - [`AuthError::CookieUnreadable`]: Cannot read the cookie file (permissions, not found)
/// - [`AuthError::IncorrectCookieSize`]: Cookie file is not 32 bytes
/// - [`AuthError::IncorrectCookie`]: Cookie value was rejected by Tor
///
/// # Security Considerations
///
/// - The cookie file should have restrictive permissions (e.g., 0600)
/// - Only the user running Tor should be able to read the cookie
/// - The cookie is transmitted in cleartext (hex-encoded) over the socket
/// - Consider using [`authenticate_safecookie`] for better security
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::auth::authenticate_cookie;
/// use stem_rs::ControlSocket;
/// use std::path::Path;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
/// let cookie_path = Path::new("/var/run/tor/control.authcookie");
/// authenticate_cookie(&mut socket, cookie_path).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Why 32 Bytes?
///
/// The cookie size is validated to prevent a malicious Tor instance from
/// tricking the client into reading arbitrary files. Without this check,
/// an attacker could claim that `~/.ssh/id_rsa` is the cookie file.
pub async fn authenticate_cookie(socket: &mut ControlSocket, path: &Path) -> Result<(), Error> {
    let cookie = read_cookie_file(path)?;
    let hex_cookie = hex_encode(&cookie);
    let command = format!("AUTHENTICATE {}", hex_cookie);
    socket.send(&command).await?;
    let response = socket.recv().await?;

    if response.is_ok() {
        Ok(())
    } else {
        Err(Error::Authentication(AuthError::IncorrectCookie))
    }
}

/// Authenticates using the SAFECOOKIE challenge-response protocol.
///
/// This is the most secure cookie-based authentication method, available in
/// Tor 0.2.3+. It uses HMAC-SHA256 challenge-response to prevent replay attacks
/// where an attacker captures and reuses the cookie value.
///
/// # Protocol Steps
///
/// 1. Client generates a random 32-byte nonce
/// 2. Client sends `AUTHCHALLENGE SAFECOOKIE <client_nonce>`
/// 3. Server responds with `SERVERHASH` and `SERVERNONCE`
/// 4. Client verifies `SERVERHASH` using HMAC-SHA256
/// 5. Client computes its own hash and sends `AUTHENTICATE <client_hash>`
///
/// # Preconditions
///
/// - The socket must be connected
/// - Tor must support SAFECOOKIE (version 0.2.3+)
/// - The cookie file must exist and be readable
/// - The cookie file must be exactly 32 bytes
///
/// # Postconditions
///
/// - On success: The socket is authenticated
/// - On failure: Tor may disconnect the socket
///
/// # Arguments
///
/// * `socket` - A connected control socket
/// * `path` - Path to the authentication cookie file
///
/// # Errors
///
/// Returns [`Error::Authentication`] with:
/// - [`AuthError::CookieUnreadable`]: Cannot read the cookie file
/// - [`AuthError::IncorrectCookieSize`]: Cookie file is not 32 bytes
/// - [`AuthError::ChallengeUnsupported`]: Tor doesn't support AUTHCHALLENGE
/// - [`AuthError::ChallengeFailed`]: Server hash verification failed or auth rejected
///
/// # Security Advantages
///
/// Unlike plain cookie authentication, SAFECOOKIE:
/// - Prevents replay attacks (nonces are unique per session)
/// - Provides mutual authentication (client verifies server)
/// - Uses constant-time comparison for cryptographic values
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::auth::authenticate_safecookie;
/// use stem_rs::ControlSocket;
/// use std::path::Path;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut socket = ControlSocket::connect_port("127.0.0.1:9051".parse()?).await?;
/// let cookie_path = Path::new("/var/run/tor/control.authcookie");
/// authenticate_safecookie(&mut socket, cookie_path).await?;
/// # Ok(())
/// # }
/// ```
///
/// # HMAC Details
///
/// The HMAC keys are fixed strings defined by the Tor specification:
/// - Server hash: `"Tor safe cookie authentication server-to-controller hash"`
/// - Client hash: `"Tor safe cookie authentication controller-to-server hash"`
pub async fn authenticate_safecookie(socket: &mut ControlSocket, path: &Path) -> Result<(), Error> {
    let cookie = read_cookie_file(path)?;
    let client_nonce = generate_nonce();
    let client_nonce_hex = hex_encode(&client_nonce);

    let challenge_command = format!("AUTHCHALLENGE SAFECOOKIE {}", client_nonce_hex);
    socket.send(&challenge_command).await?;
    let response = socket.recv().await?;

    if !response.is_ok() {
        return Err(Error::Authentication(AuthError::ChallengeUnsupported));
    }

    let (server_hash, server_nonce) = parse_authchallenge_response(&response)?;
    let expected_server_hash = compute_hmac(
        SAFECOOKIE_SERVER_TO_CONTROLLER,
        &cookie,
        &client_nonce,
        &server_nonce,
    );

    if !crate::util::secure_compare(&server_hash, &expected_server_hash) {
        return Err(Error::Authentication(AuthError::ChallengeFailed));
    }

    let client_hash = compute_hmac(
        SAFECOOKIE_CONTROLLER_TO_SERVER,
        &cookie,
        &client_nonce,
        &server_nonce,
    );

    let auth_command = format!("AUTHENTICATE {}", hex_encode(&client_hash));
    socket.send(&auth_command).await?;
    let auth_response = socket.recv().await?;

    if auth_response.is_ok() {
        Ok(())
    } else {
        Err(Error::Authentication(AuthError::ChallengeFailed))
    }
}

/// Reads and validates an authentication cookie file.
///
/// # Security
///
/// The cookie size is validated to exactly 32 bytes to prevent a malicious
/// server from tricking the client into reading arbitrary files.
fn read_cookie_file(path: &Path) -> Result<Vec<u8>, Error> {
    let cookie = std::fs::read(path).map_err(|e| {
        Error::Authentication(AuthError::CookieUnreadable(format!(
            "{}: {}",
            path.display(),
            e
        )))
    })?;

    if cookie.len() != 32 {
        return Err(Error::Authentication(AuthError::IncorrectCookieSize));
    }

    Ok(cookie)
}

/// Generates a cryptographically secure random 32-byte nonce.
fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).expect("failed to generate random nonce");
    nonce
}

/// Parses an AUTHCHALLENGE response to extract server hash and nonce.
fn parse_authchallenge_response(response: &ControlMessage) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let content = response.content();
    let mut line = ControlLine::new(content);

    if !line.is_empty() {
        let first = line.pop(false, false)?;
        if first != "AUTHCHALLENGE" {
            return Err(Error::Protocol(
                "expected AUTHCHALLENGE response".to_string(),
            ));
        }
    }

    let mut server_hash: Option<Vec<u8>> = None;
    let mut server_nonce: Option<Vec<u8>> = None;

    while !line.is_empty() {
        if line.is_next_mapping(Some("SERVERHASH"), false) {
            let (_, hash_hex) = line.pop_mapping(false, false)?;
            server_hash = Some(hex_decode(&hash_hex)?);
        } else if line.is_next_mapping(Some("SERVERNONCE"), false) {
            let (_, nonce_hex) = line.pop_mapping(false, false)?;
            server_nonce = Some(hex_decode(&nonce_hex)?);
        } else {
            let _ = line.pop(false, false);
        }
    }

    let server_hash =
        server_hash.ok_or_else(|| Error::Protocol("missing SERVERHASH".to_string()))?;
    let server_nonce =
        server_nonce.ok_or_else(|| Error::Protocol("missing SERVERNONCE".to_string()))?;

    Ok((server_hash, server_nonce))
}

/// Computes HMAC-SHA256 for SAFECOOKIE authentication.
///
/// The HMAC is computed over: cookie || client_nonce || server_nonce
fn compute_hmac(
    key_prefix: &[u8],
    cookie: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key_prefix).expect("HMAC can take key of any size");
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.finalize().into_bytes().to_vec()
}

/// Encodes bytes as uppercase hexadecimal string.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02X}", b)).collect()
}

/// Decodes a hexadecimal string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, Error> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Protocol("invalid hex string length".to_string()));
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Error::Protocol(format!("invalid hex character at position {}", i)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_from_str() {
        assert_eq!(AuthMethod::parse("NULL"), Some(AuthMethod::None));
        assert_eq!(
            AuthMethod::parse("HASHEDPASSWORD"),
            Some(AuthMethod::Password)
        );
        assert_eq!(AuthMethod::parse("COOKIE"), Some(AuthMethod::Cookie));
        assert_eq!(
            AuthMethod::parse("SAFECOOKIE"),
            Some(AuthMethod::SafeCookie)
        );
        assert_eq!(AuthMethod::parse("null"), Some(AuthMethod::None));
        assert_eq!(AuthMethod::parse("UNKNOWN"), None);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xFF, 0xAB]), "00FFAB");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x12, 0x34]), "1234");
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("00FFAB").unwrap(), vec![0x00, 0xFF, 0xAB]);
        assert_eq!(hex_decode("").unwrap(), vec![]);
        assert_eq!(hex_decode("1234").unwrap(), vec![0x12, 0x34]);
        assert_eq!(hex_decode("abcd").unwrap(), vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("123").is_err());
        assert!(hex_decode("GHIJ").is_err());
    }

    #[test]
    fn test_protocol_info_parse_simple() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=NULL".to_string(),
                "VERSION Tor=\"0.4.7.1\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.protocol_version, 1);
        assert_eq!(info.tor_version, Version::parse("0.4.7.1").unwrap());
        assert_eq!(info.auth_methods, vec![AuthMethod::None]);
        assert!(info.cookie_path.is_none());
    }

    #[test]
    fn test_protocol_info_parse_with_cookie() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/var/run/tor/control.authcookie\""
                    .to_string(),
                "VERSION Tor=\"0.4.8.0\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.protocol_version, 1);
        assert!(info.auth_methods.contains(&AuthMethod::Cookie));
        assert!(info.auth_methods.contains(&AuthMethod::SafeCookie));
        assert_eq!(
            info.cookie_path,
            Some(PathBuf::from("/var/run/tor/control.authcookie"))
        );
    }

    #[test]
    fn test_protocol_info_parse_password() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=HASHEDPASSWORD".to_string(),
                "VERSION Tor=\"0.4.7.1\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.auth_methods, vec![AuthMethod::Password]);
    }

    #[test]
    fn test_protocol_info_parse_multiple_methods() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/tmp/cookie\""
                    .to_string(),
                "VERSION Tor=\"0.4.7.1\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.auth_methods.len(), 3);
        assert!(info.auth_methods.contains(&AuthMethod::Cookie));
        assert!(info.auth_methods.contains(&AuthMethod::SafeCookie));
        assert!(info.auth_methods.contains(&AuthMethod::Password));
    }

    #[test]
    fn test_protocol_info_parse_error() {
        let message = ControlMessage {
            status_code: 515,
            lines: vec!["Authentication required".to_string()],
        };

        assert!(ProtocolInfo::parse(&message).is_err());
    }

    #[test]
    fn test_parse_authchallenge_response() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "AUTHCHALLENGE SERVERHASH=ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234 SERVERNONCE=1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF".to_string(),
            ],
        };

        let (server_hash, server_nonce) = parse_authchallenge_response(&message).unwrap();
        assert_eq!(server_hash.len(), 32);
        assert_eq!(server_nonce.len(), 32);
    }

    #[test]
    fn test_protocol_info_parse_empty_methods() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=NULL".to_string(),
                "VERSION Tor=\"0.4.7.1\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert!(info.auth_methods.contains(&AuthMethod::None));
    }

    #[test]
    fn test_protocol_info_parse_version_without_quotes() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=NULL".to_string(),
                "VERSION Tor=\"0.4.8.0-alpha-dev\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.tor_version.major, 0);
        assert_eq!(info.tor_version.minor, 4);
        assert_eq!(info.tor_version.micro, 8);
    }

    #[test]
    fn test_protocol_info_no_auth() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=NULL".to_string(),
                "VERSION Tor=\"0.2.1.30\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.protocol_version, 1);
        assert_eq!(info.tor_version, Version::parse("0.2.1.30").unwrap());
        assert_eq!(info.auth_methods, vec![AuthMethod::None]);
        assert!(info.cookie_path.is_none());
    }

    #[test]
    fn test_protocol_info_password_auth() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=HASHEDPASSWORD".to_string(),
                "VERSION Tor=\"0.2.1.30\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.auth_methods, vec![AuthMethod::Password]);
    }

    #[test]
    fn test_protocol_info_cookie_auth_with_escape() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=COOKIE COOKIEFILE=\"/tmp/my data\\\\\\\"dir//control_auth_cookie\""
                    .to_string(),
                "VERSION Tor=\"0.2.1.30\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.auth_methods, vec![AuthMethod::Cookie]);
        assert!(info.cookie_path.is_some());
        let path = info.cookie_path.unwrap();
        assert_eq!(
            path.to_str().unwrap(),
            "/tmp/my data\\\"dir//control_auth_cookie"
        );
    }

    #[test]
    fn test_protocol_info_multiple_auth_methods() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=COOKIE,HASHEDPASSWORD COOKIEFILE=\"/home/atagar/.tor/control_auth_cookie\"".to_string(),
                "VERSION Tor=\"0.2.1.30\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert!(info.auth_methods.contains(&AuthMethod::Cookie));
        assert!(info.auth_methods.contains(&AuthMethod::Password));
        assert_eq!(
            info.cookie_path,
            Some(PathBuf::from("/home/atagar/.tor/control_auth_cookie"))
        );
    }

    #[test]
    fn test_protocol_info_minimum_response() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec!["PROTOCOLINFO 5".to_string(), "OK".to_string()],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.protocol_version, 5);
        assert_eq!(info.tor_version, Version::new(0, 0, 0));
        assert!(info.auth_methods.is_empty());
        assert!(info.cookie_path.is_none());
    }

    #[test]
    fn test_protocol_info_safecookie_auth() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/var/run/tor/control.authcookie\""
                    .to_string(),
                "VERSION Tor=\"0.4.2.6\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert!(info.auth_methods.contains(&AuthMethod::Cookie));
        assert!(info.auth_methods.contains(&AuthMethod::SafeCookie));
        assert_eq!(
            info.cookie_path,
            Some(PathBuf::from("/var/run/tor/control.authcookie"))
        );
    }

    #[test]
    fn test_protocol_info_all_auth_methods() {
        let message = ControlMessage {
            status_code: 250,
            lines: vec![
                "PROTOCOLINFO 1".to_string(),
                "AUTH METHODS=NULL,HASHEDPASSWORD,COOKIE,SAFECOOKIE COOKIEFILE=\"/tmp/cookie\""
                    .to_string(),
                "VERSION Tor=\"0.4.7.1\"".to_string(),
                "OK".to_string(),
            ],
        };

        let info = ProtocolInfo::parse(&message).unwrap();
        assert_eq!(info.auth_methods.len(), 4);
        assert!(info.auth_methods.contains(&AuthMethod::None));
        assert!(info.auth_methods.contains(&AuthMethod::Password));
        assert!(info.auth_methods.contains(&AuthMethod::Cookie));
        assert!(info.auth_methods.contains(&AuthMethod::SafeCookie));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn auth_method_strategy() -> impl Strategy<Value = Vec<AuthMethod>> {
        proptest::collection::vec(
            prop_oneof![
                Just(AuthMethod::None),
                Just(AuthMethod::Password),
                Just(AuthMethod::Cookie),
                Just(AuthMethod::SafeCookie),
            ],
            1..=4,
        )
        .prop_map(|mut methods| {
            methods.sort_by_key(|m| match m {
                AuthMethod::None => 0,
                AuthMethod::Password => 1,
                AuthMethod::Cookie => 2,
                AuthMethod::SafeCookie => 3,
            });
            methods.dedup();
            methods
        })
    }

    fn version_strategy() -> impl Strategy<Value = Version> {
        (0u32..10, 0u32..10, 0u32..10, proptest::option::of(0u32..10)).prop_map(
            |(major, minor, micro, patch)| Version {
                major,
                minor,
                micro,
                patch,
                status: None,
            },
        )
    }

    fn methods_to_string(methods: &[AuthMethod]) -> String {
        methods
            .iter()
            .map(|m| match m {
                AuthMethod::None => "NULL",
                AuthMethod::Password => "HASHEDPASSWORD",
                AuthMethod::Cookie => "COOKIE",
                AuthMethod::SafeCookie => "SAFECOOKIE",
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_protocol_info_parsing_consistency(
            protocol_version in 1u32..3,
            tor_version in version_strategy(),
            auth_methods in auth_method_strategy()
        ) {
            let methods_str = methods_to_string(&auth_methods);
            let version_str = tor_version.to_string();

            let message = ControlMessage {
                status_code: 250,
                lines: vec![
                    format!("PROTOCOLINFO {}", protocol_version),
                    format!("AUTH METHODS={}", methods_str),
                    format!("VERSION Tor=\"{}\"", version_str),
                    "OK".to_string(),
                ],
            };

            let info = ProtocolInfo::parse(&message).expect("should parse");
            prop_assert_eq!(info.protocol_version, protocol_version);
            prop_assert_eq!(info.tor_version.major, tor_version.major);
            prop_assert_eq!(info.tor_version.minor, tor_version.minor);
            prop_assert_eq!(info.tor_version.micro, tor_version.micro);

            for method in &auth_methods {
                prop_assert!(
                    info.auth_methods.contains(method),
                    "missing auth method: {:?}", method
                );
            }
        }

        #[test]
        fn prop_protocol_info_with_cookie_path(
            protocol_version in 1u32..3,
            path_suffix in "[a-z]{5,15}"
        ) {
            let cookie_path = format!("/var/run/tor/{}.cookie", path_suffix);
            let message = ControlMessage {
                status_code: 250,
                lines: vec![
                    format!("PROTOCOLINFO {}", protocol_version),
                    format!("AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"{}\"", cookie_path),
                    "VERSION Tor=\"0.4.7.1\"".to_string(),
                    "OK".to_string(),
                ],
            };

            let info = ProtocolInfo::parse(&message).expect("should parse");
            prop_assert!(info.auth_methods.contains(&AuthMethod::Cookie));
            prop_assert!(info.auth_methods.contains(&AuthMethod::SafeCookie));
            prop_assert_eq!(info.cookie_path, Some(PathBuf::from(&cookie_path)));
        }

        #[test]
        fn prop_hex_encode_decode_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..32)) {
            let encoded = hex_encode(&data);
            let decoded = hex_decode(&encoded).expect("should decode");
            prop_assert_eq!(data, decoded);
        }
    }
}
