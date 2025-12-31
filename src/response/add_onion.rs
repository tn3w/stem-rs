//! ADD_ONION response parsing.
//!
//! This module parses responses from the `ADD_ONION` command, which creates
//! ephemeral (non-persistent) hidden services. These services exist only for
//! the lifetime of the Tor connection and are not written to disk.
//!
//! # Response Format
//!
//! A successful ADD_ONION response contains:
//!
//! ```text
//! 250-ServiceID=<onion_address>
//! 250-PrivateKey=<key_type>:<base64_key>  (if requested)
//! 250-ClientAuth=<username>:<credential>  (if client auth enabled)
//! 250 OK
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::response::{ControlMessage, AddOnionResponse};
//!
//! // Parse an ADD_ONION response
//! let response_text = "250-ServiceID=gfzprpioee3hoppz\r\n\
//!                      250-PrivateKey=RSA1024:MIICXgIBAAKBgQDZ...\r\n\
//!                      250 OK\r\n";
//! let msg = ControlMessage::from_str(response_text, None, false).unwrap();
//! let response = AddOnionResponse::from_message(&msg).unwrap();
//!
//! println!("Service ID: {}", response.service_id);
//! if let Some(key) = &response.private_key {
//!     println!("Private key type: {:?}", response.private_key_type);
//! }
//! ```
//!
//! # See Also
//!
//! - [`crate::Controller::create_ephemeral_hidden_service`]: High-level API for creating hidden services
//! - [Tor Control Protocol: ADD_ONION](https://spec.torproject.org/control-spec/commands.html#add_onion)

use std::collections::HashMap;

use super::ControlMessage;
use crate::Error;

/// Parsed response from the ADD_ONION command.
///
/// This struct contains the information returned when creating an ephemeral
/// hidden service via the ADD_ONION command. The service exists only for the
/// lifetime of the Tor connection.
///
/// # Fields
///
/// - `service_id`: The `.onion` address (without the `.onion` suffix)
/// - `private_key`: The base64-encoded private key (if requested with `NEW:BEST` or similar)
/// - `private_key_type`: The cryptographic algorithm used (e.g., "RSA1024", "ED25519-V3")
/// - `client_auth`: Map of client usernames to their credentials (if client auth enabled)
///
/// # Key Types
///
/// | Type | Description |
/// |------|-------------|
/// | `RSA1024` | Legacy v2 hidden service key (deprecated) |
/// | `ED25519-V3` | Modern v3 hidden service key (recommended) |
///
/// # Example
///
/// ```rust
/// use stem_rs::response::{ControlMessage, AddOnionResponse};
///
/// // Response with service ID and private key
/// let msg = ControlMessage::from_str(
///     "250-ServiceID=gfzprpioee3hoppz\r\n\
///      250-PrivateKey=ED25519-V3:base64encodedkey\r\n\
///      250 OK\r\n",
///     None,
///     false
/// ).unwrap();
///
/// let response = AddOnionResponse::from_message(&msg).unwrap();
/// assert_eq!(response.service_id, "gfzprpioee3hoppz");
/// assert_eq!(response.private_key_type, Some("ED25519-V3".to_string()));
/// ```
///
/// # Security Considerations
///
/// - The private key should be stored securely if you need to recreate the service
/// - Client auth credentials should be distributed securely to authorized clients
/// - Consider using v3 (ED25519-V3) services for better security
#[derive(Debug, Clone)]
pub struct AddOnionResponse {
    /// The hidden service address without the `.onion` suffix.
    ///
    /// For v2 services, this is a 16-character base32 string.
    /// For v3 services, this is a 56-character base32 string.
    pub service_id: String,

    /// The base64-encoded private key, if requested.
    ///
    /// This is only present if the ADD_ONION command included a key generation
    /// request (e.g., `NEW:BEST` or `NEW:ED25519-V3`). Store this securely if
    /// you need to recreate the same hidden service later.
    pub private_key: Option<String>,

    /// The type of cryptographic key used.
    ///
    /// Common values:
    /// - `"RSA1024"`: Legacy v2 hidden service (deprecated)
    /// - `"ED25519-V3"`: Modern v3 hidden service
    pub private_key_type: Option<String>,

    /// Client authentication credentials, if enabled.
    ///
    /// Maps client usernames to their base64-encoded credentials.
    /// These credentials must be provided to clients for them to access
    /// the hidden service.
    pub client_auth: HashMap<String, String>,
}

impl AddOnionResponse {
    /// Parses an ADD_ONION response from a control message.
    ///
    /// Extracts the service ID, optional private key, and any client
    /// authentication credentials from the response.
    ///
    /// # Arguments
    ///
    /// * `message` - The control message to parse
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`](crate::Error::Protocol) if:
    /// - The response status is not OK (2xx)
    /// - The response doesn't contain a ServiceID
    /// - PrivateKey line is malformed (missing `:` separator)
    /// - ClientAuth line is malformed (missing `:` separator)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::response::{ControlMessage, AddOnionResponse};
    ///
    /// // Basic response with just service ID
    /// let msg = ControlMessage::from_str(
    ///     "250-ServiceID=gfzprpioee3hoppz\r\n250 OK\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    ///
    /// let response = AddOnionResponse::from_message(&msg).unwrap();
    /// assert_eq!(response.service_id, "gfzprpioee3hoppz");
    /// assert!(response.private_key.is_none());
    ///
    /// // Response with client auth
    /// let msg = ControlMessage::from_str(
    ///     "250-ServiceID=test\r\n\
    ///      250-ClientAuth=bob:credential123\r\n\
    ///      250 OK\r\n",
    ///     None,
    ///     false
    /// ).unwrap();
    ///
    /// let response = AddOnionResponse::from_message(&msg).unwrap();
    /// assert_eq!(response.client_auth.get("bob"), Some(&"credential123".to_string()));
    /// ```
    pub fn from_message(message: &ControlMessage) -> Result<Self, Error> {
        if !message.is_ok() {
            return Err(Error::Protocol(format!(
                "ADD_ONION response didn't have an OK status: {}",
                message
            )));
        }

        let mut service_id = None;
        let mut private_key = None;
        let mut private_key_type = None;
        let mut client_auth = HashMap::new();

        for line in message.iter() {
            let content = line.to_string();
            if let Some(eq_pos) = content.find('=') {
                let key = &content[..eq_pos];
                let value = &content[eq_pos + 1..];

                match key {
                    "ServiceID" => {
                        service_id = Some(value.to_string());
                    }
                    "PrivateKey" => {
                        if !value.contains(':') {
                            return Err(Error::Protocol(format!(
                                "ADD_ONION PrivateKey lines should be of the form 'PrivateKey=[type]:[key]': {}",
                                message
                            )));
                        }
                        let (key_type, key_value) = value.split_once(':').unwrap();
                        private_key_type = Some(key_type.to_string());
                        private_key = Some(key_value.to_string());
                    }
                    "ClientAuth" => {
                        if !value.contains(':') {
                            return Err(Error::Protocol(format!(
                                "ADD_ONION ClientAuth lines should be of the form 'ClientAuth=[username]:[credential]': {}",
                                message
                            )));
                        }
                        let (username, credential) = value.split_once(':').unwrap();
                        client_auth.insert(username.to_string(), credential.to_string());
                    }
                    _ => {}
                }
            }
        }

        let service_id = service_id.ok_or_else(|| {
            Error::Protocol(format!(
                "ADD_ONION response should start with the service id: {}",
                message
            ))
        })?;

        Ok(Self {
            service_id,
            private_key,
            private_key_type,
            client_auth,
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
    fn test_add_onion_basic() {
        let msg = create_message(vec!["ServiceID=gfzprpioee3hoppz", "OK"]);
        let response = AddOnionResponse::from_message(&msg).unwrap();
        assert_eq!(response.service_id, "gfzprpioee3hoppz");
        assert!(response.private_key.is_none());
        assert!(response.client_auth.is_empty());
    }

    #[test]
    fn test_add_onion_with_private_key() {
        let msg = create_message(vec![
            "ServiceID=gfzprpioee3hoppz",
            "PrivateKey=RSA1024:MIICXgIBAAKBgQDZvYVxv",
            "OK",
        ]);
        let response = AddOnionResponse::from_message(&msg).unwrap();
        assert_eq!(response.service_id, "gfzprpioee3hoppz");
        assert_eq!(response.private_key_type, Some("RSA1024".to_string()));
        assert_eq!(
            response.private_key,
            Some("MIICXgIBAAKBgQDZvYVxv".to_string())
        );
    }

    #[test]
    fn test_add_onion_with_client_auth() {
        let msg = create_message(vec![
            "ServiceID=gfzprpioee3hoppz",
            "ClientAuth=bob:l4BT016McqV2Oail+Bwe6w",
            "ClientAuth=alice:abc123def456",
            "OK",
        ]);
        let response = AddOnionResponse::from_message(&msg).unwrap();
        assert_eq!(response.service_id, "gfzprpioee3hoppz");
        assert_eq!(
            response.client_auth.get("bob"),
            Some(&"l4BT016McqV2Oail+Bwe6w".to_string())
        );
        assert_eq!(
            response.client_auth.get("alice"),
            Some(&"abc123def456".to_string())
        );
    }

    #[test]
    fn test_add_onion_missing_service_id() {
        let msg = create_message(vec!["PrivateKey=RSA1024:key", "OK"]);
        assert!(AddOnionResponse::from_message(&msg).is_err());
    }

    #[test]
    fn test_add_onion_malformed_private_key() {
        let msg = create_message(vec![
            "ServiceID=test",
            "PrivateKey=malformed_no_colon",
            "OK",
        ]);
        assert!(AddOnionResponse::from_message(&msg).is_err());
    }

    #[test]
    fn test_add_onion_with_full_private_key() {
        let msg = create_message(vec![
            "ServiceID=gfzprpioee3hoppz",
            "PrivateKey=RSA1024:MIICXgIBAAKBgQDZvYVxvKPTWhId/8Ss9fVxjAoFDsrJ3pk6HjHrEFRm3ypkK/vArbG9BrupzzYcyms+lO06O8b/iOSHuZI5mUEGkrYqQ+hpB2SkPUEzW7vcp8SQQivna3+LfkWH4JDqfiwZutU6MMEvU6g1OqK4Hll6uHbLpsfxkS/mGjyu1C9a9wIDAQABAoGBAJxsC3a25xZJqaRFfxwmIiptSTFy+/nj4T4gPQo6k/fHMKP/+P7liT9bm+uUwbITNNIjmPzxvrcKt+pNRR/92fizxr8QXr8l0ciVOLerbvdqvVUaQ/K1IVsblOLbactMvXcHactmqqLFUaZU9PPSDla7YkzikLDIUtHXQBEt4HEhAkEA/c4n+kpwi4odCaF49ESPbZC/Qejh7U9Tq10vAHzfrrGgQjnLw2UGDxJQXc9P12fGTvD2q3Q3VaMI8TKKFqZXsQJBANufh1zfP+xX/UfxJ4QzDUCHCu2gnyTDj3nG9Bc80E5g7NwR2VBXF1R+QQCK9GZcXd2y6vBYgrHOSUiLbVjGrycCQQDpOcs0zbjUEUuTsQUT+fiO50dJSrZpus6ZFxz85sMppeItWSzsVeYWbW7adYnZ2Gu72OPjM/0xPYsXEakhHSRRAkAxlVauNQjthv/72god4pi/VL224GiNmEkwKSa6iFRPHbrcBHuXk9IElWx/ft+mrHvUraw1DwaStgv9gNzzCghJAkEA08RegCRnIzuGvgeejLk4suIeCMD/11AvmSvxbRWS5rq1leSVo7uGLSnqDbwlzE4dGb5kH15NNAp14/l2Fu/yZg==",
            "OK",
        ]);
        let response = AddOnionResponse::from_message(&msg).unwrap();
        assert_eq!(response.service_id, "gfzprpioee3hoppz");
        assert_eq!(response.private_key_type, Some("RSA1024".to_string()));
        assert!(response
            .private_key
            .as_ref()
            .unwrap()
            .starts_with("MIICXgIBAAKB"));
    }

    #[test]
    fn test_add_onion_ed25519_key() {
        let msg = create_message(vec![
            "ServiceID=oekn5sqrvcu4wote",
            "PrivateKey=ED25519-V3:somebase64key",
            "OK",
        ]);
        let response = AddOnionResponse::from_message(&msg).unwrap();
        assert_eq!(response.service_id, "oekn5sqrvcu4wote");
        assert_eq!(response.private_key_type, Some("ED25519-V3".to_string()));
        assert_eq!(response.private_key, Some("somebase64key".to_string()));
    }

    #[test]
    fn test_add_onion_wrong_first_key() {
        let msg = create_message(vec![
            "MyKey=gfzprpioee3hoppz",
            "ServiceID=gfzprpioee3hoppz",
            "OK",
        ]);
        let result = AddOnionResponse::from_message(&msg);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().service_id, "gfzprpioee3hoppz");
    }

    #[test]
    fn test_add_onion_malformed_client_auth() {
        let msg = create_message(vec![
            "ServiceID=test",
            "ClientAuth=malformed_no_colon",
            "OK",
        ]);
        assert!(AddOnionResponse::from_message(&msg).is_err());
    }

    #[test]
    fn test_add_onion_not_ok_status() {
        let parsed = vec![(
            "512".to_string(),
            ' ',
            "Invalid argument".as_bytes().to_vec(),
        )];
        let msg = ControlMessage::new(parsed, "512 Invalid argument".into(), None).unwrap();
        assert!(AddOnionResponse::from_message(&msg).is_err());
    }
}
