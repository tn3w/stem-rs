//! Key certificate parsing for Tor directory authorities.
//!
//! This module provides parsing for directory key certificates used by
//! v3 network status documents to authenticate directory authorities.
//! Key certificates bind a directory authority's long-term identity key
//! to a medium-term signing key used to sign consensus documents.
//!
//! # Overview
//!
//! Directory authorities use a two-tier key system for security:
//!
//! - **Identity Key**: A long-term RSA key that identifies the authority.
//!   This key is kept offline and used only to sign key certificates.
//! - **Signing Key**: A medium-term RSA key used to sign votes and
//!   consensus documents. This key is rotated periodically.
//!
//! Key certificates establish the binding between these keys, allowing
//! clients to verify that a signing key is authorized by a known authority.
//!
//! # Certificate Format
//!
//! Key certificates follow the Tor directory specification format:
//!
//! ```text
//! dir-key-certificate-version 3
//! dir-address <IP>:<port>
//! fingerprint <40 hex chars>
//! dir-key-published <YYYY-MM-DD HH:MM:SS>
//! dir-key-expires <YYYY-MM-DD HH:MM:SS>
//! dir-identity-key
//! -----BEGIN RSA PUBLIC KEY-----
//! <base64 encoded key>
//! -----END RSA PUBLIC KEY-----
//! dir-signing-key
//! -----BEGIN RSA PUBLIC KEY-----
//! <base64 encoded key>
//! -----END RSA PUBLIC KEY-----
//! dir-key-crosscert
//! -----BEGIN ID SIGNATURE-----
//! <signature>
//! -----END ID SIGNATURE-----
//! dir-key-certification
//! -----BEGIN SIGNATURE-----
//! <signature>
//! -----END SIGNATURE-----
//! ```
//!
//! # Example
//!
//! ```rust
//! use stem_rs::descriptor::KeyCertificate;
//!
//! let cert_content = r#"dir-key-certificate-version 3
//! fingerprint BCB380A633592C218757BEE11E630511A485658A
//! dir-key-published 2024-01-01 00:00:00
//! dir-key-expires 2025-01-01 00:00:00
//! dir-identity-key
//! -----BEGIN RSA PUBLIC KEY-----
//! MIIBCgKCAQEA
//! -----END RSA PUBLIC KEY-----
//! dir-signing-key
//! -----BEGIN RSA PUBLIC KEY-----
//! MIIBCgKCAQEA
//! -----END RSA PUBLIC KEY-----
//! dir-key-certification
//! -----BEGIN SIGNATURE-----
//! AAAA
//! -----END SIGNATURE-----
//! "#;
//!
//! let cert = KeyCertificate::parse(cert_content).unwrap();
//! assert_eq!(cert.version, Some(3));
//! assert_eq!(cert.fingerprint.as_deref(), Some("BCB380A633592C218757BEE11E630511A485658A"));
//! ```
//!
//! # Security Considerations
//!
//! - Always check [`is_expired()`](KeyCertificate::is_expired) before trusting a certificate
//! - The crosscert signature proves the signing key holder authorized the binding
//! - The certification signature proves the identity key holder authorized the binding
//! - Both signatures should be verified for full security (not implemented in this module)
//!
//! # See Also
//!
//! - [`consensus`](super::consensus): Network status documents that reference key certificates
//! - [`authority`](super::authority): Directory authority information
//! - [`certificate`](super::certificate): Ed25519 certificates (different from key certificates)

use chrono::{DateTime, NaiveDateTime, Utc};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::Error;

/// A directory authority key certificate.
///
/// Key certificates are used in Tor's v3 directory protocol to bind a
/// directory authority's long-term identity key to a medium-term signing
/// key. This allows authorities to rotate their signing keys without
/// changing their identity.
///
/// # Structure
///
/// A key certificate contains:
/// - Version information (currently version 3)
/// - Authority network address and port
/// - Authority fingerprint (SHA-1 hash of identity key)
/// - Validity period (published and expiration times)
/// - The identity key (long-term, kept offline)
/// - The signing key (medium-term, used for votes/consensus)
/// - Cross-certification signatures proving key binding
///
/// # Mandatory Fields
///
/// The following fields are required for a valid certificate:
/// - `version`
/// - `fingerprint`
/// - `published`
/// - `expires`
/// - `identity_key`
/// - `signing_key`
/// - `certification`
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::KeyCertificate;
///
/// let cert_content = r#"dir-key-certificate-version 3
/// fingerprint BCB380A633592C218757BEE11E630511A485658A
/// dir-key-published 2024-01-01 00:00:00
/// dir-key-expires 2025-01-01 00:00:00
/// dir-identity-key
/// -----BEGIN RSA PUBLIC KEY-----
/// MIIBCgKCAQEA
/// -----END RSA PUBLIC KEY-----
/// dir-signing-key
/// -----BEGIN RSA PUBLIC KEY-----
/// MIIBCgKCAQEA
/// -----END RSA PUBLIC KEY-----
/// dir-key-certification
/// -----BEGIN SIGNATURE-----
/// AAAA
/// -----END SIGNATURE-----
/// "#;
///
/// let cert = KeyCertificate::parse(cert_content)?;
/// println!("Authority fingerprint: {:?}", cert.fingerprint);
/// println!("Certificate expired: {}", cert.is_expired());
/// # Ok::<(), stem_rs::Error>(())
/// ```
///
/// # Security
///
/// - Check [`is_expired()`](Self::is_expired) before trusting a certificate
/// - Certificates should be obtained from trusted sources
/// - The signatures should be cryptographically verified (not done by this parser)
#[derive(Debug, Clone, PartialEq)]
pub struct KeyCertificate {
    /// Certificate format version (currently 3).
    ///
    /// Version 3 is the only version currently in use. This field
    /// indicates the format of the certificate and which fields
    /// are expected.
    pub version: Option<u32>,

    /// IP address where the authority's directory service is available.
    ///
    /// This is the address clients can use to fetch directory information
    /// directly from this authority. May be IPv4 or IPv6.
    pub address: Option<IpAddr>,

    /// Port number for the authority's directory service.
    ///
    /// Combined with [`address`](Self::address), this forms the complete
    /// endpoint for directory requests.
    pub dir_port: Option<u16>,

    /// SHA-1 fingerprint of the authority's identity key.
    ///
    /// This is a 40-character hexadecimal string representing the
    /// SHA-1 hash of the authority's long-term identity key. It
    /// uniquely identifies the authority across the Tor network.
    pub fingerprint: Option<String>,

    /// The authority's long-term identity key in PEM format.
    ///
    /// This RSA public key is the authority's permanent identifier.
    /// It is kept offline and used only to sign key certificates.
    /// The key is encoded as a PEM block with type "RSA PUBLIC KEY".
    pub identity_key: Option<String>,

    /// Time when this certificate was generated.
    ///
    /// Certificates should not be used before their published time.
    /// This timestamp is in UTC.
    pub published: Option<DateTime<Utc>>,

    /// Time after which this certificate is no longer valid.
    ///
    /// Certificates should not be trusted after their expiration time.
    /// Use [`is_expired()`](Self::is_expired) to check validity.
    /// This timestamp is in UTC.
    pub expires: Option<DateTime<Utc>>,

    /// The authority's medium-term signing key in PEM format.
    ///
    /// This RSA public key is used to sign votes and consensus documents.
    /// It is rotated periodically (typically every few months) and a new
    /// key certificate is issued for each rotation.
    pub signing_key: Option<String>,

    /// Cross-certification signature from the signing key.
    ///
    /// This signature, made with the signing key, proves that the
    /// signing key holder authorized the binding to the identity key.
    /// Encoded as a PEM block with type "ID SIGNATURE".
    pub crosscert: Option<String>,

    /// Certification signature from the identity key.
    ///
    /// This signature, made with the identity key, proves that the
    /// identity key holder authorized the signing key. This is the
    /// primary authentication of the certificate.
    /// Encoded as a PEM block with type "SIGNATURE".
    pub certification: Option<String>,

    /// Raw bytes of the original certificate content.
    raw_content: Vec<u8>,

    /// Lines in the certificate that were not recognized.
    ///
    /// These are preserved for debugging and forward compatibility
    /// with future certificate extensions.
    unrecognized_lines: Vec<String>,
}

impl KeyCertificate {
    /// Parses a key certificate from its string representation.
    ///
    /// This method parses the certificate with full validation enabled,
    /// ensuring all mandatory fields are present and correctly formatted.
    ///
    /// # Arguments
    ///
    /// * `content` - The certificate content as a string
    ///
    /// # Returns
    ///
    /// A parsed `KeyCertificate` on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The certificate doesn't start with `dir-key-certificate-version`
    /// - The certificate doesn't end with `dir-key-certification`
    /// - Any mandatory field is missing
    /// - Any field has an invalid format (e.g., invalid fingerprint, datetime)
    /// - Key blocks are malformed or incomplete
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::KeyCertificate;
    ///
    /// let content = r#"dir-key-certificate-version 3
    /// fingerprint BCB380A633592C218757BEE11E630511A485658A
    /// dir-key-published 2024-01-01 00:00:00
    /// dir-key-expires 2025-01-01 00:00:00
    /// dir-identity-key
    /// -----BEGIN RSA PUBLIC KEY-----
    /// MIIBCgKCAQEA
    /// -----END RSA PUBLIC KEY-----
    /// dir-signing-key
    /// -----BEGIN RSA PUBLIC KEY-----
    /// MIIBCgKCAQEA
    /// -----END RSA PUBLIC KEY-----
    /// dir-key-certification
    /// -----BEGIN SIGNATURE-----
    /// AAAA
    /// -----END SIGNATURE-----
    /// "#;
    ///
    /// let cert = KeyCertificate::parse(content)?;
    /// assert_eq!(cert.version, Some(3));
    /// # Ok::<(), stem_rs::Error>(())
    /// ```
    pub fn parse(content: &str) -> Result<Self, Error> {
        Self::parse_with_validation(content, true)
    }

    /// Parses a key certificate with optional validation.
    ///
    /// This method allows parsing certificates that may be incomplete
    /// or malformed by disabling validation. This is useful for:
    /// - Parsing partial certificates for debugging
    /// - Handling certificates from untrusted sources gracefully
    /// - Testing and development
    ///
    /// # Arguments
    ///
    /// * `content` - The certificate content as a string
    /// * `validate` - If `true`, validates all fields and structure;
    ///   if `false`, parses what it can without errors
    ///
    /// # Returns
    ///
    /// A parsed `KeyCertificate` on success. With validation disabled,
    /// many fields may be `None` even if they would normally be required.
    ///
    /// # Errors
    ///
    /// With `validate = true`, returns the same errors as [`parse()`](Self::parse).
    /// With `validate = false`, only returns errors for fundamental parsing
    /// failures (e.g., completely unparseable content).
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::KeyCertificate;
    ///
    /// // Parse incomplete certificate without validation
    /// let partial = "dir-key-certificate-version 3\nfingerprint BCB380A633592C218757BEE11E630511A485658A\n";
    /// let cert = KeyCertificate::parse_with_validation(partial, false)?;
    /// assert_eq!(cert.version, Some(3));
    /// assert!(cert.identity_key.is_none()); // Missing but no error
    /// # Ok::<(), stem_rs::Error>(())
    /// ```
    pub fn parse_with_validation(content: &str, validate: bool) -> Result<Self, Error> {
        let raw_content = content.as_bytes().to_vec();
        let lines: Vec<&str> = content.lines().collect();

        let mut version: Option<u32> = None;
        let mut address: Option<IpAddr> = None;
        let mut dir_port: Option<u16> = None;
        let mut fingerprint: Option<String> = None;
        let mut identity_key: Option<String> = None;
        let mut published: Option<DateTime<Utc>> = None;
        let mut expires: Option<DateTime<Utc>> = None;
        let mut signing_key: Option<String> = None;
        let mut crosscert: Option<String> = None;
        let mut certification: Option<String> = None;
        let mut unrecognized_lines: Vec<String> = Vec::new();

        let mut idx = 0;
        let mut first_keyword: Option<&str> = None;
        let mut last_keyword: Option<&str> = None;

        while idx < lines.len() {
            let line = lines[idx];

            if line.trim().is_empty() {
                idx += 1;
                continue;
            }

            if line.starts_with("@type ") {
                idx += 1;
                continue;
            }

            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            if first_keyword.is_none() {
                first_keyword = Some(keyword);
            }
            last_keyword = Some(keyword);

            match keyword {
                "dir-key-certificate-version" => {
                    version = value.parse().ok();
                    if validate && version.is_none() {
                        return Err(Error::Parse {
                            location: "dir-key-certificate-version".to_string(),
                            reason: format!("invalid version: {}", value),
                        });
                    }
                }
                "dir-address" => {
                    if let Some((addr_str, port_str)) = value.split_once(':') {
                        if let Ok(addr) = addr_str.parse::<IpAddr>() {
                            if let Ok(port) = port_str.parse::<u16>() {
                                address = Some(addr);
                                dir_port = Some(port);
                            } else if validate {
                                return Err(Error::Parse {
                                    location: "dir-address".to_string(),
                                    reason: format!("invalid port: {}", port_str),
                                });
                            }
                        } else if validate {
                            return Err(Error::Parse {
                                location: "dir-address".to_string(),
                                reason: format!("invalid address: {}", addr_str),
                            });
                        }
                    } else if validate && !value.is_empty() {
                        return Err(Error::Parse {
                            location: "dir-address".to_string(),
                            reason: format!("invalid dir-address format: {}", value),
                        });
                    }
                }
                "fingerprint" => {
                    if is_valid_fingerprint(value) {
                        fingerprint = Some(value.to_string());
                    } else if validate {
                        return Err(Error::Parse {
                            location: "fingerprint".to_string(),
                            reason: format!("invalid fingerprint: {}", value),
                        });
                    }
                }
                "dir-key-published" => {
                    published = parse_datetime(value);
                    if validate && published.is_none() {
                        return Err(Error::Parse {
                            location: "dir-key-published".to_string(),
                            reason: format!("invalid datetime: {}", value),
                        });
                    }
                }
                "dir-key-expires" => {
                    expires = parse_datetime(value);
                    if validate && expires.is_none() {
                        return Err(Error::Parse {
                            location: "dir-key-expires".to_string(),
                            reason: format!("invalid datetime: {}", value),
                        });
                    }
                }
                "dir-identity-key" => {
                    let (block, end_idx) =
                        extract_key_block(&lines, idx + 1, "RSA PUBLIC KEY", validate)?;
                    identity_key = block;
                    idx = end_idx;
                }
                "dir-signing-key" => {
                    let (block, end_idx) =
                        extract_key_block(&lines, idx + 1, "RSA PUBLIC KEY", validate)?;
                    signing_key = block;
                    idx = end_idx;
                }
                "dir-key-crosscert" => {
                    let (block, end_idx) =
                        extract_key_block(&lines, idx + 1, "ID SIGNATURE", validate)?;
                    crosscert = block;
                    idx = end_idx;
                }
                "dir-key-certification" => {
                    let (block, end_idx) =
                        extract_key_block(&lines, idx + 1, "SIGNATURE", validate)?;
                    certification = block;
                    idx = end_idx;
                }
                _ => {
                    if !line.is_empty() && !line.starts_with("-----") {
                        unrecognized_lines.push(line.to_string());
                    }
                }
            }
            idx += 1;
        }

        if validate {
            if first_keyword != Some("dir-key-certificate-version") {
                return Err(Error::Parse {
                    location: "KeyCertificate".to_string(),
                    reason: "Key certificates must start with a 'dir-key-certificate-version' line"
                        .to_string(),
                });
            }

            if last_keyword != Some("dir-key-certification") {
                return Err(Error::Parse {
                    location: "KeyCertificate".to_string(),
                    reason: "Key certificates must end with a 'dir-key-certification' line"
                        .to_string(),
                });
            }

            if version.is_none() {
                return Err(Error::Parse {
                    location: "KeyCertificate".to_string(),
                    reason: "Key certificates must have a 'dir-key-certificate-version' line"
                        .to_string(),
                });
            }
            if fingerprint.is_none() {
                return Err(Error::Parse {
                    location: "KeyCertificate".to_string(),
                    reason: "Key certificates must have a 'fingerprint' line".to_string(),
                });
            }
            if published.is_none() {
                return Err(Error::Parse {
                    location: "KeyCertificate".to_string(),
                    reason: "Key certificates must have a 'dir-key-published' line".to_string(),
                });
            }
            if expires.is_none() {
                return Err(Error::Parse {
                    location: "KeyCertificate".to_string(),
                    reason: "Key certificates must have a 'dir-key-expires' line".to_string(),
                });
            }
            if identity_key.is_none() {
                return Err(Error::Parse {
                    location: "KeyCertificate".to_string(),
                    reason: "Key certificates must have a 'dir-identity-key' line".to_string(),
                });
            }
            if signing_key.is_none() {
                return Err(Error::Parse {
                    location: "KeyCertificate".to_string(),
                    reason: "Key certificates must have a 'dir-signing-key' line".to_string(),
                });
            }
            if certification.is_none() {
                return Err(Error::Parse {
                    location: "KeyCertificate".to_string(),
                    reason: "Key certificates must have a 'dir-key-certification' line".to_string(),
                });
            }
        }

        Ok(KeyCertificate {
            version,
            address,
            dir_port,
            fingerprint,
            identity_key,
            published,
            expires,
            signing_key,
            crosscert,
            certification,
            raw_content,
            unrecognized_lines,
        })
    }

    /// Returns the raw bytes of the original certificate content.
    ///
    /// This provides access to the exact bytes that were parsed,
    /// which is useful for:
    /// - Computing digests for signature verification
    /// - Storing certificates in their original format
    /// - Debugging parsing issues
    ///
    /// # Returns
    ///
    /// A byte slice containing the original certificate content.
    pub fn raw_content(&self) -> &[u8] {
        &self.raw_content
    }

    /// Returns lines that were not recognized during parsing.
    ///
    /// Unrecognized lines are preserved for forward compatibility
    /// with future certificate extensions. This allows newer
    /// certificate formats to be partially parsed by older code.
    ///
    /// # Returns
    ///
    /// A slice of strings, each representing an unrecognized line.
    /// Empty if all lines were recognized.
    pub fn unrecognized_lines(&self) -> &[String] {
        &self.unrecognized_lines
    }

    /// Checks if this certificate has expired.
    ///
    /// A certificate is considered expired if the current time is
    /// past the certificate's expiration time. Expired certificates
    /// should not be trusted for signature verification.
    ///
    /// # Returns
    ///
    /// - `true` if the certificate has expired
    /// - `false` if the certificate is still valid or has no expiration time
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::KeyCertificate;
    ///
    /// // Certificate with past expiration date
    /// let old_cert_content = r#"dir-key-certificate-version 3
    /// fingerprint BCB380A633592C218757BEE11E630511A485658A
    /// dir-key-published 2017-01-01 00:00:00
    /// dir-key-expires 2018-01-01 00:00:00
    /// dir-identity-key
    /// -----BEGIN RSA PUBLIC KEY-----
    /// MIIBCgKCAQEA
    /// -----END RSA PUBLIC KEY-----
    /// dir-signing-key
    /// -----BEGIN RSA PUBLIC KEY-----
    /// MIIBCgKCAQEA
    /// -----END RSA PUBLIC KEY-----
    /// dir-key-certification
    /// -----BEGIN SIGNATURE-----
    /// AAAA
    /// -----END SIGNATURE-----
    /// "#;
    ///
    /// let cert = KeyCertificate::parse(old_cert_content)?;
    /// assert!(cert.is_expired());
    /// # Ok::<(), stem_rs::Error>(())
    /// ```
    pub fn is_expired(&self) -> bool {
        match self.expires {
            Some(exp) => Utc::now() > exp,
            None => false,
        }
    }

    /// Converts the certificate back to its string representation.
    ///
    /// This produces a string in the standard key certificate format
    /// that can be parsed again or written to a file. The output
    /// follows the same format as the original certificate.
    ///
    /// # Returns
    ///
    /// A string containing the certificate in standard format.
    ///
    /// # Note
    ///
    /// The output may not be byte-for-byte identical to the original
    /// input due to whitespace normalization, but it will be
    /// semantically equivalent.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::KeyCertificate;
    ///
    /// let content = r#"dir-key-certificate-version 3
    /// fingerprint BCB380A633592C218757BEE11E630511A485658A
    /// dir-key-published 2024-01-01 00:00:00
    /// dir-key-expires 2025-01-01 00:00:00
    /// dir-identity-key
    /// -----BEGIN RSA PUBLIC KEY-----
    /// MIIBCgKCAQEA
    /// -----END RSA PUBLIC KEY-----
    /// dir-signing-key
    /// -----BEGIN RSA PUBLIC KEY-----
    /// MIIBCgKCAQEA
    /// -----END RSA PUBLIC KEY-----
    /// dir-key-certification
    /// -----BEGIN SIGNATURE-----
    /// AAAA
    /// -----END SIGNATURE-----
    /// "#;
    ///
    /// let cert = KeyCertificate::parse(content)?;
    /// let output = cert.to_descriptor_string();
    /// assert!(output.contains("dir-key-certificate-version 3"));
    /// assert!(output.contains("fingerprint BCB380A633592C218757BEE11E630511A485658A"));
    /// # Ok::<(), stem_rs::Error>(())
    /// ```
    pub fn to_descriptor_string(&self) -> String {
        let mut result = String::new();

        if let Some(v) = self.version {
            result.push_str(&format!("dir-key-certificate-version {}\n", v));
        }

        if let (Some(addr), Some(port)) = (&self.address, self.dir_port) {
            result.push_str(&format!("dir-address {}:{}\n", addr, port));
        }

        if let Some(ref fp) = self.fingerprint {
            result.push_str(&format!("fingerprint {}\n", fp));
        }

        if let Some(ref dt) = self.published {
            result.push_str(&format!(
                "dir-key-published {}\n",
                dt.format("%Y-%m-%d %H:%M:%S")
            ));
        }

        if let Some(ref dt) = self.expires {
            result.push_str(&format!(
                "dir-key-expires {}\n",
                dt.format("%Y-%m-%d %H:%M:%S")
            ));
        }

        if let Some(ref key) = self.identity_key {
            result.push_str("dir-identity-key\n");
            result.push_str(key);
            result.push('\n');
        }

        if let Some(ref key) = self.signing_key {
            result.push_str("dir-signing-key\n");
            result.push_str(key);
            result.push('\n');
        }

        if let Some(ref sig) = self.crosscert {
            result.push_str("dir-key-crosscert\n");
            result.push_str(sig);
            result.push('\n');
        }

        if let Some(ref sig) = self.certification {
            result.push_str("dir-key-certification\n");
            result.push_str(sig);
            result.push('\n');
        }

        result
    }
}

impl FromStr for KeyCertificate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for KeyCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_descriptor_string())
    }
}

/// Validates a fingerprint string.
///
/// A valid fingerprint is exactly 40 hexadecimal characters (case-insensitive),
/// representing a 160-bit SHA-1 hash.
fn is_valid_fingerprint(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parses a datetime string in Tor's standard format.
///
/// Expected format: "YYYY-MM-DD HH:MM:SS"
fn parse_datetime(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|dt| dt.and_utc())
}

/// Extracts a PEM-encoded key block from certificate lines.
///
/// Reads lines starting from `start_idx` until finding a complete
/// PEM block of the expected type.
fn extract_key_block(
    lines: &[&str],
    start_idx: usize,
    expected_type: &str,
    validate: bool,
) -> Result<(Option<String>, usize), Error> {
    let mut block = String::new();
    let mut idx = start_idx;
    let begin_marker = format!("-----BEGIN {}-----", expected_type);
    let end_marker = format!("-----END {}-----", expected_type);
    let mut found_begin = false;
    let mut found_end = false;

    while idx < lines.len() {
        let line = lines[idx];
        block.push_str(line);
        block.push('\n');

        if line.contains(&begin_marker) {
            found_begin = true;
        }

        if line.contains(&end_marker) {
            found_end = true;
            break;
        }

        if line.starts_with("-----END ") && !line.contains(&end_marker) {
            if validate {
                return Err(Error::Parse {
                    location: "key_block".to_string(),
                    reason: format!("Expected {} block but found: {}", expected_type, line),
                });
            }
            return Ok((None, idx));
        }

        idx += 1;
    }

    if validate && (!found_begin || !found_end) {
        return Err(Error::Parse {
            location: "key_block".to_string(),
            reason: format!("Incomplete {} block", expected_type),
        });
    }

    if found_begin && found_end {
        Ok((Some(block.trim_end().to_string()), idx))
    } else {
        Ok((None, idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const SAMPLE_CERT: &str = r#"dir-key-certificate-version 3
dir-address 127.0.0.1:7000
fingerprint BCB380A633592C218757BEE11E630511A485658A
dir-key-published 2017-05-25 04:45:52
dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAxfTHG1b3Sxe8n3JQ/nIk4+1/chj7+jAyLLK+WrEBiP1vnDxTXMuo
x26ntWEjOaxjtKB12k5wMQW94/KvE754Gn98uQRFBHqLkrS4hUnn4/MqiBQVd2y3
UtE6KDSRhJZ5LfFH+dCKwu5+695PyJp/pfCUSOyPj0HQbFOnAOqdHPok8dtdfsy0
LaI7ycpzqAalzgrlwFP5KwwLtL+VapUGN4QOZlIXgL4W5e7OAG42lZhHt0b7/zdt
oIegZM1y8tK2l75ijqsvbetddQcFlnVaYzNwlQAUIZuxJOGfnPfTo+WrjCgrK2ur
ed5NiQMrEbZn5uCUscs+xLlKl4uKW0XXo1EIL45yBrVbmlP6V3/9diTHk64W9+m8
2G4ToDyH8J7LvnYPsmD0cCaQEceebxYVlmmwgqdORH/ixbeGF7JalTwtWBQYo2r0
VZAqjRwxR9dri6m1MIpzmzWmrbXghZ1IzJEL1rpB0okA/bE8AUGRx61eKnbI415O
PmO06JMpvkxxAgMBAAE=
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAvzugxJl1gc7BgXarBO5IWejNZC30U1xVjZ/myQTzxtiKkPU0agQh
sPqn4vVsaW6ZnWjJ2pSOq0/jg8WgFyGHGQ9cG8tv2TlpObeb/tI7iANxWx+MXJAh
/CnFDBQ1ifKntJrs2IcRKMivfobqaHAL3Pz93noLWOTQunWjZ8D6kovYvUXe+yUQ
tZEROrmXJx7ZIIJF6BNKYBTc+iEkYtkWlJVs0my7yP/bbS075QyBsr6CfT+O2yU4
mgIg43QuqcFRbjyUvGI/gap06QNlB6yj8pqeE5rWo++5EpEvMK76fK6ymYuTN2SN
Oil+Fo7qgG8UP/fv0GelSz6Tk7pBoeHJlQIDAQAB
-----END RSA PUBLIC KEY-----
dir-key-crosscert
-----BEGIN ID SIGNATURE-----
Oz+rvXDzlxLgQSb3nS5/4hrHVWgGCy0OnuNmFsyw8bi2eBst5Yj79dQ+D25giZke
81FRGIFU4eS6dshB+pJ+z0hc9ozlRTYh/qevY6l6o0amvuhHyk/cQXrh8oYU9Ihe
XQ1yVItvxC24HENsoGIGbr5uxc85FOcNs+R9qTLYA/56TjvAU4WUje3nTZE1awml
lj/Y6DM7ruMF6UoYJZPTklukZ+XHZg4Z2eE55e/oIaD7bfU/lFWU/alMyTV/J5oT
sxaD2XBLBScYiKypUmgrZ50W4ZqsXaYk76ClrudZnDbce+FuugVxok+jKYGjMu75
2es2ucuik7iuO7QPdPIXfg==
-----END ID SIGNATURE-----
dir-key-certification
-----BEGIN SIGNATURE-----
I86FTQ5ZyCZUzm19HVAQWByrrRgUmddoRBfNiCj0iTGN3kdIq9OfuNLhWAqz71xP
8Nn0Vun8Uj3/vBq/odIFpnngL3mKI6OEKcNDr0D5hEV9Yjrxe8msMoaUZT+LHzUW
1q3pzxfMx6EmlSilMhuzSsa4YEbXMZzMqASKANSJHo2fzUkzQOpPw2SlWSTIgyqw
wAOB6QOvFfP3c0NTwxXrYE/iT+r90wZBuzS+v7r9B94alNAkE1KZQKnq2QTTIznP
iF9LWMsZcMHCjoTxszK4jF4MRMN/S4Xl8yQo0/z6FoqBz4RIXzFtJoG/rbXdKfkE
nJK9iEhaZbS1IN0o+uIGtvOm2rQSu9gS8merurr5GDSK3szjesPVJuF00mCNgOx4
hAYPN9N8HAL4zGE/l1UM7BGg3L84A0RMpDxnpXePd9mlHLhl4UV2lrkkf8S9Z6fX
PPc3r7zKlL/jEGHwz+C7kE88HIvkVnKLLn
-----END SIGNATURE-----
"#;

    const MINIMAL_CERT: &str = r#"dir-key-certificate-version 3
fingerprint BCB380A633592C218757BEE11E630511A485658A
dir-key-published 2017-05-25 04:45:52
dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-key-certification
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;

    #[test]
    fn test_parse_full_certificate() {
        let cert = KeyCertificate::parse(SAMPLE_CERT).unwrap();

        assert_eq!(Some(3), cert.version);
        assert_eq!(Some("127.0.0.1".parse().unwrap()), cert.address);
        assert_eq!(Some(7000), cert.dir_port);
        assert_eq!(
            Some("BCB380A633592C218757BEE11E630511A485658A".to_string()),
            cert.fingerprint
        );
        assert!(cert.identity_key.is_some());
        assert!(cert
            .identity_key
            .as_ref()
            .unwrap()
            .contains("RSA PUBLIC KEY"));
        assert_eq!(
            Some(Utc.with_ymd_and_hms(2017, 5, 25, 4, 45, 52).unwrap()),
            cert.published
        );
        assert_eq!(
            Some(Utc.with_ymd_and_hms(2018, 5, 25, 4, 45, 52).unwrap()),
            cert.expires
        );
        assert!(cert.signing_key.is_some());
        assert!(cert.crosscert.is_some());
        assert!(cert.crosscert.as_ref().unwrap().contains("ID SIGNATURE"));
        assert!(cert.certification.is_some());
        assert!(cert.certification.as_ref().unwrap().contains("SIGNATURE"));
        assert!(cert.unrecognized_lines().is_empty());
    }

    #[test]
    fn test_parse_minimal_certificate() {
        let cert = KeyCertificate::parse(MINIMAL_CERT).unwrap();

        assert_eq!(Some(3), cert.version);
        assert_eq!(None, cert.address);
        assert_eq!(None, cert.dir_port);
        assert_eq!(
            Some("BCB380A633592C218757BEE11E630511A485658A".to_string()),
            cert.fingerprint
        );
        assert!(cert.identity_key.is_some());
        assert!(cert.signing_key.is_some());
        assert_eq!(None, cert.crosscert);
        assert!(cert.certification.is_some());
    }

    #[test]
    fn test_missing_version() {
        let content = r#"fingerprint BCB380A633592C218757BEE11E630511A485658A
dir-key-published 2017-05-25 04:45:52
dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-key-certification
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;
        let result = KeyCertificate::parse(content);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("dir-key-certificate-version"));
    }

    #[test]
    fn test_missing_fingerprint() {
        let content = r#"dir-key-certificate-version 3
dir-key-published 2017-05-25 04:45:52
dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-key-certification
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;
        let result = KeyCertificate::parse(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fingerprint"));
    }

    #[test]
    fn test_invalid_fingerprint() {
        let content = r#"dir-key-certificate-version 3
fingerprint INVALID
dir-key-published 2017-05-25 04:45:52
dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-key-certification
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;
        let result = KeyCertificate::parse(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fingerprint"));
    }

    #[test]
    fn test_invalid_datetime() {
        let content = r#"dir-key-certificate-version 3
fingerprint BCB380A633592C218757BEE11E630511A485658A
dir-key-published invalid-date
dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-key-certification
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;
        let result = KeyCertificate::parse(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("datetime"));
    }

    #[test]
    fn test_unrecognized_lines() {
        let content = r#"dir-key-certificate-version 3
fingerprint BCB380A633592C218757BEE11E630511A485658A
pepperjack is oh so tasty!
dir-key-published 2017-05-25 04:45:52
dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-key-certification
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;
        let cert = KeyCertificate::parse(content).unwrap();
        assert_eq!(
            vec!["pepperjack is oh so tasty!"],
            cert.unrecognized_lines()
        );
    }

    #[test]
    fn test_parse_without_validation() {
        let content = r#"dir-key-certificate-version 3
fingerprint BCB380A633592C218757BEE11E630511A485658A
"#;
        let cert = KeyCertificate::parse_with_validation(content, false).unwrap();
        assert_eq!(Some(3), cert.version);
        assert_eq!(
            Some("BCB380A633592C218757BEE11E630511A485658A".to_string()),
            cert.fingerprint
        );
        assert_eq!(None, cert.identity_key);
    }

    #[test]
    fn test_is_expired() {
        let cert = KeyCertificate::parse(SAMPLE_CERT).unwrap();
        assert!(cert.is_expired());
    }

    #[test]
    fn test_to_descriptor_string() {
        let cert = KeyCertificate::parse(SAMPLE_CERT).unwrap();
        let output = cert.to_descriptor_string();

        assert!(output.contains("dir-key-certificate-version 3"));
        assert!(output.contains("dir-address 127.0.0.1:7000"));
        assert!(output.contains("fingerprint BCB380A633592C218757BEE11E630511A485658A"));
        assert!(output.contains("dir-key-published 2017-05-25 04:45:52"));
        assert!(output.contains("dir-key-expires 2018-05-25 04:45:52"));
        assert!(output.contains("dir-identity-key"));
        assert!(output.contains("dir-signing-key"));
        assert!(output.contains("dir-key-crosscert"));
        assert!(output.contains("dir-key-certification"));
    }

    #[test]
    fn test_from_str() {
        let cert: KeyCertificate = MINIMAL_CERT.parse().unwrap();
        assert_eq!(Some(3), cert.version);
    }

    #[test]
    fn test_display() {
        let cert = KeyCertificate::parse(MINIMAL_CERT).unwrap();
        let display = format!("{}", cert);
        assert!(display.contains("dir-key-certificate-version 3"));
    }

    #[test]
    fn test_type_annotation() {
        let content = r#"@type dir-key-certificate-3 1.0
dir-key-certificate-version 3
fingerprint BCB380A633592C218757BEE11E630511A485658A
dir-key-published 2017-05-25 04:45:52
dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-key-certification
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;
        let cert = KeyCertificate::parse(content).unwrap();
        assert_eq!(Some(3), cert.version);
    }

    #[test]
    fn test_blank_lines() {
        let content = r#"dir-key-certificate-version 3
fingerprint BCB380A633592C218757BEE11E630511A485658A

dir-key-published 2017-05-25 04:45:52

dir-key-expires 2018-05-25 04:45:52
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA
-----END RSA PUBLIC KEY-----
dir-key-certification
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;
        let cert = KeyCertificate::parse(content).unwrap();
        assert_eq!(Some(3), cert.version);
    }
}
