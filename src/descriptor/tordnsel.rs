//! TorDNSEL exit list parsing.
//!
//! This module parses exit list files from [TorDNSEL](https://www.torproject.org/projects/tordnsel.html.en)
//! (Tor DNS-based Exit List). These files contain information about Tor exit
//! nodes and the IP addresses they use when exiting to the internet.
//!
//! # Overview
//!
//! TorDNSEL is a service that tracks which IP addresses are used by Tor exit
//! nodes. This information is useful for:
//!
//! - Identifying traffic originating from Tor exit nodes
//! - Implementing access controls based on Tor usage
//! - Research and analysis of the Tor network
//!
//! Exit lists are published periodically and contain entries for each known
//! exit relay, including:
//! - The relay's fingerprint (identity)
//! - When the relay was last seen in the consensus
//! - The IP addresses the relay uses for exiting
//!
//! # File Format
//!
//! Exit list files follow this format:
//!
//! ```text
//! @type tordnsel 1.0
//! Downloaded 2024-01-01 00:00:00
//! ExitNode <40 hex fingerprint>
//! Published <YYYY-MM-DD HH:MM:SS>
//! LastStatus <YYYY-MM-DD HH:MM:SS>
//! ExitAddress <IPv4 address> <YYYY-MM-DD HH:MM:SS>
//! ExitAddress <IPv4 address> <YYYY-MM-DD HH:MM:SS>
//! ExitNode <40 hex fingerprint>
//! ...
//! ```
//!
//! # Example
//!
//! ```rust
//! use stem_rs::descriptor::tordnsel::{TorDNSEL, parse_exit_list};
//!
//! let exit_list = r#"ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
//! Published 2024-01-01 12:00:00
//! LastStatus 2024-01-01 13:00:00
//! ExitAddress 192.168.1.1 2024-01-01 13:30:00
//! ExitNode 00FF300624FECA7F40515C8D854EE925332580D6
//! Published 2024-01-01 11:00:00
//! LastStatus 2024-01-01 12:00:00
//! ExitAddress 10.0.0.1 2024-01-01 12:30:00
//! "#;
//!
//! let entries = parse_exit_list(exit_list)?;
//! assert_eq!(entries.len(), 2);
//!
//! for entry in &entries {
//!     println!("Exit node: {}", entry.fingerprint);
//!     for (addr, date) in &entry.exit_addresses {
//!         println!("  Exit address: {} (seen {})", addr, date);
//!     }
//! }
//! # Ok::<(), stem_rs::Error>(())
//! ```
//!
//! # Data Source
//!
//! Exit lists can be obtained from:
//! - [Tor Metrics](https://metrics.torproject.org/collector.html) - Historical data
//! - [CollecTor](https://collector.torproject.org/) - Archive of Tor network data
//!
//! # See Also
//!
//! - [`server`](super::server): Server descriptors with full relay information
//! - [`consensus`](super::consensus): Network status documents
//! - [`remote`](super::remote): Downloading descriptors from the network

use crate::Error;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::net::Ipv4Addr;

/// A TorDNSEL exit list entry for a single relay.
///
/// Each entry represents one Tor exit relay and contains information about
/// when it was last seen and what IP addresses it uses for exiting traffic.
///
/// # Structure
///
/// A TorDNSEL entry contains:
/// - The relay's fingerprint (40-character hex string)
/// - Publication and last-seen timestamps
/// - One or more exit addresses with observation times
///
/// # Exit Addresses
///
/// A relay may have multiple exit addresses because:
/// - It may use different addresses for different exit ports
/// - It may have changed addresses over time
/// - It may be multi-homed (multiple network interfaces)
///
/// Each exit address is paired with the time it was observed being used.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::tordnsel::TorDNSEL;
///
/// let content = r#"ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
/// Published 2024-01-01 12:00:00
/// LastStatus 2024-01-01 13:00:00
/// ExitAddress 192.168.1.1 2024-01-01 13:30:00
/// "#;
///
/// let entry = TorDNSEL::parse(content)?;
/// assert_eq!(entry.fingerprint, "003A71137D959748C8157C4A76ECA639CEF5E33E");
/// assert_eq!(entry.exit_addresses.len(), 1);
/// # Ok::<(), stem_rs::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct TorDNSEL {
    /// SHA-1 fingerprint of the relay's identity key.
    ///
    /// This is a 40-character hexadecimal string that uniquely identifies
    /// the relay. It matches the fingerprint in server descriptors and
    /// consensus documents.
    pub fingerprint: String,

    /// Time when the relay published its descriptor.
    ///
    /// This indicates when the relay last updated its server descriptor.
    /// May be `None` if the field was missing or unparseable.
    pub published: Option<DateTime<Utc>>,

    /// Time when the relay was last seen in a network status.
    ///
    /// This indicates when the relay was last included in a consensus
    /// document. A relay not seen recently may no longer be active.
    /// May be `None` if the field was missing or unparseable.
    pub last_status: Option<DateTime<Utc>>,

    /// List of exit addresses observed for this relay.
    ///
    /// Each entry is a tuple of (IPv4 address, observation time).
    /// The observation time indicates when TorDNSEL detected that
    /// the relay was using this address for exit traffic.
    ///
    /// A relay may have multiple exit addresses if it uses different
    /// addresses for different connections or has changed addresses.
    pub exit_addresses: Vec<(Ipv4Addr, DateTime<Utc>)>,

    /// Raw bytes of the original entry content.
    raw_content: Vec<u8>,

    /// Lines that were not recognized during parsing.
    unrecognized_lines: Vec<String>,
}

impl TorDNSEL {
    /// Parses a TorDNSEL entry from a string.
    ///
    /// This method parses a single exit list entry containing information
    /// about one relay.
    ///
    /// # Arguments
    ///
    /// * `content` - The entry content as a string
    ///
    /// # Returns
    ///
    /// A parsed `TorDNSEL` entry on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The `ExitNode` line is missing
    /// - The fingerprint is not a valid 40-character hex string
    ///
    /// Note: Invalid timestamps are silently ignored rather than causing errors.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::tordnsel::TorDNSEL;
    ///
    /// let content = r#"ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
    /// Published 2024-01-01 12:00:00
    /// ExitAddress 192.168.1.1 2024-01-01 13:30:00
    /// "#;
    ///
    /// let entry = TorDNSEL::parse(content)?;
    /// assert_eq!(entry.fingerprint, "003A71137D959748C8157C4A76ECA639CEF5E33E");
    /// # Ok::<(), stem_rs::Error>(())
    /// ```
    pub fn parse(content: &str) -> Result<Self, Error> {
        Self::parse_bytes(content.as_bytes())
    }

    /// Parses a TorDNSEL entry from raw bytes.
    ///
    /// This is the byte-oriented version of [`parse()`](Self::parse),
    /// useful when reading directly from files or network streams.
    ///
    /// # Arguments
    ///
    /// * `content` - The entry content as bytes (UTF-8 encoded)
    ///
    /// # Returns
    ///
    /// A parsed `TorDNSEL` entry on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The `ExitNode` line is missing
    /// - The fingerprint is not a valid 40-character hex string
    ///
    /// # Note
    ///
    /// Invalid UTF-8 sequences are replaced with the Unicode replacement
    /// character (U+FFFD) rather than causing an error.
    pub fn parse_bytes(content: &[u8]) -> Result<Self, Error> {
        let content_str = String::from_utf8_lossy(content);
        let mut fingerprint = None;
        let mut published = None;
        let mut last_status = None;
        let mut exit_addresses = Vec::new();
        let mut unrecognized_lines = Vec::new();

        for line in content_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('@') {
                continue;
            }

            if let Some(value) = line.strip_prefix("ExitNode ") {
                let fp = value.trim();
                if !is_valid_fingerprint(fp) {
                    return Err(Error::Parse {
                        location: "tordnsel".into(),
                        reason: format!(
                            "Tor relay fingerprints consist of forty hex digits: {}",
                            fp
                        ),
                    });
                }
                fingerprint = Some(fp.to_string());
            } else if let Some(value) = line.strip_prefix("Published ") {
                published = parse_timestamp(value.trim());
            } else if let Some(value) = line.strip_prefix("LastStatus ") {
                last_status = parse_timestamp(value.trim());
            } else if let Some(value) = line.strip_prefix("ExitAddress ") {
                if let Some((addr_str, date_str)) = value.split_once(' ') {
                    if let Ok(addr) = addr_str.trim().parse::<Ipv4Addr>() {
                        if let Some(date) = parse_timestamp(date_str.trim()) {
                            exit_addresses.push((addr, date));
                        }
                    }
                }
            } else if !line.starts_with("Downloaded ") {
                unrecognized_lines.push(line.to_string());
            }
        }

        let fingerprint = fingerprint.ok_or_else(|| Error::Parse {
            location: "tordnsel".into(),
            reason: "Missing ExitNode fingerprint".into(),
        })?;

        Ok(Self {
            fingerprint,
            published,
            last_status,
            exit_addresses,
            raw_content: content.to_vec(),
            unrecognized_lines,
        })
    }

    /// Returns the raw bytes of the original entry content.
    ///
    /// This provides access to the exact bytes that were parsed,
    /// useful for debugging or storing entries in their original format.
    ///
    /// # Returns
    ///
    /// A byte slice containing the original entry content.
    pub fn raw_content(&self) -> &[u8] {
        &self.raw_content
    }

    /// Returns lines that were not recognized during parsing.
    ///
    /// Unrecognized lines are preserved for forward compatibility
    /// with future exit list format extensions.
    ///
    /// # Returns
    ///
    /// A slice of strings, each representing an unrecognized line.
    /// Empty if all lines were recognized.
    pub fn unrecognized_lines(&self) -> &[String] {
        &self.unrecognized_lines
    }

    /// Converts the entry back to its string representation.
    ///
    /// This produces a string in the standard TorDNSEL format
    /// that can be parsed again or written to a file.
    ///
    /// # Returns
    ///
    /// A string containing the entry in standard format.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::tordnsel::TorDNSEL;
    ///
    /// let content = r#"ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
    /// Published 2024-01-01 12:00:00
    /// ExitAddress 192.168.1.1 2024-01-01 13:30:00
    /// "#;
    ///
    /// let entry = TorDNSEL::parse(content)?;
    /// let output = entry.to_descriptor_string();
    /// assert!(output.contains("ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E"));
    /// # Ok::<(), stem_rs::Error>(())
    /// ```
    pub fn to_descriptor_string(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("ExitNode {}", self.fingerprint));
        if let Some(dt) = self.published {
            lines.push(format!("Published {}", dt.format("%Y-%m-%d %H:%M:%S")));
        }
        if let Some(dt) = self.last_status {
            lines.push(format!("LastStatus {}", dt.format("%Y-%m-%d %H:%M:%S")));
        }
        for (addr, date) in &self.exit_addresses {
            lines.push(format!(
                "ExitAddress {} {}",
                addr,
                date.format("%Y-%m-%d %H:%M:%S")
            ));
        }
        lines.join("\n")
    }
}

/// Parses a complete TorDNSEL exit list file.
///
/// This function parses a file containing multiple exit list entries,
/// returning a vector of all entries found.
///
/// # Arguments
///
/// * `content` - The complete exit list file content as a string
///
/// # Returns
///
/// A vector of parsed [`TorDNSEL`] entries on success.
///
/// # Errors
///
/// Returns [`Error::Parse`] if any entry in the file is malformed.
/// Parsing stops at the first error.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::tordnsel::parse_exit_list;
///
/// let exit_list = r#"@type tordnsel 1.0
/// Downloaded 2024-01-01 00:00:00
/// ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
/// Published 2024-01-01 12:00:00
/// ExitAddress 192.168.1.1 2024-01-01 13:30:00
/// ExitNode 00FF300624FECA7F40515C8D854EE925332580D6
/// Published 2024-01-01 11:00:00
/// ExitAddress 10.0.0.1 2024-01-01 12:30:00
/// "#;
///
/// let entries = parse_exit_list(exit_list)?;
/// assert_eq!(entries.len(), 2);
/// # Ok::<(), stem_rs::Error>(())
/// ```
pub fn parse_exit_list(content: &str) -> Result<Vec<TorDNSEL>, Error> {
    parse_exit_list_bytes(content.as_bytes())
}

/// Parses a complete TorDNSEL exit list file from raw bytes.
///
/// This is the byte-oriented version of [`parse_exit_list()`],
/// useful when reading directly from files or network streams.
///
/// # Arguments
///
/// * `content` - The complete exit list file content as bytes (UTF-8 encoded)
///
/// # Returns
///
/// A vector of parsed [`TorDNSEL`] entries on success.
///
/// # Errors
///
/// Returns [`Error::Parse`] if any entry in the file is malformed.
/// Parsing stops at the first error.
///
/// # Note
///
/// Invalid UTF-8 sequences are replaced with the Unicode replacement
/// character (U+FFFD) rather than causing an error.
pub fn parse_exit_list_bytes(content: &[u8]) -> Result<Vec<TorDNSEL>, Error> {
    let content_str = String::from_utf8_lossy(content);
    let mut entries = Vec::new();
    let mut current_entry = Vec::new();
    let mut in_entry = false;

    for line in content_str.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ExitNode ") {
            if in_entry && !current_entry.is_empty() {
                let entry_content = current_entry.join("\n");
                entries.push(TorDNSEL::parse(&entry_content)?);
                current_entry.clear();
            }
            in_entry = true;
        }
        if in_entry {
            current_entry.push(line.to_string());
        }
    }

    if !current_entry.is_empty() {
        let entry_content = current_entry.join("\n");
        entries.push(TorDNSEL::parse(&entry_content)?);
    }

    Ok(entries)
}

/// Validates a fingerprint string.
///
/// A valid fingerprint is exactly 40 hexadecimal characters (case-insensitive).
fn is_valid_fingerprint(fp: &str) -> bool {
    fp.len() == 40 && fp.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parses a timestamp string in Tor's standard format.
///
/// Expected format: "YYYY-MM-DD HH:MM:SS"
fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|dt| dt.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DESC: &str = r#"@type tordnsel 1.0
Downloaded 2013-08-19 04:02:03
ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
Published 2013-08-19 02:13:53
LastStatus 2013-08-19 03:02:47
ExitAddress 66.223.170.168 2013-08-19 03:18:51
ExitNode 00FF300624FECA7F40515C8D854EE925332580D6
Published 2013-08-18 07:02:14
LastStatus 2013-08-18 09:02:58
ExitAddress 82.252.181.153 2013-08-18 08:03:01
ExitAddress 82.252.181.154 2013-08-18 08:03:02
ExitAddress 82.252.181.155 2013-08-18 08:03:03
ExitNode 030B22437D99B2DB2908B747B6962EAD13AB4039
Published 2013-08-18 12:44:20
LastStatus 2013-08-18 13:02:57
ExitAddress 46.10.211.205 2013-08-18 13:18:48
"#;

    #[test]
    fn test_parse_exit_list() {
        let entries = parse_exit_list(TEST_DESC).unwrap();
        assert_eq!(entries.len(), 3);

        let desc = &entries[1];
        assert_eq!(desc.fingerprint, "00FF300624FECA7F40515C8D854EE925332580D6");
        assert!(desc.published.is_some());
        assert!(desc.last_status.is_some());
        assert_eq!(desc.exit_addresses.len(), 3);

        let (addr, _date) = &desc.exit_addresses[0];
        assert_eq!(*addr, "82.252.181.153".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_parse_single_entry() {
        let content = r#"ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
Published 2013-08-19 02:13:53
LastStatus 2013-08-19 03:02:47
ExitAddress 66.223.170.168 2013-08-19 03:18:51"#;

        let entry = TorDNSEL::parse(content).unwrap();
        assert_eq!(
            entry.fingerprint,
            "003A71137D959748C8157C4A76ECA639CEF5E33E"
        );
        assert_eq!(entry.exit_addresses.len(), 1);
    }

    #[test]
    fn test_invalid_fingerprint() {
        let content = "ExitNode 030B22437D99B2DB2908B747B6";
        let result = TorDNSEL::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_fingerprint() {
        let content = r#"Published 2013-08-19 02:13:53
ExitAddress 66.223.170.168 2013-08-19 03:18:51"#;
        let result = TorDNSEL::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_date_skipped() {
        let content = r#"ExitNode 030B22437D99B2DB2908B747B6962EAD13AB4038
Published Today!
LastStatus 2013-08-18 13:02:57
ExitAddress 46.10.211.205 Never"#;

        let entry = TorDNSEL::parse(content).unwrap();
        assert_eq!(
            entry.fingerprint,
            "030B22437D99B2DB2908B747B6962EAD13AB4038"
        );
        assert!(entry.published.is_none());
        assert_eq!(entry.exit_addresses.len(), 0);
    }

    #[test]
    fn test_to_descriptor_string() {
        let content = r#"ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
Published 2013-08-19 02:13:53
LastStatus 2013-08-19 03:02:47
ExitAddress 66.223.170.168 2013-08-19 03:18:51"#;

        let entry = TorDNSEL::parse(content).unwrap();
        let output = entry.to_descriptor_string();
        assert!(output.contains("ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E"));
        assert!(output.contains("Published 2013-08-19 02:13:53"));
        assert!(output.contains("ExitAddress 66.223.170.168"));
    }

    #[test]
    fn test_parse_file_assertions() {
        let entries = parse_exit_list(TEST_DESC).unwrap();
        assert_eq!(entries.len(), 3);

        let desc = &entries[1];
        assert_eq!(desc.fingerprint, "00FF300624FECA7F40515C8D854EE925332580D6");
        assert!(desc.published.is_some());
        assert!(desc.last_status.is_some());
        assert_eq!(desc.exit_addresses.len(), 3);

        let (addr, date) = &desc.exit_addresses[0];
        assert_eq!(*addr, "82.252.181.153".parse::<Ipv4Addr>().unwrap());
        assert!(date.format("%Y-%m-%d %H:%M:%S").to_string() == "2013-08-18 08:03:01");
    }

    #[test]
    fn test_multiple_exit_addresses() {
        let content = r#"ExitNode 00FF300624FECA7F40515C8D854EE925332580D6
Published 2013-08-18 07:02:14
LastStatus 2013-08-18 09:02:58
ExitAddress 82.252.181.153 2013-08-18 08:03:01
ExitAddress 82.252.181.154 2013-08-18 08:03:02
ExitAddress 82.252.181.155 2013-08-18 08:03:03"#;

        let entry = TorDNSEL::parse(content).unwrap();
        assert_eq!(entry.exit_addresses.len(), 3);
        assert_eq!(entry.exit_addresses[0].0.to_string(), "82.252.181.153");
        assert_eq!(entry.exit_addresses[1].0.to_string(), "82.252.181.154");
        assert_eq!(entry.exit_addresses[2].0.to_string(), "82.252.181.155");
    }

    #[test]
    fn test_unrecognized_lines() {
        let content = r#"ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
Published 2013-08-19 02:13:53
UnknownField some value
ExitAddress 66.223.170.168 2013-08-19 03:18:51"#;

        let entry = TorDNSEL::parse(content).unwrap();
        assert_eq!(entry.unrecognized_lines(), &["UnknownField some value"]);
    }

    #[test]
    fn test_type_annotation_ignored() {
        let content = r#"@type tordnsel 1.0
ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
Published 2013-08-19 02:13:53"#;

        let entry = TorDNSEL::parse(content).unwrap();
        assert_eq!(
            entry.fingerprint,
            "003A71137D959748C8157C4A76ECA639CEF5E33E"
        );
    }

    #[test]
    fn test_downloaded_line_ignored() {
        let content = r#"Downloaded 2013-08-19 04:02:03
ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
Published 2013-08-19 02:13:53"#;

        let entry = TorDNSEL::parse(content).unwrap();
        assert_eq!(
            entry.fingerprint,
            "003A71137D959748C8157C4A76ECA639CEF5E33E"
        );
        assert!(entry.unrecognized_lines().is_empty());
    }
}
