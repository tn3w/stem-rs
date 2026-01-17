//! Extra-info descriptor parsing for Tor relay and bridge extra-info documents.
//!
//! Extra-info descriptors contain non-vital but interesting information about
//! Tor relays such as usage statistics, bandwidth history, and directory
//! request statistics. Unlike server descriptors, these are not required for
//! Tor clients to function and are not fetched by default.
//!
//! # Overview
//!
//! Extra-info descriptors are published by relays whenever their server
//! descriptor is published. They contain detailed statistics about:
//!
//! - **Bandwidth history** - Read/write traffic over time
//! - **Directory statistics** - Request counts, response types, download speeds
//! - **Cell statistics** - Circuit cell processing metrics
//! - **Exit statistics** - Traffic per port for exit relays
//! - **Bridge statistics** - Client connection data for bridges
//! - **Hidden service statistics** - Onion service activity metrics
//!
//! # Descriptor Types
//!
//! | Type | Description | Signature |
//! |------|-------------|-----------|
//! | Relay | Standard relay extra-info | RSA signature |
//! | Bridge | Bridge relay extra-info | No signature (has router-digest) |
//!
//! # Sources
//!
//! Extra-info descriptors are available from:
//!
//! - **Control port** - Via `GETINFO extra-info/digest/*` (requires `DownloadExtraInfo 1`)
//! - **Data directory** - The `cached-extrainfo` file
//! - **CollecTor** - Archived descriptors from metrics.torproject.org
//! - **Directory authorities** - Via DirPort requests
//!
//! # Example
//!
//! ```rust
//! use stem_rs::descriptor::extra_info::ExtraInfoDescriptor;
//! use stem_rs::descriptor::Descriptor;
//!
//! let content = r#"extra-info example B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
//! published 2024-01-15 12:00:00
//! write-history 2024-01-15 12:00:00 (900 s) 1000000,2000000,3000000
//! read-history 2024-01-15 12:00:00 (900 s) 500000,1000000,1500000
//! "#;
//!
//! let desc = ExtraInfoDescriptor::parse(content).unwrap();
//! assert_eq!(desc.nickname, "example");
//! assert!(desc.write_history.is_some());
//! ```
//!
//! # Statistics Categories
//!
//! ## Bandwidth History
//!
//! The `read-history` and `write-history` lines record bytes transferred
//! over time intervals (typically 900 seconds = 15 minutes).
//!
//! ## Directory Statistics
//!
//! Directory mirrors report request statistics including:
//! - Client IP counts by country (`dirreq-v3-ips`)
//! - Request counts by country (`dirreq-v3-reqs`)
//! - Response status counts (`dirreq-v3-resp`)
//! - Download speed statistics (`dirreq-v3-direct-dl`, `dirreq-v3-tunneled-dl`)
//!
//! ## Exit Statistics
//!
//! Exit relays report traffic per destination port:
//! - `exit-kibibytes-written` - Outbound traffic
//! - `exit-kibibytes-read` - Inbound traffic
//! - `exit-streams-opened` - Connection counts
//!
//! ## Bridge Statistics
//!
//! Bridges report client connection data:
//! - `bridge-ips` - Client counts by country
//! - `bridge-ip-versions` - IPv4 vs IPv6 client counts
//! - `bridge-ip-transports` - Pluggable transport usage
//!
//! # See Also
//!
//! - [`crate::descriptor::server`] - Server descriptors (published alongside extra-info)
//! - [`crate::descriptor::consensus`] - Network status documents
//!
//! # See Also
//!
//! - [Tor Directory Protocol Specification, Section 2.1.2](https://spec.torproject.org/dir-spec)
//! - Python Stem's `ExtraInfoDescriptor` class

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, Utc};
use derive_builder::Builder;

use crate::Error;

use super::{compute_digest, Descriptor, DigestEncoding, DigestHash};

/// Result type for parsing bi-directional connection statistics.
type ConnBiDirectResult = Result<(DateTime<Utc>, u32, u32, u32, u32, u32), Error>;

/// Result type for parsing padding count statistics.
type PaddingCountsResult = Result<(DateTime<Utc>, u32, HashMap<String, String>), Error>;

/// Response status for directory requests.
///
/// These statuses indicate the outcome of network status requests
/// made to directory servers.
///
/// # Variants
///
/// | Status | Description |
/// |--------|-------------|
/// | `Ok` | Request completed successfully |
/// | `NotEnoughSigs` | Network status wasn't signed by enough authorities |
/// | `Unavailable` | Requested network status was unavailable |
/// | `NotFound` | Requested network status was not found |
/// | `NotModified` | Network status unmodified since If-Modified-Since time |
/// | `Busy` | Directory server was too busy to respond |
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::extra_info::DirResponse;
/// use std::str::FromStr;
///
/// let status = DirResponse::from_str("ok").unwrap();
/// assert_eq!(status, DirResponse::Ok);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DirResponse {
    /// Request completed successfully.
    Ok,
    /// Network status wasn't signed by enough authorities.
    NotEnoughSigs,
    /// Requested network status was unavailable.
    Unavailable,
    /// Requested network status was not found.
    NotFound,
    /// Network status unmodified since If-Modified-Since time.
    NotModified,
    /// Directory server was too busy to respond.
    Busy,
}

impl FromStr for DirResponse {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ok" => Ok(DirResponse::Ok),
            "not-enough-sigs" => Ok(DirResponse::NotEnoughSigs),
            "unavailable" => Ok(DirResponse::Unavailable),
            "not-found" => Ok(DirResponse::NotFound),
            "not-modified" => Ok(DirResponse::NotModified),
            "busy" => Ok(DirResponse::Busy),
            _ => Err(Error::Parse {
                location: "DirResponse".to_string(),
                reason: format!("unknown dir response: {}", s),
            }),
        }
    }
}

/// Download statistics for directory requests.
///
/// These statistics measure the performance of directory downloads,
/// including completion rates and speed percentiles.
///
/// # Variants
///
/// | Stat | Description |
/// |------|-------------|
/// | `Complete` | Requests that completed successfully |
/// | `Timeout` | Requests that didn't complete within timeout |
/// | `Running` | Requests still in progress when measured |
/// | `Min` | Minimum download rate (B/s) |
/// | `Max` | Maximum download rate (B/s) |
/// | `D1`-`D9` | Decile download rates (10th-90th percentile) |
/// | `Q1`, `Q3` | Quartile download rates (25th, 75th percentile) |
/// | `Md` | Median download rate |
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::extra_info::DirStat;
/// use std::str::FromStr;
///
/// let stat = DirStat::from_str("complete").unwrap();
/// assert_eq!(stat, DirStat::Complete);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DirStat {
    /// Requests that completed successfully.
    Complete,
    /// Requests that timed out (10 minute default).
    Timeout,
    /// Requests still running when measurement was taken.
    Running,
    /// Minimum download rate in bytes per second.
    Min,
    /// Maximum download rate in bytes per second.
    Max,
    /// 10th percentile download rate.
    D1,
    /// 20th percentile download rate.
    D2,
    /// 30th percentile download rate.
    D3,
    /// 40th percentile download rate.
    D4,
    /// 60th percentile download rate.
    D6,
    /// 70th percentile download rate.
    D7,
    /// 80th percentile download rate.
    D8,
    /// 90th percentile download rate.
    D9,
    /// First quartile (25th percentile) download rate.
    Q1,
    /// Third quartile (75th percentile) download rate.
    Q3,
    /// Median download rate.
    Md,
}

impl FromStr for DirStat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "complete" => Ok(DirStat::Complete),
            "timeout" => Ok(DirStat::Timeout),
            "running" => Ok(DirStat::Running),
            "min" => Ok(DirStat::Min),
            "max" => Ok(DirStat::Max),
            "d1" => Ok(DirStat::D1),
            "d2" => Ok(DirStat::D2),
            "d3" => Ok(DirStat::D3),
            "d4" => Ok(DirStat::D4),
            "d6" => Ok(DirStat::D6),
            "d7" => Ok(DirStat::D7),
            "d8" => Ok(DirStat::D8),
            "d9" => Ok(DirStat::D9),
            "q1" => Ok(DirStat::Q1),
            "q3" => Ok(DirStat::Q3),
            "md" => Ok(DirStat::Md),
            _ => Err(Error::Parse {
                location: "DirStat".to_string(),
                reason: format!("unknown dir stat: {}", s),
            }),
        }
    }
}

/// Bandwidth history data for a time period.
///
/// Records bytes transferred over a series of fixed-length intervals.
/// This is used for read/write history and directory request history.
///
/// # Format
///
/// The history line format is:
/// ```text
/// keyword YYYY-MM-DD HH:MM:SS (INTERVAL s) VALUE,VALUE,...
/// ```
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::extra_info::BandwidthHistory;
/// use chrono::Utc;
///
/// let history = BandwidthHistory {
///     end_time: Utc::now(),
///     interval: 900,  // 15 minutes
///     values: vec![1000000, 2000000, 3000000],
/// };
///
/// assert_eq!(history.interval, 900);
/// assert_eq!(history.values.len(), 3);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct BandwidthHistory {
    /// End time of the most recent interval (UTC).
    pub end_time: DateTime<Utc>,

    /// Length of each interval in seconds (typically 900 = 15 minutes).
    pub interval: u32,

    /// Bytes transferred during each interval, oldest first.
    ///
    /// Values can be negative in some cases due to historical bugs.
    pub values: Vec<i64>,
}

/// Pluggable transport information.
///
/// Describes a pluggable transport method available on a bridge.
/// In published bridge descriptors, the address and port are typically
/// scrubbed for privacy.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::extra_info::Transport;
///
/// let transport = Transport {
///     name: "obfs4".to_string(),
///     address: Some("192.0.2.1".to_string()),
///     port: Some(443),
///     args: vec!["cert=...".to_string()],
/// };
///
/// assert_eq!(transport.name, "obfs4");
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Transport {
    /// Transport method name (e.g., "obfs4", "snowflake").
    pub name: String,

    /// Transport address (may be scrubbed in published descriptors).
    pub address: Option<String>,

    /// Transport port (may be scrubbed in published descriptors).
    pub port: Option<u16>,

    /// Additional transport arguments.
    pub args: Vec<String>,
}

/// Extra-info descriptor containing relay statistics and metadata.
///
/// Extra-info descriptors are published alongside server descriptors and
/// contain detailed statistics about relay operation. They are not required
/// for Tor clients to function but provide valuable metrics for network
/// analysis.
///
/// # Overview
///
/// The descriptor contains several categories of information:
///
/// - **Identity** - Nickname, fingerprint, publication time
/// - **Bandwidth history** - Read/write traffic over time
/// - **Directory statistics** - Request counts and download speeds
/// - **Cell statistics** - Circuit cell processing metrics
/// - **Exit statistics** - Traffic per destination port
/// - **Bridge statistics** - Client connection data
/// - **Hidden service statistics** - Onion service activity
/// - **Cryptographic data** - Ed25519 certificates and signatures
///
/// # Relay vs Bridge
///
/// Use [`is_bridge()`](Self::is_bridge) to distinguish between relay and
/// bridge extra-info descriptors:
///
/// - **Relay**: Has `router-signature` line with RSA signature
/// - **Bridge**: Has `router-digest` line instead of signature
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::extra_info::ExtraInfoDescriptor;
/// use stem_rs::descriptor::Descriptor;
///
/// let content = r#"extra-info MyRelay B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
/// published 2024-01-15 12:00:00
/// write-history 2024-01-15 12:00:00 (900 s) 1000000,2000000
/// read-history 2024-01-15 12:00:00 (900 s) 500000,1000000
/// "#;
///
/// let desc = ExtraInfoDescriptor::parse(content).unwrap();
///
/// // Check identity
/// assert_eq!(desc.nickname, "MyRelay");
/// assert_eq!(desc.fingerprint.len(), 40);
///
/// // Check bandwidth history
/// if let Some(ref history) = desc.write_history {
///     println!("Write interval: {} seconds", history.interval);
///     println!("Values: {:?}", history.values);
/// }
/// ```
///
/// # Statistics Fields
///
/// ## Bandwidth History
///
/// - `read_history` / `write_history` - Relay traffic
/// - `dir_read_history` / `dir_write_history` - Directory traffic
///
/// ## Directory Statistics
///
/// - `dir_v3_ips` / `dir_v3_requests` - Client counts by country
/// - `dir_v3_responses` - Response status counts
/// - `dir_v3_direct_dl` / `dir_v3_tunneled_dl` - Download speed stats
///
/// ## Exit Statistics
///
/// - `exit_kibibytes_written` / `exit_kibibytes_read` - Traffic per port
/// - `exit_streams_opened` - Connection counts per port
///
/// ## Bridge Statistics
///
/// - `bridge_ips` - Client counts by country
/// - `ip_versions` - IPv4 vs IPv6 client counts
/// - `ip_transports` - Pluggable transport usage
///
/// # Thread Safety
///
/// `ExtraInfoDescriptor` is `Send` and `Sync`, making it safe to share
/// across threads.
///
/// # See Also
///
/// - [`crate::descriptor::server::ServerDescriptor`] - Published alongside extra-info
/// - [`BandwidthHistory`] - Bandwidth history data structure
/// - [`DirResponse`] - Directory response status codes
/// - [`DirStat`] - Directory download statistics
#[derive(Debug, Clone, PartialEq, Builder)]
#[builder(setter(into, strip_option))]
pub struct ExtraInfoDescriptor {
    /// The relay's nickname (1-19 alphanumeric characters).
    pub nickname: String,

    /// The relay's identity fingerprint (40 uppercase hex characters).
    ///
    /// This is the SHA-1 hash of the relay's identity key.
    pub fingerprint: String,

    /// When this descriptor was published (UTC).
    pub published: DateTime<Utc>,

    /// SHA-1 digest of the GeoIP database for IPv4 addresses.
    #[builder(default)]
    pub geoip_db_digest: Option<String>,

    /// SHA-1 digest of the GeoIP database for IPv6 addresses.
    #[builder(default)]
    pub geoip6_db_digest: Option<String>,

    /// Pluggable transports available on this relay (bridges only).
    ///
    /// Maps transport name to transport details.
    pub transports: HashMap<String, Transport>,

    /// Bytes read by the relay over time.
    #[builder(default)]
    pub read_history: Option<BandwidthHistory>,

    /// Bytes written by the relay over time.
    #[builder(default)]
    pub write_history: Option<BandwidthHistory>,

    /// Bytes read for directory requests over time.
    #[builder(default)]
    pub dir_read_history: Option<BandwidthHistory>,

    /// Bytes written for directory requests over time.
    #[builder(default)]
    pub dir_write_history: Option<BandwidthHistory>,

    /// End time for bi-directional connection statistics.
    #[builder(default)]
    pub conn_bi_direct_end: Option<DateTime<Utc>>,

    /// Interval for bi-directional connection statistics (seconds).
    #[builder(default)]
    pub conn_bi_direct_interval: Option<u32>,

    /// Connections that read/wrote less than 20 KiB.
    #[builder(default)]
    pub conn_bi_direct_below: Option<u32>,

    /// Connections that read at least 10x more than wrote.
    #[builder(default)]
    pub conn_bi_direct_read: Option<u32>,

    /// Connections that wrote at least 10x more than read.
    #[builder(default)]
    pub conn_bi_direct_write: Option<u32>,

    /// Connections with balanced read/write (remaining).
    #[builder(default)]
    pub conn_bi_direct_both: Option<u32>,

    /// End time for cell statistics collection.
    #[builder(default)]
    pub cell_stats_end: Option<DateTime<Utc>>,

    /// Interval for cell statistics (seconds).
    #[builder(default)]
    pub cell_stats_interval: Option<u32>,

    /// Mean processed cells per circuit, by decile.
    pub cell_processed_cells: Vec<f64>,

    /// Mean queued cells per circuit, by decile.
    pub cell_queued_cells: Vec<f64>,

    /// Mean time cells spent in queue (milliseconds), by decile.
    pub cell_time_in_queue: Vec<f64>,

    /// Mean number of circuits in a decile.
    #[builder(default)]
    pub cell_circuits_per_decile: Option<u32>,

    /// End time for directory statistics collection.
    #[builder(default)]
    pub dir_stats_end: Option<DateTime<Utc>>,

    /// Interval for directory statistics (seconds).
    #[builder(default)]
    pub dir_stats_interval: Option<u32>,

    /// V3 directory request client IPs by country code.
    pub dir_v3_ips: HashMap<String, u32>,

    /// V3 directory request counts by country code.
    pub dir_v3_requests: HashMap<String, u32>,

    /// V3 directory response status counts.
    pub dir_v3_responses: HashMap<DirResponse, u32>,

    /// Unrecognized V3 directory response statuses.
    pub dir_v3_responses_unknown: HashMap<String, u32>,

    /// V3 direct download statistics (via DirPort).
    pub dir_v3_direct_dl: HashMap<DirStat, u32>,

    /// Unrecognized V3 direct download statistics.
    pub dir_v3_direct_dl_unknown: HashMap<String, u32>,

    /// V3 tunneled download statistics (via ORPort).
    pub dir_v3_tunneled_dl: HashMap<DirStat, u32>,

    /// Unrecognized V3 tunneled download statistics.
    pub dir_v3_tunneled_dl_unknown: HashMap<String, u32>,

    /// V2 directory request client IPs by country code (deprecated).
    pub dir_v2_ips: HashMap<String, u32>,

    /// V2 directory request counts by country code (deprecated).
    pub dir_v2_requests: HashMap<String, u32>,

    /// V2 directory response status counts (deprecated).
    pub dir_v2_responses: HashMap<DirResponse, u32>,

    /// Unrecognized V2 directory response statuses (deprecated).
    pub dir_v2_responses_unknown: HashMap<String, u32>,

    /// V2 direct download statistics (deprecated).
    pub dir_v2_direct_dl: HashMap<DirStat, u32>,

    /// Unrecognized V2 direct download statistics (deprecated).
    pub dir_v2_direct_dl_unknown: HashMap<String, u32>,

    /// V2 tunneled download statistics (deprecated).
    pub dir_v2_tunneled_dl: HashMap<DirStat, u32>,

    /// Unrecognized V2 tunneled download statistics (deprecated).
    pub dir_v2_tunneled_dl_unknown: HashMap<String, u32>,

    /// End time for entry guard statistics.
    #[builder(default)]
    pub entry_stats_end: Option<DateTime<Utc>>,

    /// Interval for entry guard statistics (seconds).
    #[builder(default)]
    pub entry_stats_interval: Option<u32>,

    /// Entry guard client IPs by country code.
    pub entry_ips: HashMap<String, u32>,

    /// End time for exit statistics.
    #[builder(default)]
    pub exit_stats_end: Option<DateTime<Utc>>,

    /// Interval for exit statistics (seconds).
    #[builder(default)]
    pub exit_stats_interval: Option<u32>,

    /// Kibibytes written per destination port.
    pub exit_kibibytes_written: HashMap<PortKey, u64>,

    /// Kibibytes read per destination port.
    pub exit_kibibytes_read: HashMap<PortKey, u64>,

    /// Streams opened per destination port.
    pub exit_streams_opened: HashMap<PortKey, u64>,

    /// End time for bridge statistics.
    #[builder(default)]
    pub bridge_stats_end: Option<DateTime<Utc>>,

    /// Interval for bridge statistics (seconds).
    #[builder(default)]
    pub bridge_stats_interval: Option<u32>,

    /// Bridge client IPs by country code.
    pub bridge_ips: HashMap<String, u32>,

    /// Bridge client counts by IP version (v4, v6).
    pub ip_versions: HashMap<String, u32>,

    /// Bridge client counts by transport method.
    pub ip_transports: HashMap<String, u32>,

    /// End time for hidden service statistics.
    #[builder(default)]
    pub hs_stats_end: Option<DateTime<Utc>>,

    /// Rounded count of RENDEZVOUS1 cells relayed.
    #[builder(default)]
    pub hs_rend_cells: Option<u64>,

    /// Additional attributes for hs_rend_cells.
    pub hs_rend_cells_attr: HashMap<String, String>,

    /// Rounded count of unique onion service identities seen.
    #[builder(default)]
    pub hs_dir_onions_seen: Option<u64>,

    /// Additional attributes for hs_dir_onions_seen.
    pub hs_dir_onions_seen_attr: HashMap<String, String>,

    /// End time for padding count statistics.
    #[builder(default)]
    pub padding_counts_end: Option<DateTime<Utc>>,

    /// Interval for padding count statistics (seconds).
    #[builder(default)]
    pub padding_counts_interval: Option<u32>,

    /// Padding-related statistics.
    pub padding_counts: HashMap<String, String>,

    /// Ed25519 certificate (PEM-encoded).
    #[builder(default)]
    pub ed25519_certificate: Option<String>,

    /// Ed25519 signature of the descriptor.
    #[builder(default)]
    pub ed25519_signature: Option<String>,

    /// RSA signature of the descriptor (relay extra-info only).
    #[builder(default)]
    pub signature: Option<String>,

    /// Router digest for bridge extra-info descriptors.
    ///
    /// Present only in bridge descriptors; indicates this is a bridge.
    #[builder(default)]
    pub router_digest: Option<String>,

    /// SHA-256 router digest (base64).
    #[builder(default)]
    pub router_digest_sha256: Option<String>,

    /// Raw descriptor content for digest computation.
    raw_content: Vec<u8>,

    /// Lines not recognized during parsing.
    unrecognized_lines: Vec<String>,
}

/// Key for port-based statistics in exit traffic data.
///
/// Exit statistics are grouped by destination port. The special "other"
/// category aggregates traffic to ports not individually tracked.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::extra_info::PortKey;
///
/// let http = PortKey::Port(80);
/// let https = PortKey::Port(443);
/// let other = PortKey::Other;
///
/// assert_eq!(format!("{}", http), "80");
/// assert_eq!(format!("{}", other), "other");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PortKey {
    /// A specific port number.
    Port(u16),

    /// Aggregate of all other ports not individually tracked.
    Other,
}

impl fmt::Display for PortKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortKey::Port(p) => write!(f, "{}", p),
            PortKey::Other => write!(f, "other"),
        }
    }
}

impl Default for ExtraInfoDescriptor {
    fn default() -> Self {
        Self {
            nickname: String::new(),
            fingerprint: String::new(),
            published: DateTime::from_timestamp(0, 0).unwrap(),
            geoip_db_digest: None,
            geoip6_db_digest: None,
            transports: HashMap::new(),
            read_history: None,
            write_history: None,
            dir_read_history: None,
            dir_write_history: None,
            conn_bi_direct_end: None,
            conn_bi_direct_interval: None,
            conn_bi_direct_below: None,
            conn_bi_direct_read: None,
            conn_bi_direct_write: None,
            conn_bi_direct_both: None,
            cell_stats_end: None,
            cell_stats_interval: None,
            cell_processed_cells: Vec::new(),
            cell_queued_cells: Vec::new(),
            cell_time_in_queue: Vec::new(),
            cell_circuits_per_decile: None,
            dir_stats_end: None,
            dir_stats_interval: None,
            dir_v3_ips: HashMap::new(),
            dir_v3_requests: HashMap::new(),
            dir_v3_responses: HashMap::new(),
            dir_v3_responses_unknown: HashMap::new(),
            dir_v3_direct_dl: HashMap::new(),
            dir_v3_direct_dl_unknown: HashMap::new(),
            dir_v3_tunneled_dl: HashMap::new(),
            dir_v3_tunneled_dl_unknown: HashMap::new(),
            dir_v2_ips: HashMap::new(),
            dir_v2_requests: HashMap::new(),
            dir_v2_responses: HashMap::new(),
            dir_v2_responses_unknown: HashMap::new(),
            dir_v2_direct_dl: HashMap::new(),
            dir_v2_direct_dl_unknown: HashMap::new(),
            dir_v2_tunneled_dl: HashMap::new(),
            dir_v2_tunneled_dl_unknown: HashMap::new(),
            entry_stats_end: None,
            entry_stats_interval: None,
            entry_ips: HashMap::new(),
            exit_stats_end: None,
            exit_stats_interval: None,
            exit_kibibytes_written: HashMap::new(),
            exit_kibibytes_read: HashMap::new(),
            exit_streams_opened: HashMap::new(),
            bridge_stats_end: None,
            bridge_stats_interval: None,
            bridge_ips: HashMap::new(),
            ip_versions: HashMap::new(),
            ip_transports: HashMap::new(),
            hs_stats_end: None,
            hs_rend_cells: None,
            hs_rend_cells_attr: HashMap::new(),
            hs_dir_onions_seen: None,
            hs_dir_onions_seen_attr: HashMap::new(),
            padding_counts_end: None,
            padding_counts_interval: None,
            padding_counts: HashMap::new(),
            ed25519_certificate: None,
            ed25519_signature: None,
            signature: None,
            router_digest: None,
            router_digest_sha256: None,
            raw_content: Vec::new(),
            unrecognized_lines: Vec::new(),
        }
    }
}

impl ExtraInfoDescriptor {
    fn parse_extra_info_line(line: &str) -> Result<(String, String), Error> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(Error::Parse {
                location: "extra-info".to_string(),
                reason: "extra-info line requires nickname and fingerprint".to_string(),
            });
        }
        let nickname = parts[0].to_string();
        let fingerprint = parts[1].to_string();
        if fingerprint.len() != 40 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Parse {
                location: "extra-info".to_string(),
                reason: format!("invalid fingerprint: {}", fingerprint),
            });
        }
        Ok((nickname, fingerprint))
    }

    fn parse_published_line(line: &str) -> Result<DateTime<Utc>, Error> {
        let datetime =
            NaiveDateTime::parse_from_str(line.trim(), "%Y-%m-%d %H:%M:%S").map_err(|e| {
                Error::Parse {
                    location: "published".to_string(),
                    reason: format!("invalid datetime: {} - {}", line, e),
                }
            })?;
        Ok(datetime.and_utc())
    }

    fn parse_history_line(line: &str) -> Result<BandwidthHistory, Error> {
        let timestamp_re =
            regex::Regex::new(r"^(.+?) \((\d+) s\)(.*)$").map_err(|e| Error::Parse {
                location: "history".to_string(),
                reason: format!("regex error: {}", e),
            })?;

        let caps = timestamp_re.captures(line).ok_or_else(|| Error::Parse {
            location: "history".to_string(),
            reason: format!("invalid history format: {}", line),
        })?;

        let timestamp_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let interval_str = caps.get(2).map(|m| m.as_str()).unwrap_or("0");
        let values_str = caps.get(3).map(|m| m.as_str().trim()).unwrap_or("");

        let end_time = NaiveDateTime::parse_from_str(timestamp_str.trim(), "%Y-%m-%d %H:%M:%S")
            .map_err(|e| Error::Parse {
                location: "history".to_string(),
                reason: format!("invalid timestamp: {} - {}", timestamp_str, e),
            })?
            .and_utc();

        let interval: u32 = interval_str.parse().map_err(|_| Error::Parse {
            location: "history".to_string(),
            reason: format!("invalid interval: {}", interval_str),
        })?;

        let values: Vec<i64> = if values_str.is_empty() {
            Vec::new()
        } else {
            values_str
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().parse::<i64>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::Parse {
                    location: "history".to_string(),
                    reason: format!("invalid history values: {}", values_str),
                })?
        };

        Ok(BandwidthHistory {
            end_time,
            interval,
            values,
        })
    }

    fn parse_timestamp_and_interval(line: &str) -> Result<(DateTime<Utc>, u32, String), Error> {
        let timestamp_re =
            regex::Regex::new(r"^(.+?) \((\d+) s\)(.*)$").map_err(|e| Error::Parse {
                location: "timestamp".to_string(),
                reason: format!("regex error: {}", e),
            })?;

        let caps = timestamp_re.captures(line).ok_or_else(|| Error::Parse {
            location: "timestamp".to_string(),
            reason: format!("invalid timestamp format: {}", line),
        })?;

        let timestamp_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let interval_str = caps.get(2).map(|m| m.as_str()).unwrap_or("0");
        let remainder = caps
            .get(3)
            .map(|m| m.as_str().trim())
            .unwrap_or("")
            .to_string();

        let timestamp = NaiveDateTime::parse_from_str(timestamp_str.trim(), "%Y-%m-%d %H:%M:%S")
            .map_err(|e| Error::Parse {
                location: "timestamp".to_string(),
                reason: format!("invalid timestamp: {} - {}", timestamp_str, e),
            })?
            .and_utc();

        let interval: u32 = interval_str.parse().map_err(|_| Error::Parse {
            location: "timestamp".to_string(),
            reason: format!("invalid interval: {}", interval_str),
        })?;

        Ok((timestamp, interval, remainder))
    }

    fn parse_geoip_to_count(value: &str) -> HashMap<String, u32> {
        let mut result = HashMap::new();
        if value.is_empty() {
            return result;
        }
        for entry in value.split(',') {
            if let Some(eq_pos) = entry.find('=') {
                let locale = &entry[..eq_pos];
                let count_str = &entry[eq_pos + 1..];
                if let Ok(count) = count_str.parse::<u32>() {
                    result.insert(locale.to_string(), count);
                }
            }
        }
        result
    }

    fn parse_dirreq_resp(value: &str) -> (HashMap<DirResponse, u32>, HashMap<String, u32>) {
        let mut recognized = HashMap::new();
        let mut unrecognized = HashMap::new();
        if value.is_empty() {
            return (recognized, unrecognized);
        }
        for entry in value.split(',') {
            if let Some(eq_pos) = entry.find('=') {
                let status = &entry[..eq_pos];
                let count_str = &entry[eq_pos + 1..];
                if let Ok(count) = count_str.parse::<u32>() {
                    if let Ok(dir_resp) = DirResponse::from_str(status) {
                        recognized.insert(dir_resp, count);
                    } else {
                        unrecognized.insert(status.to_string(), count);
                    }
                }
            }
        }
        (recognized, unrecognized)
    }

    fn parse_dirreq_dl(value: &str) -> (HashMap<DirStat, u32>, HashMap<String, u32>) {
        let mut recognized = HashMap::new();
        let mut unrecognized = HashMap::new();
        if value.is_empty() {
            return (recognized, unrecognized);
        }
        for entry in value.split(',') {
            if let Some(eq_pos) = entry.find('=') {
                let stat = &entry[..eq_pos];
                let count_str = &entry[eq_pos + 1..];
                if let Ok(count) = count_str.parse::<u32>() {
                    if let Ok(dir_stat) = DirStat::from_str(stat) {
                        recognized.insert(dir_stat, count);
                    } else {
                        unrecognized.insert(stat.to_string(), count);
                    }
                }
            }
        }
        (recognized, unrecognized)
    }

    fn parse_port_count(value: &str) -> HashMap<PortKey, u64> {
        let mut result = HashMap::new();
        if value.is_empty() {
            return result;
        }
        for entry in value.split(',') {
            if let Some(eq_pos) = entry.find('=') {
                let port_str = &entry[..eq_pos];
                let count_str = &entry[eq_pos + 1..];
                if let Ok(count) = count_str.parse::<u64>() {
                    let port_key = if port_str == "other" {
                        PortKey::Other
                    } else if let Ok(port) = port_str.parse::<u16>() {
                        PortKey::Port(port)
                    } else {
                        continue;
                    };
                    result.insert(port_key, count);
                }
            }
        }
        result
    }

    fn parse_cell_values(value: &str) -> Vec<f64> {
        if value.is_empty() {
            return Vec::new();
        }
        value
            .split(',')
            .filter_map(|s| s.trim().parse::<f64>().ok())
            .collect()
    }

    fn parse_conn_bi_direct(value: &str) -> ConnBiDirectResult {
        let (timestamp, interval, remainder) = Self::parse_timestamp_and_interval(value)?;
        let stats: Vec<&str> = remainder.split(',').collect();
        if stats.len() != 4 {
            return Err(Error::Parse {
                location: "conn-bi-direct".to_string(),
                reason: format!("expected 4 values, got {}", stats.len()),
            });
        }
        let below: u32 = stats[0].parse().map_err(|_| Error::Parse {
            location: "conn-bi-direct".to_string(),
            reason: "invalid below value".to_string(),
        })?;
        let read: u32 = stats[1].parse().map_err(|_| Error::Parse {
            location: "conn-bi-direct".to_string(),
            reason: "invalid read value".to_string(),
        })?;
        let write: u32 = stats[2].parse().map_err(|_| Error::Parse {
            location: "conn-bi-direct".to_string(),
            reason: "invalid write value".to_string(),
        })?;
        let both: u32 = stats[3].parse().map_err(|_| Error::Parse {
            location: "conn-bi-direct".to_string(),
            reason: "invalid both value".to_string(),
        })?;
        Ok((timestamp, interval, below, read, write, both))
    }

    fn parse_transport_line(value: &str) -> Transport {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.is_empty() {
            return Transport {
                name: String::new(),
                address: None,
                port: None,
                args: Vec::new(),
            };
        }
        let name = parts[0].to_string();
        if parts.len() < 2 {
            return Transport {
                name,
                address: None,
                port: None,
                args: Vec::new(),
            };
        }
        let addr_port = parts[1];
        let (address, port) = if let Some(colon_pos) = addr_port.rfind(':') {
            let addr = addr_port[..colon_pos]
                .trim_matches(|c| c == '[' || c == ']')
                .to_string();
            let port = addr_port[colon_pos + 1..].parse::<u16>().ok();
            (Some(addr), port)
        } else {
            (None, None)
        };
        let args: Vec<String> = parts.iter().skip(2).map(|s| s.to_string()).collect();
        Transport {
            name,
            address,
            port,
            args,
        }
    }

    fn parse_hs_stats(value: &str) -> (Option<u64>, HashMap<String, String>) {
        let mut stat = None;
        let mut extra = HashMap::new();
        if value.is_empty() {
            return (stat, extra);
        }
        let parts: Vec<&str> = value.split_whitespace().collect();
        if let Some(first) = parts.first() {
            stat = first.parse::<u64>().ok();
        }
        for part in parts.iter().skip(1) {
            if let Some(eq_pos) = part.find('=') {
                let key = &part[..eq_pos];
                let val = &part[eq_pos + 1..];
                extra.insert(key.to_string(), val.to_string());
            }
        }
        (stat, extra)
    }

    fn parse_padding_counts(value: &str) -> PaddingCountsResult {
        let (timestamp, interval, remainder) = Self::parse_timestamp_and_interval(value)?;
        let mut counts = HashMap::new();
        for part in remainder.split_whitespace() {
            if let Some(eq_pos) = part.find('=') {
                let key = &part[..eq_pos];
                let val = &part[eq_pos + 1..];
                counts.insert(key.to_string(), val.to_string());
            }
        }
        Ok((timestamp, interval, counts))
    }

    fn extract_pem_block(lines: &[&str], start_idx: usize) -> (String, usize) {
        let mut block = String::new();
        let mut idx = start_idx;
        while idx < lines.len() {
            let line = lines[idx];
            block.push_str(line);
            block.push('\n');
            if line.starts_with("-----END ") {
                break;
            }
            idx += 1;
        }
        (block.trim_end().to_string(), idx)
    }

    /// Finds the content to be hashed for digest computation.
    ///
    /// For relay extra-info descriptors, the digest is computed over
    /// the content from "extra-info " through "router-signature\n".
    fn find_digest_content(content: &str) -> Option<&str> {
        let start_marker = "extra-info ";
        let end_marker = "\nrouter-signature\n";
        let start = content.find(start_marker)?;
        let end = content.find(end_marker)?;
        Some(&content[start..end + end_marker.len()])
    }

    /// Returns whether this is a bridge extra-info descriptor.
    ///
    /// Bridge descriptors have a `router-digest` line instead of a
    /// `router-signature` line.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::extra_info::ExtraInfoDescriptor;
    /// use stem_rs::descriptor::Descriptor;
    ///
    /// let relay_content = r#"extra-info relay B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
    /// published 2024-01-15 12:00:00
    /// "#;
    ///
    /// let bridge_content = r#"extra-info bridge B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
    /// published 2024-01-15 12:00:00
    /// router-digest 00A2AECCEAD3FEE033CFE29893387143146728EC
    /// "#;
    ///
    /// let relay = ExtraInfoDescriptor::parse(relay_content).unwrap();
    /// let bridge = ExtraInfoDescriptor::parse(bridge_content).unwrap();
    ///
    /// assert!(!relay.is_bridge());
    /// assert!(bridge.is_bridge());
    /// ```
    pub fn is_bridge(&self) -> bool {
        self.router_digest.is_some()
    }
}

impl Descriptor for ExtraInfoDescriptor {
    fn parse(content: &str) -> Result<Self, Error> {
        let raw_content = content.as_bytes().to_vec();
        let lines: Vec<&str> = content.lines().collect();
        let mut desc = ExtraInfoDescriptor {
            raw_content,
            ..Default::default()
        };

        let mut idx = 0;
        while idx < lines.len() {
            let line = lines[idx];

            if line.starts_with("@type ") {
                idx += 1;
                continue;
            }

            let (keyword, value) = if let Some(space_pos) = line.find(' ') {
                (&line[..space_pos], line[space_pos + 1..].trim())
            } else {
                (line, "")
            };

            match keyword {
                "extra-info" => {
                    let (nickname, fingerprint) = Self::parse_extra_info_line(value)?;
                    desc.nickname = nickname;
                    desc.fingerprint = fingerprint;
                }
                "published" => {
                    desc.published = Self::parse_published_line(value)?;
                }
                "identity-ed25519" => {
                    let (block, end_idx) = Self::extract_pem_block(&lines, idx + 1);
                    desc.ed25519_certificate = Some(block);
                    idx = end_idx;
                }
                "router-sig-ed25519" => {
                    desc.ed25519_signature = Some(value.to_string());
                }
                "router-signature" => {
                    let (block, end_idx) = Self::extract_pem_block(&lines, idx + 1);
                    desc.signature = Some(block);
                    idx = end_idx;
                }
                "router-digest" => {
                    desc.router_digest = Some(value.to_string());
                }
                "router-digest-sha256" => {
                    desc.router_digest_sha256 = Some(value.to_string());
                }
                "master-key-ed25519" => {
                    desc.ed25519_certificate = Some(value.to_string());
                }
                "geoip-db-digest" => {
                    desc.geoip_db_digest = Some(value.to_string());
                }
                "geoip6-db-digest" => {
                    desc.geoip6_db_digest = Some(value.to_string());
                }
                "transport" => {
                    let transport = Self::parse_transport_line(value);
                    desc.transports.insert(transport.name.clone(), transport);
                }
                "read-history" => {
                    desc.read_history = Some(Self::parse_history_line(value)?);
                }
                "write-history" => {
                    desc.write_history = Some(Self::parse_history_line(value)?);
                }
                "dirreq-read-history" => {
                    desc.dir_read_history = Some(Self::parse_history_line(value)?);
                }
                "dirreq-write-history" => {
                    desc.dir_write_history = Some(Self::parse_history_line(value)?);
                }
                "conn-bi-direct" => {
                    let (ts, interval, below, read, write, both) =
                        Self::parse_conn_bi_direct(value)?;
                    desc.conn_bi_direct_end = Some(ts);
                    desc.conn_bi_direct_interval = Some(interval);
                    desc.conn_bi_direct_below = Some(below);
                    desc.conn_bi_direct_read = Some(read);
                    desc.conn_bi_direct_write = Some(write);
                    desc.conn_bi_direct_both = Some(both);
                }
                "cell-stats-end" => {
                    let (ts, interval, _) = Self::parse_timestamp_and_interval(value)?;
                    desc.cell_stats_end = Some(ts);
                    desc.cell_stats_interval = Some(interval);
                }
                "cell-processed-cells" => {
                    desc.cell_processed_cells = Self::parse_cell_values(value);
                }
                "cell-queued-cells" => {
                    desc.cell_queued_cells = Self::parse_cell_values(value);
                }
                "cell-time-in-queue" => {
                    desc.cell_time_in_queue = Self::parse_cell_values(value);
                }
                "cell-circuits-per-decile" => {
                    desc.cell_circuits_per_decile = value.parse().ok();
                }
                "dirreq-stats-end" => {
                    let (ts, interval, _) = Self::parse_timestamp_and_interval(value)?;
                    desc.dir_stats_end = Some(ts);
                    desc.dir_stats_interval = Some(interval);
                }
                "dirreq-v3-ips" => {
                    desc.dir_v3_ips = Self::parse_geoip_to_count(value);
                }
                "dirreq-v3-reqs" => {
                    desc.dir_v3_requests = Self::parse_geoip_to_count(value);
                }
                "dirreq-v3-resp" => {
                    let (recognized, unrecognized) = Self::parse_dirreq_resp(value);
                    desc.dir_v3_responses = recognized;
                    desc.dir_v3_responses_unknown = unrecognized;
                }
                "dirreq-v3-direct-dl" => {
                    let (recognized, unrecognized) = Self::parse_dirreq_dl(value);
                    desc.dir_v3_direct_dl = recognized;
                    desc.dir_v3_direct_dl_unknown = unrecognized;
                }
                "dirreq-v3-tunneled-dl" => {
                    let (recognized, unrecognized) = Self::parse_dirreq_dl(value);
                    desc.dir_v3_tunneled_dl = recognized;
                    desc.dir_v3_tunneled_dl_unknown = unrecognized;
                }
                "dirreq-v2-ips" => {
                    desc.dir_v2_ips = Self::parse_geoip_to_count(value);
                }
                "dirreq-v2-reqs" => {
                    desc.dir_v2_requests = Self::parse_geoip_to_count(value);
                }
                "dirreq-v2-resp" => {
                    let (recognized, unrecognized) = Self::parse_dirreq_resp(value);
                    desc.dir_v2_responses = recognized;
                    desc.dir_v2_responses_unknown = unrecognized;
                }
                "dirreq-v2-direct-dl" => {
                    let (recognized, unrecognized) = Self::parse_dirreq_dl(value);
                    desc.dir_v2_direct_dl = recognized;
                    desc.dir_v2_direct_dl_unknown = unrecognized;
                }
                "dirreq-v2-tunneled-dl" => {
                    let (recognized, unrecognized) = Self::parse_dirreq_dl(value);
                    desc.dir_v2_tunneled_dl = recognized;
                    desc.dir_v2_tunneled_dl_unknown = unrecognized;
                }
                "entry-stats-end" => {
                    let (ts, interval, _) = Self::parse_timestamp_and_interval(value)?;
                    desc.entry_stats_end = Some(ts);
                    desc.entry_stats_interval = Some(interval);
                }
                "entry-ips" => {
                    desc.entry_ips = Self::parse_geoip_to_count(value);
                }
                "exit-stats-end" => {
                    let (ts, interval, _) = Self::parse_timestamp_and_interval(value)?;
                    desc.exit_stats_end = Some(ts);
                    desc.exit_stats_interval = Some(interval);
                }
                "exit-kibibytes-written" => {
                    desc.exit_kibibytes_written = Self::parse_port_count(value);
                }
                "exit-kibibytes-read" => {
                    desc.exit_kibibytes_read = Self::parse_port_count(value);
                }
                "exit-streams-opened" => {
                    desc.exit_streams_opened = Self::parse_port_count(value);
                }
                "bridge-stats-end" => {
                    let (ts, interval, _) = Self::parse_timestamp_and_interval(value)?;
                    desc.bridge_stats_end = Some(ts);
                    desc.bridge_stats_interval = Some(interval);
                }
                "bridge-ips" => {
                    desc.bridge_ips = Self::parse_geoip_to_count(value);
                }
                "bridge-ip-versions" => {
                    desc.ip_versions = Self::parse_geoip_to_count(value);
                }
                "bridge-ip-transports" => {
                    desc.ip_transports = Self::parse_geoip_to_count(value);
                }
                "hidserv-stats-end" => {
                    desc.hs_stats_end = Some(Self::parse_published_line(value)?);
                }
                "hidserv-rend-relayed-cells" => {
                    let (stat, attr) = Self::parse_hs_stats(value);
                    desc.hs_rend_cells = stat;
                    desc.hs_rend_cells_attr = attr;
                }
                "hidserv-dir-onions-seen" => {
                    let (stat, attr) = Self::parse_hs_stats(value);
                    desc.hs_dir_onions_seen = stat;
                    desc.hs_dir_onions_seen_attr = attr;
                }
                "padding-counts" => {
                    let (ts, interval, counts) = Self::parse_padding_counts(value)?;
                    desc.padding_counts_end = Some(ts);
                    desc.padding_counts_interval = Some(interval);
                    desc.padding_counts = counts;
                }
                _ => {
                    if !line.is_empty() && !line.starts_with("-----") {
                        desc.unrecognized_lines.push(line.to_string());
                    }
                }
            }
            idx += 1;
        }

        if desc.nickname.is_empty() {
            return Err(Error::Parse {
                location: "extra-info".to_string(),
                reason: "missing extra-info line".to_string(),
            });
        }

        Ok(desc)
    }

    fn to_descriptor_string(&self) -> String {
        let mut result = String::new();

        result.push_str(&format!(
            "extra-info {} {}\n",
            self.nickname, self.fingerprint
        ));
        result.push_str(&format!(
            "published {}\n",
            self.published.format("%Y-%m-%d %H:%M:%S")
        ));

        if let Some(ref history) = self.write_history {
            let values: String = history
                .values
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",");
            result.push_str(&format!(
                "write-history {} ({} s) {}\n",
                history.end_time.format("%Y-%m-%d %H:%M:%S"),
                history.interval,
                values
            ));
        }

        if let Some(ref history) = self.read_history {
            let values: String = history
                .values
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",");
            result.push_str(&format!(
                "read-history {} ({} s) {}\n",
                history.end_time.format("%Y-%m-%d %H:%M:%S"),
                history.interval,
                values
            ));
        }

        if let Some(ref history) = self.dir_write_history {
            let values: String = history
                .values
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",");
            result.push_str(&format!(
                "dirreq-write-history {} ({} s) {}\n",
                history.end_time.format("%Y-%m-%d %H:%M:%S"),
                history.interval,
                values
            ));
        }

        if let Some(ref history) = self.dir_read_history {
            let values: String = history
                .values
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",");
            result.push_str(&format!(
                "dirreq-read-history {} ({} s) {}\n",
                history.end_time.format("%Y-%m-%d %H:%M:%S"),
                history.interval,
                values
            ));
        }

        if let Some(ref digest) = self.geoip_db_digest {
            result.push_str(&format!("geoip-db-digest {}\n", digest));
        }

        if let Some(ref digest) = self.geoip6_db_digest {
            result.push_str(&format!("geoip6-db-digest {}\n", digest));
        }

        if let Some(ref sig) = self.signature {
            result.push_str("router-signature\n");
            result.push_str(sig);
            result.push('\n');
        }

        if let Some(ref digest) = self.router_digest {
            result.push_str(&format!("router-digest {}\n", digest));
        }

        result
    }

    fn digest(&self, hash: DigestHash, encoding: DigestEncoding) -> Result<String, Error> {
        if self.is_bridge() {
            match (hash, encoding) {
                (DigestHash::Sha1, DigestEncoding::Hex) => {
                    self.router_digest.clone().ok_or_else(|| Error::Parse {
                        location: "digest".to_string(),
                        reason: "bridge descriptor missing router-digest".to_string(),
                    })
                }
                (DigestHash::Sha256, DigestEncoding::Base64) => self
                    .router_digest_sha256
                    .clone()
                    .ok_or_else(|| Error::Parse {
                        location: "digest".to_string(),
                        reason: "bridge descriptor missing router-digest-sha256".to_string(),
                    }),
                _ => Err(Error::Parse {
                    location: "digest".to_string(),
                    reason: "bridge extrainfo digests only available as sha1/hex or sha256/base64"
                        .to_string(),
                }),
            }
        } else {
            let content_str = std::str::from_utf8(&self.raw_content).map_err(|_| Error::Parse {
                location: "digest".to_string(),
                reason: "invalid UTF-8 in raw content".to_string(),
            })?;

            match hash {
                DigestHash::Sha1 => {
                    let digest_content =
                        Self::find_digest_content(content_str).ok_or_else(|| Error::Parse {
                            location: "digest".to_string(),
                            reason: "could not find digest content boundaries".to_string(),
                        })?;
                    Ok(compute_digest(digest_content.as_bytes(), hash, encoding))
                }
                DigestHash::Sha256 => Ok(compute_digest(&self.raw_content, hash, encoding)),
            }
        }
    }

    fn raw_content(&self) -> &[u8] {
        &self.raw_content
    }

    fn unrecognized_lines(&self) -> &[String] {
        &self.unrecognized_lines
    }
}

impl FromStr for ExtraInfoDescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for ExtraInfoDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_descriptor_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY_EXTRA_INFO: &str = r#"@type extra-info 1.0
extra-info NINJA B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
write-history 2012-05-05 17:02:45 (900 s) 1082368,19456,50176,272384,485376,1850368,1132544,1790976,2459648,4091904,6310912,13701120,3209216,3871744,7873536,5440512,7287808,10561536,9979904,11247616,11982848,7590912,10611712,20728832,38534144,6839296,3173376,16678912
read-history 2012-05-05 17:02:45 (900 s) 3309568,9216,41984,27648,123904,2004992,364544,576512,1607680,3808256,4672512,12783616,2938880,2562048,7348224,3574784,6488064,10954752,9359360,4438016,6286336,6438912,4502528,10720256,38165504,1524736,2336768,8186880
dirreq-write-history 2012-05-05 17:02:45 (900 s) 0,0,0,227328,349184,382976,738304,1171456,850944,657408,1675264,987136,702464,1335296,587776,1941504,893952,533504,695296,6828032,6326272,1287168,6310912,10085376,1048576,5372928,894976,8610816
dirreq-read-history 2012-05-05 17:02:45 (900 s) 0,0,0,0,33792,27648,48128,46080,60416,51200,63488,64512,45056,27648,37888,48128,57344,34816,46080,50176,37888,51200,25600,33792,39936,32768,28672,30720
router-signature
-----BEGIN SIGNATURE-----
K5FSywk7qvw/boA4DQcqkls6Ize5vcBYfhQ8JnOeRQC9+uDxbnpm3qaYN9jZ8myj
k0d2aofcVbHr4fPQOSST0LXDrhFl5Fqo5um296zpJGvRUeO6S44U/EfJAGShtqWw
7LZqklu+gVvhMKREpchVqlAwXkWR44VENm24Hs+mT3M=
-----END SIGNATURE-----
"#;

    const BRIDGE_EXTRA_INFO: &str = r#"@type bridge-extra-info 1.0
extra-info ec2bridgereaac65a3 1EC248422B57D9C0BD751892FE787585407479A4
published 2012-06-08 02:21:27
write-history 2012-06-08 02:10:38 (900 s) 343040,991232,5649408
read-history 2012-06-08 02:10:38 (900 s) 337920,437248,3995648
geoip-db-digest A27BE984989AB31C50D0861C7106B17A7EEC3756
dirreq-stats-end 2012-06-07 06:33:46 (86400 s)
dirreq-v3-ips 
dirreq-v3-reqs 
dirreq-v3-resp ok=72,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
dirreq-v3-direct-dl complete=0,timeout=0,running=0
dirreq-v3-tunneled-dl complete=68,timeout=4,running=0,min=2626,d1=7795,d2=14369,q1=18695,d3=29117,d4=52562,md=70626,d6=102271,d7=164175,q3=181522,d8=271682,d9=563791,max=32136142
bridge-stats-end 2012-06-07 06:33:53 (86400 s)
bridge-ips cn=16,ir=16,sy=16,us=16
router-digest 00A2AECCEAD3FEE033CFE29893387143146728EC
"#;

    const ED25519_EXTRA_INFO: &str = r#"@type extra-info 1.0
extra-info silverfoxden 4970B1DC3DBC8D82D7F1E43FF44B28DBF4765A4E
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABhz0AQFcf5tGWLvPvr1sktoezBB95j6tAWSECa3Eo2ZuBtRNAQAgBABFAwSN
GcRlGIte4I1giLvQSTcXefT93rvx2PZ8wEDewxWdy6tzcLouPfE3Beu/eUyg8ntt
YuVlzi50WXzGlGnPmeounGLo0EDHTGzcLucFWpe0g/0ia6UDqgQiAySMBwI=
-----END ED25519 CERT-----
published 2015-08-22 19:21:12
write-history 2015-08-22 19:20:44 (14400 s) 14409728,23076864,7756800,6234112,7446528,12290048
read-history 2015-08-22 19:20:44 (14400 s) 20449280,23888896,9099264,7185408,8880128,13230080
geoip-db-digest 6882B8663F74C23E26E3C2274C24CAB2E82D67A2
geoip6-db-digest F063BD5247EB9829E6B9E586393D7036656DAF44
dirreq-stats-end 2015-08-22 11:58:30 (86400 s)
dirreq-v3-ips 
dirreq-v3-reqs 
dirreq-v3-resp ok=0,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
dirreq-v3-direct-dl complete=0,timeout=0,running=0
dirreq-v3-tunneled-dl complete=0,timeout=0,running=0
router-sig-ed25519 g6Zg7Er8K7C1etmt7p20INE1ExIvMRPvhwt6sjbLqEK+EtQq8hT+86hQ1xu7cnz6bHee+Zhhmcc4JamV4eiMAw
router-signature
-----BEGIN SIGNATURE-----
R7kNaIWZrg3n3FWFBRMlEK2cbnha7gUIs8ToksLe+SF0dgoZiLyV3GKrnzdE/K6D
qdiOMN7eK04MOZVlgxkA5ayi61FTYVveK1HrDbJ+sEUwsviVGdif6kk/9DXOiyIJ
7wP/tofgHj/aCbFZb1PGU0zrEVLa72hVJ6cCW8w/t1s=
-----END SIGNATURE-----
"#;

    #[test]
    fn test_parse_relay_extra_info() {
        let desc = ExtraInfoDescriptor::parse(RELAY_EXTRA_INFO).unwrap();

        assert_eq!(desc.nickname, "NINJA");
        assert_eq!(desc.fingerprint, "B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48");
        assert_eq!(
            desc.published.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2012-05-05 17:03:50"
        );
        assert!(!desc.is_bridge());

        let write_history = desc.write_history.as_ref().unwrap();
        assert_eq!(write_history.interval, 900);
        assert_eq!(write_history.values.len(), 28);
        assert_eq!(write_history.values[0], 1082368);

        let read_history = desc.read_history.as_ref().unwrap();
        assert_eq!(read_history.interval, 900);
        assert_eq!(read_history.values.len(), 28);
        assert_eq!(read_history.values[0], 3309568);

        assert!(desc.signature.is_some());
    }

    #[test]
    fn test_parse_bridge_extra_info() {
        let desc = ExtraInfoDescriptor::parse(BRIDGE_EXTRA_INFO).unwrap();

        assert_eq!(desc.nickname, "ec2bridgereaac65a3");
        assert_eq!(desc.fingerprint, "1EC248422B57D9C0BD751892FE787585407479A4");
        assert!(desc.is_bridge());
        assert_eq!(
            desc.router_digest,
            Some("00A2AECCEAD3FEE033CFE29893387143146728EC".to_string())
        );

        assert_eq!(
            desc.geoip_db_digest,
            Some("A27BE984989AB31C50D0861C7106B17A7EEC3756".to_string())
        );

        assert_eq!(desc.dir_stats_interval, Some(86400));
        assert_eq!(desc.dir_v3_responses.get(&DirResponse::Ok), Some(&72));
        assert_eq!(
            desc.dir_v3_responses.get(&DirResponse::NotEnoughSigs),
            Some(&0)
        );

        assert_eq!(desc.dir_v3_direct_dl.get(&DirStat::Complete), Some(&0));
        assert_eq!(desc.dir_v3_tunneled_dl.get(&DirStat::Complete), Some(&68));
        assert_eq!(desc.dir_v3_tunneled_dl.get(&DirStat::Timeout), Some(&4));

        assert_eq!(desc.bridge_stats_interval, Some(86400));
        assert_eq!(desc.bridge_ips.get("cn"), Some(&16));
        assert_eq!(desc.bridge_ips.get("us"), Some(&16));
    }

    #[test]
    fn test_parse_ed25519_extra_info() {
        let desc = ExtraInfoDescriptor::parse(ED25519_EXTRA_INFO).unwrap();

        assert_eq!(desc.nickname, "silverfoxden");
        assert_eq!(desc.fingerprint, "4970B1DC3DBC8D82D7F1E43FF44B28DBF4765A4E");
        assert!(!desc.is_bridge());

        assert!(desc.ed25519_certificate.is_some());
        assert!(desc
            .ed25519_certificate
            .as_ref()
            .unwrap()
            .contains("ED25519 CERT"));

        assert!(desc.ed25519_signature.is_some());
        assert!(desc
            .ed25519_signature
            .as_ref()
            .unwrap()
            .starts_with("g6Zg7Er8K7C1"));

        assert_eq!(
            desc.geoip_db_digest,
            Some("6882B8663F74C23E26E3C2274C24CAB2E82D67A2".to_string())
        );
        assert_eq!(
            desc.geoip6_db_digest,
            Some("F063BD5247EB9829E6B9E586393D7036656DAF44".to_string())
        );

        let write_history = desc.write_history.as_ref().unwrap();
        assert_eq!(write_history.interval, 14400);
        assert_eq!(write_history.values.len(), 6);
    }

    #[test]
    fn test_dir_response_parsing() {
        assert_eq!(DirResponse::from_str("ok").unwrap(), DirResponse::Ok);
        assert_eq!(
            DirResponse::from_str("not-enough-sigs").unwrap(),
            DirResponse::NotEnoughSigs
        );
        assert_eq!(
            DirResponse::from_str("unavailable").unwrap(),
            DirResponse::Unavailable
        );
        assert_eq!(
            DirResponse::from_str("not-found").unwrap(),
            DirResponse::NotFound
        );
        assert_eq!(
            DirResponse::from_str("not-modified").unwrap(),
            DirResponse::NotModified
        );
        assert_eq!(DirResponse::from_str("busy").unwrap(), DirResponse::Busy);
    }

    #[test]
    fn test_dir_stat_parsing() {
        assert_eq!(DirStat::from_str("complete").unwrap(), DirStat::Complete);
        assert_eq!(DirStat::from_str("timeout").unwrap(), DirStat::Timeout);
        assert_eq!(DirStat::from_str("running").unwrap(), DirStat::Running);
        assert_eq!(DirStat::from_str("min").unwrap(), DirStat::Min);
        assert_eq!(DirStat::from_str("max").unwrap(), DirStat::Max);
        assert_eq!(DirStat::from_str("d1").unwrap(), DirStat::D1);
        assert_eq!(DirStat::from_str("q1").unwrap(), DirStat::Q1);
        assert_eq!(DirStat::from_str("md").unwrap(), DirStat::Md);
    }

    #[test]
    fn test_history_parsing() {
        let history = ExtraInfoDescriptor::parse_history_line(
            "2012-05-05 17:02:45 (900 s) 1082368,19456,50176",
        )
        .unwrap();

        assert_eq!(history.interval, 900);
        assert_eq!(history.values, vec![1082368, 19456, 50176]);
    }

    #[test]
    fn test_geoip_to_count_parsing() {
        let result = ExtraInfoDescriptor::parse_geoip_to_count("cn=16,ir=16,us=8");
        assert_eq!(result.get("cn"), Some(&16));
        assert_eq!(result.get("ir"), Some(&16));
        assert_eq!(result.get("us"), Some(&8));
    }

    #[test]
    fn test_port_count_parsing() {
        let result = ExtraInfoDescriptor::parse_port_count("80=1000,443=2000,other=500");
        assert_eq!(result.get(&PortKey::Port(80)), Some(&1000));
        assert_eq!(result.get(&PortKey::Port(443)), Some(&2000));
        assert_eq!(result.get(&PortKey::Other), Some(&500));
    }

    #[test]
    fn test_missing_extra_info_line() {
        let content = "published 2012-05-05 17:03:50\n";
        let result = ExtraInfoDescriptor::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_fingerprint() {
        let content = "extra-info NINJA INVALID\npublished 2012-05-05 17:03:50\n";
        let result = ExtraInfoDescriptor::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_conn_bi_direct() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
conn-bi-direct 2012-05-03 12:07:50 (500 s) 277431,12089,0,2134
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.conn_bi_direct_end.is_some());
        assert_eq!(desc.conn_bi_direct_interval, Some(500));
        assert_eq!(desc.conn_bi_direct_below, Some(277431));
        assert_eq!(desc.conn_bi_direct_read, Some(12089));
        assert_eq!(desc.conn_bi_direct_write, Some(0));
        assert_eq!(desc.conn_bi_direct_both, Some(2134));
    }

    #[test]
    fn test_cell_circuits_per_decile() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
cell-circuits-per-decile 25
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.cell_circuits_per_decile, Some(25));
    }

    #[test]
    fn test_hidden_service_stats() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
hidserv-stats-end 2012-05-03 12:07:50
hidserv-rend-relayed-cells 345 spiffy=true snowmen=neat
hidserv-dir-onions-seen 123
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.hs_stats_end.is_some());
        assert_eq!(desc.hs_rend_cells, Some(345));
        assert_eq!(
            desc.hs_rend_cells_attr.get("spiffy"),
            Some(&"true".to_string())
        );
        assert_eq!(
            desc.hs_rend_cells_attr.get("snowmen"),
            Some(&"neat".to_string())
        );
        assert_eq!(desc.hs_dir_onions_seen, Some(123));
    }

    #[test]
    fn test_padding_counts() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
padding-counts 2017-05-17 11:02:58 (86400 s) bin-size=10000 write-drop=0 write-pad=10000
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.padding_counts_end.is_some());
        assert_eq!(desc.padding_counts_interval, Some(86400));
        assert_eq!(
            desc.padding_counts.get("bin-size"),
            Some(&"10000".to_string())
        );
        assert_eq!(
            desc.padding_counts.get("write-drop"),
            Some(&"0".to_string())
        );
        assert_eq!(
            desc.padding_counts.get("write-pad"),
            Some(&"10000".to_string())
        );
    }

    #[test]
    fn test_transport_line() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
transport obfs2 83.212.96.201:33570
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.transports.contains_key("obfs2"));
        let transport = desc.transports.get("obfs2").unwrap();
        assert_eq!(transport.address, Some("83.212.96.201".to_string()));
        assert_eq!(transport.port, Some(33570));
    }

    #[test]
    fn test_bridge_ip_versions() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
bridge-ip-versions v4=16,v6=40
router-digest 00A2AECCEAD3FEE033CFE29893387143146728EC
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.ip_versions.get("v4"), Some(&16));
        assert_eq!(desc.ip_versions.get("v6"), Some(&40));
    }

    #[test]
    fn test_bridge_ip_transports() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
bridge-ip-transports <OR>=16,<??>=40
router-digest 00A2AECCEAD3FEE033CFE29893387143146728EC
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.ip_transports.get("<OR>"), Some(&16));
        assert_eq!(desc.ip_transports.get("<??>"), Some(&40));
    }

    #[test]
    fn test_exit_stats() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
exit-stats-end 2012-05-03 12:07:50 (86400 s)
exit-kibibytes-written 80=115533759,443=1777,other=500
exit-kibibytes-read 80=100,443=200
exit-streams-opened 80=50,443=100
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.exit_stats_end.is_some());
        assert_eq!(desc.exit_stats_interval, Some(86400));
        assert_eq!(
            desc.exit_kibibytes_written.get(&PortKey::Port(80)),
            Some(&115533759)
        );
        assert_eq!(
            desc.exit_kibibytes_written.get(&PortKey::Port(443)),
            Some(&1777)
        );
        assert_eq!(desc.exit_kibibytes_written.get(&PortKey::Other), Some(&500));
        assert_eq!(desc.exit_kibibytes_read.get(&PortKey::Port(80)), Some(&100));
        assert_eq!(desc.exit_streams_opened.get(&PortKey::Port(80)), Some(&50));
    }

    #[test]
    fn test_entry_stats() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
entry-stats-end 2012-05-03 12:07:50 (86400 s)
entry-ips uk=5,de=3,jp=2
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.entry_stats_end.is_some());
        assert_eq!(desc.entry_stats_interval, Some(86400));
        assert_eq!(desc.entry_ips.get("uk"), Some(&5));
        assert_eq!(desc.entry_ips.get("de"), Some(&3));
        assert_eq!(desc.entry_ips.get("jp"), Some(&2));
    }

    #[test]
    fn test_cell_stats() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
cell-stats-end 2012-05-03 12:07:50 (86400 s)
cell-processed-cells 2.3,-4.6,8.9
cell-queued-cells 1.0,2.0,3.0
cell-time-in-queue 10.5,20.5,30.5
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.cell_stats_end.is_some());
        assert_eq!(desc.cell_stats_interval, Some(86400));
        assert_eq!(desc.cell_processed_cells, vec![2.3, -4.6, 8.9]);
        assert_eq!(desc.cell_queued_cells, vec![1.0, 2.0, 3.0]);
        assert_eq!(desc.cell_time_in_queue, vec![10.5, 20.5, 30.5]);
    }

    #[test]
    fn test_empty_history_values() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
write-history 2012-05-05 17:02:45 (900 s) 
read-history 2012-05-05 17:02:45 (900 s)
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.write_history.is_some());
        assert!(desc.read_history.is_some());
        assert_eq!(desc.write_history.as_ref().unwrap().values.len(), 0);
        assert_eq!(desc.read_history.as_ref().unwrap().values.len(), 0);
    }

    #[test]
    fn test_empty_geoip_counts() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
dirreq-stats-end 2012-05-03 12:07:50 (86400 s)
dirreq-v3-ips 
dirreq-v3-reqs 
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.dir_stats_end.is_some());
        assert_eq!(desc.dir_v3_ips.len(), 0);
        assert_eq!(desc.dir_v3_requests.len(), 0);
    }

    #[test]
    fn test_negative_bandwidth_values() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
write-history 2012-05-05 17:02:45 (900 s) -100,200,-300,400
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        let history = desc.write_history.as_ref().unwrap();
        assert_eq!(history.values, vec![-100, 200, -300, 400]);
    }

    #[test]
    fn test_large_bandwidth_values() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
write-history 2012-05-05 17:02:45 (900 s) 9223372036854775807,1000000000000
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        let history = desc.write_history.as_ref().unwrap();
        assert_eq!(history.values.len(), 2);
        assert_eq!(history.values[0], 9223372036854775807);
        assert_eq!(history.values[1], 1000000000000);
    }

    #[test]
    fn test_unrecognized_lines_captured() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
unknown-keyword some value here
another-unknown-line with data
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.unrecognized_lines.len(), 2);
        assert!(desc
            .unrecognized_lines
            .contains(&"unknown-keyword some value here".to_string()));
        assert!(desc
            .unrecognized_lines
            .contains(&"another-unknown-line with data".to_string()));
    }

    #[test]
    fn test_round_trip_serialization() {
        let desc = ExtraInfoDescriptor::parse(RELAY_EXTRA_INFO).unwrap();
        let serialized = desc.to_descriptor_string();
        let reparsed = ExtraInfoDescriptor::parse(&serialized).unwrap();

        assert_eq!(desc.nickname, reparsed.nickname);
        assert_eq!(desc.fingerprint, reparsed.fingerprint);
        assert_eq!(
            desc.published.format("%Y-%m-%d %H:%M:%S").to_string(),
            reparsed.published.format("%Y-%m-%d %H:%M:%S").to_string()
        );

        if let (Some(ref orig), Some(ref new)) = (&desc.write_history, &reparsed.write_history) {
            assert_eq!(orig.interval, new.interval);
            assert_eq!(orig.values, new.values);
        }

        if let (Some(ref orig), Some(ref new)) = (&desc.read_history, &reparsed.read_history) {
            assert_eq!(orig.interval, new.interval);
            assert_eq!(orig.values, new.values);
        }
    }

    #[test]
    fn test_transport_with_ipv6_address() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
transport obfs4 [2001:db8::1]:9001 cert=abc123
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.transports.contains_key("obfs4"));
        let transport = desc.transports.get("obfs4").unwrap();
        assert_eq!(transport.address, Some("2001:db8::1".to_string()));
        assert_eq!(transport.port, Some(9001));
        assert_eq!(transport.args, vec!["cert=abc123".to_string()]);
    }

    #[test]
    fn test_transport_without_address() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
transport snowflake
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert!(desc.transports.contains_key("snowflake"));
        let transport = desc.transports.get("snowflake").unwrap();
        assert_eq!(transport.address, None);
        assert_eq!(transport.port, None);
        assert_eq!(transport.args.len(), 0);
    }

    #[test]
    fn test_multiple_transports() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
transport obfs2 192.168.1.1:9001
transport obfs3 192.168.1.1:9002
transport obfs4 192.168.1.1:9003 cert=xyz
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.transports.len(), 3);
        assert!(desc.transports.contains_key("obfs2"));
        assert!(desc.transports.contains_key("obfs3"));
        assert!(desc.transports.contains_key("obfs4"));
    }

    #[test]
    fn test_dirreq_response_with_unknown_status() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
dirreq-stats-end 2012-05-03 12:07:50 (86400 s)
dirreq-v3-resp ok=100,unknown-status=50,busy=25
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.dir_v3_responses.get(&DirResponse::Ok), Some(&100));
        assert_eq!(desc.dir_v3_responses.get(&DirResponse::Busy), Some(&25));
        assert_eq!(
            desc.dir_v3_responses_unknown.get("unknown-status"),
            Some(&50)
        );
    }

    #[test]
    fn test_dirreq_dl_with_unknown_stat() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
dirreq-stats-end 2012-05-03 12:07:50 (86400 s)
dirreq-v3-direct-dl complete=100,unknown-stat=50,timeout=25
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.dir_v3_direct_dl.get(&DirStat::Complete), Some(&100));
        assert_eq!(desc.dir_v3_direct_dl.get(&DirStat::Timeout), Some(&25));
        assert_eq!(desc.dir_v3_direct_dl_unknown.get("unknown-stat"), Some(&50));
    }

    #[test]
    fn test_hidden_service_stats_without_attributes() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
hidserv-stats-end 2012-05-03 12:07:50
hidserv-rend-relayed-cells 12345
hidserv-dir-onions-seen 678
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.hs_rend_cells, Some(12345));
        assert_eq!(desc.hs_rend_cells_attr.len(), 0);
        assert_eq!(desc.hs_dir_onions_seen, Some(678));
        assert_eq!(desc.hs_dir_onions_seen_attr.len(), 0);
    }

    #[test]
    fn test_padding_counts_multiple_attributes() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
padding-counts 2017-05-17 11:02:58 (86400 s) bin-size=10000 write-drop=0 write-pad=10000 write-total=20000 read-drop=5 read-pad=15000 read-total=25000
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.padding_counts.len(), 7);
        assert_eq!(
            desc.padding_counts.get("bin-size"),
            Some(&"10000".to_string())
        );
        assert_eq!(
            desc.padding_counts.get("write-total"),
            Some(&"20000".to_string())
        );
        assert_eq!(
            desc.padding_counts.get("read-total"),
            Some(&"25000".to_string())
        );
    }

    #[test]
    fn test_minimal_valid_descriptor() {
        let content = r#"extra-info minimal B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.nickname, "minimal");
        assert_eq!(desc.fingerprint, "B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48");
        assert!(!desc.is_bridge());
        assert_eq!(desc.transports.len(), 0);
        assert_eq!(desc.unrecognized_lines.len(), 0);
    }

    #[test]
    fn test_type_annotation_ignored() {
        let content = r#"@type extra-info 1.0
@type bridge-extra-info 1.1
extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.nickname, "test");
        assert_eq!(desc.unrecognized_lines.len(), 0);
    }

    #[test]
    fn test_port_key_display() {
        assert_eq!(format!("{}", PortKey::Port(80)), "80");
        assert_eq!(format!("{}", PortKey::Port(443)), "443");
        assert_eq!(format!("{}", PortKey::Other), "other");
    }

    #[test]
    fn test_bandwidth_history_with_single_value() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
write-history 2012-05-05 17:02:45 (900 s) 1234567890
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        let history = desc.write_history.as_ref().unwrap();
        assert_eq!(history.values.len(), 1);
        assert_eq!(history.values[0], 1234567890);
    }

    #[test]
    fn test_conn_bi_direct_with_zeros() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
conn-bi-direct 2012-05-03 12:07:50 (500 s) 0,0,0,0
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.conn_bi_direct_below, Some(0));
        assert_eq!(desc.conn_bi_direct_read, Some(0));
        assert_eq!(desc.conn_bi_direct_write, Some(0));
        assert_eq!(desc.conn_bi_direct_both, Some(0));
    }

    #[test]
    fn test_exit_stats_with_only_other_port() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
exit-stats-end 2012-05-03 12:07:50 (86400 s)
exit-kibibytes-written other=1000000
exit-kibibytes-read other=500000
exit-streams-opened other=1000
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(
            desc.exit_kibibytes_written.get(&PortKey::Other),
            Some(&1000000)
        );
        assert_eq!(desc.exit_kibibytes_read.get(&PortKey::Other), Some(&500000));
        assert_eq!(desc.exit_streams_opened.get(&PortKey::Other), Some(&1000));
        assert_eq!(desc.exit_kibibytes_written.len(), 1);
    }

    #[test]
    fn test_geoip_with_special_country_codes() {
        let content = r#"extra-info test B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48
published 2012-05-05 17:03:50
bridge-stats-end 2012-05-03 12:07:50 (86400 s)
bridge-ips ??=100,a1=50,zz=25
router-digest 00A2AECCEAD3FEE033CFE29893387143146728EC
"#;
        let desc = ExtraInfoDescriptor::parse(content).unwrap();
        assert_eq!(desc.bridge_ips.get("??"), Some(&100));
        assert_eq!(desc.bridge_ips.get("a1"), Some(&50));
        assert_eq!(desc.bridge_ips.get("zz"), Some(&25));
    }
}
