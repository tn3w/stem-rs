//! Bandwidth Authority metrics file parsing.
//!
//! This module parses bandwidth files as described in Tor's
//! [bandwidth-file-spec](https://spec.torproject.org/bandwidth-file-spec).
//! These files contain relay bandwidth measurements collected by bandwidth
//! authorities and are used to inform the consensus about relay capacities.
//!
//! # Overview
//!
//! Bandwidth files are produced by bandwidth scanners (like sbws) that measure
//! the actual throughput of relays in the Tor network. Directory authorities
//! use these measurements to assign bandwidth weights in the consensus, which
//! affects how much traffic each relay receives.
//!
//! # File Format Versions
//!
//! The module supports multiple format versions:
//!
//! | Version | Features |
//! |---------|----------|
//! | 1.0.0 | Basic format with timestamp and measurements only |
//! | 1.1.0 | Added header section with metadata |
//! | 1.2.0 | Added relay eligibility statistics |
//! | 1.3.0 | Added scanner location information |
//! | 1.4.0 | Added detailed measurement statistics |
//!
//! # File Structure
//!
//! ```text
//! <unix_timestamp>
//! version=1.4.0
//! software=sbws
//! ... other headers ...
//! =====
//! bw=1000 node_id=$FINGERPRINT nick=RelayName ...
//! bw=2000 node_id=$FINGERPRINT nick=AnotherRelay ...
//! ```
//!
//! # Example
//!
//! ```rust
//! use stem_rs::descriptor::bandwidth_file::BandwidthFile;
//!
//! let content = r#"1547487689
//! node_id=$221C91D4C51E4C73CB6A8F0BEE01B0A6BB4A8476 bw=38000 nick=myrelay"#;
//!
//! let bw_file = BandwidthFile::parse(content)?;
//! assert_eq!(bw_file.version, "1.0.0");
//! assert_eq!(bw_file.measurements.len(), 1);
//! # Ok::<(), stem_rs::Error>(())
//! ```
//!
//! # See Also
//!
//! - [Bandwidth File Specification](https://spec.torproject.org/bandwidth-file-spec)
//! - Python Stem's [`stem.descriptor.bandwidth_file`](https://stem.torproject.org/api/descriptor/bandwidth_file.html)

use crate::Error;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::collections::HashMap;

/// Header divider separating metadata from measurements (5 equals signs).
const HEADER_DIV: &str = "=====";
/// Alternate header divider for backward compatibility (4 equals signs).
const HEADER_DIV_ALT: &str = "====";

/// Statistical information collected over the recent data period.
///
/// This struct contains aggregate statistics about bandwidth measurements
/// collected over the scanner's data period (typically five days).
///
/// # Version Support
///
/// These fields were introduced in bandwidth file version 1.4.0.
#[derive(Debug, Clone, Default)]
pub struct RecentStats {
    /// Number of consensuses published during the data period.
    pub consensus_count: Option<u32>,
    /// Number of relays prioritized to be measured.
    pub prioritized_relays: Option<u32>,
    /// Number of times a set of relays were prioritized for measurement.
    pub prioritized_relay_lists: Option<u32>,
    /// Total number of relay measurement attempts.
    pub measurement_attempts: Option<u32>,
    /// Number of measurement attempts that failed.
    pub measurement_failures: Option<u32>,
    /// Breakdown of relay measurement failures by reason.
    pub relay_failures: RelayFailures,
}

/// Summary of relay measurement failures by category.
///
/// This struct breaks down the reasons why relays could not be
/// successfully measured during the data period.
#[derive(Debug, Clone, Default)]
pub struct RelayFailures {
    /// Relays with no successful measurements at all.
    pub no_measurement: Option<u32>,
    /// Relays whose measurements were collected over too short a period.
    pub insufficient_period: Option<u32>,
    /// Relays with too few measurements (typically less than 2).
    pub insufficient_measurements: Option<u32>,
    /// Relays whose latest measurement is too old (typically over 5 days).
    pub stale: Option<u32>,
}

/// Bandwidth measurement data for a single relay.
///
/// Each relay in the bandwidth file has an associated measurement entry
/// containing the measured bandwidth and various metadata about the
/// measurement process.
///
/// # Required Fields
///
/// - `node_id`: The relay's fingerprint (required)
/// - `bandwidth`: The measured bandwidth value (required)
///
/// # Optional Fields
///
/// All other fields are optional and may not be present depending on
/// the bandwidth file version and scanner configuration.
#[derive(Debug, Clone, Default)]
pub struct BandwidthMeasurement {
    /// The relay's fingerprint (40 hex characters, without `$` prefix).
    pub node_id: String,
    /// The measured bandwidth in bytes per second.
    pub bandwidth: u64,
    /// The relay's nickname.
    pub nick: Option<String>,
    /// The relay's Ed25519 master key (base64 encoded).
    pub master_key_ed25519: Option<String>,
    /// When this measurement was taken.
    pub measured_at: Option<DateTime<Utc>>,
    /// When this measurement was last updated.
    pub updated_at: Option<DateTime<Utc>>,
    /// Mean of bandwidth measurements.
    pub bw_mean: Option<u64>,
    /// Median of bandwidth measurements.
    pub bw_median: Option<u64>,
    /// Average bandwidth from the relay's descriptor.
    pub desc_bw_avg: Option<u64>,
    /// Last observed bandwidth from the relay's descriptor.
    pub desc_bw_obs_last: Option<u64>,
    /// Mean observed bandwidth from the relay's descriptor.
    pub desc_bw_obs_mean: Option<u64>,
    /// Burst bandwidth from the relay's descriptor.
    pub desc_bw_bur: Option<u64>,
    /// Bandwidth value from the consensus.
    pub consensus_bandwidth: Option<u64>,
    /// Whether the consensus bandwidth was unmeasured.
    pub consensus_bandwidth_is_unmeasured: Option<bool>,
    /// Number of successful measurements.
    pub success: Option<u32>,
    /// Number of circuit-related errors.
    pub error_circ: Option<u32>,
    /// Number of stream-related errors.
    pub error_stream: Option<u32>,
    /// Number of miscellaneous errors.
    pub error_misc: Option<u32>,
    /// Number of destination-related errors.
    pub error_destination: Option<u32>,
    /// Number of second relay errors.
    pub error_second_relay: Option<u32>,
    /// Number of consensuses this relay appeared in recently.
    pub relay_in_recent_consensus_count: Option<u32>,
    /// Number of recent measurement attempts for this relay.
    pub relay_recent_measurement_attempt_count: Option<u32>,
    /// Number of recent measurements excluded due to errors.
    pub relay_recent_measurements_excluded_error_count: Option<u32>,
    /// Number of times this relay was in the priority list.
    pub relay_recent_priority_list_count: Option<u32>,
    /// Additional key-value pairs not explicitly parsed.
    pub extra: HashMap<String, String>,
}

/// Tor bandwidth authority measurements file.
///
/// Bandwidth files contain relay bandwidth measurements collected by bandwidth
/// scanners (like sbws) that measure the actual throughput of relays in the
/// Tor network. Directory authorities use these measurements to assign
/// bandwidth weights in the consensus, which affects how much traffic each
/// relay receives.
///
/// # File Format Versions
///
/// The bandwidth file format has evolved over time:
///
/// | Version | Features |
/// |---------|----------|
/// | 1.0.0 | Basic format with timestamp and measurements only |
/// | 1.1.0 | Added header section with metadata |
/// | 1.2.0 | Added relay eligibility statistics |
/// | 1.3.0 | Added scanner location information |
/// | 1.4.0 | Added detailed measurement statistics |
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::bandwidth_file::BandwidthFile;
///
/// let content = r#"1547487689
/// node_id=$221C91D4C51E4C73CB6A8F0BEE01B0A6BB4A8476 bw=38000 nick=myrelay"#;
///
/// let bw_file = BandwidthFile::parse(content)?;
/// assert_eq!(bw_file.version, "1.0.0");
/// assert_eq!(bw_file.measurements.len(), 1);
/// # Ok::<(), stem_rs::Error>(())
/// ```
///
/// # See Also
///
/// - [Bandwidth File Specification](https://spec.torproject.org/bandwidth-file-spec)
/// - Python Stem's [`stem.descriptor.bandwidth_file`](https://stem.torproject.org/api/descriptor/bandwidth_file.html)
#[derive(Debug, Clone)]
pub struct BandwidthFile {
    /// Unix timestamp when these metrics were published.
    pub timestamp: DateTime<Utc>,
    /// Document format version (e.g., "1.0.0", "1.4.0").
    ///
    /// Defaults to "1.0.0" if no version header is present.
    pub version: String,
    /// Raw header key-value pairs from the file.
    ///
    /// Contains all header fields, including those parsed into dedicated fields.
    pub header: HashMap<String, String>,
    /// Mapping of relay fingerprints to their bandwidth measurements.
    ///
    /// Keys are 40-character hex fingerprints (without the `$` prefix).
    pub measurements: HashMap<String, BandwidthMeasurement>,
    /// Application that generated these metrics (e.g., "sbws").
    pub software: Option<String>,
    /// Version of the application that generated these metrics.
    pub software_version: Option<String>,
    /// Time of the first bandwidth sampling in this file.
    pub earliest_bandwidth: Option<DateTime<Utc>>,
    /// Time of the last bandwidth sampling in this file.
    pub latest_bandwidth: Option<DateTime<Utc>>,
    /// Time when this file was created.
    pub created_at: Option<DateTime<Utc>>,
    /// Time when collection of these metrics started.
    pub generated_at: Option<DateTime<Utc>>,
    /// Number of relays in the consensus at the time of measurement.
    pub consensus_size: Option<u32>,
    /// Number of relays with enough measurements to be included.
    pub eligible_count: Option<u32>,
    /// Percentage of consensus relays with enough measurements.
    pub eligible_percent: Option<u32>,
    /// Minimum number of eligible relays required for results to be provided.
    pub min_count: Option<u32>,
    /// Minimum measured percentage of the consensus required.
    pub min_percent: Option<u32>,
    /// Two-letter country code where the scanner is located.
    pub scanner_country: Option<String>,
    /// List of country codes for all destinations that were scanned.
    pub destinations_countries: Option<Vec<String>>,
    /// Tor version used by the scanner.
    pub tor_version: Option<String>,
    /// Estimated seconds required to measure half the network.
    ///
    /// Based on recent measurement rates.
    pub time_to_report_half_network: Option<u32>,
    /// Statistical information collected over the recent data period.
    ///
    /// Typically covers the last five days of measurements.
    pub recent_stats: RecentStats,
    raw_content: Vec<u8>,
    unrecognized_lines: Vec<String>,
}

impl BandwidthFile {
    /// Parses a bandwidth file from its string content.
    ///
    /// # Format
    ///
    /// The file format consists of:
    /// 1. A Unix timestamp on the first line
    /// 2. Optional header key-value pairs (version 1.1.0+)
    /// 3. A divider line (`=====` or `====`)
    /// 4. Measurement lines with relay bandwidth data
    ///
    /// # Arguments
    ///
    /// * `content` - The raw bandwidth file content as a string
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The file is empty
    /// - The first line is not a valid Unix timestamp
    /// - The `version` header is not in the second position (if present)
    /// - A relay fingerprint appears multiple times
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::bandwidth_file::BandwidthFile;
    ///
    /// // Version 1.0.0 format (no headers)
    /// let v1_content = "1547487689\nnode_id=$ABC123 bw=1000";
    /// let bw = BandwidthFile::parse(v1_content)?;
    /// assert_eq!(bw.version, "1.0.0");
    ///
    /// // Version 1.2.0+ format (with headers)
    /// let v1_2_content = r#"1547487689
    /// version=1.2.0
    /// software=sbws
    /// =====
    /// node_id=$ABC123 bw=1000"#;
    /// let bw = BandwidthFile::parse(v1_2_content)?;
    /// assert_eq!(bw.version, "1.2.0");
    /// # Ok::<(), stem_rs::Error>(())
    /// ```
    pub fn parse(content: &str) -> Result<Self, Error> {
        let raw_content = content.as_bytes().to_vec();
        let mut lines = content.lines();

        let first_line = lines.next().ok_or_else(|| Error::Parse {
            location: "bandwidth_file".into(),
            reason: "Empty file".into(),
        })?;

        let timestamp = parse_unix_timestamp(first_line)?;
        let mut header = HashMap::new();
        let mut version = "1.0.0".to_string();
        let mut version_index = None;
        let mut index = 0;
        let mut body_lines = Vec::new();
        let mut in_body = false;

        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if in_body {
                body_lines.push(line);
                continue;
            }

            if line == HEADER_DIV || line == HEADER_DIV_ALT {
                in_body = true;
                continue;
            }

            if header.is_empty() && line.contains("node_id=") {
                body_lines.push(line);
                in_body = true;
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                header.insert(key.to_string(), value.to_string());
                if key == "version" {
                    version = value.to_string();
                    version_index = Some(index);
                }
                index += 1;
            }
        }

        if let Some(vi) = version_index {
            if vi != 0 {
                return Err(Error::Parse {
                    location: "bandwidth_file".into(),
                    reason: "The 'version' header must be in the second position".into(),
                });
            }
        }

        let software = header.get("software").cloned();
        let software_version = header.get("software_version").cloned();
        let earliest_bandwidth = header
            .get("earliest_bandwidth")
            .and_then(|s| parse_iso_date(s));
        let latest_bandwidth = header
            .get("latest_bandwidth")
            .and_then(|s| parse_iso_date(s));
        let created_at = header.get("file_created").and_then(|s| parse_iso_date(s));
        let generated_at = header
            .get("generator_started")
            .and_then(|s| parse_iso_date(s));
        let consensus_size = header
            .get("number_consensus_relays")
            .and_then(|s| s.parse().ok());
        let eligible_count = header
            .get("number_eligible_relays")
            .and_then(|s| s.parse().ok());
        let eligible_percent = header
            .get("percent_eligible_relays")
            .and_then(|s| s.parse().ok());
        let min_count = header
            .get("minimum_number_eligible_relays")
            .and_then(|s| s.parse().ok());
        let min_percent = header
            .get("minimum_percent_eligible_relays")
            .and_then(|s| s.parse().ok());
        let scanner_country = header.get("scanner_country").cloned();
        let destinations_countries = header
            .get("destinations_countries")
            .map(|s| s.split(',').map(|c| c.trim().to_string()).collect());
        let tor_version = header.get("tor_version").cloned();
        let time_to_report_half_network = header
            .get("time_to_report_half_network")
            .and_then(|s| s.parse().ok());

        let recent_stats = RecentStats {
            consensus_count: header
                .get("recent_consensus_count")
                .and_then(|s| s.parse().ok()),
            prioritized_relay_lists: header
                .get("recent_priority_list_count")
                .and_then(|s| s.parse().ok()),
            prioritized_relays: header
                .get("recent_priority_relay_count")
                .and_then(|s| s.parse().ok()),
            measurement_attempts: header
                .get("recent_measurement_attempt_count")
                .and_then(|s| s.parse().ok()),
            measurement_failures: header
                .get("recent_measurement_failure_count")
                .and_then(|s| s.parse().ok()),
            relay_failures: RelayFailures {
                no_measurement: header
                    .get("recent_measurements_excluded_error_count")
                    .and_then(|s| s.parse().ok()),
                insufficient_period: header
                    .get("recent_measurements_excluded_near_count")
                    .and_then(|s| s.parse().ok()),
                insufficient_measurements: header
                    .get("recent_measurements_excluded_few_count")
                    .and_then(|s| s.parse().ok()),
                stale: header
                    .get("recent_measurements_excluded_old_count")
                    .and_then(|s| s.parse().ok()),
            },
        };

        let mut measurements = HashMap::new();
        let mut unrecognized_lines = Vec::new();

        for line in body_lines {
            match parse_measurement_line(line) {
                Ok(measurement) => {
                    if measurements.contains_key(&measurement.node_id) {
                        return Err(Error::Parse {
                            location: "bandwidth_file".into(),
                            reason: format!(
                                "Relay {} is listed multiple times",
                                measurement.node_id
                            ),
                        });
                    }
                    measurements.insert(measurement.node_id.clone(), measurement);
                }
                Err(_) => {
                    unrecognized_lines.push(line.to_string());
                }
            }
        }

        Ok(Self {
            timestamp,
            version,
            header,
            measurements,
            software,
            software_version,
            earliest_bandwidth,
            latest_bandwidth,
            created_at,
            generated_at,
            consensus_size,
            eligible_count,
            eligible_percent,
            min_count,
            min_percent,
            scanner_country,
            destinations_countries,
            tor_version,
            time_to_report_half_network,
            recent_stats,
            raw_content,
            unrecognized_lines,
        })
    }

    /// Returns the raw bytes of the original bandwidth file content.
    ///
    /// This preserves the exact content as it was parsed, which can be
    /// useful for signature verification or debugging.
    pub fn raw_content(&self) -> &[u8] {
        &self.raw_content
    }

    /// Returns lines from the measurement body that could not be parsed.
    ///
    /// Lines are considered unrecognized if they don't contain a valid
    /// `node_id` field. This can happen with malformed entries or
    /// future format extensions.
    pub fn unrecognized_lines(&self) -> &[String] {
        &self.unrecognized_lines
    }

    /// Serializes the bandwidth file back to its string representation.
    ///
    /// The output format depends on the version:
    /// - Version 1.0.0: Just timestamp and measurements
    /// - Version 1.1.0+: Includes header section with divider
    ///
    /// # Note
    ///
    /// The output may not be byte-for-byte identical to the original
    /// input due to field ordering and formatting differences.
    pub fn to_descriptor_string(&self) -> String {
        let mut lines = Vec::new();
        lines.push(self.timestamp.timestamp().to_string());

        if self.version != "1.0.0" {
            lines.push(format!("version={}", self.version));
            for (key, value) in &self.header {
                if key != "version" {
                    lines.push(format!("{}={}", key, value));
                }
            }
            lines.push(HEADER_DIV.to_string());
        }

        for measurement in self.measurements.values() {
            lines.push(measurement_to_string(measurement));
        }

        lines.join("\n")
    }
}

fn parse_unix_timestamp(s: &str) -> Result<DateTime<Utc>, Error> {
    let ts: i64 = s.trim().parse().map_err(|_| Error::Parse {
        location: "bandwidth_file".into(),
        reason: format!("First line should be a unix timestamp, but was '{}'", s),
    })?;
    DateTime::from_timestamp(ts, 0).ok_or_else(|| Error::Parse {
        location: "bandwidth_file".into(),
        reason: format!("Invalid unix timestamp: {}", ts),
    })
}

fn parse_iso_date(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .map(|dt| dt.and_utc())
}

fn parse_measurement_line(line: &str) -> Result<BandwidthMeasurement, Error> {
    let mut measurement = BandwidthMeasurement::default();
    let mut has_node_id = false;

    for part in line.split_whitespace() {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "node_id" => {
                    measurement.node_id = value.trim_start_matches('$').to_string();
                    has_node_id = true;
                }
                "bw" => measurement.bandwidth = value.parse().unwrap_or(0),
                "nick" => measurement.nick = Some(value.to_string()),
                "master_key_ed25519" => measurement.master_key_ed25519 = Some(value.to_string()),
                "measured_at" => {
                    measurement.measured_at = value
                        .parse::<i64>()
                        .ok()
                        .and_then(|ts| DateTime::from_timestamp(ts, 0))
                }
                "updated_at" => {
                    measurement.updated_at = value
                        .parse::<i64>()
                        .ok()
                        .and_then(|ts| DateTime::from_timestamp(ts, 0))
                }
                "time" => measurement.measured_at = parse_iso_date(value),
                "bw_mean" => measurement.bw_mean = value.parse().ok(),
                "bw_median" => measurement.bw_median = value.parse().ok(),
                "desc_bw_avg" => measurement.desc_bw_avg = value.parse().ok(),
                "desc_bw_obs_last" => measurement.desc_bw_obs_last = value.parse().ok(),
                "desc_bw_obs_mean" => measurement.desc_bw_obs_mean = value.parse().ok(),
                "desc_bw_bur" => measurement.desc_bw_bur = value.parse().ok(),
                "consensus_bandwidth" => measurement.consensus_bandwidth = value.parse().ok(),
                "consensus_bandwidth_is_unmeasured" => {
                    measurement.consensus_bandwidth_is_unmeasured = Some(value == "True")
                }
                "success" => measurement.success = value.parse().ok(),
                "error_circ" => measurement.error_circ = value.parse().ok(),
                "error_stream" => measurement.error_stream = value.parse().ok(),
                "error_misc" => measurement.error_misc = value.parse().ok(),
                "error_destination" => measurement.error_destination = value.parse().ok(),
                "error_second_relay" => measurement.error_second_relay = value.parse().ok(),
                "relay_in_recent_consensus_count" => {
                    measurement.relay_in_recent_consensus_count = value.parse().ok()
                }
                "relay_recent_measurement_attempt_count" => {
                    measurement.relay_recent_measurement_attempt_count = value.parse().ok()
                }
                "relay_recent_measurements_excluded_error_count" => {
                    measurement.relay_recent_measurements_excluded_error_count = value.parse().ok()
                }
                "relay_recent_priority_list_count" => {
                    measurement.relay_recent_priority_list_count = value.parse().ok()
                }
                _ => {
                    measurement.extra.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    if !has_node_id {
        return Err(Error::Parse {
            location: "bandwidth_file".into(),
            reason: "Every measurement must include 'node_id'".into(),
        });
    }

    Ok(measurement)
}

fn measurement_to_string(m: &BandwidthMeasurement) -> String {
    let mut parts = Vec::new();
    parts.push(format!("bw={}", m.bandwidth));
    if let Some(ref nick) = m.nick {
        parts.push(format!("nick={}", nick));
    }
    parts.push(format!("node_id=${}", m.node_id));
    if let Some(ref key) = m.master_key_ed25519 {
        parts.push(format!("master_key_ed25519={}", key));
    }
    if let Some(bw_mean) = m.bw_mean {
        parts.push(format!("bw_mean={}", bw_mean));
    }
    if let Some(bw_median) = m.bw_median {
        parts.push(format!("bw_median={}", bw_median));
    }
    if let Some(success) = m.success {
        parts.push(format!("success={}", success));
    }
    if let Some(dt) = m.measured_at {
        parts.push(format!("time={}", dt.format("%Y-%m-%dT%H:%M:%S")));
    }
    for (key, value) in &m.extra {
        parts.push(format!("{}={}", key, value));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v1_0() {
        let content = r#"1547487689
node_id=$221C91D4C51E4C73CB6A8F0BEE01B0A6BB4A8476 bw=38000 nick=digitalocean1 measured_at=1546325250
node_id=$1F509589F7F70B69A38719A201451CF4B70F89C6 bw=589 nick=CulNoir measured_at=1547441722"#;

        let bw = BandwidthFile::parse(content).unwrap();
        assert_eq!(bw.version, "1.0.0");
        assert_eq!(bw.measurements.len(), 2);
        assert!(bw
            .measurements
            .contains_key("221C91D4C51E4C73CB6A8F0BEE01B0A6BB4A8476"));
        let m = &bw.measurements["221C91D4C51E4C73CB6A8F0BEE01B0A6BB4A8476"];
        assert_eq!(m.bandwidth, 38000);
        assert_eq!(m.nick, Some("digitalocean1".to_string()));
    }

    #[test]
    fn test_parse_v1_2() {
        let content = r#"1547444099
version=1.2.0
earliest_bandwidth=2019-01-04T05:35:29
file_created=2019-01-14T05:35:06
software=sbws
software_version=1.0.2
=====
bw=1 bw_mean=191643 nick=mrkoolltor node_id=$92808CA58D8F32CA34A34C547610869BF4E2A6EC success=10"#;

        let bw = BandwidthFile::parse(content).unwrap();
        assert_eq!(bw.version, "1.2.0");
        assert_eq!(bw.software, Some("sbws".to_string()));
        assert_eq!(bw.software_version, Some("1.0.2".to_string()));
        assert!(bw.earliest_bandwidth.is_some());
        assert!(bw.created_at.is_some());
        assert_eq!(bw.measurements.len(), 1);
    }

    #[test]
    fn test_parse_v1_4() {
        let content = r#"1555882497
version=1.4.0
scanner_country=US
software=sbws
software_version=1.1.0
recent_consensus_count=34
recent_measurement_attempt_count=86417
time_to_report_half_network=223519
tor_version=0.3.5.10
=====
bw=1 bw_mean=21403 consensus_bandwidth=1000 nick=t7 node_id=$F63DF6AA4F395AD2F5F363333D104279F2171381"#;

        let bw = BandwidthFile::parse(content).unwrap();
        assert_eq!(bw.version, "1.4.0");
        assert_eq!(bw.scanner_country, Some("US".to_string()));
        assert_eq!(bw.tor_version, Some("0.3.5.10".to_string()));
        assert_eq!(bw.time_to_report_half_network, Some(223519));
        assert_eq!(bw.recent_stats.consensus_count, Some(34));
        assert_eq!(bw.recent_stats.measurement_attempts, Some(86417));
    }

    #[test]
    fn test_duplicate_relay_error() {
        let content = r#"1547487689
node_id=$221C91D4C51E4C73CB6A8F0BEE01B0A6BB4A8476 bw=38000
node_id=$221C91D4C51E4C73CB6A8F0BEE01B0A6BB4A8476 bw=39000"#;

        let result = BandwidthFile::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_node_id_in_body() {
        let content = r#"1547487689
node_id=$ABC bw=100
bw=38000 nick=test"#;

        let result = BandwidthFile::parse(content);
        assert!(result.is_ok());
        let bw = result.unwrap();
        assert_eq!(bw.measurements.len(), 1);
        assert_eq!(bw.unrecognized_lines.len(), 1);
    }

    #[test]
    fn test_invalid_timestamp_error() {
        let content = "not_a_timestamp\nnode_id=$ABC bw=100";
        let result = BandwidthFile::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_alternate_div() {
        let content = r#"1547444099
version=1.2.0
software=sbws
====
bw=1 nick=test node_id=$92808CA58D8F32CA34A34C547610869BF4E2A6EC"#;

        let bw = BandwidthFile::parse(content).unwrap();
        assert_eq!(bw.version, "1.2.0");
        assert_eq!(bw.software, Some("sbws".to_string()));
        assert_eq!(bw.measurements.len(), 1);
    }

    #[test]
    fn test_minimal_bandwidth_file() {
        let content = "1410723598";
        let bw = BandwidthFile::parse(content).unwrap();
        assert_eq!(bw.version, "1.0.0");
        assert!(bw.software.is_none());
        assert!(bw.software_version.is_none());
        assert!(bw.earliest_bandwidth.is_none());
        assert!(bw.latest_bandwidth.is_none());
        assert!(bw.created_at.is_none());
        assert!(bw.generated_at.is_none());
        assert!(bw.consensus_size.is_none());
        assert!(bw.eligible_count.is_none());
        assert!(bw.measurements.is_empty());
    }

    #[test]
    fn test_invalid_timestamp_variations() {
        let test_values = ["", "boo", "123.4"];
        for value in test_values {
            let result = BandwidthFile::parse(value);
            assert!(result.is_err(), "Expected error for timestamp: {}", value);
        }
    }

    #[test]
    fn test_measurement_all_fields() {
        let content = r#"1547487689
node_id=$221C91D4C51E4C73CB6A8F0BEE01B0A6BB4A8476 bw=38000 nick=digitalocean1 master_key_ed25519=abc123 bw_mean=40000 bw_median=39000 success=10 error_circ=1 error_stream=2"#;

        let bw = BandwidthFile::parse(content).unwrap();
        let m = &bw.measurements["221C91D4C51E4C73CB6A8F0BEE01B0A6BB4A8476"];
        assert_eq!(m.bandwidth, 38000);
        assert_eq!(m.nick, Some("digitalocean1".to_string()));
        assert_eq!(m.master_key_ed25519, Some("abc123".to_string()));
        assert_eq!(m.bw_mean, Some(40000));
        assert_eq!(m.bw_median, Some(39000));
        assert_eq!(m.success, Some(10));
        assert_eq!(m.error_circ, Some(1));
        assert_eq!(m.error_stream, Some(2));
    }

    #[test]
    fn test_v1_4_specific_fields() {
        let content = r#"1555882497
version=1.4.0
scanner_country=US
destinations_countries=ZZ,US,DE
time_to_report_half_network=223519
recent_consensus_count=34
recent_priority_list_count=260
recent_priority_relay_count=86417
recent_measurement_attempt_count=86417
recent_measurement_failure_count=57023
=====
bw=1 node_id=$F63DF6AA4F395AD2F5F363333D104279F2171381"#;

        let bw = BandwidthFile::parse(content).unwrap();
        assert_eq!(bw.scanner_country, Some("US".to_string()));
        assert_eq!(
            bw.destinations_countries,
            Some(vec!["ZZ".to_string(), "US".to_string(), "DE".to_string()])
        );
        assert_eq!(bw.time_to_report_half_network, Some(223519));
        assert_eq!(bw.recent_stats.consensus_count, Some(34));
        assert_eq!(bw.recent_stats.prioritized_relay_lists, Some(260));
        assert_eq!(bw.recent_stats.prioritized_relays, Some(86417));
        assert_eq!(bw.recent_stats.measurement_attempts, Some(86417));
        assert_eq!(bw.recent_stats.measurement_failures, Some(57023));
    }
}
