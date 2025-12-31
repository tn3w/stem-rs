//! Remote descriptor downloading from directory authorities and mirrors.
//!
//! This module provides functionality to download Tor descriptors from
//! directory authorities and fallback mirrors. It enables fetching various
//! types of network data including consensus documents, server descriptors,
//! microdescriptors, and key certificates.
//!
//! # Overview
//!
//! The Tor network publishes its state through a distributed directory system.
//! Directory authorities are trusted servers that vote on the network consensus,
//! while directory mirrors cache and serve this data to reduce load on authorities.
//!
//! This module provides:
//! - A list of known directory authorities
//! - Functions to download specific descriptor types
//! - Support for compression (gzip, zstd, lzma)
//! - Configurable timeouts and retry logic
//!
//! # Descriptor Types
//!
//! | Type | Function | Description |
//! |------|----------|-------------|
//! | Consensus | [`download_consensus()`] | Network status document |
//! | Server Descriptors | [`download_server_descriptors()`] | Full relay metadata |
//! | Extra-Info | [`download_extrainfo_descriptors()`] | Bandwidth statistics |
//! | Microdescriptors | [`download_microdescriptors()`] | Compact client descriptors |
//! | Key Certificates | [`download_key_certificates()`] | Authority signing keys |
//! | Bandwidth File | [`download_bandwidth_file()`] | Bandwidth measurements |
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::descriptor::remote::{download_consensus, DirPort};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! // Download the current consensus with a 30-second timeout
//! let result = download_consensus(
//!     false,  // full consensus, not microdescriptor
//!     None,   // use default authorities
//!     Some(Duration::from_secs(30)),
//! ).await?;
//!
//! println!("Downloaded {} bytes from {:?}", result.content.len(), result.source);
//! println!("Download took {:?}", result.runtime);
//! # Ok(())
//! # }
//! ```
//!
//! # Rate Limits
//!
//! The Tor directory protocol has limits on how many descriptors can be
//! requested at once:
//! - Maximum 96 fingerprints per request for server/extra-info descriptors
//! - Maximum 90 hashes per request for microdescriptors
//!
//! These limits exist due to URL length restrictions in proxy servers.
//!
//! # Compression
//!
//! Downloads support multiple compression formats to reduce bandwidth:
//! - **gzip**: Widely supported, good compression
//! - **zstd**: Better compression ratio, faster decompression
//! - **lzma**: Best compression, slower
//! - **identity**: No compression (plaintext)
//!
//! The server will use the best mutually supported format.
//!
//! # Error Handling
//!
//! Download functions try multiple endpoints and return the first successful
//! result. If all endpoints fail, the last error is returned.
//!
//! # See Also
//!
//! - [`consensus`](super::consensus): Parsing downloaded consensus documents
//! - [`server`](super::server): Parsing server descriptors
//! - [`micro`](super::micro): Parsing microdescriptors
//! - [`key_cert`](super::key_cert): Parsing key certificates

use crate::Error;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// User agent string sent with HTTP requests.
const USER_AGENT: &str = "stem-rs/0.1.0";

/// Maximum number of fingerprints that can be requested at once.
///
/// This limit exists due to URL length restrictions in proxy servers
/// that may sit between clients and directory servers.
const MAX_FINGERPRINTS: usize = 96;

/// Maximum number of microdescriptor hashes that can be requested at once.
///
/// Microdescriptor hashes are longer than fingerprints, so fewer can
/// fit in a single request URL.
const MAX_MICRODESCRIPTOR_HASHES: usize = 90;

/// Compression formats supported for descriptor downloads.
///
/// Directory servers can compress responses to reduce bandwidth usage.
/// Clients advertise which formats they support, and the server uses
/// the best mutually supported format.
///
/// # Compression Comparison
///
/// | Format | Compression | Speed | Support |
/// |--------|-------------|-------|---------|
/// | Plaintext | None | Fastest | Universal |
/// | Gzip | Good | Fast | Universal |
/// | Zstd | Better | Faster | Modern Tor |
/// | Lzma | Best | Slower | Modern Tor |
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::remote::Compression;
///
/// let formats = [Compression::Zstd, Compression::Gzip, Compression::Plaintext];
/// for fmt in &formats {
///     println!("Encoding: {}", fmt.encoding());
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression (identity encoding).
    ///
    /// Data is transferred as-is without any compression.
    /// Always supported but uses the most bandwidth.
    Plaintext,

    /// Gzip compression (RFC 1952).
    ///
    /// Good compression ratio with fast decompression.
    /// Universally supported by all Tor versions.
    Gzip,

    /// Zstandard compression.
    ///
    /// Better compression ratio than gzip with faster decompression.
    /// Supported by modern Tor versions (0.3.1+).
    Zstd,

    /// LZMA compression.
    ///
    /// Best compression ratio but slower decompression.
    /// Supported by modern Tor versions.
    Lzma,
}

impl Compression {
    /// Returns the HTTP Accept-Encoding value for this compression format.
    ///
    /// This is the string used in HTTP headers to indicate support
    /// for this compression format.
    ///
    /// # Returns
    ///
    /// The encoding name as used in HTTP headers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::remote::Compression;
    ///
    /// assert_eq!(Compression::Gzip.encoding(), "gzip");
    /// assert_eq!(Compression::Plaintext.encoding(), "identity");
    /// ```
    pub fn encoding(&self) -> &'static str {
        match self {
            Compression::Plaintext => "identity",
            Compression::Gzip => "gzip",
            Compression::Zstd => "zstd",
            Compression::Lzma => "x-tor-lzma",
        }
    }
}

/// A directory port endpoint for downloading descriptors.
///
/// Directory ports (DirPorts) are HTTP endpoints where Tor relays and
/// authorities serve directory information. This struct represents
/// the address and port of such an endpoint.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::remote::DirPort;
/// use std::net::IpAddr;
///
/// let addr: IpAddr = "128.31.0.39".parse().unwrap();
/// let dirport = DirPort::new(addr, 9131);
///
/// println!("Connecting to {}", dirport.socket_addr());
/// ```
#[derive(Debug, Clone)]
pub struct DirPort {
    /// IP address of the directory server.
    ///
    /// Can be either IPv4 or IPv6.
    pub address: IpAddr,

    /// Port number for the directory service.
    ///
    /// Common values are 80, 443, or 9030.
    pub port: u16,
}

impl DirPort {
    /// Creates a new directory port endpoint.
    ///
    /// # Arguments
    ///
    /// * `address` - IP address of the directory server
    /// * `port` - Port number for the directory service
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::descriptor::remote::DirPort;
    /// use std::net::IpAddr;
    ///
    /// let addr: IpAddr = "127.0.0.1".parse().unwrap();
    /// let dirport = DirPort::new(addr, 9030);
    /// ```
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self { address, port }
    }

    /// Returns the socket address for this endpoint.
    ///
    /// Combines the IP address and port into a `SocketAddr` suitable
    /// for use with network operations.
    ///
    /// # Returns
    ///
    /// A `SocketAddr` combining the address and port.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// Information about a Tor directory authority.
///
/// Directory authorities are trusted servers that vote on the network
/// consensus. They are hardcoded into Tor clients and are the root of
/// trust for the Tor network.
///
/// # Fields
///
/// Each authority has:
/// - A nickname for identification
/// - Network addresses (IP, DirPort, ORPort)
/// - A fingerprint (identity key hash)
/// - A v3ident (v3 authority identity) for consensus voting
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::remote::get_authorities;
///
/// for auth in get_authorities() {
///     println!("{}: {}:{}", auth.nickname, auth.address, auth.dir_port);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DirectoryAuthority {
    /// Human-readable name of the authority.
    ///
    /// Examples: "moria1", "tor26", "gabelmoo"
    pub nickname: String,

    /// IP address of the authority.
    pub address: IpAddr,

    /// Port for directory requests (HTTP).
    ///
    /// Used for downloading descriptors and consensus documents.
    pub dir_port: u16,

    /// Port for onion routing connections (TLS).
    ///
    /// Used for relay-to-relay communication.
    pub or_port: u16,

    /// SHA-1 fingerprint of the authority's identity key.
    ///
    /// A 40-character hexadecimal string.
    pub fingerprint: String,

    /// V3 directory authority identity.
    ///
    /// Used for signing votes and the consensus.
    /// Some authorities may not have this if they don't participate
    /// in v3 consensus voting.
    pub v3ident: Option<String>,
}

/// Returns the list of known directory authorities.
///
/// These are the trusted servers that vote on the Tor network consensus.
/// The list is hardcoded and matches the authorities configured in the
/// official Tor client.
///
/// # Returns
///
/// A vector of [`DirectoryAuthority`] structs for all known authorities.
///
/// # Note
///
/// Some authorities (like "tor26") intentionally throttle their DirPort
/// to discourage abuse. The download functions automatically skip these
/// when using default endpoints.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::remote::get_authorities;
///
/// let authorities = get_authorities();
/// println!("Known authorities: {}", authorities.len());
///
/// for auth in &authorities {
///     println!("  {} - {}", auth.nickname, auth.fingerprint);
/// }
/// ```
pub fn get_authorities() -> Vec<DirectoryAuthority> {
    vec![
        DirectoryAuthority {
            nickname: "moria1".into(),
            address: "128.31.0.39".parse().unwrap(),
            dir_port: 9131,
            or_port: 9101,
            fingerprint: "9695DFC35FFEB861329B9F1AB04C46397020CE31".into(),
            v3ident: Some("D586D18309DED4CD6D57C18FDB97EFA96D330566".into()),
        },
        DirectoryAuthority {
            nickname: "tor26".into(),
            address: "86.59.21.38".parse().unwrap(),
            dir_port: 80,
            or_port: 443,
            fingerprint: "847B1F850344D7876491A54892F904934E4EB85D".into(),
            v3ident: Some("14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4".into()),
        },
        DirectoryAuthority {
            nickname: "dizum".into(),
            address: "45.66.33.45".parse().unwrap(),
            dir_port: 80,
            or_port: 443,
            fingerprint: "7EA6EAD6FD83083C538F44038BBFA077587DD755".into(),
            v3ident: Some("E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58".into()),
        },
        DirectoryAuthority {
            nickname: "gabelmoo".into(),
            address: "131.188.40.189".parse().unwrap(),
            dir_port: 80,
            or_port: 443,
            fingerprint: "F2044413DAC2E02E3D6BCF4735A19BCA1DE97281".into(),
            v3ident: Some("ED03BB616EB2F60BEC80151114BB25CEF515B226".into()),
        },
        DirectoryAuthority {
            nickname: "dannenberg".into(),
            address: "193.23.244.244".parse().unwrap(),
            dir_port: 80,
            or_port: 443,
            fingerprint: "7BE683E65D48141321C5ED92F075C55364AC7123".into(),
            v3ident: Some("0232AF901C31A04EE9848595AF9BB7620D4C5B2E".into()),
        },
        DirectoryAuthority {
            nickname: "maatuska".into(),
            address: "171.25.193.9".parse().unwrap(),
            dir_port: 443,
            or_port: 80,
            fingerprint: "BD6A829255CB08E66FBE7D3748363586E46B3810".into(),
            v3ident: Some("49015F787433103580E3B66A1707A00E60F2D15B".into()),
        },
        DirectoryAuthority {
            nickname: "Faravahar".into(),
            address: "154.35.175.225".parse().unwrap(),
            dir_port: 80,
            or_port: 443,
            fingerprint: "CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC".into(),
            v3ident: Some("EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97".into()),
        },
        DirectoryAuthority {
            nickname: "longclaw".into(),
            address: "199.58.81.140".parse().unwrap(),
            dir_port: 80,
            or_port: 443,
            fingerprint: "74A910646BCEEFBCD2E874FC1DC997430F968145".into(),
            v3ident: Some("23D15D965BC35114467363C165C4F724B64B4F66".into()),
        },
        DirectoryAuthority {
            nickname: "bastet".into(),
            address: "204.13.164.118".parse().unwrap(),
            dir_port: 80,
            or_port: 443,
            fingerprint: "24E2F139121D4394C54B5BCC368B3B411857C413".into(),
            v3ident: Some("27102BC123E7AF1D4741AE047E160C91ADC76B21".into()),
        },
    ]
}

/// Result of a successful descriptor download.
///
/// Contains the downloaded content along with metadata about the
/// download including the source endpoint and timing information.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::descriptor::remote::download_consensus;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let result = download_consensus(false, None, Some(Duration::from_secs(30))).await?;
///
/// println!("Downloaded {} bytes", result.content.len());
/// println!("From: {:?}", result.source.socket_addr());
/// println!("Time: {:?}", result.runtime);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct DownloadResult {
    /// The downloaded content as raw bytes.
    ///
    /// This may be compressed depending on what the server sent.
    /// Use the appropriate decompression based on the Content-Encoding
    /// header (not currently exposed).
    pub content: Vec<u8>,

    /// The endpoint that provided this content.
    ///
    /// Useful for debugging and logging which server was used.
    pub source: DirPort,

    /// How long the download took.
    ///
    /// Includes connection time, request/response, and data transfer.
    pub runtime: Duration,
}

/// Downloads a resource from a directory port.
///
/// This is the low-level download function that handles HTTP communication
/// with a single endpoint. Higher-level functions like [`download_consensus()`]
/// use this internally with retry logic.
///
/// # Arguments
///
/// * `endpoint` - The directory port to download from
/// * `resource` - The URL path to request (e.g., "/tor/status-vote/current/consensus")
/// * `compression` - List of acceptable compression formats, in preference order
/// * `request_timeout` - Optional timeout for the entire request
///
/// # Returns
///
/// A [`DownloadResult`] containing the response body and metadata.
///
/// # Errors
///
/// Returns [`Error::Download`] if:
/// - Connection to the endpoint fails
/// - The HTTP response indicates an error (non-200 status)
/// - The response is malformed
///
/// Returns [`Error::DownloadTimeout`] if the request exceeds the timeout.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::descriptor::remote::{download_from_dirport, DirPort, Compression};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let endpoint = DirPort::new("128.31.0.39".parse().unwrap(), 9131);
/// let result = download_from_dirport(
///     &endpoint,
///     "/tor/status-vote/current/consensus",
///     &[Compression::Gzip, Compression::Plaintext],
///     Some(Duration::from_secs(30)),
/// ).await?;
///
/// println!("Downloaded {} bytes", result.content.len());
/// # Ok(())
/// # }
/// ```
pub async fn download_from_dirport(
    endpoint: &DirPort,
    resource: &str,
    compression: &[Compression],
    request_timeout: Option<Duration>,
) -> Result<DownloadResult, Error> {
    let start = std::time::Instant::now();
    let socket_addr = endpoint.socket_addr();

    let accept_encoding = compression
        .iter()
        .map(|c| c.encoding())
        .collect::<Vec<_>>()
        .join(", ");

    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}:{}\r\nAccept-Encoding: {}\r\nUser-Agent: {}\r\n\r\n",
        resource, endpoint.address, endpoint.port, accept_encoding, USER_AGENT
    );

    let connect_and_download = async {
        let mut stream = TcpStream::connect(socket_addr)
            .await
            .map_err(|e| Error::Download {
                url: format!("http://{}:{}{}", endpoint.address, endpoint.port, resource),
                reason: e.to_string(),
            })?;

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Error::Download {
                url: format!("http://{}:{}{}", endpoint.address, endpoint.port, resource),
                reason: e.to_string(),
            })?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| Error::Download {
                url: format!("http://{}:{}{}", endpoint.address, endpoint.port, resource),
                reason: e.to_string(),
            })?;

        Ok::<Vec<u8>, Error>(response)
    };

    let response = match request_timeout {
        Some(t) => {
            timeout(t, connect_and_download)
                .await
                .map_err(|_| Error::DownloadTimeout {
                    url: format!("http://{}:{}{}", endpoint.address, endpoint.port, resource),
                })??
        }
        None => connect_and_download.await?,
    };

    let content = extract_http_body(&response)?;
    let runtime = start.elapsed();

    Ok(DownloadResult {
        content,
        source: endpoint.clone(),
        runtime,
    })
}

/// Extracts the HTTP body from a raw HTTP response.
///
/// Parses the HTTP response, validates the status code, and returns
/// just the body content.
fn extract_http_body(response: &[u8]) -> Result<Vec<u8>, Error> {
    let response_str = String::from_utf8_lossy(response);
    if let Some(pos) = response_str.find("\r\n\r\n") {
        let header = &response_str[..pos];
        if !header.starts_with("HTTP/1.") {
            return Err(Error::Download {
                url: String::new(),
                reason: "Invalid HTTP response".into(),
            });
        }
        let status_line = header.lines().next().unwrap_or("");
        if !status_line.contains(" 200 ") {
            return Err(Error::Download {
                url: String::new(),
                reason: format!("HTTP error: {}", status_line),
            });
        }
        Ok(response[pos + 4..].to_vec())
    } else {
        Err(Error::Download {
            url: String::new(),
            reason: "Invalid HTTP response: no body separator".into(),
        })
    }
}

/// Downloads the current network consensus.
///
/// The consensus is the agreed-upon view of the Tor network, containing
/// information about all known relays. It is signed by a majority of
/// directory authorities.
///
/// # Arguments
///
/// * `microdescriptor` - If `true`, downloads the microdescriptor consensus
///   (smaller, used by clients). If `false`, downloads the full consensus.
/// * `endpoints` - Optional list of endpoints to try. If `None`, uses
///   default directory authorities.
/// * `request_timeout` - Optional timeout for each download attempt.
///
/// # Returns
///
/// A [`DownloadResult`] containing the consensus document.
///
/// # Errors
///
/// Returns [`Error::Download`] if all endpoints fail.
/// Returns [`Error::DownloadTimeout`] if all attempts timeout.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::descriptor::remote::download_consensus;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// // Download microdescriptor consensus (smaller, for clients)
/// let result = download_consensus(true, None, Some(Duration::from_secs(60))).await?;
/// println!("Consensus size: {} bytes", result.content.len());
/// # Ok(())
/// # }
/// ```
pub async fn download_consensus(
    microdescriptor: bool,
    endpoints: Option<&[DirPort]>,
    request_timeout: Option<Duration>,
) -> Result<DownloadResult, Error> {
    let resource = if microdescriptor {
        "/tor/status-vote/current/consensus-microdesc"
    } else {
        "/tor/status-vote/current/consensus"
    };

    download_resource(resource, endpoints, request_timeout).await
}

/// Downloads server descriptors.
///
/// Server descriptors contain detailed information about relays including
/// their keys, exit policies, and capabilities.
///
/// # Arguments
///
/// * `fingerprints` - Optional list of relay fingerprints to fetch.
///   If `None`, downloads all server descriptors (large!).
///   Maximum 96 fingerprints per request.
/// * `endpoints` - Optional list of endpoints to try.
/// * `request_timeout` - Optional timeout for each download attempt.
///
/// # Returns
///
/// A [`DownloadResult`] containing the server descriptors.
///
/// # Errors
///
/// Returns [`Error::InvalidRequest`] if more than 96 fingerprints are requested.
/// Returns [`Error::Download`] if all endpoints fail.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::descriptor::remote::download_server_descriptors;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// // Download specific relay descriptors
/// let fingerprints = ["9695DFC35FFEB861329B9F1AB04C46397020CE31"];
/// let result = download_server_descriptors(
///     Some(&fingerprints.iter().map(|s| *s).collect::<Vec<_>>()),
///     None,
///     Some(Duration::from_secs(30)),
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn download_server_descriptors(
    fingerprints: Option<&[&str]>,
    endpoints: Option<&[DirPort]>,
    request_timeout: Option<Duration>,
) -> Result<DownloadResult, Error> {
    let resource = match fingerprints {
        Some(fps) => {
            if fps.len() > MAX_FINGERPRINTS {
                return Err(Error::InvalidRequest(format!(
                    "Cannot request more than {} descriptors at a time",
                    MAX_FINGERPRINTS
                )));
            }
            format!("/tor/server/fp/{}", fps.join("+"))
        }
        None => "/tor/server/all".to_string(),
    };

    download_resource(&resource, endpoints, request_timeout).await
}

/// Downloads extra-info descriptors.
///
/// Extra-info descriptors contain additional relay information not included
/// in server descriptors, such as bandwidth statistics and transport details.
///
/// # Arguments
///
/// * `fingerprints` - Optional list of relay fingerprints to fetch.
///   If `None`, downloads all extra-info descriptors.
///   Maximum 96 fingerprints per request.
/// * `endpoints` - Optional list of endpoints to try.
/// * `request_timeout` - Optional timeout for each download attempt.
///
/// # Returns
///
/// A [`DownloadResult`] containing the extra-info descriptors.
///
/// # Errors
///
/// Returns [`Error::InvalidRequest`] if more than 96 fingerprints are requested.
/// Returns [`Error::Download`] if all endpoints fail.
pub async fn download_extrainfo_descriptors(
    fingerprints: Option<&[&str]>,
    endpoints: Option<&[DirPort]>,
    request_timeout: Option<Duration>,
) -> Result<DownloadResult, Error> {
    let resource = match fingerprints {
        Some(fps) => {
            if fps.len() > MAX_FINGERPRINTS {
                return Err(Error::InvalidRequest(format!(
                    "Cannot request more than {} descriptors at a time",
                    MAX_FINGERPRINTS
                )));
            }
            format!("/tor/extra/fp/{}", fps.join("+"))
        }
        None => "/tor/extra/all".to_string(),
    };

    download_resource(&resource, endpoints, request_timeout).await
}

/// Downloads microdescriptors by their hashes.
///
/// Microdescriptors are compact relay descriptions used by Tor clients.
/// They are identified by their digest (hash) rather than fingerprint.
///
/// # Arguments
///
/// * `hashes` - List of microdescriptor digests to fetch.
///   Maximum 90 hashes per request.
/// * `endpoints` - Optional list of endpoints to try.
/// * `request_timeout` - Optional timeout for each download attempt.
///
/// # Returns
///
/// A [`DownloadResult`] containing the microdescriptors.
///
/// # Errors
///
/// Returns [`Error::InvalidRequest`] if more than 90 hashes are requested.
/// Returns [`Error::Download`] if all endpoints fail.
///
/// # Note
///
/// Microdescriptor hashes are obtained from the microdescriptor consensus.
/// Each router status entry contains the hash of its microdescriptor.
pub async fn download_microdescriptors(
    hashes: &[&str],
    endpoints: Option<&[DirPort]>,
    request_timeout: Option<Duration>,
) -> Result<DownloadResult, Error> {
    if hashes.len() > MAX_MICRODESCRIPTOR_HASHES {
        return Err(Error::InvalidRequest(format!(
            "Cannot request more than {} microdescriptors at a time",
            MAX_MICRODESCRIPTOR_HASHES
        )));
    }

    let resource = format!("/tor/micro/d/{}", hashes.join("-"));
    download_resource(&resource, endpoints, request_timeout).await
}

/// Downloads authority key certificates.
///
/// Key certificates bind directory authority identity keys to their
/// signing keys. They are needed to verify consensus signatures.
///
/// # Arguments
///
/// * `v3idents` - Optional list of v3 authority identities to fetch.
///   If `None`, downloads all key certificates.
/// * `endpoints` - Optional list of endpoints to try.
/// * `request_timeout` - Optional timeout for each download attempt.
///
/// # Returns
///
/// A [`DownloadResult`] containing the key certificates.
///
/// # Errors
///
/// Returns [`Error::Download`] if all endpoints fail.
///
/// # See Also
///
/// - [`super::key_cert::KeyCertificate`] for parsing the downloaded certificates
pub async fn download_key_certificates(
    v3idents: Option<&[&str]>,
    endpoints: Option<&[DirPort]>,
    request_timeout: Option<Duration>,
) -> Result<DownloadResult, Error> {
    let resource = match v3idents {
        Some(ids) => format!("/tor/keys/fp/{}", ids.join("+")),
        None => "/tor/keys/all".to_string(),
    };

    download_resource(&resource, endpoints, request_timeout).await
}

/// Downloads the bandwidth file for the next consensus.
///
/// Bandwidth files contain measurements used by authorities to assign
/// bandwidth weights in the consensus. These are produced by bandwidth
/// measurement systems like sbws or Torflow.
///
/// # Arguments
///
/// * `endpoints` - Optional list of endpoints to try.
/// * `request_timeout` - Optional timeout for each download attempt.
///
/// # Returns
///
/// A [`DownloadResult`] containing the bandwidth file.
///
/// # Errors
///
/// Returns [`Error::Download`] if all endpoints fail.
///
/// # See Also
///
/// - [`super::bandwidth_file::BandwidthFile`] for parsing the downloaded file
pub async fn download_bandwidth_file(
    endpoints: Option<&[DirPort]>,
    request_timeout: Option<Duration>,
) -> Result<DownloadResult, Error> {
    download_resource(
        "/tor/status-vote/next/bandwidth",
        endpoints,
        request_timeout,
    )
    .await
}

/// Downloads detached signatures for the next consensus.
///
/// Detached signatures are authority signatures collected during the
/// consensus voting process. They are used to create the final signed
/// consensus document.
///
/// # Arguments
///
/// * `endpoints` - Optional list of endpoints to try.
/// * `request_timeout` - Optional timeout for each download attempt.
///
/// # Returns
///
/// A [`DownloadResult`] containing the detached signatures.
///
/// # Errors
///
/// Returns [`Error::Download`] if all endpoints fail.
///
/// # Note
///
/// This is primarily useful for directory authority operators and
/// researchers studying the consensus process.
pub async fn download_detached_signatures(
    endpoints: Option<&[DirPort]>,
    request_timeout: Option<Duration>,
) -> Result<DownloadResult, Error> {
    download_resource(
        "/tor/status-vote/next/consensus-signatures",
        endpoints,
        request_timeout,
    )
    .await
}

/// Internal function to download a resource with retry logic.
///
/// Tries each endpoint in order until one succeeds. Automatically
/// skips known problematic authorities (tor26, Serge).
async fn download_resource(
    resource: &str,
    endpoints: Option<&[DirPort]>,
    request_timeout: Option<Duration>,
) -> Result<DownloadResult, Error> {
    let authorities = get_authorities();
    let default_endpoints: Vec<DirPort> = authorities
        .iter()
        .filter(|a| a.nickname != "tor26" && a.nickname != "Serge")
        .map(|a| DirPort::new(a.address, a.dir_port))
        .collect();

    let endpoints = endpoints.unwrap_or(&default_endpoints);
    let compression = vec![Compression::Gzip, Compression::Plaintext];

    let mut last_error = None;

    for endpoint in endpoints {
        match download_from_dirport(endpoint, resource, &compression, request_timeout).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| Error::Download {
        url: resource.to_string(),
        reason: "No endpoints available".into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_authorities() {
        let authorities = get_authorities();
        assert!(!authorities.is_empty());
        assert!(authorities.iter().any(|a| a.nickname == "moria1"));
    }

    #[test]
    fn test_compression_encoding() {
        assert_eq!(Compression::Plaintext.encoding(), "identity");
        assert_eq!(Compression::Gzip.encoding(), "gzip");
        assert_eq!(Compression::Zstd.encoding(), "zstd");
        assert_eq!(Compression::Lzma.encoding(), "x-tor-lzma");
    }

    #[test]
    fn test_dirport() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let dirport = DirPort::new(addr, 9030);
        assert_eq!(dirport.socket_addr(), SocketAddr::new(addr, 9030));
    }

    #[test]
    fn test_extract_http_body() {
        let response = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, World!";
        let body = extract_http_body(response).unwrap();
        assert_eq!(body, b"Hello, World!");
    }

    #[test]
    fn test_extract_http_body_error() {
        let response = b"HTTP/1.0 404 Not Found\r\n\r\nNot Found";
        let result = extract_http_body(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_fingerprints() {
        assert_eq!(MAX_FINGERPRINTS, 96);
        assert_eq!(MAX_MICRODESCRIPTOR_HASHES, 90);
    }
}
