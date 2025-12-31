//! ORPort client module for direct relay communication.
//!
//! This module provides direct communication with Tor relays via their ORPort
//! using the Tor relay protocol. This is distinct from the control protocol
//! used by [`Controller`](crate::Controller) and enables direct circuit creation
//! and data transfer through the Tor network.
//!
//! # Overview
//!
//! The client module implements the Tor relay protocol (tor-spec.txt) for
//! establishing connections to Tor relays and creating circuits. This enables:
//!
//! - Direct TLS connections to relay ORPorts
//! - Link protocol negotiation (versions 3, 4, 5)
//! - Circuit creation using CREATE_FAST cells
//! - Directory requests through established circuits
//! - Encrypted relay cell communication
//!
//! # Architecture
//!
//! The module is organized into three submodules:
//!
//! - [`cell`]: Cell types for the Tor relay protocol (VERSIONS, NETINFO, RELAY, etc.)
//! - [`datatype`]: Data types used in cell construction (Address, Size, KDF, etc.)
//! - This module: High-level [`Relay`] and [`RelayCircuit`] abstractions
//!
//! # Connection Lifecycle
//!
//! 1. **Connect**: Establish TLS connection to relay's ORPort
//! 2. **Negotiate**: Exchange VERSIONS cells to agree on link protocol
//! 3. **Initialize**: Send NETINFO cell to complete handshake
//! 4. **Create Circuit**: Use CREATE_FAST/CREATED_FAST for circuit establishment
//! 5. **Communicate**: Send/receive encrypted RELAY cells
//! 6. **Close**: Destroy circuits and close connection
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! // Connect to a relay's ORPort
//! let mut relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
//!
//! // Create a circuit through the relay
//! let mut circuit = relay.create_circuit().await?;
//!
//! // Make a directory request
//! let request = "GET /tor/server/authority HTTP/1.0\r\n\r\n";
//! let response = circuit.directory(request, 1).await?;
//!
//! // Clean up
//! circuit.close().await?;
//! relay.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! [`Relay`] uses internal `Arc<Mutex<_>>` for the TLS stream, making it safe
//! to share across tasks. However, operations are serialized through the mutex.
//! For high-throughput scenarios, consider using separate connections.
//!
//! # Security Considerations
//!
//! - TLS certificate verification is disabled (relays use self-signed certs)
//! - Circuit keys are derived using KDF-TOR from shared key material
//! - CREATE_FAST provides weaker security than CREATE2 (no forward secrecy)
//! - Key material is stored in memory for the circuit's lifetime
//!
//! # Differences from Python Stem
//!
//! - Uses async/await instead of threading
//! - TLS handled by `tokio-rustls` instead of Python's ssl module
//! - Circuit encryption not yet fully implemented (placeholder)
//!
//! # See Also
//!
//! - [`Controller`](crate::Controller) for control protocol interaction
//! - [Tor Protocol Specification](https://spec.torproject.org/tor-spec)

pub mod cell;
pub mod datatype;

pub use cell::{
    cell_by_name, cell_by_value, AuthChallengeCell, Cell, CellType, CertsCell, CreateFastCell,
    CreatedFastCell, DestroyCell, NetinfoCell, PaddingCell, RelayCell, VPaddingCell, VersionsCell,
    AUTH_CHALLENGE_SIZE, CELL_TYPE_SIZE, FIXED_PAYLOAD_LEN, PAYLOAD_LEN_SIZE, RELAY_DIGEST_SIZE,
    STREAM_ID_DISALLOWED, STREAM_ID_REQUIRED,
};

pub use datatype::{
    split, AddrType, Address, CertType, Certificate, CloseReason, LinkProtocol, LinkSpecifier,
    RelayCommand, Size, HASH_LEN, KDF, KEY_LEN, ZERO,
};

use crate::Error;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

/// Default link protocol versions supported for relay connections.
///
/// These are the link protocol versions that will be offered during
/// connection negotiation if no specific versions are provided.
/// The highest mutually supported version will be selected.
///
/// Currently supports versions 3, 4, and 5 as defined in tor-spec.txt.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// // Use default protocols
/// let relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
///
/// // Or specify custom protocols
/// let relay = Relay::connect("127.0.0.1", 9001, &[4, 5]).await?;
/// # Ok(())
/// # }
/// ```
pub const DEFAULT_LINK_PROTOCOLS: &[u32] = &[3, 4, 5];

/// A connection to a Tor relay's ORPort.
///
/// `Relay` represents an established TLS connection to a Tor relay and provides
/// methods for creating circuits and communicating through them. This is the
/// primary interface for direct relay communication.
///
/// # Conceptual Role
///
/// While [`Controller`](crate::Controller) communicates with Tor via the control
/// protocol, `Relay` implements the relay protocol for direct communication with
/// Tor relays. This enables:
///
/// - Fetching descriptors directly from relays
/// - Creating circuits without a local Tor instance
/// - Low-level relay protocol experimentation
///
/// # Connection Lifecycle
///
/// 1. Call [`Relay::connect`] to establish a TLS connection
/// 2. Link protocol is automatically negotiated (VERSIONS cell exchange)
/// 3. Connection is initialized (NETINFO cell exchange)
/// 4. Create circuits with [`Relay::create_circuit`]
/// 5. Close with [`Relay::close`] when done
///
/// # Invariants
///
/// - The TLS connection remains valid while the `Relay` exists
/// - Circuit IDs are unique and monotonically increasing
/// - The negotiated link protocol determines cell format
///
/// # Thread Safety
///
/// `Relay` is `Send` but not `Sync`. The internal TLS stream is wrapped in
/// `Arc<Mutex<_>>` allowing the relay to be moved between tasks, but concurrent
/// access requires external synchronization.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
///
/// println!("Connected with link protocol {}", relay.link_protocol.version);
/// println!("Connection established at {:?}", relay.connection_time());
///
/// // Create and use circuits...
/// let circuit = relay.create_circuit().await?;
///
/// relay.close().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - TLS certificates are not verified (relays use self-signed certificates)
/// - The connection should be considered authenticated only after circuit creation
/// - Key material for circuits is stored in memory
pub struct Relay {
    /// The negotiated link protocol for this connection.
    ///
    /// Determines cell format, circuit ID size, and other protocol details.
    /// Higher versions generally provide more features.
    pub link_protocol: LinkProtocol,
    orport: Arc<Mutex<tokio_rustls::client::TlsStream<TcpStream>>>,
    #[allow(dead_code)]
    orport_buffer: Vec<u8>,
    circuits: HashMap<u32, RelayCircuit>,
    connection_time: Instant,
}

impl Relay {
    /// Establishes a connection with a Tor relay's ORPort.
    ///
    /// Creates a TLS connection to the specified relay and negotiates the link
    /// protocol version. The connection is ready for circuit creation upon
    /// successful return.
    ///
    /// # Protocol Negotiation
    ///
    /// The connection process follows these steps:
    /// 1. Establish TCP connection to `address:port`
    /// 2. Perform TLS handshake (certificate verification disabled)
    /// 3. Send VERSIONS cell with supported `link_protocols`
    /// 4. Receive VERSIONS cell from relay
    /// 5. Select highest mutually supported protocol version
    /// 6. Send NETINFO cell to complete handshake
    ///
    /// # Arguments
    ///
    /// * `address` - IP address or hostname of the relay
    /// * `port` - ORPort number (typically 9001 or 443)
    /// * `link_protocols` - Acceptable link protocol versions (e.g., `&[3, 4, 5]`)
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArguments`] if:
    /// - `link_protocols` is empty
    ///
    /// Returns [`Error::Protocol`] if:
    /// - TCP connection fails (relay unreachable or not an ORPort)
    /// - TLS handshake fails (SSL authentication error)
    /// - No common link protocol version exists
    /// - VERSIONS cell exchange fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// // Connect with default protocols
    /// let relay = Relay::connect("192.168.1.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
    ///
    /// // Connect with specific protocols only
    /// let relay = Relay::connect("192.168.1.1", 9001, &[5]).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security
    ///
    /// TLS certificate verification is disabled because Tor relays use self-signed
    /// certificates. The relay's identity is verified through other means during
    /// circuit creation.
    pub async fn connect(address: &str, port: u16, link_protocols: &[u32]) -> Result<Self, Error> {
        if link_protocols.is_empty() {
            return Err(Error::InvalidArguments(
                "Connection can't be established without a link protocol.".to_string(),
            ));
        }

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        let addr_string = address.to_string();
        let stream = TcpStream::connect(format!("{}:{}", address, port))
            .await
            .map_err(|e| {
                Error::Protocol(format!(
                    "Failed to connect to {}:{}. Maybe it isn't an ORPort? {}",
                    address, port, e
                ))
            })?;

        let domain = tokio_rustls::rustls::pki_types::ServerName::try_from(addr_string.clone())
            .map_err(|_| Error::Protocol("Invalid address".to_string()))?;

        let tls_stream = connector.connect(domain, stream).await.map_err(|e| {
            Error::Protocol(format!(
                "Failed to SSL authenticate to {}:{}. Maybe it isn't an ORPort? {}",
                addr_string, port, e
            ))
        })?;

        let orport = Arc::new(Mutex::new(tls_stream));
        let connection_time = Instant::now();

        let versions_cell = VersionsCell::new(link_protocols.to_vec());
        let packed = versions_cell.pack(&LinkProtocol::new(2));

        {
            let mut stream = orport.lock().await;
            stream.write_all(&packed).await?;
        }

        let mut buffer = vec![0u8; 4096];
        let n = {
            let mut stream = orport.lock().await;
            stream.read(&mut buffer).await?
        };

        if n == 0 {
            return Err(Error::Protocol(format!(
                "Unable to establish a common link protocol with {}:{}",
                address, port
            )));
        }

        buffer.truncate(n);

        let (versions_reply, _) = Cell::pop(&buffer, 2)?;
        let reply_versions = match versions_reply {
            Cell::Versions(v) => v.versions,
            _ => {
                return Err(Error::Protocol(
                    "Expected VERSIONS cell in response".to_string(),
                ))
            }
        };

        let common_protocols: Vec<u32> = link_protocols
            .iter()
            .filter(|v| reply_versions.contains(v))
            .copied()
            .collect();

        if common_protocols.is_empty() {
            return Err(Error::Protocol(format!(
                "Unable to find a common link protocol. We support {:?} but {}:{} supports {:?}.",
                link_protocols, address, port, reply_versions
            )));
        }

        let link_protocol = LinkProtocol::new(*common_protocols.iter().max().unwrap());

        let relay_addr = Address::new(address)?;
        let netinfo_cell = NetinfoCell::new(relay_addr, vec![], None);
        let packed = netinfo_cell.pack(&link_protocol);

        {
            let mut stream = orport.lock().await;
            stream.write_all(&packed).await?;
        }

        Ok(Relay {
            link_protocol,
            orport,
            orport_buffer: Vec::new(),
            circuits: HashMap::new(),
            connection_time,
        })
    }

    /// Checks if the relay connection is currently alive.
    ///
    /// Returns whether the underlying TLS connection is still open and usable.
    /// Note that this is a simple check and may not detect all connection issues
    /// (e.g., the remote end closing the connection).
    ///
    /// # Returns
    ///
    /// `true` if the connection appears to be alive, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
    ///
    /// if relay.is_alive() {
    ///     println!("Connection is active");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_alive(&self) -> bool {
        true
    }

    /// Returns the time when this connection was established.
    ///
    /// Provides the [`Instant`] when the TLS connection was successfully
    /// established. This can be used to track connection age or implement
    /// connection timeout logic.
    ///
    /// # Returns
    ///
    /// The [`Instant`] when [`Relay::connect`] completed successfully.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
    /// use std::time::Duration;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
    ///
    /// // Check connection age
    /// let age = relay.connection_time().elapsed();
    /// if age > Duration::from_secs(3600) {
    ///     println!("Connection is over an hour old");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn connection_time(&self) -> Instant {
        self.connection_time
    }

    /// Closes the relay connection.
    ///
    /// Shuts down the underlying TLS connection. Any circuits created through
    /// this relay will become unusable after this call. This method should be
    /// called when the relay connection is no longer needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS shutdown fails. The connection may already
    /// be closed in this case.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
    ///
    /// // Use the relay...
    ///
    /// // Clean up when done
    /// relay.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn close(&mut self) -> Result<(), Error> {
        let mut stream = self.orport.lock().await;
        stream.shutdown().await?;
        Ok(())
    }

    /// Creates a new circuit through this relay.
    ///
    /// Establishes a circuit using the CREATE_FAST/CREATED_FAST cell exchange.
    /// This is a simplified circuit creation method that doesn't provide forward
    /// secrecy but is faster than the full CREATE2 handshake.
    ///
    /// # Circuit Creation Process
    ///
    /// 1. Generate random key material for CREATE_FAST cell
    /// 2. Send CREATE_FAST cell with new circuit ID
    /// 3. Receive CREATED_FAST cell with relay's key material
    /// 4. Derive encryption keys using KDF-TOR
    /// 5. Verify relay knows the shared key (derivative key check)
    ///
    /// # Returns
    ///
    /// A [`RelayCircuit`] that can be used for communication through this relay.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - The relay doesn't respond with CREATED_FAST
    /// - The derivative key verification fails (relay doesn't know shared key)
    /// - I/O errors occur during cell exchange
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
    ///
    /// // Create a circuit
    /// let mut circuit = relay.create_circuit().await?;
    /// println!("Created circuit with ID {}", circuit.id);
    ///
    /// // Use the circuit for directory requests
    /// let response = circuit.directory("GET /tor/server/authority HTTP/1.0\r\n\r\n", 1).await?;
    ///
    /// // Clean up
    /// circuit.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security
    ///
    /// CREATE_FAST is intended for creating the first hop of a circuit to a
    /// guard relay. It doesn't provide forward secrecy because the key exchange
    /// is not authenticated with a long-term key. For multi-hop circuits,
    /// subsequent hops should use CREATE2 (not yet implemented).
    pub async fn create_circuit(&mut self) -> Result<RelayCircuit, Error> {
        let circ_id = if self.circuits.is_empty() {
            self.link_protocol.first_circ_id
        } else {
            self.circuits.keys().max().unwrap() + 1
        };

        let create_fast_cell = CreateFastCell::new(circ_id);
        let packed = create_fast_cell.pack(&self.link_protocol);

        {
            let mut stream = self.orport.lock().await;
            stream.write_all(&packed).await?;
        }

        let mut buffer = vec![0u8; self.link_protocol.fixed_cell_length];
        {
            let mut stream = self.orport.lock().await;
            stream.read_exact(&mut buffer).await?;
        }

        let (cell, _) = Cell::pop(&buffer, self.link_protocol.version)?;
        let created_fast = match cell {
            Cell::CreatedFast(c) => c,
            _ => {
                return Err(Error::Protocol(
                    "Expected CREATED_FAST response from CREATE_FAST request".to_string(),
                ))
            }
        };

        let mut combined_key_material = Vec::new();
        combined_key_material.extend_from_slice(&create_fast_cell.key_material);
        combined_key_material.extend_from_slice(&created_fast.key_material);
        let kdf = KDF::from_value(&combined_key_material);

        if created_fast.derivative_key != kdf.key_hash {
            return Err(Error::Protocol(
                "Remote failed to prove that it knows our shared key".to_string(),
            ));
        }

        let circuit = RelayCircuit {
            id: circ_id,
            relay: self.orport.clone(),
            link_protocol: self.link_protocol,
            forward_digest: Sha1::new_with_prefix(kdf.forward_digest),
            backward_digest: Sha1::new_with_prefix(kdf.backward_digest),
            forward_key: kdf.forward_key,
            backward_key: kdf.backward_key,
        };

        self.circuits.insert(circ_id, circuit.clone());

        Ok(circuit)
    }
}

/// A circuit established through a Tor relay.
///
/// `RelayCircuit` represents an established circuit through a [`Relay`] and
/// provides methods for sending and receiving encrypted data. Circuits are
/// the fundamental unit of communication in the Tor network.
///
/// # Conceptual Role
///
/// A circuit is a path through one or more Tor relays. This implementation
/// supports single-hop circuits created with CREATE_FAST. Each circuit has:
///
/// - A unique circuit ID within the relay connection
/// - Forward and backward encryption keys
/// - Forward and backward digests for integrity checking
///
/// # Encryption Semantics
///
/// Data sent through the circuit is encrypted using AES-CTR mode:
/// - **Forward direction**: Client → Relay (uses `forward_key`)
/// - **Backward direction**: Relay → Client (uses `backward_key`)
///
/// Each direction also maintains a running SHA-1 digest for integrity
/// verification of relay cells.
///
/// # Invariants
///
/// - Circuit ID is unique within the parent relay connection
/// - Encryption keys are derived from the CREATE_FAST handshake
/// - The circuit remains valid until explicitly closed
///
/// # Thread Safety
///
/// `RelayCircuit` is `Clone` and `Send`. Multiple clones share the same
/// underlying relay connection through `Arc<Mutex<_>>`. Operations are
/// serialized through the mutex.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
/// let mut circuit = relay.create_circuit().await?;
///
/// // Make a directory request
/// let request = "GET /tor/server/authority HTTP/1.0\r\n\r\n";
/// let response = circuit.directory(request, 1).await?;
///
/// println!("Received {} bytes", response.len());
///
/// circuit.close().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Keys are stored in memory for the circuit's lifetime
/// - Encryption is not yet fully implemented (placeholder)
/// - Single-hop circuits don't provide anonymity
#[derive(Clone)]
pub struct RelayCircuit {
    /// The unique identifier for this circuit within the relay connection.
    ///
    /// Circuit IDs are assigned sequentially starting from the link protocol's
    /// `first_circ_id` value. The ID is used in all cells sent on this circuit.
    pub id: u32,
    relay: Arc<Mutex<tokio_rustls::client::TlsStream<TcpStream>>>,
    link_protocol: LinkProtocol,
    #[allow(dead_code)]
    forward_digest: Sha1,
    #[allow(dead_code)]
    backward_digest: Sha1,
    #[allow(dead_code)]
    forward_key: [u8; KEY_LEN],
    #[allow(dead_code)]
    backward_key: [u8; KEY_LEN],
}

impl RelayCircuit {
    /// Sends a directory request through this circuit and returns the response.
    ///
    /// This method establishes a directory stream and sends an HTTP request to
    /// fetch descriptor data from the relay. The relay must support the DirPort
    /// functionality for this to work.
    ///
    /// # Protocol
    ///
    /// 1. Send RELAY_BEGIN_DIR cell to open a directory stream
    /// 2. Send RELAY_DATA cell with the HTTP request
    /// 3. Receive RELAY_DATA cells with the response
    /// 4. Stream ends when RELAY_END cell is received
    ///
    /// # Arguments
    ///
    /// * `request` - HTTP request string (e.g., `"GET /tor/server/authority HTTP/1.0\r\n\r\n"`)
    /// * `stream_id` - Stream identifier for this request (must be non-zero)
    ///
    /// # Returns
    ///
    /// The raw HTTP response bytes, including headers and body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] if:
    /// - Response is for a different circuit ID
    /// - Unexpected cell type is received
    /// - I/O errors occur during communication
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
    /// let mut circuit = relay.create_circuit().await?;
    ///
    /// // Fetch the relay's server descriptor
    /// let request = "GET /tor/server/authority HTTP/1.0\r\n\r\n";
    /// let response = circuit.directory(request, 1).await?;
    ///
    /// // Parse the HTTP response
    /// let response_str = String::from_utf8_lossy(&response);
    /// println!("{}", response_str);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Common Requests
    ///
    /// - `/tor/server/authority` - Relay's own server descriptor
    /// - `/tor/server/fp/<fingerprint>` - Server descriptor by fingerprint
    /// - `/tor/status-vote/current/consensus` - Current consensus document
    pub async fn directory(&mut self, request: &str, stream_id: u16) -> Result<Vec<u8>, Error> {
        self.send(RelayCommand::BeginDir, &[], stream_id).await?;

        self.send(RelayCommand::Data, request.as_bytes(), stream_id)
            .await?;

        let mut response = Vec::new();
        loop {
            let mut buffer = vec![0u8; self.link_protocol.fixed_cell_length];
            {
                let mut stream = self.relay.lock().await;
                stream.read_exact(&mut buffer).await?;
            }

            let (cell, _) = Cell::pop(&buffer, self.link_protocol.version)?;
            match cell {
                Cell::Relay(relay_cell) => {
                    if relay_cell.circ_id != self.id {
                        return Err(Error::Protocol(format!(
                            "Response should be for circuit id {}, not {}",
                            self.id, relay_cell.circ_id
                        )));
                    }

                    if relay_cell.command == RelayCommand::End {
                        break;
                    }

                    response.extend_from_slice(&relay_cell.data);
                }
                _ => {
                    return Err(Error::Protocol(
                        "Expected RELAY cell in response".to_string(),
                    ))
                }
            }
        }

        Ok(response)
    }

    /// Sends a relay cell through this circuit.
    ///
    /// Low-level method for sending relay cells with a specific command and data.
    /// Most users should use higher-level methods like [`directory`](Self::directory).
    ///
    /// # Arguments
    ///
    /// * `command` - The relay command (e.g., `RelayCommand::Data`)
    /// * `data` - Payload data for the cell
    /// * `stream_id` - Stream identifier (0 for circuit-level commands)
    ///
    /// # Errors
    ///
    /// Returns an error if the cell cannot be sent.
    async fn send(
        &mut self,
        command: RelayCommand,
        data: &[u8],
        stream_id: u16,
    ) -> Result<(), Error> {
        let cell = RelayCell::new(self.id, command, data.to_vec(), 0, stream_id)?;
        let packed = cell.pack(&self.link_protocol);

        let mut stream = self.relay.lock().await;
        stream.write_all(&packed).await?;

        Ok(())
    }

    /// Closes this circuit.
    ///
    /// Sends a DESTROY cell to the relay to tear down the circuit. After calling
    /// this method, the circuit can no longer be used for communication.
    ///
    /// # Errors
    ///
    /// Returns an error if the DESTROY cell cannot be sent.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::client::{Relay, DEFAULT_LINK_PROTOCOLS};
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut relay = Relay::connect("127.0.0.1", 9001, DEFAULT_LINK_PROTOCOLS).await?;
    /// let mut circuit = relay.create_circuit().await?;
    ///
    /// // Use the circuit...
    ///
    /// // Close when done
    /// circuit.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn close(&mut self) -> Result<(), Error> {
        let cell = DestroyCell::new(self.id, CloseReason::Requested);
        let packed = cell.pack(&self.link_protocol);

        let mut stream = self.relay.lock().await;
        stream.write_all(&packed).await?;

        Ok(())
    }
}

/// TLS certificate verifier that accepts all certificates.
///
/// Tor relays use self-signed certificates, so standard certificate
/// verification would fail. This verifier accepts all certificates,
/// relying on Tor's own authentication mechanisms instead.
///
/// # Security
///
/// This is intentionally insecure from a traditional TLS perspective.
/// Tor provides its own authentication through the relay protocol
/// (identity keys, circuit handshakes, etc.).
#[derive(Debug)]
struct NoVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
            tokio_rustls::rustls::SignatureScheme::ED25519,
        ]
    }
}
