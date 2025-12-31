//! Event parsing for Tor control protocol async notifications.
//!
//! This module provides parsing for asynchronous event messages received from
//! Tor's control protocol. Events are notifications sent by Tor when certain
//! conditions occur, such as bandwidth usage, circuit state changes, or log
//! messages.
//!
//! # Event Format
//!
//! Events are sent with status code 650 and follow this format:
//!
//! ```text
//! 650 EVENT_TYPE [positional_args] [KEY=value ...]
//! ```
//!
//! Multi-line events use the extended format:
//!
//! ```text
//! 650-EVENT_TYPE [args]
//! 650-additional data
//! 650 OK
//! ```
//!
//! # Supported Event Types
//!
//! | Event | Description |
//! |-------|-------------|
//! | `BW` | Bandwidth usage (bytes read/written per second) |
//! | `CIRC` | Circuit status changes |
//! | `STREAM` | Stream status changes |
//! | `ORCONN` | OR connection status changes |
//! | `NOTICE`, `WARN`, `ERR` | Log messages at various levels |
//! | `NEWDESC` | New relay descriptors available |
//! | `ADDRMAP` | Address mapping changes |
//! | `SIGNAL` | Signal received by Tor |
//! | `HS_DESC` | Hidden service descriptor events |
//! | And many more... | See [`EventType`](crate::EventType) for full list |
//!
//! # Example
//!
//! ```rust
//! use stem_rs::response::{ControlMessage, events::parse_event};
//!
//! // Parse a bandwidth event
//! let msg = ControlMessage::from_str("650 BW 1024 2048", None, true).unwrap();
//! let event = parse_event(&msg).unwrap();
//!
//! // Events are returned as ParsedEvent enum variants
//! match event {
//!     stem_rs::events::ParsedEvent::Bandwidth(bw) => {
//!         println!("Read: {} bytes, Written: {} bytes", bw.read, bw.written);
//!     }
//!     _ => {}
//! }
//! ```
//!
//! # See Also
//!
//! - [`crate::events`]: Event type definitions and structures
//! - [`crate::Controller::add_event_listener`]: Subscribe to events
//! - [`crate::EventType`]: Enumeration of all event types
//! - [Tor Control Protocol: Async Events](https://spec.torproject.org/control-spec/replies.html#async-events)

use crate::events::ParsedEvent;
use crate::{Error, EventType};

use super::ControlMessage;

pub use crate::events::{Event, ParsedEvent as EventEnum};

/// Parses an event from a control message.
///
/// Extracts the event type and content from a 650-status message and
/// returns the appropriate [`ParsedEvent`] variant.
///
/// # Arguments
///
/// * `message` - The control message to parse (must have status code 650)
///
/// # Returns
///
/// A [`ParsedEvent`] variant corresponding to the event type. Unknown
/// event types are returned as [`ParsedEvent::Unknown`].
///
/// # Errors
///
/// Returns [`Error::Protocol`](crate::Error::Protocol) if:
/// - The message is empty
/// - The status code is not 650
/// - The event content is empty
/// - The event-specific parsing fails
///
/// # Example
///
/// ```rust
/// use stem_rs::response::{ControlMessage, events::parse_event};
/// use stem_rs::events::ParsedEvent;
///
/// // Parse a circuit event
/// let msg = ControlMessage::from_str("650 CIRC 1 BUILT", None, true).unwrap();
/// let event = parse_event(&msg).unwrap();
///
/// match event {
///     ParsedEvent::Circuit(circ) => {
///         println!("Circuit {} status changed", circ.id.0);
///     }
///     _ => {}
/// }
///
/// // Unknown events are still parsed
/// let msg = ControlMessage::from_str("650 FUTURE_EVENT data", None, true).unwrap();
/// let event = parse_event(&msg).unwrap();
///
/// match event {
///     ParsedEvent::Unknown { event_type, content } => {
///         println!("Unknown event: {} - {}", event_type, content);
///     }
///     _ => {}
/// }
/// ```
pub fn parse_event(message: &ControlMessage) -> Result<ParsedEvent, Error> {
    let content = message.content();
    if content.is_empty() {
        return Err(Error::Protocol("Empty event message".to_string()));
    }

    let (code, _, first_line) = &content[0];

    if code != "650" {
        return Err(Error::Protocol(format!(
            "Expected event status code 650, got {}",
            code
        )));
    }

    let event_type = first_line
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::Protocol("Empty event content".to_string()))?;

    let event_content = first_line
        .strip_prefix(event_type)
        .map(|s| s.trim_start())
        .unwrap_or("");

    let lines: Vec<String> = if content.len() > 1 {
        content[1..]
            .iter()
            .filter(|(_, _, line)| !line.is_empty() && line != "OK")
            .map(|(_, _, line)| line.clone())
            .collect()
    } else {
        Vec::new()
    };

    ParsedEvent::parse(event_type, event_content, Some(&lines))
}

/// Converts an event type string to its corresponding [`EventType`] enum.
///
/// This function maps event type names (as they appear in control protocol
/// messages) to the [`EventType`] enum used for event subscription.
///
/// # Arguments
///
/// * `event_type` - The event type string (case-insensitive)
///
/// # Returns
///
/// `Some(EventType)` if the event type is recognized, `None` otherwise.
///
/// # Example
///
/// ```rust
/// use stem_rs::response::events::event_type_to_class;
/// use stem_rs::EventType;
///
/// assert_eq!(event_type_to_class("BW"), Some(EventType::Bw));
/// assert_eq!(event_type_to_class("CIRC"), Some(EventType::Circ));
/// assert_eq!(event_type_to_class("bw"), Some(EventType::Bw)); // Case-insensitive
/// assert_eq!(event_type_to_class("UNKNOWN"), None);
/// ```
///
/// # Note
///
/// The `STATUS_CLIENT`, `STATUS_GENERAL`, and `STATUS_SERVER` event types
/// all map to [`EventType::Status`] since they share the same structure.
pub fn event_type_to_class(event_type: &str) -> Option<EventType> {
    match event_type.to_uppercase().as_str() {
        "ADDRMAP" => Some(EventType::AddrMap),
        "BUILDTIMEOUT_SET" => Some(EventType::BuildTimeoutSet),
        "BW" => Some(EventType::Bw),
        "CELL_STATS" => Some(EventType::CellStats),
        "CIRC" => Some(EventType::Circ),
        "CIRC_BW" => Some(EventType::CircBw),
        "CIRC_MINOR" => Some(EventType::CircMinor),
        "CLIENTS_SEEN" => Some(EventType::ClientsSeen),
        "CONF_CHANGED" => Some(EventType::ConfChanged),
        "CONN_BW" => Some(EventType::ConnBw),
        "DEBUG" => Some(EventType::Debug),
        "DESCCHANGED" => Some(EventType::DescChanged),
        "ERR" => Some(EventType::Err),
        "GUARD" => Some(EventType::Guard),
        "HS_DESC" => Some(EventType::HsDesc),
        "HS_DESC_CONTENT" => Some(EventType::HsDescContent),
        "INFO" => Some(EventType::Info),
        "NETWORK_LIVENESS" => Some(EventType::NetworkLiveness),
        "NEWCONSENSUS" => Some(EventType::NewConsensus),
        "NEWDESC" => Some(EventType::NewDesc),
        "NOTICE" => Some(EventType::Notice),
        "NS" => Some(EventType::Ns),
        "ORCONN" => Some(EventType::OrConn),
        "SIGNAL" => Some(EventType::Signal),
        "STATUS_CLIENT" | "STATUS_GENERAL" | "STATUS_SERVER" => Some(EventType::Status),
        "STREAM" => Some(EventType::Stream),
        "STREAM_BW" => Some(EventType::StreamBw),
        "TRANSPORT_LAUNCHED" => Some(EventType::TransportLaunched),
        "WARN" => Some(EventType::Warn),
        _ => None,
    }
}

/// Checks if an event type string is a known/recognized event type.
///
/// This is a convenience function that returns `true` if the event type
/// can be mapped to an [`EventType`] enum variant.
///
/// # Arguments
///
/// * `event_type` - The event type string to check (case-insensitive)
///
/// # Returns
///
/// `true` if the event type is recognized, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use stem_rs::response::events::is_known_event_type;
///
/// assert!(is_known_event_type("BW"));
/// assert!(is_known_event_type("CIRC"));
/// assert!(is_known_event_type("stream")); // Case-insensitive
/// assert!(!is_known_event_type("UNKNOWN_EVENT"));
/// ```
pub fn is_known_event_type(event_type: &str) -> bool {
    event_type_to_class(event_type).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Runlevel;

    #[test]
    fn test_parse_bandwidth_event() {
        let msg = ControlMessage::from_str("650 BW 100 200", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Bandwidth(bw) => {
                assert_eq!(bw.read, 100);
                assert_eq!(bw.written, 200);
            }
            _ => panic!("Expected bandwidth event"),
        }
    }

    #[test]
    fn test_parse_bandwidth_event_zero() {
        let msg = ControlMessage::from_str("650 BW 0 0", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Bandwidth(bw) => {
                assert_eq!(bw.read, 0);
                assert_eq!(bw.written, 0);
            }
            _ => panic!("Expected bandwidth event"),
        }
    }

    #[test]
    fn test_parse_circuit_event() {
        let msg = ControlMessage::from_str("650 CIRC 1 BUILT", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Circuit(circ) => {
                assert_eq!(circ.id.0, "1");
            }
            _ => panic!("Expected circuit event"),
        }
    }

    #[test]
    fn test_parse_circuit_launched() {
        let msg = ControlMessage::from_str("650 CIRC 7 LAUNCHED", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Circuit(circ) => {
                assert_eq!(circ.id.0, "7");
            }
            _ => panic!("Expected circuit event"),
        }
    }

    #[test]
    fn test_parse_log_event() {
        let msg = ControlMessage::from_str("650 NOTICE test message", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Log(log) => {
                assert_eq!(log.runlevel, Runlevel::Notice);
                assert_eq!(log.message, "test message");
            }
            _ => panic!("Expected log event"),
        }
    }

    #[test]
    fn test_parse_debug_log_event() {
        let msg = ControlMessage::from_str(
            "650 DEBUG connection_edge_process_relay_cell(): Got an extended cell! Yay.",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Log(log) => {
                assert_eq!(log.runlevel, Runlevel::Debug);
                assert_eq!(
                    log.message,
                    "connection_edge_process_relay_cell(): Got an extended cell! Yay."
                );
            }
            _ => panic!("Expected log event"),
        }
    }

    #[test]
    fn test_parse_info_log_event() {
        let msg = ControlMessage::from_str(
            "650 INFO circuit_finish_handshake(): Finished building circuit hop:",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Log(log) => {
                assert_eq!(log.runlevel, Runlevel::Info);
                assert_eq!(
                    log.message,
                    "circuit_finish_handshake(): Finished building circuit hop:"
                );
            }
            _ => panic!("Expected log event"),
        }
    }

    #[test]
    fn test_parse_stream_event_new() {
        let msg = ControlMessage::from_str(
            "650 STREAM 18 NEW 0 encrypted.google.com:443 SOURCE_ADDR=127.0.0.1:47849 PURPOSE=USER",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Stream(stream) => {
                assert_eq!(stream.id.0, "18");
                assert_eq!(stream.target_host, "encrypted.google.com");
                assert_eq!(stream.target_port, 443);
            }
            _ => panic!("Expected stream event"),
        }
    }

    #[test]
    fn test_parse_stream_event_succeeded() {
        let msg =
            ControlMessage::from_str("650 STREAM 18 SUCCEEDED 26 74.125.227.129:443", None, true)
                .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Stream(stream) => {
                assert_eq!(stream.id.0, "18");
                assert_eq!(stream.target_host, "74.125.227.129");
                assert_eq!(stream.target_port, 443);
            }
            _ => panic!("Expected stream event"),
        }
    }

    #[test]
    fn test_event_type_mapping() {
        assert_eq!(event_type_to_class("BW"), Some(EventType::Bw));
        assert_eq!(event_type_to_class("CIRC"), Some(EventType::Circ));
        assert_eq!(event_type_to_class("STREAM"), Some(EventType::Stream));
        assert_eq!(event_type_to_class("UNKNOWN"), None);
    }

    #[test]
    fn test_event_type_mapping_all_types() {
        assert_eq!(event_type_to_class("ADDRMAP"), Some(EventType::AddrMap));
        assert_eq!(
            event_type_to_class("BUILDTIMEOUT_SET"),
            Some(EventType::BuildTimeoutSet)
        );
        assert_eq!(event_type_to_class("BW"), Some(EventType::Bw));
        assert_eq!(
            event_type_to_class("CELL_STATS"),
            Some(EventType::CellStats)
        );
        assert_eq!(event_type_to_class("CIRC"), Some(EventType::Circ));
        assert_eq!(event_type_to_class("CIRC_BW"), Some(EventType::CircBw));
        assert_eq!(
            event_type_to_class("CIRC_MINOR"),
            Some(EventType::CircMinor)
        );
        assert_eq!(
            event_type_to_class("CLIENTS_SEEN"),
            Some(EventType::ClientsSeen)
        );
        assert_eq!(
            event_type_to_class("CONF_CHANGED"),
            Some(EventType::ConfChanged)
        );
        assert_eq!(event_type_to_class("CONN_BW"), Some(EventType::ConnBw));
        assert_eq!(event_type_to_class("DEBUG"), Some(EventType::Debug));
        assert_eq!(
            event_type_to_class("DESCCHANGED"),
            Some(EventType::DescChanged)
        );
        assert_eq!(event_type_to_class("ERR"), Some(EventType::Err));
        assert_eq!(event_type_to_class("GUARD"), Some(EventType::Guard));
        assert_eq!(event_type_to_class("HS_DESC"), Some(EventType::HsDesc));
        assert_eq!(
            event_type_to_class("HS_DESC_CONTENT"),
            Some(EventType::HsDescContent)
        );
        assert_eq!(event_type_to_class("INFO"), Some(EventType::Info));
        assert_eq!(
            event_type_to_class("NETWORK_LIVENESS"),
            Some(EventType::NetworkLiveness)
        );
        assert_eq!(
            event_type_to_class("NEWCONSENSUS"),
            Some(EventType::NewConsensus)
        );
        assert_eq!(event_type_to_class("NEWDESC"), Some(EventType::NewDesc));
        assert_eq!(event_type_to_class("NOTICE"), Some(EventType::Notice));
        assert_eq!(event_type_to_class("NS"), Some(EventType::Ns));
        assert_eq!(event_type_to_class("ORCONN"), Some(EventType::OrConn));
        assert_eq!(event_type_to_class("SIGNAL"), Some(EventType::Signal));
        assert_eq!(
            event_type_to_class("STATUS_CLIENT"),
            Some(EventType::Status)
        );
        assert_eq!(
            event_type_to_class("STATUS_GENERAL"),
            Some(EventType::Status)
        );
        assert_eq!(
            event_type_to_class("STATUS_SERVER"),
            Some(EventType::Status)
        );
        assert_eq!(event_type_to_class("STREAM"), Some(EventType::Stream));
        assert_eq!(event_type_to_class("STREAM_BW"), Some(EventType::StreamBw));
        assert_eq!(
            event_type_to_class("TRANSPORT_LAUNCHED"),
            Some(EventType::TransportLaunched)
        );
        assert_eq!(event_type_to_class("WARN"), Some(EventType::Warn));
    }

    #[test]
    fn test_event_type_mapping_case_insensitive() {
        assert_eq!(event_type_to_class("bw"), Some(EventType::Bw));
        assert_eq!(event_type_to_class("Bw"), Some(EventType::Bw));
        assert_eq!(event_type_to_class("circ"), Some(EventType::Circ));
        assert_eq!(event_type_to_class("Circ"), Some(EventType::Circ));
    }

    #[test]
    fn test_is_known_event_type() {
        assert!(is_known_event_type("BW"));
        assert!(is_known_event_type("CIRC"));
        assert!(is_known_event_type("STREAM"));
        assert!(!is_known_event_type("UNKNOWN_EVENT"));
    }

    #[test]
    fn test_is_known_event_type_case_insensitive() {
        assert!(is_known_event_type("bw"));
        assert!(is_known_event_type("circ"));
        assert!(is_known_event_type("stream"));
    }

    #[test]
    fn test_parse_event_wrong_status_code() {
        let msg = ControlMessage::from_str("250 OK", None, true).unwrap();
        let result = parse_event(&msg);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Expected event status code 650"));
    }

    #[test]
    fn test_parse_signal_event() {
        let msg = ControlMessage::from_str("650 SIGNAL NEWNYM", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Signal(sig) => {
                assert!(matches!(sig.signal, crate::Signal::Newnym));
            }
            _ => panic!("Expected signal event"),
        }
    }

    #[test]
    fn test_parse_network_liveness_up() {
        let msg = ControlMessage::from_str("650 NETWORK_LIVENESS UP", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::NetworkLiveness(nl) => {
                assert_eq!(nl.status, "UP");
            }
            _ => panic!("Expected network liveness event"),
        }
    }

    #[test]
    fn test_parse_network_liveness_down() {
        let msg = ControlMessage::from_str("650 NETWORK_LIVENESS DOWN", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::NetworkLiveness(nl) => {
                assert_eq!(nl.status, "DOWN");
            }
            _ => panic!("Expected network liveness event"),
        }
    }

    #[test]
    fn test_parse_guard_event_new() {
        let msg = ControlMessage::from_str(
            "650 GUARD ENTRY $36B5DBA788246E8369DBAF58577C6BC044A9A374 NEW",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Guard(guard) => {
                assert_eq!(
                    guard.endpoint_fingerprint,
                    "36B5DBA788246E8369DBAF58577C6BC044A9A374"
                );
            }
            _ => panic!("Expected guard event"),
        }
    }

    #[test]
    fn test_parse_newdesc_single() {
        let msg = ControlMessage::from_str(
            "650 NEWDESC $B3FA3110CC6F42443F039220C134CBD2FC4F0493=Sakura",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::NewDesc(nd) => {
                assert!(!nd.relays.is_empty());
            }
            _ => panic!("Expected newdesc event"),
        }
    }

    #[test]
    fn test_parse_status_general_event() {
        let msg =
            ControlMessage::from_str("650 STATUS_GENERAL NOTICE CONSENSUS_ARRIVED", None, true)
                .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Status(status) => {
                assert_eq!(status.runlevel, Runlevel::Notice);
                assert_eq!(status.action, "CONSENSUS_ARRIVED");
            }
            _ => panic!("Expected status event"),
        }
    }

    #[test]
    fn test_parse_status_client_event() {
        let msg = ControlMessage::from_str("650 STATUS_CLIENT NOTICE ENOUGH_DIR_INFO", None, true)
            .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Status(status) => {
                assert_eq!(status.runlevel, Runlevel::Notice);
                assert_eq!(status.action, "ENOUGH_DIR_INFO");
            }
            _ => panic!("Expected status event"),
        }
    }

    #[test]
    fn test_parse_status_client_circuit_established() {
        let msg =
            ControlMessage::from_str("650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED", None, true)
                .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Status(status) => {
                assert_eq!(status.runlevel, Runlevel::Notice);
                assert_eq!(status.action, "CIRCUIT_ESTABLISHED");
            }
            _ => panic!("Expected status event"),
        }
    }

    #[test]
    fn test_parse_circ_bw_event() {
        let msg =
            ControlMessage::from_str("650 CIRC_BW ID=11 READ=272 WRITTEN=817", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::CircuitBandwidth(cb) => {
                assert_eq!(cb.id.0, "11");
                assert_eq!(cb.read, 272);
                assert_eq!(cb.written, 817);
            }
            _ => panic!("Expected circuit bandwidth event"),
        }
    }

    #[test]
    fn test_parse_conn_bw_event() {
        let msg = ControlMessage::from_str(
            "650 CONN_BW ID=11 TYPE=DIR READ=272 WRITTEN=817",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::ConnectionBandwidth(cb) => {
                assert_eq!(cb.id, "11");
                assert_eq!(cb.read, 272);
                assert_eq!(cb.written, 817);
            }
            _ => panic!("Expected connection bandwidth event"),
        }
    }

    #[test]
    fn test_parse_orconn_closed() {
        let msg = ControlMessage::from_str(
            "650 ORCONN $A1130635A0CDA6F60C276FBF6994EFBD4ECADAB1~tama CLOSED REASON=DONE",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::OrConn(orconn) => {
                assert_eq!(
                    orconn.target,
                    "$A1130635A0CDA6F60C276FBF6994EFBD4ECADAB1~tama"
                );
            }
            _ => panic!("Expected orconn event"),
        }
    }

    #[test]
    fn test_parse_orconn_connected() {
        let msg = ControlMessage::from_str(
            "650 ORCONN 127.0.0.1:9000 CONNECTED NCIRCS=20 ID=18",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::OrConn(orconn) => {
                assert_eq!(orconn.target, "127.0.0.1:9000");
                assert_eq!(orconn.num_circuits, Some(20));
                assert_eq!(orconn.id, Some("18".to_string()));
            }
            _ => panic!("Expected orconn event"),
        }
    }

    #[test]
    fn test_parse_orconn_launched() {
        let msg = ControlMessage::from_str(
            "650 ORCONN $7ED90E2833EE38A75795BA9237B0A4560E51E1A0=GreenDragon LAUNCHED",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::OrConn(orconn) => {
                assert_eq!(
                    orconn.target,
                    "$7ED90E2833EE38A75795BA9237B0A4560E51E1A0=GreenDragon"
                );
            }
            _ => panic!("Expected orconn event"),
        }
    }

    #[test]
    fn test_parse_unknown_event() {
        let msg = ControlMessage::from_str("650 UNKNOWN_EVENT some content", None, true).unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::Unknown {
                event_type,
                content,
            } => {
                assert_eq!(event_type, "UNKNOWN_EVENT");
                assert_eq!(content, "some content");
            }
            _ => panic!("Expected unknown event"),
        }
    }

    #[test]
    fn test_parse_addrmap_event() {
        let msg =
            ControlMessage::from_str("650 ADDRMAP www.example.com 192.0.2.1 NEVER", None, true)
                .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::AddrMap(am) => {
                assert_eq!(am.hostname, "www.example.com");
                assert_eq!(am.destination, Some("192.0.2.1".to_string()));
            }
            _ => panic!("Expected addrmap event"),
        }
    }

    #[test]
    fn test_parse_hs_desc_event() {
        let msg = ControlMessage::from_str(
            "650 HS_DESC REQUESTED ajhb7kljbiru65qo NO_AUTH $67B2BDA4264D8A189D9270E28B1D30A262838243=europa1 b3oeducbhjmbqmgw2i3jtz4fekkrinwj",
            None,
            true,
        )
        .unwrap();
        let event = parse_event(&msg).unwrap();
        match event {
            ParsedEvent::HsDesc(hsd) => {
                assert_eq!(hsd.address, "ajhb7kljbiru65qo");
            }
            _ => panic!("Expected hs_desc event"),
        }
    }
}
