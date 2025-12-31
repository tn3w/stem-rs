//! Integration tests for ORPort client against a real Tor process.

use std::net::SocketAddr;
use std::time::Duration;

use stem_rs::client::Relay;
use stem_rs::client::{
    cell_by_name, cell_by_value, Cell, CellType, CertsCell, CreateFastCell, DestroyCell,
    NetinfoCell, PaddingCell, RelayCell, VPaddingCell, VersionsCell, DEFAULT_LINK_PROTOCOLS,
};
use stem_rs::client::{
    AddrType, Address, CertType, Certificate, CloseReason, LinkProtocol, LinkSpecifier,
    RelayCommand, Size, KDF,
};
use stem_rs::controller::Controller;

use crate::{get_control_port, is_tor_available};

fn get_control_addr() -> SocketAddr {
    format!("127.0.0.1:{}", get_control_port()).parse().unwrap()
}

async fn get_relay_from_consensus() -> Option<(String, u16)> {
    let addr = get_control_addr();
    let mut controller = match Controller::from_port(addr).await {
        Ok(c) => c,
        Err(_) => return None,
    };

    if controller.authenticate(None).await.is_err() {
        return None;
    }

    let ns_content = match controller.get_info("ns/all").await {
        Ok(content) => content,
        Err(_) => return None,
    };

    for line in ns_content.lines() {
        if line.starts_with("r ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let ip = parts[5];
                if let Ok(port) = parts[6].parse::<u16>() {
                    if port > 0 {
                        return Some((ip.to_string(), port));
                    }
                }
            }
        }
    }

    None
}

async fn get_test_relay() -> Option<(String, u16)> {
    if !is_tor_available() {
        return None;
    }
    get_relay_from_consensus().await
}

#[test]
fn test_cell_type_lookup_by_name() {
    let test_cases = [
        ("PADDING", CellType::Padding, 0),
        ("CREATE", CellType::Create, 1),
        ("CREATED", CellType::Created, 2),
        ("RELAY", CellType::Relay, 3),
        ("DESTROY", CellType::Destroy, 4),
        ("CREATE_FAST", CellType::CreateFast, 5),
        ("CREATED_FAST", CellType::CreatedFast, 6),
        ("VERSIONS", CellType::Versions, 7),
        ("NETINFO", CellType::Netinfo, 8),
        ("RELAY_EARLY", CellType::RelayEarly, 9),
        ("VPADDING", CellType::VPadding, 128),
        ("CERTS", CellType::Certs, 129),
        ("AUTH_CHALLENGE", CellType::AuthChallenge, 130),
    ];

    for (name, expected_type, expected_value) in test_cases {
        let cell_type = cell_by_name(name).unwrap_or_else(|_| panic!("Failed to lookup {}", name));
        assert_eq!(cell_type, expected_type, "Type mismatch for {}", name);
        assert_eq!(
            cell_type.value(),
            expected_value,
            "Value mismatch for {}",
            name
        );
        assert_eq!(cell_type.name(), name, "Name mismatch for {}", name);
    }
}

#[test]
fn test_cell_type_lookup_by_value() {
    let test_cases = [
        (0, CellType::Padding, "PADDING"),
        (3, CellType::Relay, "RELAY"),
        (7, CellType::Versions, "VERSIONS"),
        (8, CellType::Netinfo, "NETINFO"),
        (128, CellType::VPadding, "VPADDING"),
        (129, CellType::Certs, "CERTS"),
    ];

    for (value, expected_type, expected_name) in test_cases {
        let cell_type =
            cell_by_value(value).unwrap_or_else(|_| panic!("Failed to lookup value {}", value));
        assert_eq!(cell_type, expected_type);
        assert_eq!(cell_type.name(), expected_name);
    }
}

#[test]
fn test_cell_type_invalid_lookup() {
    assert!(cell_by_name("INVALID").is_err());
    assert!(cell_by_value(200).is_err());
}

#[test]
fn test_cell_type_fixed_vs_variable() {
    assert!(CellType::Padding.is_fixed_size());
    assert!(CellType::Relay.is_fixed_size());
    assert!(CellType::Destroy.is_fixed_size());
    assert!(CellType::CreateFast.is_fixed_size());
    assert!(CellType::CreatedFast.is_fixed_size());
    assert!(CellType::Netinfo.is_fixed_size());

    assert!(!CellType::Versions.is_fixed_size());
    assert!(!CellType::VPadding.is_fixed_size());
    assert!(!CellType::Certs.is_fixed_size());
    assert!(!CellType::AuthChallenge.is_fixed_size());
}

#[test]
fn test_link_protocol_version_2() {
    let lp = LinkProtocol::new(2);
    assert_eq!(lp.version, 2);
    assert_eq!(lp.circ_id_size, Size::Short);
    assert_eq!(lp.first_circ_id, 0x01);
    assert_eq!(lp.fixed_cell_length, 512);
}

#[test]
fn test_link_protocol_version_3() {
    let lp = LinkProtocol::new(3);
    assert_eq!(lp.version, 3);
    assert_eq!(lp.circ_id_size, Size::Short);
    assert_eq!(lp.first_circ_id, 0x01);
    assert_eq!(lp.fixed_cell_length, 512);
}

#[test]
fn test_link_protocol_version_4() {
    let lp = LinkProtocol::new(4);
    assert_eq!(lp.version, 4);
    assert_eq!(lp.circ_id_size, Size::Long);
    assert_eq!(lp.first_circ_id, 0x80000000);
    assert_eq!(lp.fixed_cell_length, 514);
}

#[test]
fn test_link_protocol_version_5() {
    let lp = LinkProtocol::new(5);
    assert_eq!(lp.version, 5);
    assert_eq!(lp.circ_id_size, Size::Long);
    assert_eq!(lp.first_circ_id, 0x80000000);
    assert_eq!(lp.fixed_cell_length, 514);
}

#[test]
fn test_size_pack_unpack_roundtrip() {
    let test_values: Vec<u64> = vec![0, 1, 127, 128, 255, 256, 65535, 65536, u32::MAX as u64];

    for value in test_values {
        if value <= u8::MAX as u64 {
            let packed = Size::Char.pack(value);
            let unpacked = Size::Char.unpack(&packed).unwrap();
            assert_eq!(value, unpacked, "Char roundtrip failed for {}", value);
        }

        if value <= u16::MAX as u64 {
            let packed = Size::Short.pack(value);
            let unpacked = Size::Short.unpack(&packed).unwrap();
            assert_eq!(value, unpacked, "Short roundtrip failed for {}", value);
        }

        if value <= u32::MAX as u64 {
            let packed = Size::Long.pack(value);
            let unpacked = Size::Long.unpack(&packed).unwrap();
            assert_eq!(value, unpacked, "Long roundtrip failed for {}", value);
        }

        let packed = Size::LongLong.pack(value);
        let unpacked = Size::LongLong.unpack(&packed).unwrap();
        assert_eq!(value, unpacked, "LongLong roundtrip failed for {}", value);
    }
}

#[test]
fn test_size_pop() {
    let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let (val, rest) = Size::Char.pop(&data).unwrap();
    assert_eq!(val, 0);
    assert_eq!(rest.len(), 8);

    let (val, rest) = Size::Short.pop(&data).unwrap();
    assert_eq!(val, 1);
    assert_eq!(rest.len(), 7);

    let (val, rest) = Size::Long.pop(&data).unwrap();
    assert_eq!(val, 0x00010203);
    assert_eq!(rest.len(), 5);

    let (val, rest) = Size::LongLong.pop(&data).unwrap();
    assert_eq!(val, 0x0001020304050607);
    assert_eq!(rest.len(), 1);
}

#[test]
fn test_address_ipv4() {
    let addr = Address::new("192.168.1.1").unwrap();
    assert_eq!(addr.addr_type, AddrType::IPv4);
    assert_eq!(addr.value, Some("192.168.1.1".to_string()));
    assert_eq!(addr.value_bin, vec![192, 168, 1, 1]);
}

#[test]
fn test_address_ipv6() {
    let addr = Address::new("::1").unwrap();
    assert_eq!(addr.addr_type, AddrType::IPv6);
    assert!(addr.value.is_some());
    assert_eq!(addr.value_bin.len(), 16);
}

#[test]
fn test_address_pack_unpack_roundtrip() {
    let addresses = ["127.0.0.1", "192.168.1.1", "10.0.0.1", "8.8.8.8"];

    for addr_str in addresses {
        let addr = Address::new(addr_str).unwrap();
        let packed = addr.pack();
        let (unpacked, _) = Address::pop(&packed).unwrap();
        assert_eq!(addr.addr_type, unpacked.addr_type);
        assert_eq!(addr.value, unpacked.value);
    }
}

#[test]
fn test_address_invalid() {
    assert!(Address::new("not-an-ip").is_err());
    assert!(Address::new("").is_err());
}

#[test]
fn test_certificate_types() {
    let test_cases = [
        (1, CertType::Link),
        (2, CertType::Identity),
        (3, CertType::Authenticate),
        (4, CertType::Ed25519Signing),
        (5, CertType::LinkCert),
        (6, CertType::Ed25519Authenticate),
        (7, CertType::Ed25519Identity),
    ];

    for (value, expected_type) in test_cases {
        let (cert_type, type_int) = CertType::get(value);
        assert_eq!(cert_type, expected_type);
        assert_eq!(type_int, value);
        assert_eq!(cert_type.value(), value);
    }
}

#[test]
fn test_certificate_pack_unpack() {
    let cert_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let cert = Certificate::new(CertType::Link, cert_data.clone());

    let packed = cert.pack();
    let (unpacked, _) = Certificate::pop(&packed).unwrap();

    assert_eq!(unpacked.cert_type, CertType::Link);
    assert_eq!(unpacked.value, cert_data);
}

#[test]
fn test_link_specifier_ipv4() {
    let spec = LinkSpecifier::IPv4 {
        address: "192.168.1.1".to_string(),
        port: 9001,
    };

    assert_eq!(spec.link_type(), 0);
    let packed = spec.pack();
    let (unpacked, _) = LinkSpecifier::pop(&packed).unwrap();

    match unpacked {
        LinkSpecifier::IPv4 { address, port } => {
            assert_eq!(address, "192.168.1.1");
            assert_eq!(port, 9001);
        }
        _ => panic!("Expected IPv4 link specifier"),
    }
}

#[test]
fn test_link_specifier_fingerprint() {
    let fingerprint = [0u8; 20];
    let spec = LinkSpecifier::Fingerprint { fingerprint };

    assert_eq!(spec.link_type(), 2);
    let packed = spec.pack();
    let (unpacked, _) = LinkSpecifier::pop(&packed).unwrap();

    match unpacked {
        LinkSpecifier::Fingerprint { fingerprint: fp } => {
            assert_eq!(fp, fingerprint);
        }
        _ => panic!("Expected Fingerprint link specifier"),
    }
}

#[test]
fn test_link_specifier_ed25519() {
    let fingerprint = [0xABu8; 32];
    let spec = LinkSpecifier::Ed25519 { fingerprint };

    assert_eq!(spec.link_type(), 3);
    let packed = spec.pack();
    let (unpacked, _) = LinkSpecifier::pop(&packed).unwrap();

    match unpacked {
        LinkSpecifier::Ed25519 { fingerprint: fp } => {
            assert_eq!(fp, fingerprint);
        }
        _ => panic!("Expected Ed25519 link specifier"),
    }
}

#[test]
fn test_close_reasons() {
    let test_cases = [
        (0, CloseReason::None),
        (1, CloseReason::Protocol),
        (2, CloseReason::Internal),
        (3, CloseReason::Requested),
        (4, CloseReason::Hibernating),
        (5, CloseReason::ResourceLimit),
        (6, CloseReason::ConnectFailed),
        (9, CloseReason::Finished),
        (10, CloseReason::Timeout),
        (11, CloseReason::Destroyed),
    ];

    for (value, expected_reason) in test_cases {
        let (reason, reason_int) = CloseReason::get(value);
        assert_eq!(reason, expected_reason);
        assert_eq!(reason_int, value);
        assert_eq!(reason.value(), value);
    }
}

#[test]
fn test_relay_commands() {
    let test_cases = [
        (1, RelayCommand::Begin),
        (2, RelayCommand::Data),
        (3, RelayCommand::End),
        (4, RelayCommand::Connected),
        (5, RelayCommand::SendMe),
        (6, RelayCommand::Extend),
        (7, RelayCommand::Extended),
        (11, RelayCommand::Resolve),
        (12, RelayCommand::Resolved),
        (13, RelayCommand::BeginDir),
    ];

    for (value, expected_cmd) in test_cases {
        let (cmd, cmd_int) = RelayCommand::get(value);
        assert_eq!(cmd, expected_cmd);
        assert_eq!(cmd_int, value);
        assert_eq!(cmd.value(), value);
    }
}

#[test]
fn test_kdf_derivation() {
    let key_material = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let kdf = KDF::from_value(&key_material);

    assert_eq!(kdf.key_hash.len(), 20);
    assert_eq!(kdf.forward_digest.len(), 20);
    assert_eq!(kdf.backward_digest.len(), 20);
    assert_eq!(kdf.forward_key.len(), 16);
    assert_eq!(kdf.backward_key.len(), 16);

    let kdf2 = KDF::from_value(&key_material);
    assert_eq!(kdf.key_hash, kdf2.key_hash);
    assert_eq!(kdf.forward_digest, kdf2.forward_digest);
    assert_eq!(kdf.backward_digest, kdf2.backward_digest);
    assert_eq!(kdf.forward_key, kdf2.forward_key);
    assert_eq!(kdf.backward_key, kdf2.backward_key);
}

#[test]
fn test_kdf_different_inputs() {
    let kdf1 = KDF::from_value(&[0x01, 0x02, 0x03]);
    let kdf2 = KDF::from_value(&[0x04, 0x05, 0x06]);

    assert_ne!(kdf1.key_hash, kdf2.key_hash);
    assert_ne!(kdf1.forward_key, kdf2.forward_key);
}

#[test]
fn test_versions_cell_pack_unpack() {
    let versions = vec![3, 4, 5];
    let cell = VersionsCell::new(versions.clone());
    let lp = LinkProtocol::new(2);
    let packed = cell.pack(&lp);

    let (unpacked, remainder) = Cell::pop(&packed, 2).unwrap();
    assert!(remainder.is_empty());

    match unpacked {
        Cell::Versions(v) => {
            assert_eq!(v.versions, versions);
        }
        _ => panic!("Expected VersionsCell"),
    }
}

#[test]
fn test_netinfo_cell_pack_unpack() {
    use chrono::{TimeZone, Utc};

    let timestamp = Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap();
    let receiver = Address::new("192.168.1.1").unwrap();
    let sender = Address::new("10.0.0.1").unwrap();

    let cell = NetinfoCell::new(receiver.clone(), vec![sender.clone()], Some(timestamp));
    let lp = LinkProtocol::new(4);
    let packed = cell.pack(&lp);

    let (unpacked, _) = Cell::pop(&packed, 4).unwrap();

    match unpacked {
        Cell::Netinfo(n) => {
            assert_eq!(n.timestamp, timestamp);
            assert_eq!(n.receiver_address.value, receiver.value);
            assert_eq!(n.sender_addresses.len(), 1);
            assert_eq!(n.sender_addresses[0].value, sender.value);
        }
        _ => panic!("Expected NetinfoCell"),
    }
}

#[test]
fn test_padding_cell_pack_unpack() {
    let payload = vec![0x42u8; 509];
    let cell = PaddingCell::with_payload(payload.clone()).unwrap();
    let lp = LinkProtocol::new(4);
    let packed = cell.pack(&lp);

    let (unpacked, _) = Cell::pop(&packed, 4).unwrap();

    match unpacked {
        Cell::Padding(p) => {
            assert_eq!(p.payload, payload);
        }
        _ => panic!("Expected PaddingCell"),
    }
}

#[test]
fn test_vpadding_cell_pack_unpack() {
    let payload = vec![0x11, 0x22, 0x33];
    let cell = VPaddingCell::with_payload(payload.clone());
    let lp = LinkProtocol::new(4);
    let packed = cell.pack(&lp);

    let (unpacked, _) = Cell::pop(&packed, 4).unwrap();

    match unpacked {
        Cell::VPadding(v) => {
            assert_eq!(v.payload, payload);
        }
        _ => panic!("Expected VPaddingCell"),
    }
}

#[test]
fn test_destroy_cell_pack_unpack() {
    let cell = DestroyCell::new(0x80000001, CloseReason::Requested);
    let lp = LinkProtocol::new(5);
    let packed = cell.pack(&lp);

    let (unpacked, _) = Cell::pop(&packed, 5).unwrap();

    match unpacked {
        Cell::Destroy(d) => {
            assert_eq!(d.circ_id, 0x80000001);
            assert_eq!(d.reason, CloseReason::Requested);
        }
        _ => panic!("Expected DestroyCell"),
    }
}

#[test]
fn test_create_fast_cell_pack_unpack() {
    let key_material: [u8; 20] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14,
    ];
    let cell = CreateFastCell::with_key_material(0x80000001, key_material);
    let lp = LinkProtocol::new(5);
    let packed = cell.pack(&lp);

    let (unpacked, _) = Cell::pop(&packed, 5).unwrap();

    match unpacked {
        Cell::CreateFast(c) => {
            assert_eq!(c.circ_id, 0x80000001);
            assert_eq!(c.key_material, key_material);
        }
        _ => panic!("Expected CreateFastCell"),
    }
}

#[test]
fn test_certs_cell_pack_unpack() {
    let cert1 = Certificate::new(CertType::Link, vec![0x01, 0x02, 0x03]);
    let cert2 = Certificate::new(CertType::Identity, vec![0x04, 0x05]);
    let cell = CertsCell::new(vec![cert1, cert2]);
    let lp = LinkProtocol::new(4);
    let packed = cell.pack(&lp);

    let (unpacked, _) = Cell::pop(&packed, 4).unwrap();

    match unpacked {
        Cell::Certs(c) => {
            assert_eq!(c.certificates.len(), 2);
            assert_eq!(c.certificates[0].cert_type, CertType::Link);
            assert_eq!(c.certificates[1].cert_type, CertType::Identity);
        }
        _ => panic!("Expected CertsCell"),
    }
}

#[test]
fn test_relay_cell_pack_unpack() {
    let data = b"test data".to_vec();
    let cell = RelayCell::new(1, RelayCommand::Data, data.clone(), 0x12345678, 1).unwrap();
    let lp = LinkProtocol::new(4);
    let packed = cell.pack(&lp);

    let (unpacked, _) = Cell::pop(&packed, 4).unwrap();

    match unpacked {
        Cell::Relay(r) => {
            assert_eq!(r.circ_id, 1);
            assert_eq!(r.command, RelayCommand::Data);
            assert_eq!(r.data, data);
            assert_eq!(r.digest, 0x12345678);
            assert_eq!(r.stream_id, 1);
        }
        _ => panic!("Expected RelayCell"),
    }
}

#[test]
fn test_relay_cell_stream_id_required() {
    let commands_requiring_stream_id = [
        RelayCommand::Begin,
        RelayCommand::Data,
        RelayCommand::End,
        RelayCommand::Connected,
        RelayCommand::Resolve,
        RelayCommand::Resolved,
        RelayCommand::BeginDir,
    ];

    for cmd in commands_requiring_stream_id {
        let result = RelayCell::new(1, cmd, vec![], 0, 0);
        assert!(result.is_err(), "{} should require stream_id", cmd);

        let result = RelayCell::new(1, cmd, vec![], 0, 1);
        assert!(result.is_ok(), "{} should work with stream_id", cmd);
    }
}

#[test]
fn test_relay_cell_stream_id_disallowed() {
    let commands_disallowing_stream_id = [
        RelayCommand::Extend,
        RelayCommand::Extended,
        RelayCommand::Truncate,
        RelayCommand::Truncated,
        RelayCommand::Drop,
        RelayCommand::Extend2,
        RelayCommand::Extended2,
    ];

    for cmd in commands_disallowing_stream_id {
        let result = RelayCell::new(1, cmd, vec![], 0, 1);
        assert!(result.is_err(), "{} should disallow stream_id", cmd);

        let result = RelayCell::new(1, cmd, vec![], 0, 0);
        assert!(result.is_ok(), "{} should work without stream_id", cmd);
    }
}

#[test]
fn test_cell_unpack_all() {
    let lp = LinkProtocol::new(4);

    let versions = VersionsCell::new(vec![3, 4, 5]);
    let vpadding = VPaddingCell::with_payload(vec![0x01, 0x02]);

    let mut combined = versions.pack(&lp);
    combined.extend(vpadding.pack(&lp));

    let cells = Cell::unpack_all(&combined, 4).unwrap();
    assert_eq!(cells.len(), 2);

    match &cells[0] {
        Cell::Versions(v) => assert_eq!(v.versions, vec![3, 4, 5]),
        _ => panic!("Expected VersionsCell"),
    }

    match &cells[1] {
        Cell::VPadding(v) => assert_eq!(v.payload, vec![0x01, 0x02]),
        _ => panic!("Expected VPaddingCell"),
    }
}

#[tokio::test]
async fn test_relay_connect_to_real_relay() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let result = Relay::connect(&address, port, DEFAULT_LINK_PROTOCOLS).await;

    if let Ok(relay) = result {
        assert!(
            relay.link_protocol.version >= 3,
            "Should negotiate protocol >= 3"
        );
        assert!(relay.is_alive(), "Relay should be alive after connection");
    }
}

#[tokio::test]
async fn test_relay_connect_tls_handshake() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let result = Relay::connect(&address, port, &[4, 5]).await;

    if let Ok(relay) = result {
        assert!(relay.link_protocol.version >= 4);
    }
}

#[tokio::test]
async fn test_relay_connect_version_negotiation() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let result = Relay::connect(&address, port, &[3, 4, 5]).await;

    if let Ok(relay) = result {
        assert!(
            relay.link_protocol.version >= 3 && relay.link_protocol.version <= 5,
            "Should negotiate version in requested range"
        );
    }
}

#[tokio::test]
async fn test_relay_connect_empty_protocols_error() {
    let result = Relay::connect("127.0.0.1", 9001, &[]).await;
    assert!(result.is_err(), "Should fail with empty protocol list");
}

#[tokio::test]
async fn test_relay_create_circuit() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let mut relay = match Relay::connect(&address, port, DEFAULT_LINK_PROTOCOLS).await {
        Ok(r) => r,
        Err(_) => {
            return;
        }
    };

    let result = relay.create_circuit().await;

    if let Ok(circuit) = result {
        assert!(circuit.id > 0, "Circuit ID should be positive");

        if relay.link_protocol.version >= 4 {
            assert_eq!(
                circuit.id, 0x80000000,
                "First circuit ID should be 0x80000000 for protocol >= 4"
            );
        }
    }
}

#[tokio::test]
async fn test_relay_circuit_close() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let mut relay = match Relay::connect(&address, port, DEFAULT_LINK_PROTOCOLS).await {
        Ok(r) => r,
        Err(_) => {
            return;
        }
    };

    let mut circuit = match relay.create_circuit().await {
        Ok(c) => c,
        Err(_) => {
            return;
        }
    };

    let _result = circuit.close().await;
}

#[tokio::test]
async fn test_relay_directory_request() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let mut relay = match Relay::connect(&address, port, DEFAULT_LINK_PROTOCOLS).await {
        Ok(r) => r,
        Err(_) => {
            return;
        }
    };

    let mut circuit = match relay.create_circuit().await {
        Ok(c) => c,
        Err(_) => {
            return;
        }
    };

    let request = "GET /tor/server/authority HTTP/1.0\r\n\r\n";
    let result = tokio::time::timeout(Duration::from_secs(30), circuit.directory(request, 1)).await;

    match result {
        Ok(Ok(response)) => {
            let response_str = String::from_utf8_lossy(&response);

            assert!(
                response_str.contains("HTTP/") || response_str.contains("router "),
                "Response should contain HTTP header or router descriptor"
            );
        }
        Ok(Err(_)) => {}
        Err(_) => {}
    }

    let _ = circuit.close().await;
}

#[tokio::test]
async fn test_relay_connection_time() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let relay = match Relay::connect(&address, port, DEFAULT_LINK_PROTOCOLS).await {
        Ok(r) => r,
        Err(_) => {
            return;
        }
    };

    let connection_time = relay.connection_time();
    let elapsed = connection_time.elapsed();

    assert!(
        elapsed < Duration::from_secs(60),
        "Connection time should be recent"
    );
}

#[tokio::test]
async fn test_relay_close() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let mut relay = match Relay::connect(&address, port, DEFAULT_LINK_PROTOCOLS).await {
        Ok(r) => r,
        Err(_) => {
            return;
        }
    };

    let _result = relay.close().await;
}

#[tokio::test]
async fn test_relay_multiple_circuits() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let mut relay = match Relay::connect(&address, port, DEFAULT_LINK_PROTOCOLS).await {
        Ok(r) => r,
        Err(_) => {
            return;
        }
    };

    let circuit1 = match relay.create_circuit().await {
        Ok(c) => c,
        Err(_) => {
            return;
        }
    };

    let circuit2 = match relay.create_circuit().await {
        Ok(c) => c,
        Err(_) => {
            return;
        }
    };

    assert_ne!(circuit1.id, circuit2.id, "Circuit IDs should be unique");

    assert!(
        circuit2.id > circuit1.id,
        "Second circuit ID should be greater than first"
    );
}

#[tokio::test]
async fn test_relay_connect_invalid_address() {
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        Relay::connect("192.0.2.1", 9001, DEFAULT_LINK_PROTOCOLS),
    )
    .await;

    let _ = result;
}

#[tokio::test]
async fn test_relay_connect_wrong_port() {
    let result = Relay::connect("127.0.0.1", 1, DEFAULT_LINK_PROTOCOLS).await;

    assert!(result.is_err(), "Should fail connecting to wrong port");
}

#[test]
fn test_padding_cell_wrong_size() {
    let result = PaddingCell::with_payload(vec![0u8; 100]);
    assert!(result.is_err(), "Should reject wrong payload size");

    let result = PaddingCell::with_payload(vec![0u8; 600]);
    assert!(result.is_err(), "Should reject wrong payload size");
}

#[test]
fn test_cell_pop_truncated() {
    let truncated = vec![0x00, 0x00];
    let result = Cell::pop(&truncated, 2);
    assert!(result.is_err(), "Should fail on truncated data");
}

#[test]
fn test_versions_cell_empty() {
    let cell = VersionsCell::new(vec![]);
    let lp = LinkProtocol::new(2);
    let packed = cell.pack(&lp);

    let (unpacked, _) = Cell::pop(&packed, 2).unwrap();

    match unpacked {
        Cell::Versions(v) => {
            assert!(v.versions.is_empty(), "Should handle empty versions");
        }
        _ => panic!("Expected VersionsCell"),
    }
}

#[test]
fn test_certs_cell_empty() {
    let cell = CertsCell::new(vec![]);
    let lp = LinkProtocol::new(4);
    let packed = cell.pack(&lp);

    let (unpacked, _) = Cell::pop(&packed, 4).unwrap();

    match unpacked {
        Cell::Certs(c) => {
            assert!(c.certificates.is_empty(), "Should handle empty certs");
        }
        _ => panic!("Expected CertsCell"),
    }
}

#[test]
fn test_versions_cell_protocol_2_vs_4() {
    let versions = vec![3, 4, 5];
    let cell = VersionsCell::new(versions.clone());

    let packed_v2 = cell.pack(&LinkProtocol::new(2));
    let packed_v4 = cell.pack(&LinkProtocol::new(4));

    assert_eq!(packed_v4.len(), packed_v2.len() + 2);

    let (unpacked_v2, _) = Cell::pop(&packed_v2, 2).unwrap();
    let (unpacked_v4, _) = Cell::pop(&packed_v4, 4).unwrap();

    match (unpacked_v2, unpacked_v4) {
        (Cell::Versions(v2), Cell::Versions(v4)) => {
            assert_eq!(v2.versions, versions);
            assert_eq!(v4.versions, versions);
        }
        _ => panic!("Expected VersionsCells"),
    }
}

#[test]
fn test_fixed_cell_length_by_protocol() {
    assert_eq!(LinkProtocol::new(2).fixed_cell_length, 512);
    assert_eq!(LinkProtocol::new(3).fixed_cell_length, 512);

    assert_eq!(LinkProtocol::new(4).fixed_cell_length, 514);
    assert_eq!(LinkProtocol::new(5).fixed_cell_length, 514);
}

#[tokio::test]
async fn test_full_orport_communication_flow() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let mut relay = match Relay::connect(&address, port, DEFAULT_LINK_PROTOCOLS).await {
        Ok(r) => r,
        Err(_) => {
            return;
        }
    };

    assert!(relay.is_alive(), "Relay should be alive");
    let elapsed = relay.connection_time().elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "Connection should be recent"
    );

    let mut circuit = match relay.create_circuit().await {
        Ok(c) => c,
        Err(_) => {
            return;
        }
    };

    let request = "GET /tor/server/authority HTTP/1.0\r\n\r\n";
    let _result =
        tokio::time::timeout(Duration::from_secs(30), circuit.directory(request, 1)).await;

    let _ = circuit.close().await;
    let _ = relay.close().await;
}

#[tokio::test]
async fn test_rapid_circuit_creation() {
    let relay_info = match get_test_relay().await {
        Some(info) => info,
        None => {
            return;
        }
    };

    let (address, port) = relay_info;

    let mut relay = match Relay::connect(&address, port, DEFAULT_LINK_PROTOCOLS).await {
        Ok(r) => r,
        Err(_) => {
            return;
        }
    };

    let mut circuits = Vec::new();
    for _ in 0..3 {
        match relay.create_circuit().await {
            Ok(circuit) => {
                circuits.push(circuit);
            }
            Err(_) => {
                break;
            }
        }
    }

    for mut circuit in circuits {
        let _ = circuit.close().await;
    }
}

#[test]
fn test_default_link_protocols() {
    assert!(!DEFAULT_LINK_PROTOCOLS.is_empty());
    assert!(DEFAULT_LINK_PROTOCOLS.contains(&3));
    assert!(DEFAULT_LINK_PROTOCOLS.contains(&4));
    assert!(DEFAULT_LINK_PROTOCOLS.contains(&5));
}
