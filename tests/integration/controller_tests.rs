//! Integration tests for Controller API and events against a real Tor process.

use std::net::SocketAddr;
use std::time::Duration;

use stem_rs::controller::Controller;
use stem_rs::version::Version;
use stem_rs::{EventType, Signal};

use crate::{get_control_port, is_tor_available};

fn get_control_addr() -> SocketAddr {
    format!("127.0.0.1:{}", get_control_port()).parse().unwrap()
}

#[tokio::test]
async fn test_controller_from_port() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let result = Controller::from_port(addr).await;
    assert!(
        result.is_ok(),
        "Failed to create controller: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_controller_authenticate() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    let result = controller.authenticate(None).await;
    assert!(result.is_ok(), "Authentication failed: {:?}", result.err());
}

#[tokio::test]
async fn test_get_version() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let version = controller.get_version().await;
    assert!(version.is_ok(), "get_version failed: {:?}", version.err());

    let ver = version.unwrap();
    assert!(
        ver.major == 0 && ver.minor >= 4,
        "Expected Tor 0.4.x or higher, got {}",
        ver
    );
}

#[tokio::test]
async fn test_get_pid() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let pid = controller.get_pid().await;
    assert!(pid.is_ok(), "get_pid failed: {:?}", pid.err());

    let pid_value = pid.unwrap();
    assert!(pid_value > 0, "PID should be positive, got {}", pid_value);
}

#[tokio::test]
async fn test_get_info_version() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let info = controller.get_info("version").await;
    assert!(info.is_ok(), "get_info(version) failed: {:?}", info.err());

    let version_str = info.unwrap();
    assert!(
        version_str.contains('.'),
        "Version should contain dots: {}",
        version_str
    );
}

#[tokio::test]
async fn test_get_info_config_file() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let info = controller.get_info("config-file").await;
    assert!(
        info.is_ok(),
        "get_info(config-file) failed: {:?}",
        info.err()
    );
}

#[tokio::test]
async fn test_get_info_traffic() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let read_info = controller.get_info("traffic/read").await;
    assert!(
        read_info.is_ok(),
        "get_info(traffic/read) failed: {:?}",
        read_info.err()
    );

    let written_info = controller.get_info("traffic/written").await;
    assert!(
        written_info.is_ok(),
        "get_info(traffic/written) failed: {:?}",
        written_info.err()
    );

    let read_str = read_info.unwrap();
    let _read: u64 = read_str.parse().expect("traffic/read should be a number");

    let written_str = written_info.unwrap();
    let _written: u64 = written_str
        .parse()
        .expect("traffic/written should be a number");
}

#[tokio::test]
async fn test_get_conf_socksport() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let conf = controller.get_conf("SocksPort").await;
    assert!(conf.is_ok(), "get_conf(SocksPort) failed: {:?}", conf.err());

    let values = conf.unwrap();
    assert!(
        !values.is_empty(),
        "SocksPort should have at least one value"
    );
}

#[tokio::test]
async fn test_get_conf_controlport() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let conf = controller.get_conf("ControlPort").await;
    assert!(
        conf.is_ok(),
        "get_conf(ControlPort) failed: {:?}",
        conf.err()
    );
}

#[tokio::test]
async fn test_signal_newnym() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.signal(Signal::Newnym).await;
    assert!(result.is_ok(), "signal(NEWNYM) failed: {:?}", result.err());
}

#[tokio::test]
async fn test_signal_cleardnscache() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.signal(Signal::ClearDnsCache).await;
    assert!(
        result.is_ok(),
        "signal(CLEARDNSCACHE) failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_get_circuits() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let circuits = controller.get_circuits().await;
    assert!(
        circuits.is_ok(),
        "get_circuits failed: {:?}",
        circuits.err()
    );

    let circuit_list = circuits.unwrap();
    let _ = circuit_list.len();
}

#[tokio::test]
async fn test_get_streams() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let streams = controller.get_streams().await;
    assert!(streams.is_ok(), "get_streams failed: {:?}", streams.err());

    let stream_list = streams.unwrap();
    let _ = stream_list.len();
}

#[tokio::test]
async fn test_new_circuit_and_close() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let circuit_result = controller.new_circuit(None).await;

    if let Ok(circuit_id) = circuit_result {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let _close_result = controller.close_circuit(&circuit_id).await;
    }
}

#[tokio::test]
async fn test_set_events_bw() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.set_events(&[EventType::Bw]).await;
    assert!(result.is_ok(), "set_events(BW) failed: {:?}", result.err());

    let result = controller.set_events(&[]).await;
    assert!(result.is_ok(), "set_events([]) failed: {:?}", result.err());
}

#[tokio::test]
async fn test_set_events_multiple() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let events = [
        EventType::Bw,
        EventType::Circ,
        EventType::Stream,
        EventType::Notice,
    ];
    let result = controller.set_events(&events).await;
    assert!(
        result.is_ok(),
        "set_events(multiple) failed: {:?}",
        result.err()
    );

    let result = controller.set_events(&[]).await;
    assert!(result.is_ok(), "set_events([]) failed: {:?}", result.err());
}

#[tokio::test]
async fn test_recv_bandwidth_event() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    controller
        .set_events(&[EventType::Bw])
        .await
        .expect("set_events failed");

    let event_result = tokio::time::timeout(Duration::from_secs(5), controller.recv_event()).await;

    let _ = controller.set_events(&[]).await;

    let _ = event_result;
}

#[tokio::test]
async fn test_map_address() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let _result = controller
        .map_address("test.example.com", "127.0.0.1")
        .await;
}

#[tokio::test]
async fn test_msg_raw_command() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.msg("GETINFO version").await;
    assert!(
        result.is_ok(),
        "msg(GETINFO version) failed: {:?}",
        result.err()
    );

    let response = result.unwrap();
    assert!(
        response.contains("250"),
        "Response should contain 250 status"
    );
}

#[tokio::test]
async fn test_multiple_getinfo_calls() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let keys = [
        "version",
        "config-file",
        "process/pid",
        "traffic/read",
        "traffic/written",
    ];

    for key in keys {
        let result = controller.get_info(key).await;
        assert!(
            result.is_ok(),
            "get_info({}) failed: {:?}",
            key,
            result.err()
        );
    }
}

#[tokio::test]
async fn test_get_info_address() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let _result = controller.get_info("address").await;
}

#[tokio::test]
async fn test_get_info_fingerprint() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.get_info("fingerprint").await;
    if let Ok(fingerprint) = result {
        assert_eq!(fingerprint.len(), 40, "Fingerprint should be 40 hex chars");
    }
}

#[tokio::test]
async fn test_get_conf_unknown_key() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.get_conf("UnknownConfigKey12345").await;
    assert!(result.is_err(), "get_conf with unknown key should fail");
}

#[tokio::test]
async fn test_signal_heartbeat() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.signal(Signal::Heartbeat).await;
    assert!(
        result.is_ok(),
        "signal(HEARTBEAT) failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_circuit_status_info() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.get_info("circuit-status").await;
    assert!(
        result.is_ok(),
        "get_info(circuit-status) failed: {:?}",
        result.err()
    );

    let status = result.unwrap();
    let _ = status;
}

#[tokio::test]
async fn test_stream_status_info() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.get_info("stream-status").await;
    assert!(
        result.is_ok(),
        "get_info(stream-status) failed: {:?}",
        result.err()
    );

    let status = result.unwrap();
    let _ = status;
}

#[tokio::test]
async fn test_orconn_status_info() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.get_info("orconn-status").await;
    assert!(
        result.is_ok(),
        "get_info(orconn-status) failed: {:?}",
        result.err()
    );

    let status = result.unwrap();
    let _ = status;
}

#[tokio::test]
async fn test_entry_guards_info() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.get_info("entry-guards").await;
    let _ = result;
}

#[tokio::test]
async fn test_get_version_comparison() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let version = controller.get_version().await.expect("get_version failed");

    let min_version = Version::new(0, 4, 0);
    assert!(
        version >= min_version,
        "Tor version {} should be >= {}",
        version,
        min_version
    );
}

#[tokio::test]
async fn test_get_version_components() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let version = controller.get_version().await.expect("get_version failed");

    assert_eq!(version.major, 0, "Tor major version should be 0");
    assert!(version.minor >= 4, "Tor minor version should be >= 4");
}

#[tokio::test]
async fn test_get_conf_multiple_keys() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let keys = ["SocksPort", "ControlPort", "DataDirectory"];

    for key in keys {
        let _result = controller.get_conf(key).await;
    }
}

#[tokio::test]
async fn test_get_conf_log() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let _result = controller.get_conf("Log").await;
}

#[tokio::test]
async fn test_get_conf_hidden_service_options() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let keys = ["HiddenServiceDir", "HiddenServicePort"];

    for key in keys {
        let _result = controller.get_conf(key).await;
    }
}

#[tokio::test]
async fn test_signal_dump() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.signal(Signal::Dump).await;
    assert!(result.is_ok(), "signal(DUMP) failed: {:?}", result.err());
}

#[tokio::test]
async fn test_signal_debug() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.signal(Signal::Debug).await;
    assert!(result.is_ok(), "signal(DEBUG) failed: {:?}", result.err());
}

#[tokio::test]
async fn test_signal_active() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let _result = controller.signal(Signal::Active).await;
}

#[tokio::test]
async fn test_signal_dormant() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.signal(Signal::Dormant).await;
    if result.is_ok() {
        let _ = controller.signal(Signal::Active).await;
    }
}

#[tokio::test]
async fn test_get_info_accounting() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let keys = [
        "accounting/enabled",
        "accounting/hibernating",
        "accounting/bytes",
        "accounting/bytes-left",
    ];

    for key in keys {
        let _result = controller.get_info(key).await;
    }
}

#[tokio::test]
async fn test_get_info_dir_server_status() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let keys = [
        "dir-usage",
        "status/clients-seen",
        "status/fresh-relay-descs",
    ];

    for key in keys {
        let _result = controller.get_info(key).await;
    }
}

#[tokio::test]
async fn test_get_info_network_status() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let keys = ["network-status", "ns/all", "ns/purpose/general"];

    for key in keys {
        let _result = controller.get_info(key).await;
    }
}

#[tokio::test]
async fn test_get_info_ip_to_country() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.get_info("ip-to-country/8.8.8.8").await;
    if let Ok(country) = result {
        assert!(!country.is_empty(), "Country should not be empty");
    }
}

#[tokio::test]
async fn test_get_info_uptime() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.get_info("uptime").await;
    if let Ok(uptime_str) = result {
        let _uptime: u64 = uptime_str.parse().expect("uptime should be a number");
    }
}

#[tokio::test]
async fn test_circuit_lifecycle() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let circuit_result = controller.new_circuit(None).await;

    if let Ok(circuit_id) = circuit_result {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let circuits = controller
            .get_circuits()
            .await
            .expect("get_circuits failed");
        let _our_circuit = circuits.iter().find(|c| c.id == circuit_id);

        let _close_result = controller.close_circuit(&circuit_id).await;
    }
}

#[tokio::test]
async fn test_get_circuits_detailed() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let circuits = controller
        .get_circuits()
        .await
        .expect("get_circuits failed");

    let _ = circuits.len();

    for circuit in &circuits {
        let _ = (&circuit.id, circuit.status, circuit.path.len());

        for (i, relay) in circuit.path.iter().enumerate() {
            let _ = (i, relay.fingerprint.as_str(), relay.nickname.as_ref());
        }
    }
}

#[tokio::test]
async fn test_get_streams_detailed() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let streams = controller.get_streams().await.expect("get_streams failed");

    let _ = streams.len();

    for stream in &streams {
        let _ = (
            &stream.id,
            stream.status,
            stream.circuit_id.as_ref(),
            stream.target_host.as_str(),
            stream.target_port,
        );
    }
}

#[tokio::test]
async fn test_msg_getinfo_multiple() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller
        .msg("GETINFO version traffic/read traffic/written")
        .await;
    assert!(
        result.is_ok(),
        "msg(GETINFO multiple) failed: {:?}",
        result.err()
    );

    let response = result.unwrap();

    assert!(
        response.contains("version="),
        "Response should contain version"
    );
    assert!(
        response.contains("traffic/read="),
        "Response should contain traffic/read"
    );
    assert!(
        response.contains("traffic/written="),
        "Response should contain traffic/written"
    );
}

#[tokio::test]
async fn test_msg_signal() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.msg("SIGNAL HEARTBEAT").await;
    assert!(
        result.is_ok(),
        "msg(SIGNAL HEARTBEAT) failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_msg_getconf() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let result = controller.msg("GETCONF SocksPort ControlPort").await;
    assert!(result.is_ok(), "msg(GETCONF) failed: {:?}", result.err());

    let _response = result.unwrap();
}

#[tokio::test]
async fn test_multiple_operations_same_connection() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    for i in 0..10 {
        let version = controller.get_version().await;
        assert!(version.is_ok(), "get_version failed on iteration {}", i);

        let pid = controller.get_pid().await;
        assert!(pid.is_ok(), "get_pid failed on iteration {}", i);

        let circuits = controller.get_circuits().await;
        assert!(circuits.is_ok(), "get_circuits failed on iteration {}", i);
    }
}

#[tokio::test]
async fn test_rapid_getinfo_calls() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut controller = Controller::from_port(addr)
        .await
        .expect("Failed to create controller");
    controller
        .authenticate(None)
        .await
        .expect("Authentication failed");

    let keys = [
        "version",
        "config-file",
        "process/pid",
        "traffic/read",
        "traffic/written",
        "uptime",
    ];

    for _ in 0..5 {
        for key in &keys {
            let result = controller.get_info(key).await;
            assert!(
                result.is_ok(),
                "get_info({}) failed: {:?}",
                key,
                result.err()
            );
        }
    }
}
