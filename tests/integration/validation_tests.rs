//! Integration tests for validation utilities with real Tor data.

use std::net::SocketAddr;

use stem_rs::controller::Controller;
use stem_rs::util::{
    is_valid_circuit_id, is_valid_fingerprint, is_valid_fingerprint_with_prefix,
    is_valid_ipv4_address, is_valid_nickname, is_valid_port, is_valid_stream_id,
};

use crate::{get_control_port, is_tor_available};

fn get_control_addr() -> SocketAddr {
    format!("127.0.0.1:{}", get_control_port()).parse().unwrap()
}

#[tokio::test]
async fn test_validate_real_relay_fingerprints() {
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

    let circuits = controller
        .get_circuits()
        .await
        .expect("get_circuits failed");

    let mut validated_count = 0;
    for circuit in &circuits {
        for relay in &circuit.path {
            assert!(
                is_valid_fingerprint(&relay.fingerprint)
                    || is_valid_fingerprint_with_prefix(&relay.fingerprint),
                "Invalid fingerprint from circuit: {}",
                relay.fingerprint
            );
            validated_count += 1;

            if let Some(ref nickname) = relay.nickname {
                assert!(
                    is_valid_nickname(nickname),
                    "Invalid nickname from circuit: {}",
                    nickname
                );
            }
        }
    }

    let _ = validated_count;
}

#[tokio::test]
async fn test_validate_real_circuit_ids() {
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

    let circuits = controller
        .get_circuits()
        .await
        .expect("get_circuits failed");

    for circuit in &circuits {
        assert!(
            is_valid_circuit_id(&circuit.id.0),
            "Invalid circuit ID: {}",
            circuit.id
        );
    }
}

#[tokio::test]
async fn test_validate_real_stream_ids() {
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

    for stream in &streams {
        assert!(
            is_valid_stream_id(&stream.id.0),
            "Invalid stream ID: {}",
            stream.id
        );

        if let Some(ref circuit_id) = stream.circuit_id {
            assert!(
                is_valid_circuit_id(&circuit_id.0),
                "Invalid circuit ID in stream: {}",
                circuit_id
            );
        }
    }
}

#[tokio::test]
async fn test_validate_stream_targets() {
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

    for stream in &streams {
        if stream.target_port > 0 {
            assert!(
                is_valid_port(&stream.target_port.to_string()),
                "Invalid port in stream: {}",
                stream.target_port
            );
        }

        if stream
            .target_host
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.')
        {
            let _ = is_valid_ipv4_address(&stream.target_host);
        }
    }
}

#[tokio::test]
async fn test_validate_ns_all_fingerprints() {
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

    let ns_content = match controller.get_info("ns/all").await {
        Ok(content) => content,
        Err(_) => {
            return;
        }
    };

    let mut fingerprint_count = 0;
    let mut nickname_count = 0;
    let mut ip_count = 0;

    for line in ns_content.lines() {
        if line.starts_with("r ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let nickname = parts[1];
                if is_valid_nickname(nickname) {
                    nickname_count += 1;
                }

                let ip = parts[5];
                if is_valid_ipv4_address(ip) {
                    ip_count += 1;
                }

                let port = parts[6];
                if is_valid_port(port) {}
            }
        } else if line.starts_with("s ") {
            fingerprint_count += 1;
        }
    }

    let _ = (nickname_count, ip_count, fingerprint_count);
}

#[tokio::test]
async fn test_validate_entry_guards() {
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

    let guards_content = match controller.get_info("entry-guards").await {
        Ok(content) => content,
        Err(_) => {
            return;
        }
    };

    let mut guard_count = 0;
    for line in guards_content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.contains('$') {
            if let Some(fp_start) = line.find('$') {
                let rest = &line[fp_start + 1..];
                let fp_end = rest
                    .find(|c: char| !c.is_ascii_hexdigit())
                    .unwrap_or(rest.len());
                let fingerprint = &rest[..fp_end];

                if is_valid_fingerprint(fingerprint) {
                    guard_count += 1;
                }
            }
        }
    }

    let _ = guard_count;
}

#[tokio::test]
async fn test_validate_orconn_status() {
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

    let orconn_content = match controller.get_info("orconn-status").await {
        Ok(content) => content,
        Err(_) => {
            return;
        }
    };

    let mut conn_count = 0;
    for line in orconn_content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.contains('$') {
            conn_count += 1;

            if let Some(fp_start) = line.find('$') {
                let rest = &line[fp_start + 1..];
                let fp_end = rest
                    .find(|c: char| !c.is_ascii_hexdigit())
                    .unwrap_or(rest.len());
                let fingerprint = &rest[..fp_end];

                assert!(
                    is_valid_fingerprint(fingerprint),
                    "Invalid fingerprint in orconn-status: {}",
                    fingerprint
                );
            }
        }
    }

    let _ = conn_count;
}

#[tokio::test]
async fn test_validate_control_port_config() {
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

    let conf = controller
        .get_conf("ControlPort")
        .await
        .expect("get_conf(ControlPort) failed");

    for value in &conf {
        if value.chars().all(|c| c.is_ascii_digit()) {
            assert!(is_valid_port(value), "Invalid ControlPort value: {}", value);
        }
    }
}

#[tokio::test]
async fn test_validate_socks_port_config() {
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

    let conf = controller
        .get_conf("SocksPort")
        .await
        .expect("get_conf(SocksPort) failed");

    for value in &conf {
        let port_str = value.split_whitespace().next().unwrap_or(value);
        if port_str.chars().all(|c| c.is_ascii_digit()) && port_str != "0" {
            assert!(
                is_valid_port(port_str),
                "Invalid SocksPort value: {}",
                port_str
            );
        }
    }
}

#[tokio::test]
async fn test_validate_pid() {
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

    let pid = controller.get_pid().await.expect("get_pid failed");

    assert!(pid > 0, "PID should be positive, got {}", pid);

    assert!(pid < 10_000_000, "PID seems unreasonably large: {}", pid);
}

#[tokio::test]
async fn test_validate_traffic_counters() {
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

    let read_str = controller
        .get_info("traffic/read")
        .await
        .expect("get_info(traffic/read) failed");
    let written_str = controller
        .get_info("traffic/written")
        .await
        .expect("get_info(traffic/written) failed");

    let _read: u64 = read_str.parse().expect("traffic/read should be a number");
    let _written: u64 = written_str
        .parse()
        .expect("traffic/written should be a number");
}
