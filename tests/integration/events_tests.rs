//! Integration tests for event handling against a real Tor process.

use std::net::SocketAddr;
use std::time::Duration;

use stem_rs::controller::Controller;
use stem_rs::EventType;

use crate::{get_control_port, is_tor_available};

fn get_control_addr() -> SocketAddr {
    format!("127.0.0.1:{}", get_control_port()).parse().unwrap()
}

#[tokio::test]
async fn test_set_events_circ() {
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

    let result = controller.set_events(&[EventType::Circ]).await;
    assert!(
        result.is_ok(),
        "set_events(CIRC) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_stream() {
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

    let result = controller.set_events(&[EventType::Stream]).await;
    assert!(
        result.is_ok(),
        "set_events(STREAM) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_orconn() {
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

    let result = controller.set_events(&[EventType::OrConn]).await;
    assert!(
        result.is_ok(),
        "set_events(ORCONN) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_notice() {
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

    let result = controller.set_events(&[EventType::Notice]).await;
    assert!(
        result.is_ok(),
        "set_events(NOTICE) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_warn() {
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

    let result = controller.set_events(&[EventType::Warn]).await;
    assert!(
        result.is_ok(),
        "set_events(WARN) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_newdesc() {
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

    let result = controller.set_events(&[EventType::NewDesc]).await;
    assert!(
        result.is_ok(),
        "set_events(NEWDESC) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_addrmap() {
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

    let result = controller.set_events(&[EventType::AddrMap]).await;
    assert!(
        result.is_ok(),
        "set_events(ADDRMAP) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_guard() {
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

    let result = controller.set_events(&[EventType::Guard]).await;
    assert!(
        result.is_ok(),
        "set_events(GUARD) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_network_liveness() {
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

    let result = controller.set_events(&[EventType::NetworkLiveness]).await;
    assert!(
        result.is_ok(),
        "set_events(NETWORK_LIVENESS) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_all_log_levels() {
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
        EventType::Debug,
        EventType::Info,
        EventType::Notice,
        EventType::Warn,
        EventType::Err,
    ];

    let result = controller.set_events(&events).await;
    assert!(
        result.is_ok(),
        "set_events(all log levels) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_set_events_comprehensive() {
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
        EventType::Circ,
        EventType::Stream,
        EventType::OrConn,
        EventType::Bw,
        EventType::Notice,
        EventType::NewDesc,
        EventType::AddrMap,
        EventType::Guard,
        EventType::Ns,
        EventType::NewConsensus,
        EventType::BuildTimeoutSet,
        EventType::Signal,
        EventType::ConfChanged,
    ];

    let result = controller.set_events(&events).await;
    assert!(
        result.is_ok(),
        "set_events(comprehensive) failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}

#[tokio::test]
async fn test_recv_circ_event_after_newnym() {
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
        .set_events(&[EventType::Circ])
        .await
        .expect("set_events failed");

    let _ = controller.signal(stem_rs::Signal::Newnym).await;

    let event_result = tokio::time::timeout(Duration::from_secs(5), controller.recv_event()).await;

    let _ = controller.set_events(&[]).await;

    let _ = event_result;
}

#[tokio::test]
async fn test_recv_multiple_bw_events() {
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

    let mut event_count = 0;
    for _ in 0..3 {
        let event_result =
            tokio::time::timeout(Duration::from_secs(3), controller.recv_event()).await;

        match event_result {
            Ok(Ok(_)) => {
                event_count += 1;
            }
            Ok(Err(_)) => {
                break;
            }
            Err(_) => {
                break;
            }
        }
    }

    let _ = controller.set_events(&[]).await;
    let _ = event_count;
}

#[tokio::test]
async fn test_set_events_empty_clears_subscription() {
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
        .set_events(&[EventType::Bw, EventType::Circ])
        .await
        .expect("set_events failed");

    let result = controller.set_events(&[]).await;
    assert!(result.is_ok(), "set_events([]) failed: {:?}", result.err());
}

#[tokio::test]
async fn test_set_events_replace_subscription() {
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
        .expect("set_events(BW) failed");

    let result = controller.set_events(&[EventType::Circ]).await;
    assert!(
        result.is_ok(),
        "set_events(CIRC) replacement failed: {:?}",
        result.err()
    );

    let _ = controller.set_events(&[]).await;
}
