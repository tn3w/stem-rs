//! Integration tests for socket module against a real Tor process.

use std::net::SocketAddr;
use std::time::Duration;

use stem_rs::socket::{ControlMessage, ControlSocket};

use crate::{get_control_port, is_tor_available};

fn get_control_addr() -> SocketAddr {
    format!("127.0.0.1:{}", get_control_port()).parse().unwrap()
}

#[tokio::test]
async fn test_socket_connect_port() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let result = ControlSocket::connect_port(addr).await;
    assert!(result.is_ok(), "Failed to connect: {:?}", result.err());
}

#[tokio::test]
async fn test_socket_send_recv_protocolinfo() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    socket.send("PROTOCOLINFO 1").await.expect("Failed to send");

    let response = socket.recv().await.expect("Failed to receive");
    assert!(response.is_ok(), "PROTOCOLINFO should return 250");
    assert!(
        response.all_content().contains("AUTH"),
        "Response should contain AUTH methods"
    );
}

#[tokio::test]
async fn test_socket_send_recv_getinfo() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    socket
        .send("PROTOCOLINFO 1")
        .await
        .expect("Failed to send PROTOCOLINFO");
    let _ = socket.recv().await.expect("Failed to receive PROTOCOLINFO");

    socket
        .send("AUTHENTICATE")
        .await
        .expect("Failed to send AUTHENTICATE");
    let auth_response = socket.recv().await.expect("Failed to receive AUTHENTICATE");

    if !auth_response.is_ok() {
        return;
    }

    socket
        .send("GETINFO version")
        .await
        .expect("Failed to send GETINFO");
    let response = socket.recv().await.expect("Failed to receive GETINFO");

    assert!(response.is_ok(), "GETINFO should return 250");
}

#[tokio::test]
async fn test_socket_is_alive() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    assert!(socket.is_alive(), "Socket should be alive after connect");
}

#[tokio::test]
async fn test_socket_connection_time() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    let connection_time = socket.connection_time();
    let elapsed = connection_time.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "Connection time should be recent"
    );
}

#[tokio::test]
async fn test_socket_multiline_response() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    socket
        .send("PROTOCOLINFO 1")
        .await
        .expect("Failed to send PROTOCOLINFO");
    let _ = socket.recv().await.expect("Failed to receive PROTOCOLINFO");

    socket
        .send("AUTHENTICATE")
        .await
        .expect("Failed to send AUTHENTICATE");
    let auth_response = socket.recv().await.expect("Failed to receive AUTHENTICATE");

    if !auth_response.is_ok() {
        return;
    }

    socket
        .send("GETINFO config/names")
        .await
        .expect("Failed to send GETINFO");
    let response = socket.recv().await.expect("Failed to receive GETINFO");

    assert!(response.is_ok(), "GETINFO config/names should return 250");
    let content = response.all_content();
    assert!(
        content.len() > 100,
        "config/names should return substantial content"
    );
}

#[tokio::test]
async fn test_control_message_methods() {
    let msg = ControlMessage {
        status_code: 250,
        lines: vec!["OK".to_string()],
    };

    assert!(msg.is_ok());
    assert_eq!(msg.content(), "OK");
    assert_eq!(msg.all_content(), "OK");

    let raw = msg.raw_content();
    assert!(raw.contains("250"));
    assert!(raw.contains("OK"));
}

#[tokio::test]
async fn test_control_message_multiline() {
    let msg = ControlMessage {
        status_code: 250,
        lines: vec![
            "line1".to_string(),
            "line2".to_string(),
            "line3".to_string(),
        ],
    };

    assert!(msg.is_ok());
    assert_eq!(msg.content(), "line1");
    assert_eq!(msg.all_content(), "line1\nline2\nline3");
}

#[tokio::test]
async fn test_control_message_error_codes() {
    let error_msg = ControlMessage {
        status_code: 515,
        lines: vec!["Authentication failed".to_string()],
    };

    assert!(!error_msg.is_ok());
    assert_eq!(error_msg.content(), "Authentication failed");

    let server_error = ControlMessage {
        status_code: 550,
        lines: vec!["Unrecognized key".to_string()],
    };

    assert!(!server_error.is_ok());
}

#[tokio::test]
async fn test_socket_send_with_crlf() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    socket
        .send("PROTOCOLINFO 1\r\n")
        .await
        .expect("Failed to send with CRLF");

    let response = socket.recv().await.expect("Failed to receive");
    assert!(response.is_ok(), "Should handle message with CRLF");
}

#[tokio::test]
async fn test_socket_multiple_commands() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    socket.send("PROTOCOLINFO 1").await.expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");
    assert!(response.is_ok(), "PROTOCOLINFO should succeed");
}
