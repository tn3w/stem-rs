//! Integration tests for socket and authentication against a real Tor process.

use std::net::SocketAddr;
use std::time::Duration;

use stem_rs::auth::{
    authenticate, authenticate_cookie, authenticate_none, authenticate_safecookie,
    get_protocol_info, AuthMethod,
};
use stem_rs::ControlSocket;

use crate::{get_control_port, is_tor_available};

fn get_control_addr() -> SocketAddr {
    format!("127.0.0.1:{}", get_control_port()).parse().unwrap()
}

#[tokio::test]
async fn test_tcp_connection_to_control_port() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let result = ControlSocket::connect_port(addr).await;
    assert!(
        result.is_ok(),
        "Failed to connect to Tor control port: {:?}",
        result.err()
    );

    let socket = result.unwrap();
    assert!(socket.is_alive());
}

#[tokio::test]
async fn test_protocolinfo_query() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    let protocol_info = get_protocol_info(&mut socket).await;
    assert!(
        protocol_info.is_ok(),
        "PROTOCOLINFO failed: {:?}",
        protocol_info.err()
    );

    let info = protocol_info.unwrap();
    assert_eq!(info.protocol_version, 1);
    assert!(info.tor_version.major > 0 || info.tor_version.minor > 0);
    assert!(!info.auth_methods.is_empty());
}

#[tokio::test]
async fn test_protocolinfo_auth_methods() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    let info = get_protocol_info(&mut socket)
        .await
        .expect("PROTOCOLINFO failed");

    let has_cookie_auth = info.auth_methods.contains(&AuthMethod::Cookie)
        || info.auth_methods.contains(&AuthMethod::SafeCookie);
    assert!(
        has_cookie_auth || info.auth_methods.contains(&AuthMethod::None),
        "Expected cookie or no auth, got: {:?}",
        info.auth_methods
    );

    if has_cookie_auth {
        assert!(
            info.cookie_path.is_some(),
            "Cookie path should be set for cookie auth"
        );
    }
}

#[tokio::test]
async fn test_cookie_authentication() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    let info = get_protocol_info(&mut socket)
        .await
        .expect("PROTOCOLINFO failed");

    if !info.auth_methods.contains(&AuthMethod::Cookie) {
        return;
    }

    let cookie_path = info
        .cookie_path
        .as_ref()
        .expect("Cookie path should be set");

    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    let result = authenticate_cookie(&mut socket, cookie_path).await;
    assert!(
        result.is_ok(),
        "Cookie authentication failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_safecookie_authentication() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    let info = get_protocol_info(&mut socket)
        .await
        .expect("PROTOCOLINFO failed");

    if !info.auth_methods.contains(&AuthMethod::SafeCookie) {
        return;
    }

    let cookie_path = info
        .cookie_path
        .as_ref()
        .expect("Cookie path should be set");

    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    let result = authenticate_safecookie(&mut socket, cookie_path).await;
    assert!(
        result.is_ok(),
        "SafeCookie authentication failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_automatic_authentication() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    let result = authenticate(&mut socket, None).await;
    assert!(
        result.is_ok(),
        "Automatic authentication failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_send_recv_after_auth() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    socket
        .send("GETINFO version")
        .await
        .expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");

    assert!(response.is_ok(), "GETINFO version should succeed");
    assert!(
        response.content().contains("version="),
        "Response should contain version"
    );
}

#[tokio::test]
async fn test_multiline_response() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    socket
        .send("GETINFO version config-file")
        .await
        .expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");

    assert!(response.is_ok(), "GETINFO should succeed");
    assert!(
        response.lines.len() >= 2,
        "Should have multiple response lines"
    );
}

#[tokio::test]
async fn test_getinfo_traffic() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    socket
        .send("GETINFO traffic/read traffic/written")
        .await
        .expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");

    assert!(response.is_ok(), "GETINFO traffic should succeed");
    let content = response.all_content();
    assert!(
        content.contains("traffic/read="),
        "Should contain traffic/read"
    );
    assert!(
        content.contains("traffic/written="),
        "Should contain traffic/written"
    );
}

#[tokio::test]
async fn test_authentication_failure_wrong_cookie() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    let fake_path = std::path::Path::new("/tmp/nonexistent_cookie_file_12345");
    let result = authenticate_cookie(&mut socket, fake_path).await;
    assert!(
        result.is_err(),
        "Authentication with fake cookie should fail"
    );
}

#[tokio::test]
async fn test_connection_time() {
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
async fn test_multiple_commands_same_connection() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    for _ in 0..5 {
        socket
            .send("GETINFO version")
            .await
            .expect("Failed to send");
        let response = socket.recv().await.expect("Failed to receive");
        assert!(response.is_ok(), "GETINFO should succeed");
    }
}

#[tokio::test]
async fn test_invalid_command() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    socket.send("INVALIDCOMMAND").await.expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");

    assert!(!response.is_ok(), "Invalid command should return error");
    assert!(response.status_code >= 500, "Should return 5xx error code");
}

#[tokio::test]
async fn test_getinfo_unknown_key() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    socket
        .send("GETINFO unknown-key-12345")
        .await
        .expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");

    assert!(!response.is_ok(), "GETINFO with unknown key should fail");
    assert_eq!(
        response.status_code, 552,
        "Should return 552 for unrecognized key"
    );
}

#[tokio::test]
async fn test_signal_newnym() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    socket.send("SIGNAL NEWNYM").await.expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");

    assert!(response.is_ok(), "SIGNAL NEWNYM should succeed");
}

#[tokio::test]
async fn test_getconf_socksport() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    socket
        .send("GETCONF SocksPort")
        .await
        .expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");

    assert!(response.is_ok(), "GETCONF SocksPort should succeed");
    assert!(
        response.content().contains("SocksPort"),
        "Should contain SocksPort"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_unix_socket_connection() {
    let socket_path = std::path::Path::new("/var/run/tor/control");
    if !socket_path.exists() {
        return;
    }

    let result = ControlSocket::connect_unix(socket_path).await;
    if result.is_err() {
        return;
    }

    let mut socket = result.unwrap();
    let info = get_protocol_info(&mut socket).await;
    assert!(info.is_ok(), "PROTOCOLINFO should work over Unix socket");
}

#[tokio::test]
async fn test_reconnection_after_disconnect() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();

    {
        let mut socket = ControlSocket::connect_port(addr)
            .await
            .expect("Failed to connect");
        authenticate(&mut socket, None)
            .await
            .expect("Authentication failed");
        socket
            .send("GETINFO version")
            .await
            .expect("Failed to send");
        let _ = socket.recv().await.expect("Failed to receive");
    }

    {
        let mut socket = ControlSocket::connect_port(addr)
            .await
            .expect("Failed to reconnect");
        authenticate(&mut socket, None)
            .await
            .expect("Authentication failed");
        socket
            .send("GETINFO version")
            .await
            .expect("Failed to send");
        let response = socket.recv().await.expect("Failed to receive");
        assert!(response.is_ok(), "Should work after reconnection");
    }
}

#[tokio::test]
async fn test_protocol_info_tor_version() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    let info = get_protocol_info(&mut socket)
        .await
        .expect("PROTOCOLINFO failed");

    assert!(
        info.tor_version.major == 0 && info.tor_version.minor >= 4,
        "Expected Tor version 0.4.x or higher, got {}",
        info.tor_version
    );
}

#[tokio::test]
async fn test_concurrent_connections() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();

    let handles: Vec<_> = (0..3)
        .map(|i| {
            tokio::spawn(async move {
                let mut socket = ControlSocket::connect_port(addr).await?;
                authenticate(&mut socket, None).await?;
                socket.send("GETINFO version").await?;
                let response = socket.recv().await?;
                Ok::<_, stem_rs::Error>((i, response.is_ok()))
            })
        })
        .collect();

    for handle in handles {
        let result = handle.await.expect("Task panicked");
        assert!(
            result.is_ok(),
            "Concurrent connection failed: {:?}",
            result.err()
        );
        let (_, is_ok) = result.unwrap();
        assert!(is_ok, "Response should be OK");
    }
}

#[tokio::test]
async fn test_getinfo_config_file() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    socket
        .send("GETINFO config-file")
        .await
        .expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");

    assert!(response.is_ok(), "GETINFO config-file should succeed");
    assert!(
        response.content().contains("config-file="),
        "Should contain config-file"
    );
}

#[tokio::test]
async fn test_getinfo_process_pid() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    authenticate(&mut socket, None)
        .await
        .expect("Authentication failed");

    socket
        .send("GETINFO process/pid")
        .await
        .expect("Failed to send");
    let response = socket.recv().await.expect("Failed to receive");

    assert!(response.is_ok(), "GETINFO process/pid should succeed");
    let content = response.content();
    assert!(
        content.contains("process/pid="),
        "Should contain process/pid"
    );

    if let Some(pid_str) = content.strip_prefix("process/pid=") {
        let pid: u32 = pid_str.trim().parse().expect("PID should be a number");
        assert!(pid > 0, "PID should be positive");
    }
}

#[tokio::test]
async fn test_none_authentication_when_available() {
    if !is_tor_available() {
        return;
    }

    let addr = get_control_addr();
    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");

    let info = get_protocol_info(&mut socket)
        .await
        .expect("PROTOCOLINFO failed");

    if !info.auth_methods.contains(&AuthMethod::None) {
        return;
    }

    let mut socket = ControlSocket::connect_port(addr)
        .await
        .expect("Failed to connect");
    let result = authenticate_none(&mut socket).await;
    assert!(
        result.is_ok(),
        "NULL authentication should succeed when available"
    );
}
