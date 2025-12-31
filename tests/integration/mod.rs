//! Integration tests for stem-rs against a real Tor process.

mod client_tests;
mod controller_tests;
mod core_tests;
mod descriptor_tests;
mod events_tests;
mod interpreter_tests;
mod socket_tests;
mod validation_tests;

use std::env;
use std::path::PathBuf;

pub fn get_control_port() -> u16 {
    env::var("TOR_CONTROL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9051)
}

pub fn get_cookie_path() -> Option<PathBuf> {
    env::var("TOR_COOKIE_PATH").ok().map(PathBuf::from)
}

pub fn get_socks_port() -> u16 {
    env::var("TOR_SOCKS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9050)
}

pub fn is_tor_available() -> bool {
    use std::net::TcpStream;
    let port = get_control_port();
    TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok()
}

#[test]
fn test_tor_is_available() {
    let port = get_control_port();
    assert!(
        is_tor_available(),
        "CRITICAL: Tor is not available on port {}. \
         Integration tests require a running Tor instance. \
         Set TOR_CONTROL_PORT env var if using a different port. \
         In CI, ensure Tor is started and bootstrapped before running tests.",
        port
    );
}
