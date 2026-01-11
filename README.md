<h1 align="center">stem-rs</h1>

<h3 align="center">A complete Rust library for Tor control protocol</h3>
<p align="center">
  Build privacy-focused applications with type-safe, async-first APIs
</p>

<p align="center">
  <a href="https://crates.io/crates/stem-rs">
    <img src="https://img.shields.io/crates/v/stem-rs?style=for-the-badge&logo=rust&logoColor=white&color=f74c00" alt="Crates.io">
  </a>
  <a href="https://stem.tn3w.dev/docs/">
    <img src="https://img.shields.io/docsrs/stem-rs?style=for-the-badge&logo=docs.rs&logoColor=white" alt="docs.rs">
  </a>
  <a href="https://github.com/tn3w/stem-rs/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge" alt="License">
  </a>
</p>

<p align="center">
  <a href="https://github.com/tn3w/stem-rs/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/tn3w/stem-rs/tests.yml?style=for-the-badge&logo=github&logoColor=white&label=CI" alt="CI">
  </a>
  <a href="https://github.com/tn3w/stem-rs">
    <img src="https://img.shields.io/github/stars/tn3w/stem-rs?style=for-the-badge&logo=github&logoColor=white" alt="Stars">
  </a>
</p>

<p align="center">
  <a href="https://stem.tn3w.dev">🌐 Website</a> •
  <a href="https://stem.tn3w.dev/docs/">📚 Documentation</a> •
  <a href="https://stem.tn3w.dev/tutorials">📖 Tutorials</a> •
  <a href="#-quick-start">🚀 Quick Start</a> •
  <a href="#-examples">💡 Examples</a>
</p>

## Overview

**stem-rs** is a Rust implementation of [Stem](https://stem.torproject.org/), the Python library for interacting with Tor's control protocol. It provides idiomatic, type-safe Rust APIs while maintaining complete functional parity with Python Stem.

Whether you're building privacy tools, monitoring Tor relays, managing circuits, or creating onion services — stem-rs gives you the building blocks you need with the safety guarantees Rust provides.

```rust
use stem_rs::{Controller, Error};

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Connect to Tor's control port
    let mut ctrl = Controller::from_port("127.0.0.1:9051".parse()?).await?;

    // Authenticate (auto-detects method)
    ctrl.authenticate(None).await?;

    // Query Tor version
    let version = ctrl.get_version().await?;
    println!("Connected to Tor {}", version);

    Ok(())
}
```

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔌 Control Socket

Connect to Tor via TCP or Unix domain sockets with full async I/O powered by Tokio.

- TCP port connections (`127.0.0.1:9051`)
- Unix domain sockets (`/var/run/tor/control`)
- Non-blocking async operations
- Automatic reconnection handling

</td>
<td width="50%">

### 🔐 Authentication

All authentication methods with automatic detection and secure credential handling.

- **SAFECOOKIE** — Challenge-response (recommended)
- **COOKIE** — File-based authentication
- **PASSWORD** — HashedControlPassword
- **NONE** — Open control port

</td>
</tr>
<tr>
<td width="50%">

### 🎛️ Controller API

High-level interface for complete Tor interaction.

- Query configuration and status
- Send signals (NEWNYM, RELOAD, etc.)
- Create, extend, and close circuits
- Attach and manage streams
- Create ephemeral hidden services
- Map addresses for custom routing

</td>
<td width="50%">

### 📄 Descriptor Parsing

Complete parsing for all Tor descriptor types.

- **Server Descriptors** — Full relay metadata
- **Microdescriptors** — Compact client-side info
- **Consensus Documents** — Network status
- **Extra-Info** — Bandwidth statistics
- **Hidden Service** — v2 and v3 descriptors
- **Bandwidth Files** — Authority measurements

</td>
</tr>
<tr>
<td width="50%">

### 📡 Event Handling

Subscribe to real-time Tor events with strongly-typed event structs.

- Bandwidth monitoring (`BW`, `CIRC_BW`)
- Circuit lifecycle (`CIRC`, `CIRC_MINOR`)
- Stream tracking (`STREAM`, `STREAM_BW`)
- Log messages (`DEBUG` → `ERR`)
- Status updates (`STATUS_*`)
- Hidden service events (`HS_DESC`)

</td>
<td width="50%">

### 🚪 Exit Policy

Parse and evaluate relay exit policies.

- Full exit policy parsing
- IPv4 and IPv6 support
- CIDR notation for address ranges
- Port range evaluation
- Policy summarization

</td>
</tr>
</table>

## 🚀 Quick Start

Add stem-rs to your `Cargo.toml`:

```toml
[dependencies]
stem-rs = "1.1"
tokio = { version = "1", features = ["full"] }
```

Or install via cargo:

```bash
cargo add stem-rs tokio --features tokio/full
```

### Enable Tor's Control Port

Add to your `torrc`:

```
ControlPort 9051
CookieAuthentication 1
```

Or for password authentication:

```
ControlPort 9051
HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C
```

Generate a hashed password:

```bash
tor --hash-password "your-password"
```

## 💡 Examples

### Connect and Authenticate

```rust
use stem_rs::{Controller, Error};

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Connect via TCP
    let mut ctrl = Controller::from_port("127.0.0.1:9051".parse()?).await?;

    // Or via Unix socket
    // let mut ctrl = Controller::from_socket_file(Path::new("/var/run/tor/control")).await?;

    // Auto-detect authentication method
    ctrl.authenticate(None).await?;

    // Or use password
    // ctrl.authenticate(Some("my_password")).await?;

    println!("Connected!");
    Ok(())
}
```

### Query Information

```rust
// Get Tor version
let version = ctrl.get_version().await?;
println!("Tor {}", version);

// Get process ID
let pid = ctrl.get_pid().await?;
println!("PID: {}", pid);

// Query arbitrary info
let traffic_read = ctrl.get_info("traffic/read").await?;
let traffic_written = ctrl.get_info("traffic/written").await?;
println!("Traffic: {} read, {} written", traffic_read, traffic_written);

// Get configuration
let socks_ports = ctrl.get_conf("SocksPort").await?;
for port in socks_ports {
    println!("SOCKS port: {}", port);
}
```

### Circuit Management

```rust
use stem_rs::CircStatus;

// List all circuits
let circuits = ctrl.get_circuits().await?;
for circuit in circuits {
    if circuit.status == CircStatus::Built {
        println!("Circuit {} ({} hops):", circuit.id, circuit.path.len());
        for relay in &circuit.path {
            println!("  → {} ({:?})", relay.fingerprint, relay.nickname);
        }
    }
}

// Create a new circuit
let circuit_id = ctrl.new_circuit(None).await?;
println!("Created circuit: {}", circuit_id);

// Close a circuit
ctrl.close_circuit(circuit_id).await?;
```

### Stream Management

```rust
use stem_rs::StreamStatus;

// List all streams
let streams = ctrl.get_streams().await?;
for stream in streams {
    println!("Stream {} → {}:{} ({:?})",
        stream.id,
        stream.target_host,
        stream.target_port,
        stream.status
    );
}
```

### Event Subscription

```rust
use stem_rs::EventType;

// Subscribe to events
ctrl.set_events(&[
    EventType::Bw,      // Bandwidth
    EventType::Circ,    // Circuits
    EventType::Stream,  // Streams
    EventType::Notice,  // Log messages
]).await?;

// Process events
loop {
    let event = ctrl.recv_event().await?;
    match event {
        ParsedEvent::Bandwidth(bw) => {
            println!("BW: {} read, {} written", bw.read, bw.written);
        }
        ParsedEvent::Circuit(circ) => {
            println!("Circuit {}: {:?}", circ.id, circ.status);
        }
        ParsedEvent::Log(log) => {
            println!("[{}] {}", log.runlevel, log.message);
        }
        _ => {}
    }
}
```

### Send Signals

```rust
use stem_rs::Signal;

// Request new identity (new circuits)
ctrl.signal(Signal::Newnym).await?;

// Clear DNS cache
ctrl.signal(Signal::ClearDnsCache).await?;

// Reload configuration
ctrl.signal(Signal::Reload).await?;

// Graceful shutdown
ctrl.signal(Signal::Shutdown).await?;
```

### Hidden Services

```rust
// Create ephemeral hidden service (v3 onion)
let response = ctrl.create_ephemeral_hidden_service(
    &[(80, "127.0.0.1:8080")],  // Map port 80 to local 8080
    "NEW",                       // Generate new key
    "ED25519-V3",                // Use v3 onion (recommended)
    &[],                         // No special flags
).await?;

println!("Hidden service: {}.onion", response.service_id);
println!("Private key: {:?}", response.private_key);

// Remove hidden service
ctrl.remove_ephemeral_hidden_service(&response.service_id).await?;
```

### Descriptor Parsing

```rust
use stem_rs::descriptor::{
    ServerDescriptor, Microdescriptor, NetworkStatusDocument,
    Descriptor, DigestHash, DigestEncoding,
    download_consensus, download_server_descriptors,
};

// Download and parse consensus
let consensus = download_consensus(None).await?;
println!("Valid until: {}", consensus.valid_until);
println!("Relays: {}", consensus.routers.len());

// Parse server descriptor
let content = std::fs::read_to_string("cached-descriptors")?;
let descriptor = ServerDescriptor::parse(&content)?;
println!("Relay: {} ({})", descriptor.nickname, descriptor.fingerprint);
println!("Bandwidth: {} avg, {} burst",
    descriptor.bandwidth_avg, descriptor.bandwidth_burst);

// Compute digest
let digest = descriptor.digest(DigestHash::Sha1, DigestEncoding::Hex)?;
println!("Digest: {}", digest);
```

### Exit Policy Evaluation

```rust
use stem_rs::exit_policy::ExitPolicy;
use std::net::IpAddr;

let policy = ExitPolicy::parse("accept *:80, accept *:443, reject *:*")?;

// Check if traffic is allowed
let addr: IpAddr = "93.184.216.34".parse()?;
if policy.can_exit_to(addr, 443) {
    println!("HTTPS traffic allowed");
}

// Get policy summary
println!("Policy: {}", policy.summary());
```

### Version Comparison

```rust
use stem_rs::Version;

let version = ctrl.get_version().await?;

// Compare versions
let min_version = Version::parse("0.4.0.0")?;
if version >= min_version {
    println!("Tor {} supports required features", version);
}
```

## 📦 Module Reference

| Module                                                   | Description                                                       |
| -------------------------------------------------------- | ----------------------------------------------------------------- |
| [`controller`](https://stem.tn3w.dev/docs/controller/)   | High-level Tor control interface                                  |
| [`socket`](https://stem.tn3w.dev/docs/socket/)           | Low-level control socket communication                            |
| [`auth`](https://stem.tn3w.dev/docs/auth/)               | Authentication methods and protocol info                          |
| [`descriptor`](https://stem.tn3w.dev/docs/descriptor/)   | Tor descriptor parsing (server, micro, consensus, hidden service) |
| [`events`](https://stem.tn3w.dev/docs/events/)           | Event types and real-time handling                                |
| [`exit_policy`](https://stem.tn3w.dev/docs/exit_policy/) | Exit policy parsing and evaluation                                |
| [`version`](https://stem.tn3w.dev/docs/version/)         | Version parsing and comparison                                    |
| [`client`](https://stem.tn3w.dev/docs/client/)           | Direct ORPort relay communication                                 |
| [`interpreter`](https://stem.tn3w.dev/docs/interpreter/) | Interactive Tor control interpreter                               |
| [`util`](https://stem.tn3w.dev/docs/util/)               | Validation utilities (fingerprints, nicknames, etc.)              |

## 🔒 Security

stem-rs is designed with security as a priority:

- **100% Safe Rust** — No `unsafe` code
- **Constant-time comparison** — For authentication tokens and cookies
- **Memory clearing** — Sensitive data cleared after use
- **Input validation** — Prevents protocol injection attacks
- **Signature verification** — Optional cryptographic validation for descriptors

## ⚡ Performance

- **Async-first** — Built on Tokio for high-performance async I/O
- **Zero-copy parsing** — Efficient descriptor parsing where possible
- **Event streaming** — Non-blocking real-time event handling
- **Connection pooling** — Efficient socket management

## 🛠️ Requirements

- **Rust** 1.70+
- **Tokio** runtime
- **Tor** instance with control port enabled

## 🧪 Testing

```bash
# Run unit tests
cargo test

# Run with integration tests (requires running Tor)
cargo test --features integration

# Run extensive tests
cargo test --features extensive
```

## 📊 Comparison with Python Stem

stem-rs maintains functional parity with Python Stem while providing Rust's safety guarantees:

| Feature                | Python Stem | stem-rs |
| ---------------------- | ----------- | ------- |
| Control Protocol       | ✅          | ✅      |
| All Auth Methods       | ✅          | ✅      |
| Descriptor Parsing     | ✅          | ✅      |
| Event Handling         | ✅          | ✅      |
| Exit Policy            | ✅          | ✅      |
| Hidden Services        | ✅          | ✅      |
| Type Safety            | ❌          | ✅      |
| Memory Safety          | ❌          | ✅      |
| Async/Await            | ❌          | ✅      |
| Zero-cost Abstractions | ❌          | ✅      |

## 📄 License

Copyright 2026 stem-rs contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🔗 Links

<p align="center">
  <a href="https://stem.tn3w.dev">Website</a> •
  <a href="https://stem.tn3w.dev/docs/">Documentation</a> •
  <a href="https://stem.tn3w.dev/tutorials">Tutorials</a> •
  <a href="https://crates.io/crates/stem-rs">crates.io</a> •
  <a href="https://github.com/tn3w/stem-rs">GitHub</a> •
  <a href="https://stem.torproject.org/">Python Stem</a>
</p>

<p align="center">
  <sub>Built with 🦀 by the stem-rs contributors</sub>
</p>
