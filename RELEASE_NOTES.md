# stem-rs v1.0.0

The first stable release of stem-rs — a complete Rust implementation of the Tor control protocol.

## Highlights

stem-rs brings the power of Python's Stem library to Rust with type-safe, async-first APIs for building privacy-focused applications.

## Features

### Control Protocol

- Full Tor control protocol implementation over TCP and Unix sockets
- Async I/O powered by Tokio
- Automatic reconnection handling

### Authentication

- All methods supported: SAFECOOKIE, COOKIE, PASSWORD, NONE
- Automatic method detection
- Secure credential handling with constant-time comparison

### Controller API

- Query configuration and status
- Send signals (NEWNYM, RELOAD, SHUTDOWN, etc.)
- Circuit management (create, extend, close)
- Stream management and attachment
- Ephemeral hidden service creation
- Address mapping for custom routing

### Descriptor Parsing

- Server descriptors
- Microdescriptors
- Consensus documents
- Extra-info descriptors
- Hidden service descriptors (v2 and v3)
- Bandwidth files
- Remote descriptor downloading

### Event Handling

- Real-time event subscription
- Strongly-typed event structs
- Bandwidth, circuit, stream, and log events
- Hidden service events

### Additional Modules

- Exit policy parsing and evaluation (IPv4/IPv6, CIDR, port ranges)
- Version parsing and comparison
- Interactive control interpreter
- Direct ORPort relay communication
- Validation utilities for fingerprints and nicknames

## Requirements

- Rust 1.70+
- Tokio runtime
- Tor instance with control port enabled

## License

MPL-2.0
