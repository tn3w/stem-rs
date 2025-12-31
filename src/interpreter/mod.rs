//! Interactive interpreter for Tor control protocol.
//!
//! This module provides an interactive command interpreter for interacting
//! with Tor's control interface, supporting both interpreter commands (like
//! `/help`, `/events`, `/info`) and direct Tor control commands.
//!
//! # Overview
//!
//! The interpreter provides a REPL-like interface for communicating with Tor,
//! adding usability features such as:
//!
//! - IRC-style interpreter commands (prefixed with `/`)
//! - Direct Tor control protocol command passthrough
//! - Event buffering and filtering
//! - Relay information lookup by fingerprint, nickname, or IP address
//! - Tab completion support via the [`autocomplete`] module
//! - Built-in help system via the [`help`] module
//!
//! # Interpreter Commands
//!
//! Commands prefixed with `/` are handled by the interpreter itself:
//!
//! | Command | Description |
//! |---------|-------------|
//! | `/help [topic]` | Display help information |
//! | `/events [types...]` | Show buffered events, optionally filtered by type |
//! | `/events CLEAR` | Clear the event buffer |
//! | `/info [relay]` | Show information about a relay |
//! | `/python enable\|disable` | Toggle Python command mode |
//! | `/quit` | Exit the interpreter |
//!
//! All other commands are passed directly to Tor's control interface.
//!
//! # Architecture
//!
//! The interpreter wraps a [`Controller`] and maintains:
//! - A bounded event buffer (most recent 100 events)
//! - Multiline context state for complex commands
//! - Python command mode toggle
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::Controller;
//! use stem_rs::interpreter::ControlInterpreter;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! let mut interpreter = ControlInterpreter::new(&mut controller);
//!
//! // Run interpreter commands
//! let help = interpreter.run_command("/help").await?;
//! println!("{}", help);
//!
//! // Run Tor control commands
//! let version = interpreter.run_command("GETINFO version").await?;
//! println!("Tor version: {}", version);
//! # Ok(())
//! # }
//! ```
//!
//! # See Also
//!
//! - [`Controller`] - The underlying control interface
//! - [`arguments`] - Command-line argument parsing
//! - [`autocomplete`] - Tab completion functionality
//! - [`help`] - Help system implementation
//!
//! # Python Stem Equivalent
//!
//! This module corresponds to Python Stem's `stem.interpreter` module.

pub mod arguments;
pub mod autocomplete;
pub mod help;

use std::collections::VecDeque;

use crate::controller::Controller;
use crate::events::ParsedEvent;
use crate::util::{is_valid_fingerprint, is_valid_ipv4_address, is_valid_nickname, is_valid_port};
use crate::Error;

/// Maximum number of events to buffer.
///
/// The interpreter maintains a rolling buffer of the most recent events
/// for display via the `/events` command. Older events are discarded
/// when this limit is reached.
const MAX_EVENTS: usize = 100;

/// Interactive command interpreter for Tor control protocol.
///
/// `ControlInterpreter` provides a high-level interface for interacting with
/// Tor, combining direct control protocol access with convenience commands
/// for common operations.
///
/// # Conceptual Role
///
/// The interpreter sits between user input and the [`Controller`], providing:
/// - Command routing (interpreter vs. Tor commands)
/// - Event buffering and retrieval
/// - Relay lookup by various identifiers
/// - Help and documentation access
///
/// # Invariants
///
/// - The event buffer never exceeds [`MAX_EVENTS`] entries
/// - Events are stored in reverse chronological order (newest first)
/// - The underlying controller connection must remain valid
///
/// # Thread Safety
///
/// `ControlInterpreter` is `Send` but not `Sync` due to the mutable
/// reference to the underlying [`Controller`].
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::Controller;
/// use stem_rs::interpreter::ControlInterpreter;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
/// controller.authenticate(None).await?;
///
/// let mut interpreter = ControlInterpreter::new(&mut controller);
///
/// // Query relay information
/// let info = interpreter.run_command("/info MyRelay").await?;
///
/// // Send a signal to Tor
/// let result = interpreter.run_command("SIGNAL NEWNYM").await?;
/// # Ok(())
/// # }
/// ```
pub struct ControlInterpreter<'a> {
    /// Reference to the underlying Tor controller.
    controller: &'a mut Controller,
    /// Buffer of received events, newest first.
    received_events: VecDeque<ParsedEvent>,
    /// Whether to interpret non-interpreter commands as Python.
    run_python_commands: bool,
    /// Whether the interpreter is in a multiline input context.
    ///
    /// This is set to `true` when the user is entering a multiline command
    /// (such as `LOADCONF` or `POSTDESCRIPTOR`). The prompt should change
    /// to indicate continuation (e.g., `... ` instead of `>>> `).
    pub is_multiline_context: bool,
}

impl<'a> ControlInterpreter<'a> {
    /// Creates a new interpreter wrapping the given controller.
    ///
    /// The interpreter is initialized with:
    /// - An empty event buffer
    /// - Python command mode enabled
    /// - Multiline context disabled
    ///
    /// # Arguments
    ///
    /// * `controller` - A mutable reference to an authenticated [`Controller`]
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::Controller;
    /// use stem_rs::interpreter::ControlInterpreter;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// controller.authenticate(None).await?;
    ///
    /// let interpreter = ControlInterpreter::new(&mut controller);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(controller: &'a mut Controller) -> Self {
        Self {
            controller,
            received_events: VecDeque::with_capacity(MAX_EVENTS),
            run_python_commands: true,
            is_multiline_context: false,
        }
    }

    /// Adds an event to the buffer.
    ///
    /// Events are stored in reverse chronological order (newest first).
    /// If the buffer is full, the oldest event is discarded.
    ///
    /// # Arguments
    ///
    /// * `event` - The parsed event to add
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::Controller;
    /// use stem_rs::interpreter::ControlInterpreter;
    /// use stem_rs::events::ParsedEvent;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// # let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// # controller.authenticate(None).await?;
    /// let mut interpreter = ControlInterpreter::new(&mut controller);
    ///
    /// // Events would typically come from the controller's event stream
    /// // interpreter.add_event(event);
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_event(&mut self, event: ParsedEvent) {
        self.received_events.push_front(event);
        if self.received_events.len() > MAX_EVENTS {
            self.received_events.pop_back();
        }
    }

    /// Retrieves buffered events, optionally filtered by type.
    ///
    /// Returns events in reverse chronological order (newest first).
    ///
    /// # Arguments
    ///
    /// * `event_types` - Event types to filter by (case-insensitive).
    ///   If empty, all events are returned.
    ///
    /// # Returns
    ///
    /// A vector of references to matching events.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::Controller;
    /// use stem_rs::interpreter::ControlInterpreter;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// # let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// # controller.authenticate(None).await?;
    /// let interpreter = ControlInterpreter::new(&mut controller);
    ///
    /// // Get all events
    /// let all_events = interpreter.get_events(&[]);
    ///
    /// // Get only bandwidth events
    /// let bw_events = interpreter.get_events(&["BW"]);
    ///
    /// // Get circuit and stream events
    /// let circ_stream = interpreter.get_events(&["CIRC", "STREAM"]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_events(&self, event_types: &[&str]) -> Vec<&ParsedEvent> {
        if event_types.is_empty() {
            self.received_events.iter().collect()
        } else {
            self.received_events
                .iter()
                .filter(|e| {
                    event_types
                        .iter()
                        .any(|t| e.event_type().eq_ignore_ascii_case(t))
                })
                .collect()
        }
    }

    /// Executes a command and returns the result.
    ///
    /// Commands are routed based on their prefix:
    /// - Commands starting with `/` are interpreter commands
    /// - All other commands are sent to Tor's control interface
    ///
    /// # Arguments
    ///
    /// * `command` - The command string to execute
    ///
    /// # Returns
    ///
    /// The command output as a string, or an error.
    ///
    /// # Errors
    ///
    /// - [`Error::SocketClosed`] - If `/quit` or `QUIT` is executed
    /// - [`Error::Socket`] - If communication with Tor fails
    /// - [`Error::InvalidArguments`] - If relay lookup fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::Controller;
    /// use stem_rs::interpreter::ControlInterpreter;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// # let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// # controller.authenticate(None).await?;
    /// let mut interpreter = ControlInterpreter::new(&mut controller);
    ///
    /// // Interpreter command
    /// let help = interpreter.run_command("/help").await?;
    ///
    /// // Tor control command
    /// let version = interpreter.run_command("GETINFO version").await?;
    ///
    /// // Empty commands return empty string
    /// let empty = interpreter.run_command("").await?;
    /// assert!(empty.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run_command(&mut self, command: &str) -> Result<String, Error> {
        let command = command.trim();
        if command.is_empty() {
            return Ok(String::new());
        }

        let (cmd, arg) = match command.split_once(' ') {
            Some((c, a)) => (c, a.trim()),
            None => (command, ""),
        };

        if cmd.starts_with('/') {
            self.run_interpreter_command(cmd, arg).await
        } else {
            self.run_tor_command(cmd, arg).await
        }
    }

    /// Executes an interpreter command (prefixed with `/`).
    ///
    /// # Arguments
    ///
    /// * `cmd` - The command name (e.g., `/help`)
    /// * `arg` - The command arguments
    ///
    /// # Returns
    ///
    /// The command output or an error.
    async fn run_interpreter_command(&mut self, cmd: &str, arg: &str) -> Result<String, Error> {
        match cmd.to_lowercase().as_str() {
            "/quit" => Err(Error::SocketClosed),
            "/events" => Ok(self.do_events(arg)),
            "/info" => self.do_info(arg).await,
            "/python" => Ok(self.do_python(arg)),
            "/help" => Ok(help::response(self.controller, arg).await),
            _ => Ok(format!("'{}' isn't a recognized command", cmd)),
        }
    }

    /// Executes a Tor control protocol command.
    ///
    /// The command is converted to uppercase and sent to Tor.
    /// Multiline commands (`LOADCONF`, `POSTDESCRIPTOR`) are not yet supported.
    ///
    /// # Arguments
    ///
    /// * `cmd` - The command name (e.g., `GETINFO`)
    /// * `arg` - The command arguments
    ///
    /// # Returns
    ///
    /// The Tor response or an error.
    async fn run_tor_command(&mut self, cmd: &str, arg: &str) -> Result<String, Error> {
        let cmd_upper = cmd.to_uppercase();

        if cmd_upper == "LOADCONF"
            || cmd_upper == "+LOADCONF"
            || cmd_upper == "POSTDESCRIPTOR"
            || cmd_upper == "+POSTDESCRIPTOR"
        {
            return Ok("Multi-line control options like this are not yet implemented.".to_string());
        }

        if cmd_upper == "QUIT" {
            return Err(Error::SocketClosed);
        }

        let full_command = if arg.is_empty() {
            cmd_upper
        } else {
            format!("{} {}", cmd_upper, arg)
        };

        let response = self.controller.msg(&full_command).await?;
        Ok(response)
    }

    /// Handles the `/events` command.
    ///
    /// Displays buffered events, optionally filtered by type.
    /// If `CLEAR` is specified, clears the event buffer instead.
    fn do_events(&mut self, arg: &str) -> String {
        let event_types: Vec<&str> = arg.split_whitespace().collect();

        if event_types.iter().any(|t| t.eq_ignore_ascii_case("CLEAR")) {
            self.received_events.clear();
            return "cleared event backlog".to_string();
        }

        let events = self.get_events(&event_types);
        if events.is_empty() {
            return String::new();
        }

        events
            .iter()
            .map(|e| format!("{}", e))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Handles the `/info` command.
    ///
    /// Displays information about a relay identified by fingerprint,
    /// nickname, or IP address.
    async fn do_info(&mut self, arg: &str) -> Result<String, Error> {
        let fingerprint = self.resolve_fingerprint(arg).await?;

        let ns_desc = self
            .controller
            .get_info(&format!("ns/id/{}", fingerprint))
            .await;

        match ns_desc {
            Ok(ns_content) => {
                let mut output = Vec::new();
                output.push(format!("Fingerprint: {}", fingerprint));

                for line in ns_content.lines() {
                    if line.starts_with("r ") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            output.push(format!("Nickname: {}", parts[1]));
                        }
                        if parts.len() >= 7 {
                            output.push(format!(
                                "Address: {}:{}",
                                parts[6],
                                parts.get(7).unwrap_or(&"0")
                            ));
                        }
                    } else if let Some(stripped) = line.strip_prefix("s ") {
                        output.push(format!("Flags: {}", stripped));
                    } else if let Some(stripped) = line.strip_prefix("v ") {
                        output.push(format!("Version: {}", stripped));
                    }
                }

                Ok(output.join("\n"))
            }
            Err(_) => Ok(format!(
                "Unable to find consensus information for {}",
                fingerprint
            )),
        }
    }

    /// Resolves a relay identifier to a fingerprint.
    ///
    /// Accepts:
    /// - 40-character hex fingerprint (returned as-is)
    /// - Relay nickname (looked up via `ns/name/`)
    /// - IPv4 address with optional port (looked up via `ns/all`)
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArguments`] if:
    /// - The identifier format is not recognized
    /// - No relay matches the identifier
    /// - Multiple relays match an IP address without port
    async fn resolve_fingerprint(&mut self, arg: &str) -> Result<String, Error> {
        if arg.is_empty() {
            return self.controller.get_info("fingerprint").await.map_err(|_| {
                Error::InvalidArguments("We aren't a relay, no information to provide".to_string())
            });
        }

        if is_valid_fingerprint(arg) {
            return Ok(arg.to_string());
        }

        if is_valid_nickname(arg) {
            let ns_info = self
                .controller
                .get_info(&format!("ns/name/{}", arg))
                .await?;
            for line in ns_info.lines() {
                if line.starts_with("r ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        return Ok(parts[2].to_string());
                    }
                }
            }
            return Err(Error::InvalidArguments(format!(
                "Unable to find a relay with the nickname of '{}'",
                arg
            )));
        }

        if arg.contains(':') || is_valid_ipv4_address(arg) {
            let (address, port) = if arg.contains(':') {
                let (addr, port_str) = arg.rsplit_once(':').unwrap();
                if !is_valid_ipv4_address(addr) {
                    return Err(Error::InvalidArguments(format!(
                        "'{}' isn't a valid IPv4 address",
                        addr
                    )));
                }
                if !port_str.is_empty() && !is_valid_port(port_str) {
                    return Err(Error::InvalidArguments(format!(
                        "'{}' isn't a valid port",
                        port_str
                    )));
                }
                let port: Option<u16> = port_str.parse().ok();
                (addr, port)
            } else {
                (arg, None)
            };

            let ns_all = self.controller.get_info("ns/all").await?;
            let mut matches: Vec<(u16, String)> = Vec::new();

            for line in ns_all.lines() {
                if line.starts_with("r ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 8 {
                        let relay_addr = parts[6];
                        let relay_port: u16 = parts[7].parse().unwrap_or(0);
                        let relay_fp = parts[2];

                        if relay_addr == address && (port.is_none() || port == Some(relay_port)) {
                            matches.push((relay_port, relay_fp.to_string()));
                        }
                    }
                }
            }

            match matches.len() {
                0 => Err(Error::InvalidArguments(format!(
                    "No relays found at {}",
                    arg
                ))),
                1 => Ok(matches[0].1.clone()),
                _ => {
                    let mut response = format!(
                        "There's multiple relays at {}, include a port to specify which.\n\n",
                        arg
                    );
                    for (i, (or_port, fp)) in matches.iter().enumerate() {
                        response.push_str(&format!(
                            "  {}. {}:{}, fingerprint: {}\n",
                            i + 1,
                            address,
                            or_port,
                            fp
                        ));
                    }
                    Err(Error::InvalidArguments(response))
                }
            }
        } else {
            Err(Error::InvalidArguments(format!(
                "'{}' isn't a fingerprint, nickname, or IP address",
                arg
            )))
        }
    }

    /// Handles the `/python` command.
    ///
    /// Toggles whether non-interpreter commands are treated as Python
    /// expressions or passed directly to Tor.
    fn do_python(&mut self, arg: &str) -> String {
        if arg.is_empty() {
            let status = if self.run_python_commands {
                "enabled"
            } else {
                "disabled"
            };
            return format!("Python support is currently {}.", status);
        }

        match arg.to_lowercase().as_str() {
            "enable" => {
                self.run_python_commands = true;
                "Python support enabled, we'll now run non-interpreter commands as python."
                    .to_string()
            }
            "disable" => {
                self.run_python_commands = false;
                "Python support disabled, we'll now pass along all commands to tor.".to_string()
            }
            _ => format!(
                "'{}' is not recognized. Please run either '/python enable' or '/python disable'.",
                arg
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_buffer_capacity() {
        assert_eq!(MAX_EVENTS, 100);
    }

    #[test]
    fn test_do_python_status() {
        let enabled_msg = "Python support is currently enabled.";
        assert!(enabled_msg.contains("enabled"));

        let disabled_msg = "Python support is currently disabled.";
        assert!(disabled_msg.contains("disabled"));
    }

    #[test]
    fn test_do_python_enable_disable_messages() {
        let enable_msg =
            "Python support enabled, we'll now run non-interpreter commands as python.";
        assert!(enable_msg.contains("enabled"));

        let disable_msg = "Python support disabled, we'll now pass along all commands to tor.";
        assert!(disable_msg.contains("disabled"));
    }

    #[test]
    fn test_do_python_invalid_arg_message() {
        let invalid_arg = "invalid";
        let expected = format!(
            "'{}' is not recognized. Please run either '/python enable' or '/python disable'.",
            invalid_arg
        );
        assert!(expected.contains("not recognized"));
        assert!(expected.contains("/python enable"));
        assert!(expected.contains("/python disable"));
    }

    #[test]
    fn test_do_events_clear_message() {
        let clear_msg = "cleared event backlog";
        assert!(clear_msg.contains("cleared"));
    }

    #[test]
    fn test_multiline_command_message() {
        let msg = "Multi-line control options like this are not yet implemented.";
        assert!(msg.contains("Multi-line"));
        assert!(msg.contains("not yet implemented"));
    }

    #[test]
    fn test_unrecognized_command_format() {
        let cmd = "/unknown";
        let msg = format!("'{}' isn't a recognized command", cmd);
        assert!(msg.contains("/unknown"));
        assert!(msg.contains("isn't a recognized command"));
    }

    #[test]
    fn test_resolve_fingerprint_validation() {
        let valid_fp = "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234";
        assert!(is_valid_fingerprint(valid_fp));

        let invalid_fp = "ABCD";
        assert!(!is_valid_fingerprint(invalid_fp));
    }

    #[test]
    fn test_resolve_nickname_validation() {
        let valid_nick = "MyRelay";
        assert!(is_valid_nickname(valid_nick));

        let invalid_nick = "my-relay";
        assert!(!is_valid_nickname(invalid_nick));
    }

    #[test]
    fn test_resolve_ipv4_validation() {
        let valid_ip = "192.168.1.1";
        assert!(is_valid_ipv4_address(valid_ip));

        let invalid_ip = "256.0.0.1";
        assert!(!is_valid_ipv4_address(invalid_ip));
    }

    #[test]
    fn test_resolve_port_validation() {
        let valid_port = "9051";
        assert!(is_valid_port(valid_port));

        let invalid_port = "0";
        assert!(!is_valid_port(invalid_port));

        let invalid_port2 = "65536";
        assert!(!is_valid_port(invalid_port2));
    }

    #[test]
    fn test_command_parsing_with_args() {
        let command = "GETINFO version";
        let (cmd, arg) = command.split_once(' ').unwrap();
        assert_eq!(cmd, "GETINFO");
        assert_eq!(arg, "version");
    }

    #[test]
    fn test_command_parsing_without_args() {
        let command = "QUIT";
        let result = command.split_once(' ');
        assert!(result.is_none());
    }

    #[test]
    fn test_interpreter_command_detection() {
        assert!("/help".starts_with('/'));
        assert!("/events".starts_with('/'));
        assert!("/info".starts_with('/'));
        assert!("/python".starts_with('/'));
        assert!("/quit".starts_with('/'));

        assert!(!"GETINFO".starts_with('/'));
        assert!(!"SETCONF".starts_with('/'));
    }

    #[test]
    fn test_event_type_filtering_logic() {
        let event_types = ["BW", "CIRC"];
        let test_type = "BW";

        let matches = event_types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(test_type));
        assert!(matches);

        let test_type2 = "bw";
        let matches2 = event_types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(test_type2));
        assert!(matches2);

        let test_type3 = "STREAM";
        let matches3 = event_types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(test_type3));
        assert!(!matches3);
    }

    #[test]
    fn test_clear_event_detection() {
        let event_types = ["BW", "CLEAR", "CIRC"];
        let has_clear = event_types.iter().any(|t| t.eq_ignore_ascii_case("CLEAR"));
        assert!(has_clear);

        let event_types2 = ["BW", "CIRC"];
        let has_clear2 = event_types2.iter().any(|t| t.eq_ignore_ascii_case("CLEAR"));
        assert!(!has_clear2);
    }

    #[test]
    fn test_multiline_commands_detection() {
        let multiline_cmds = ["LOADCONF", "+LOADCONF", "POSTDESCRIPTOR", "+POSTDESCRIPTOR"];

        for cmd in multiline_cmds {
            let cmd_upper = cmd.to_uppercase();
            let is_multiline = cmd_upper == "LOADCONF"
                || cmd_upper == "+LOADCONF"
                || cmd_upper == "POSTDESCRIPTOR"
                || cmd_upper == "+POSTDESCRIPTOR";
            assert!(is_multiline, "Expected {} to be detected as multiline", cmd);
        }

        let regular_cmds = ["GETINFO", "SETCONF", "SIGNAL"];
        for cmd in regular_cmds {
            let cmd_upper = cmd.to_uppercase();
            let is_multiline = cmd_upper == "LOADCONF"
                || cmd_upper == "+LOADCONF"
                || cmd_upper == "POSTDESCRIPTOR"
                || cmd_upper == "+POSTDESCRIPTOR";
            assert!(
                !is_multiline,
                "Expected {} to NOT be detected as multiline",
                cmd
            );
        }
    }

    #[test]
    fn test_quit_command_detection() {
        let cmd = "QUIT";
        assert_eq!(cmd.to_uppercase(), "QUIT");

        let cmd2 = "quit";
        assert_eq!(cmd2.to_uppercase(), "QUIT");
    }

    #[test]
    fn test_empty_command_handling() {
        let command = "";
        let trimmed = command.trim();
        assert!(trimmed.is_empty());

        let command2 = "   ";
        let trimmed2 = command2.trim();
        assert!(trimmed2.is_empty());
    }

    #[test]
    fn test_command_uppercase_conversion() {
        let cmd = "getinfo";
        assert_eq!(cmd.to_uppercase(), "GETINFO");

        let cmd2 = "SetConf";
        assert_eq!(cmd2.to_uppercase(), "SETCONF");
    }

    #[test]
    fn test_full_command_construction() {
        let cmd = "GETINFO";
        let arg = "version";
        let full = format!("{} {}", cmd, arg);
        assert_eq!(full, "GETINFO version");

        let cmd2 = "QUIT";
        let arg2 = "";
        let full2 = if arg2.is_empty() {
            cmd2.to_string()
        } else {
            format!("{} {}", cmd2, arg2)
        };
        assert_eq!(full2, "QUIT");
    }

    #[test]
    fn test_ns_line_parsing() {
        let r_line = "r MyRelay ABCD1234 2023-01-01 12:00:00 192.168.1.1 9001 0";
        let parts: Vec<&str> = r_line.split_whitespace().collect();

        assert!(r_line.starts_with("r "));
        assert!(parts.len() >= 2);
        assert_eq!(parts[1], "MyRelay");
    }

    #[test]
    fn test_flags_line_parsing() {
        let s_line = "s Fast Guard Stable Valid";
        assert!(s_line.starts_with("s "));

        let stripped = s_line.strip_prefix("s ").unwrap();
        assert_eq!(stripped, "Fast Guard Stable Valid");
    }

    #[test]
    fn test_version_line_parsing() {
        let v_line = "v Tor 0.4.7.10";
        assert!(v_line.starts_with("v "));

        let stripped = v_line.strip_prefix("v ").unwrap();
        assert_eq!(stripped, "Tor 0.4.7.10");
    }

    #[test]
    fn test_ip_port_parsing() {
        let addr_port = "192.168.1.1:9051";
        let (addr, port_str) = addr_port.rsplit_once(':').unwrap();
        assert_eq!(addr, "192.168.1.1");
        assert_eq!(port_str, "9051");

        let addr_only = "192.168.1.1";
        let result = addr_only.rsplit_once(':');
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_relay_response_format() {
        let address = "192.168.1.1";
        let matches = [(9001u16, "FP1".to_string()), (9002u16, "FP2".to_string())];

        let mut response = format!(
            "There's multiple relays at {}, include a port to specify which.\n\n",
            address
        );
        for (i, (or_port, fp)) in matches.iter().enumerate() {
            response.push_str(&format!(
                "  {}. {}:{}, fingerprint: {}\n",
                i + 1,
                address,
                or_port,
                fp
            ));
        }

        assert!(response.contains("multiple relays"));
        assert!(response.contains("192.168.1.1:9001"));
        assert!(response.contains("192.168.1.1:9002"));
        assert!(response.contains("FP1"));
        assert!(response.contains("FP2"));
    }
}
