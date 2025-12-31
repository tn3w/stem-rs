//! Command-line argument parsing for the interpreter prompt.
//!
//! This module provides argument parsing for the Tor interpreter command-line
//! interface, handling connection options, execution modes, and display settings.
//!
//! # Overview
//!
//! The interpreter accepts various command-line arguments to configure:
//! - Control interface connection (TCP port or Unix socket)
//! - Tor binary path for auto-starting
//! - Single command or script execution
//! - Output formatting options
//!
//! # Supported Arguments
//!
//! | Short | Long | Description |
//! |-------|------|-------------|
//! | `-i` | `--interface` | Control interface `[ADDRESS:]PORT` |
//! | `-s` | `--socket` | Unix domain socket path |
//! | | `--tor` | Path to Tor binary |
//! | | `--run` | Command or script file to execute |
//! | | `--no-color` | Disable colored output |
//! | `-h` | `--help` | Show help message |
//!
//! # Example
//!
//! ```rust
//! use stem_rs::interpreter::arguments::Arguments;
//!
//! // Parse command-line arguments
//! let args = Arguments::parse(&[
//!     "-i".to_string(),
//!     "9051".to_string(),
//!     "--no-color".to_string(),
//! ]).unwrap();
//!
//! assert_eq!(args.control_port, Some(9051));
//! assert!(args.disable_color);
//! ```
//!
//! # Python Stem Equivalent
//!
//! This module corresponds to Python Stem's `stem.interpreter.arguments` module.

use crate::util::{is_valid_ipv4_address, is_valid_port};

/// Parsed command-line arguments for the interpreter.
///
/// This struct holds all configuration options that can be specified
/// via command-line arguments when launching the interpreter.
///
/// # Default Values
///
/// | Field | Default |
/// |-------|---------|
/// | `control_address` | `"127.0.0.1"` |
/// | `control_port` | `None` (uses Tor's default) |
/// | `control_socket` | `"/var/run/tor/control"` |
/// | `tor_path` | `"tor"` |
///
/// # Example
///
/// ```rust
/// use stem_rs::interpreter::arguments::Arguments;
///
/// // Use defaults
/// let defaults = Arguments::default();
/// assert_eq!(defaults.control_address, "127.0.0.1");
///
/// // Parse from command line
/// let args = Arguments::parse(&["--interface".to_string(), "192.168.1.1:9051".to_string()]).unwrap();
/// assert_eq!(args.control_address, "192.168.1.1");
/// assert_eq!(args.control_port, Some(9051));
/// ```
#[derive(Debug, Clone)]
pub struct Arguments {
    /// IP address for the control interface.
    ///
    /// Defaults to `"127.0.0.1"` (localhost).
    pub control_address: String,
    /// Port number for the control interface.
    ///
    /// If `None`, the default Tor control port is used.
    pub control_port: Option<u16>,
    /// Whether the user explicitly specified a port.
    ///
    /// Used to determine connection priority when both port and socket
    /// are available.
    pub user_provided_port: bool,
    /// Path to the Unix domain socket for control connection.
    ///
    /// Defaults to `"/var/run/tor/control"`.
    pub control_socket: String,
    /// Whether the user explicitly specified a socket path.
    ///
    /// Used to determine connection priority when both port and socket
    /// are available.
    pub user_provided_socket: bool,
    /// Path to the Tor binary.
    ///
    /// Used when Tor needs to be started automatically.
    /// Defaults to `"tor"` (found via PATH).
    pub tor_path: String,
    /// Single command to execute and exit.
    ///
    /// If set, the interpreter runs this command and exits instead of
    /// entering interactive mode.
    pub run_cmd: Option<String>,
    /// Path to a script file to execute.
    ///
    /// If set, the interpreter runs all commands in the file and exits.
    /// Takes precedence over `run_cmd` if the path exists.
    pub run_path: Option<String>,
    /// Whether to disable colored output.
    ///
    /// When `true`, all output is plain text without ANSI color codes.
    pub disable_color: bool,
    /// Whether to print help and exit.
    ///
    /// When `true`, the interpreter prints usage information and exits
    /// without connecting to Tor.
    pub print_help: bool,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            control_address: "127.0.0.1".to_string(),
            control_port: None,
            user_provided_port: false,
            control_socket: "/var/run/tor/control".to_string(),
            user_provided_socket: false,
            tor_path: "tor".to_string(),
            run_cmd: None,
            run_path: None,
            disable_color: false,
            print_help: false,
        }
    }
}

impl Arguments {
    /// Parses command-line arguments into an `Arguments` struct.
    ///
    /// # Arguments
    ///
    /// * `argv` - Slice of command-line argument strings (excluding program name)
    ///
    /// # Returns
    ///
    /// Parsed arguments on success, or an error message on failure.
    ///
    /// # Errors
    ///
    /// Returns an error string if:
    /// - An argument requires a value but none is provided
    /// - An IP address is invalid
    /// - A port number is invalid (not 1-65535)
    /// - An unrecognized argument is provided
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::interpreter::arguments::Arguments;
    ///
    /// // Parse port only
    /// let args = Arguments::parse(&["-i".to_string(), "9051".to_string()]).unwrap();
    /// assert_eq!(args.control_port, Some(9051));
    ///
    /// // Parse address and port
    /// let args = Arguments::parse(&["-i".to_string(), "192.168.1.1:9051".to_string()]).unwrap();
    /// assert_eq!(args.control_address, "192.168.1.1");
    /// assert_eq!(args.control_port, Some(9051));
    ///
    /// // Invalid port returns error
    /// let result = Arguments::parse(&["-i".to_string(), "99999".to_string()]);
    /// assert!(result.is_err());
    /// ```
    pub fn parse(argv: &[String]) -> Result<Self, String> {
        let mut args = Arguments::default();
        let mut i = 0;

        while i < argv.len() {
            let arg = &argv[i];
            match arg.as_str() {
                "-i" | "--interface" => {
                    i += 1;
                    if i >= argv.len() {
                        return Err("--interface requires an argument".to_string());
                    }
                    let interface = &argv[i];
                    if let Some((addr, port_str)) = interface.rsplit_once(':') {
                        if !is_valid_ipv4_address(addr) {
                            return Err(format!("'{}' isn't a valid IPv4 address", addr));
                        }
                        if !is_valid_port(port_str) {
                            return Err(format!("'{}' isn't a valid port number", port_str));
                        }
                        args.control_address = addr.to_string();
                        args.control_port = Some(port_str.parse().unwrap());
                    } else {
                        if !is_valid_port(interface) {
                            return Err(format!("'{}' isn't a valid port number", interface));
                        }
                        args.control_port = Some(interface.parse().unwrap());
                    }
                    args.user_provided_port = true;
                }
                "-s" | "--socket" => {
                    i += 1;
                    if i >= argv.len() {
                        return Err("--socket requires an argument".to_string());
                    }
                    args.control_socket = argv[i].clone();
                    args.user_provided_socket = true;
                }
                "--tor" => {
                    i += 1;
                    if i >= argv.len() {
                        return Err("--tor requires an argument".to_string());
                    }
                    args.tor_path = argv[i].clone();
                }
                "--run" => {
                    i += 1;
                    if i >= argv.len() {
                        return Err("--run requires an argument".to_string());
                    }
                    let run_arg = &argv[i];
                    if std::path::Path::new(run_arg).exists() {
                        args.run_path = Some(run_arg.clone());
                    } else {
                        args.run_cmd = Some(run_arg.clone());
                    }
                }
                "--no-color" => {
                    args.disable_color = true;
                }
                "-h" | "--help" => {
                    args.print_help = true;
                }
                other => {
                    return Err(format!(
                        "'{}' isn't a recognized argument (for usage provide --help)",
                        other
                    ));
                }
            }
            i += 1;
        }

        Ok(args)
    }

    /// Returns the help message for command-line usage.
    ///
    /// The help message includes all available options with their
    /// descriptions and default values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::interpreter::arguments::Arguments;
    ///
    /// let help = Arguments::get_help();
    /// assert!(help.contains("--interface"));
    /// assert!(help.contains("--socket"));
    /// assert!(help.contains("--help"));
    /// ```
    pub fn get_help() -> String {
        let defaults = Arguments::default();
        format!(
            r#"Interactive interpreter for Tor. This provides you with direct access
to Tor's control interface via either python or direct requests.

  -i, --interface [ADDRESS:]PORT  change control interface from {}:{}
  -s, --socket SOCKET_PATH        attach using unix domain socket if present,
                                    SOCKET_PATH defaults to: {}
      --tor PATH                  tor binary if tor isn't already running
      --run                       executes the given command or file of commands
  --no-color                      disables colorized output
  -h, --help                      presents this help
"#,
            defaults.control_address,
            defaults
                .control_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "default".to_string()),
            defaults.control_socket
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_arguments() {
        let args = Arguments::default();
        assert_eq!(args.control_address, "127.0.0.1");
        assert_eq!(args.control_port, None);
        assert!(!args.user_provided_port);
        assert_eq!(args.control_socket, "/var/run/tor/control");
        assert!(!args.user_provided_socket);
        assert_eq!(args.tor_path, "tor");
        assert!(args.run_cmd.is_none());
        assert!(args.run_path.is_none());
        assert!(!args.disable_color);
        assert!(!args.print_help);
    }

    #[test]
    fn test_parse_help() {
        let args = Arguments::parse(&["--help".to_string()]).unwrap();
        assert!(args.print_help);
    }

    #[test]
    fn test_parse_help_short() {
        let args = Arguments::parse(&["-h".to_string()]).unwrap();
        assert!(args.print_help);
    }

    #[test]
    fn test_parse_interface_port_only() {
        let args = Arguments::parse(&["-i".to_string(), "9051".to_string()]).unwrap();
        assert_eq!(args.control_port, Some(9051));
        assert!(args.user_provided_port);
    }

    #[test]
    fn test_parse_interface_address_and_port() {
        let args =
            Arguments::parse(&["--interface".to_string(), "192.168.1.1:9051".to_string()]).unwrap();
        assert_eq!(args.control_address, "192.168.1.1");
        assert_eq!(args.control_port, Some(9051));
        assert!(args.user_provided_port);
    }

    #[test]
    fn test_parse_socket() {
        let args = Arguments::parse(&["-s".to_string(), "/tmp/tor.sock".to_string()]).unwrap();
        assert_eq!(args.control_socket, "/tmp/tor.sock");
        assert!(args.user_provided_socket);
    }

    #[test]
    fn test_parse_tor_path() {
        let args = Arguments::parse(&["--tor".to_string(), "/usr/bin/tor".to_string()]).unwrap();
        assert_eq!(args.tor_path, "/usr/bin/tor");
    }

    #[test]
    fn test_parse_run_cmd() {
        let args = Arguments::parse(&["--run".to_string(), "GETINFO version".to_string()]).unwrap();
        assert_eq!(args.run_cmd, Some("GETINFO version".to_string()));
        assert!(args.run_path.is_none());
    }

    #[test]
    fn test_parse_no_color() {
        let args = Arguments::parse(&["--no-color".to_string()]).unwrap();
        assert!(args.disable_color);
    }

    #[test]
    fn test_parse_invalid_port() {
        let result = Arguments::parse(&["-i".to_string(), "99999".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_address() {
        let result = Arguments::parse(&["-i".to_string(), "invalid:9051".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unrecognized_argument() {
        let result = Arguments::parse(&["--unknown".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_multiple_arguments() {
        let args = Arguments::parse(&[
            "-i".to_string(),
            "9051".to_string(),
            "-s".to_string(),
            "/tmp/tor.sock".to_string(),
            "--no-color".to_string(),
        ])
        .unwrap();
        assert_eq!(args.control_port, Some(9051));
        assert!(args.user_provided_port);
        assert_eq!(args.control_socket, "/tmp/tor.sock");
        assert!(args.user_provided_socket);
        assert!(args.disable_color);
    }

    #[test]
    fn test_get_help() {
        let help = Arguments::get_help();
        assert!(help.contains("--interface"));
        assert!(help.contains("--socket"));
        assert!(help.contains("--tor"));
        assert!(help.contains("--run"));
        assert!(help.contains("--no-color"));
        assert!(help.contains("--help"));
    }
}
