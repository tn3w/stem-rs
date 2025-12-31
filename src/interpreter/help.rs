//! Help system for the interpreter prompt.
//!
//! This module provides help text and usage information for interpreter
//! commands and Tor control protocol commands.
//!
//! # Overview
//!
//! The help system provides documentation for:
//! - Interpreter commands (`/help`, `/events`, `/info`, `/python`, `/quit`)
//! - Tor control commands (`GETINFO`, `GETCONF`, `SETCONF`, `SIGNAL`, etc.)
//!
//! For some commands (like `GETINFO` and `GETCONF`), the help system queries
//! Tor to provide a complete list of available options.
//!
//! # Usage
//!
//! Help is accessed via the `/help` interpreter command:
//!
//! ```text
//! /help           # General help overview
//! /help GETINFO   # Help for GETINFO command
//! /help signal    # Help for SIGNAL command (case-insensitive)
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::Controller;
//! use stem_rs::interpreter::help;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! // Get general help
//! let general = help::response(&mut controller, "").await;
//! println!("{}", general);
//!
//! // Get help for a specific command
//! let signal_help = help::response(&mut controller, "SIGNAL").await;
//! println!("{}", signal_help);
//! # Ok(())
//! # }
//! ```
//!
//! # Python Stem Equivalent
//!
//! This module corresponds to Python Stem's `stem.interpreter.help` module.

use crate::controller::Controller;

/// Returns help text for the given topic.
///
/// If no topic is provided (empty string), returns general help with an
/// overview of all available commands. Otherwise, returns detailed help
/// for the specified command.
///
/// # Arguments
///
/// * `controller` - An authenticated controller connection (used to query
///   available options for some commands)
/// * `arg` - The help topic (command name), or empty for general help
///
/// # Returns
///
/// Help text as a string. If the topic is not recognized, returns an
/// error message.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::Controller;
/// use stem_rs::interpreter::help;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// # let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
/// # controller.authenticate(None).await?;
/// // General help
/// let help_text = help::response(&mut controller, "").await;
/// assert!(help_text.contains("/help"));
///
/// // Command-specific help
/// let signal_help = help::response(&mut controller, "SIGNAL").await;
/// assert!(signal_help.contains("NEWNYM"));
///
/// // Unknown topic
/// let unknown = help::response(&mut controller, "UNKNOWN").await;
/// assert!(unknown.contains("No help information"));
/// # Ok(())
/// # }
/// ```
pub async fn response(controller: &mut Controller, arg: &str) -> String {
    let arg = normalize(arg);

    if arg.is_empty() {
        return general_help();
    }

    match arg.as_str() {
        "HELP" => help_help(),
        "EVENTS" => help_events(),
        "INFO" => help_info(),
        "PYTHON" => help_python(),
        "QUIT" => help_quit(),
        "GETINFO" => help_getinfo(controller).await,
        "GETCONF" => help_getconf(controller).await,
        "SETCONF" => help_setconf(),
        "RESETCONF" => help_resetconf(),
        "SIGNAL" => help_signal(),
        "SETEVENTS" => help_setevents(controller).await,
        "USEFEATURE" => help_usefeature(controller).await,
        "SAVECONF" => help_saveconf(),
        "LOADCONF" => help_loadconf(),
        "MAPADDRESS" => help_mapaddress(),
        "POSTDESCRIPTOR" => help_postdescriptor(),
        "EXTENDCIRCUIT" => help_extendcircuit(),
        "SETCIRCUITPURPOSE" => help_setcircuitpurpose(),
        "CLOSECIRCUIT" => help_closecircuit(),
        "ATTACHSTREAM" => help_attachstream(),
        "REDIRECTSTREAM" => help_redirectstream(),
        "CLOSESTREAM" => help_closestream(),
        "ADD_ONION" => help_add_onion(),
        "DEL_ONION" => help_del_onion(),
        "HSFETCH" => help_hsfetch(),
        "HSPOST" => help_hspost(),
        "RESOLVE" => help_resolve(),
        "TAKEOWNERSHIP" => help_takeownership(),
        "PROTOCOLINFO" => help_protocolinfo(),
        _ => format!("No help information available for '{}'...", arg),
    }
}

/// Normalizes a help topic argument.
///
/// Converts to uppercase, takes only the first word, and strips leading `/`.
fn normalize(arg: &str) -> String {
    let arg = arg.to_uppercase();
    let arg = arg.split_whitespace().next().unwrap_or("");
    arg.trim_start_matches('/').to_string()
}

/// Returns the general help overview listing all commands.
fn general_help() -> String {
    r#"Interpreter commands include:
  /help   - provides information for interpreter and tor commands
  /events - prints events that we've received
  /info   - general information for a relay
  /python - enable or disable support for running python commands
  /quit   - shuts down the interpreter

Tor commands include:
  GETINFO - queries information from tor
  GETCONF, SETCONF, RESETCONF - show or edit a configuration option
  SIGNAL - issues control signal to the process (for resetting, stopping, etc)
  SETEVENTS - configures the events tor will notify us of

  USEFEATURE - enables custom behavior for the controller
  SAVECONF - writes tor's current configuration to our torrc
  LOADCONF - loads the given input like it was part of our torrc
  MAPADDRESS - replaces requests for one address with another
  POSTDESCRIPTOR - adds a relay descriptor to our cache
  EXTENDCIRCUIT - create or extend a tor circuit
  SETCIRCUITPURPOSE - configures the purpose associated with a circuit
  CLOSECIRCUIT - closes the given circuit
  ATTACHSTREAM - associates an application's stream with a tor circuit
  REDIRECTSTREAM - sets a stream's destination
  CLOSESTREAM - closes the given stream
  ADD_ONION - create a new hidden service
  DEL_ONION - delete a hidden service that was created with ADD_ONION
  HSFETCH - retrieve a hidden service descriptor
  HSPOST - uploads a hidden service descriptor
  RESOLVE - issues an asynchronous dns or rdns request over tor
  TAKEOWNERSHIP - instructs tor to quit when this control connection is closed
  PROTOCOLINFO - queries version and controller authentication information
  QUIT - disconnect the control connection

For more information use '/help [OPTION]'."#
        .to_string()
}

/// Returns help for the `/help` command.
fn help_help() -> String {
    r#"/help [OPTION]

Provides usage information for the given interpreter, tor command, or tor
configuration option.

Example:
  /help info        # provides a description of the '/info' option
  /help GETINFO     # usage information for tor's GETINFO controller option"#
        .to_string()
}

/// Returns help for the `/events` command.
fn help_events() -> String {
    r#"/events [types]

Provides events that we've received belonging to the given event types. If
no types are specified then this provides all the messages that we've
received.

You can also run '/events clear' to clear the backlog of events we've
received."#
        .to_string()
}

/// Returns help for the `/info` command.
fn help_info() -> String {
    r#"/info [relay fingerprint, nickname, or IP address]

Provides information for a relay that's currently in the consensus. If no
relay is specified then this provides information on ourselves."#
        .to_string()
}

/// Returns help for the `/python` command.
fn help_python() -> String {
    r#"/python [enable,disable]

Enables or disables support for running python commands. This determines how
we treat commands this interpreter doesn't recognize...

* If enabled then unrecognized commands are executed as python.
* If disabled then unrecognized commands are passed along to tor."#
        .to_string()
}

/// Returns help for the `/quit` command.
fn help_quit() -> String {
    "/quit\n\nTerminates the interpreter.".to_string()
}

/// Returns help for the `GETINFO` command, including available options.
async fn help_getinfo(controller: &mut Controller) -> String {
    let mut output =
        "GETINFO OPTION\n\nQueries the tor process for information. Options are...\n\n".to_string();

    if let Ok(results) = controller.get_info("info/names").await {
        for line in results.lines() {
            if let Some((opt, summary)) = line.split_once(" -- ") {
                output.push_str(&format!("{:<33} - {}\n", opt, summary));
            }
        }
    }

    output
}

/// Returns help for the `GETCONF` command, including available options.
async fn help_getconf(controller: &mut Controller) -> String {
    let mut output = "GETCONF OPTION\n\nProvides the current value for a given configuration value. Options include...\n\n".to_string();

    if let Ok(results) = controller.get_info("config/names").await {
        let options: Vec<&str> = results
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .collect();

        for chunk in options.chunks(2) {
            let line = chunk
                .iter()
                .map(|s| format!("{:<42}", s))
                .collect::<Vec<_>>()
                .join("");
            output.push_str(&format!("{}\n", line.trim_end()));
        }
    }

    output
}

/// Returns help for the `SETCONF` command.
fn help_setconf() -> String {
    r#"SETCONF PARAM[=VALUE]

Sets the given configuration parameters. Values can be quoted or non-quoted
strings, and reverts the option to 0 or NULL if not provided.

Examples:
  * Sets a contact address and resets our family to NULL
    SETCONF MyFamily ContactInfo=foo@bar.com

  * Sets an exit policy that only includes port 80/443
    SETCONF ExitPolicy="accept *:80, accept *:443, reject *:*""#
        .to_string()
}

/// Returns help for the `RESETCONF` command.
fn help_resetconf() -> String {
    r#"RESETCONF PARAM[=VALUE]

Reverts the given configuration options to their default values. If a value
is provided then this behaves in the same way as SETCONF.

Examples:
  * Returns both of our accounting parameters to their defaults
    RESETCONF AccountingMax AccountingStart

  * Uses the default exit policy and sets our nickname to be 'Goomba'
    RESETCONF ExitPolicy Nickname=Goomba"#
        .to_string()
}

/// Returns help for the `SIGNAL` command.
fn help_signal() -> String {
    r#"SIGNAL SIG

Issues a signal that tells the tor process to reload its torrc, dump its
stats, halt, etc.

RELOAD / HUP      - reload our torrc
SHUTDOWN / INT    - gracefully shut down, waiting 30 seconds if we're a relay
DUMP / USR1       - logs information about open connections and circuits
DEBUG / USR2      - makes us log at the DEBUG runlevel
HALT / TERM       - immediately shut down
CLEARDNSCACHE     - clears any cached DNS results
NEWNYM            - clears the DNS cache and uses new circuits for future connections"#
        .to_string()
}

/// Returns help for the `SETEVENTS` command, including available events.
async fn help_setevents(controller: &mut Controller) -> String {
    let mut output = r#"SETEVENTS [EXTENDED] [EVENTS]

Sets the events that we will receive. This turns off any events that aren't
listed so sending 'SETEVENTS' without any values will turn off all event reporting.

Events include...

"#
    .to_string();

    if let Ok(results) = controller.get_info("events/names").await {
        let entries: Vec<&str> = results.split_whitespace().collect();
        for chunk in entries.chunks(4) {
            let line = chunk
                .iter()
                .map(|s| format!("{:<20}", s))
                .collect::<Vec<_>>()
                .join("");
            output.push_str(&format!("{}\n", line.trim_end()));
        }
    }

    output
}

/// Returns help for the `USEFEATURE` command, including available features.
async fn help_usefeature(controller: &mut Controller) -> String {
    let mut output =
        "USEFEATURE OPTION\n\nCustomizes the behavior of the control port. Options include...\n\n"
            .to_string();

    if let Ok(results) = controller.get_info("features/names").await {
        output.push_str(&results);
        output.push('\n');
    }

    output
}

/// Returns help for the `SAVECONF` command.
fn help_saveconf() -> String {
    "SAVECONF\n\nWrites Tor's current configuration to its torrc.".to_string()
}

/// Returns help for the `LOADCONF` command.
fn help_loadconf() -> String {
    r#"LOADCONF...

Reads the given text like it belonged to our torrc.

Example:
  +LOADCONF
  # sets our exit policy to just accept ports 80 and 443
  ExitPolicy accept *:80
  ExitPolicy accept *:443
  ExitPolicy reject *:*
  .

Multi-line control options like this are not yet implemented."#
        .to_string()
}

/// Returns help for the `MAPADDRESS` command.
fn help_mapaddress() -> String {
    r#"MAPADDRESS SOURCE_ADDR=DESTINATION_ADDR

Replaces future requests for one address with another.

Example:
  MAPADDRESS 0.0.0.0=torproject.org 1.2.3.4=tor.freehaven.net"#
        .to_string()
}

/// Returns help for the `POSTDESCRIPTOR` command.
fn help_postdescriptor() -> String {
    r#"POSTDESCRIPTOR [purpose=general/controller/bridge] [cache=yes/no]...

Simulates getting a new relay descriptor.

Multi-line control options like this are not yet implemented."#
        .to_string()
}

/// Returns help for the `EXTENDCIRCUIT` command.
fn help_extendcircuit() -> String {
    r#"EXTENDCIRCUIT CircuitID [PATH] [purpose=general/controller]

Extends the given circuit or create a new one if the CircuitID is zero. The
PATH is a comma separated list of fingerprints. If it isn't set then this
uses Tor's normal path selection."#
        .to_string()
}

/// Returns help for the `SETCIRCUITPURPOSE` command.
fn help_setcircuitpurpose() -> String {
    "SETCIRCUITPURPOSE CircuitID purpose=general/controller\n\nSets the purpose attribute for a circuit.".to_string()
}

/// Returns help for the `CLOSECIRCUIT` command.
fn help_closecircuit() -> String {
    r#"CLOSECIRCUIT CircuitID [IfUnused]

Closes the given circuit. If "IfUnused" is included then this only closes
the circuit if it isn't currently being used."#
        .to_string()
}

/// Returns help for the `ATTACHSTREAM` command.
fn help_attachstream() -> String {
    r#"ATTACHSTREAM StreamID CircuitID [HOP=HopNum]

Attaches a stream with the given built circuit (tor picks one on its own if
CircuitID is zero). If HopNum is given then this hop is used to exit the
circuit, otherwise the last relay is used."#
        .to_string()
}

/// Returns help for the `REDIRECTSTREAM` command.
fn help_redirectstream() -> String {
    r#"REDIRECTSTREAM StreamID Address [Port]

Sets the destination for a given stream. This can only be done after a
stream is created but before it's attached to a circuit."#
        .to_string()
}

/// Returns help for the `CLOSESTREAM` command.
fn help_closestream() -> String {
    r#"CLOSESTREAM StreamID Reason [Flag]

Closes the given stream, the reason being an integer matching a reason as
per section 6.3 of the tor-spec."#
        .to_string()
}

/// Returns help for the `ADD_ONION` command.
fn help_add_onion() -> String {
    r#"KeyType:KeyBlob [Flags=Flag] (Port=Port [,Target])...

Creates a new hidden service. Unlike 'SETCONF HiddenServiceDir...' this
doesn't persist the service to disk."#
        .to_string()
}

/// Returns help for the `DEL_ONION` command.
fn help_del_onion() -> String {
    "DEL_ONION ServiceID\n\nDelete a hidden service that was created with ADD_ONION.".to_string()
}

/// Returns help for the `HSFETCH` command.
fn help_hsfetch() -> String {
    r#"HSFETCH (HSAddress/v2-DescId) [SERVER=Server]...

Retrieves the descriptor for a hidden service. This is an asynchronous
request, with the descriptor provided by a HS_DESC_CONTENT event."#
        .to_string()
}

/// Returns help for the `HSPOST` command.
fn help_hspost() -> String {
    "HSPOST [SERVER=Server] DESCRIPTOR\n\nUploads a descriptor to a hidden service directory."
        .to_string()
}

/// Returns help for the `RESOLVE` command.
fn help_resolve() -> String {
    r#"RESOLVE [mode=reverse] address

Performs IPv4 DNS resolution over tor, doing a reverse lookup instead if
"mode=reverse" is included. This request is processed in the background and
results in a ADDRMAP event with the response."#
        .to_string()
}

/// Returns help for the `TAKEOWNERSHIP` command.
fn help_takeownership() -> String {
    "TAKEOWNERSHIP\n\nInstructs Tor to gracefully shut down when this control connection is closed."
        .to_string()
}

/// Returns help for the `PROTOCOLINFO` command.
fn help_protocolinfo() -> String {
    r#"PROTOCOLINFO [ProtocolVersion]

Provides bootstrapping information that a controller might need when first
starting, like Tor's version and controller authentication. This can be done
before authenticating to the control port."#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_uppercase() {
        assert_eq!(normalize("getinfo"), "GETINFO");
    }

    #[test]
    fn test_normalize_strips_slash() {
        assert_eq!(normalize("/help"), "HELP");
    }

    #[test]
    fn test_normalize_takes_first_word() {
        assert_eq!(normalize("GETINFO version"), "GETINFO");
    }

    #[test]
    fn test_normalize_empty() {
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn test_general_help_contains_commands() {
        let help = general_help();
        assert!(help.contains("/help"));
        assert!(help.contains("/events"));
        assert!(help.contains("/info"));
        assert!(help.contains("/python"));
        assert!(help.contains("/quit"));
        assert!(help.contains("GETINFO"));
        assert!(help.contains("GETCONF"));
        assert!(help.contains("SETCONF"));
        assert!(help.contains("SIGNAL"));
    }

    #[test]
    fn test_help_help() {
        let help = help_help();
        assert!(help.contains("/help"));
        assert!(help.contains("Example"));
    }

    #[test]
    fn test_help_events() {
        let help = help_events();
        assert!(help.contains("/events"));
        assert!(help.contains("clear"));
    }

    #[test]
    fn test_help_signal() {
        let help = help_signal();
        assert!(help.contains("RELOAD"));
        assert!(help.contains("SHUTDOWN"));
        assert!(help.contains("NEWNYM"));
    }

    #[test]
    fn test_help_info() {
        let help = help_info();
        assert!(help.contains("/info"));
        assert!(help.contains("fingerprint"));
        assert!(help.contains("nickname"));
    }

    #[test]
    fn test_help_python() {
        let help = help_python();
        assert!(help.contains("/python"));
        assert!(help.contains("enable"));
        assert!(help.contains("disable"));
    }

    #[test]
    fn test_help_quit() {
        let help = help_quit();
        assert!(help.contains("/quit"));
        assert!(help.contains("Terminates"));
    }

    #[test]
    fn test_help_setconf() {
        let help = help_setconf();
        assert!(help.contains("SETCONF"));
        assert!(help.contains("Example"));
        assert!(help.contains("MyFamily"));
    }

    #[test]
    fn test_help_resetconf() {
        let help = help_resetconf();
        assert!(help.contains("RESETCONF"));
        assert!(help.contains("default"));
        assert!(help.contains("Example"));
    }

    #[test]
    fn test_help_saveconf() {
        let help = help_saveconf();
        assert!(help.contains("SAVECONF"));
        assert!(help.contains("torrc"));
    }

    #[test]
    fn test_help_loadconf() {
        let help = help_loadconf();
        assert!(help.contains("LOADCONF"));
        assert!(help.contains("Multi-line"));
    }

    #[test]
    fn test_help_mapaddress() {
        let help = help_mapaddress();
        assert!(help.contains("MAPADDRESS"));
        assert!(help.contains("Example"));
    }

    #[test]
    fn test_help_postdescriptor() {
        let help = help_postdescriptor();
        assert!(help.contains("POSTDESCRIPTOR"));
        assert!(help.contains("Multi-line"));
    }

    #[test]
    fn test_help_extendcircuit() {
        let help = help_extendcircuit();
        assert!(help.contains("EXTENDCIRCUIT"));
        assert!(help.contains("CircuitID"));
        assert!(help.contains("PATH"));
    }

    #[test]
    fn test_help_setcircuitpurpose() {
        let help = help_setcircuitpurpose();
        assert!(help.contains("SETCIRCUITPURPOSE"));
        assert!(help.contains("purpose"));
    }

    #[test]
    fn test_help_closecircuit() {
        let help = help_closecircuit();
        assert!(help.contains("CLOSECIRCUIT"));
        assert!(help.contains("IfUnused"));
    }

    #[test]
    fn test_help_attachstream() {
        let help = help_attachstream();
        assert!(help.contains("ATTACHSTREAM"));
        assert!(help.contains("StreamID"));
        assert!(help.contains("CircuitID"));
    }

    #[test]
    fn test_help_redirectstream() {
        let help = help_redirectstream();
        assert!(help.contains("REDIRECTSTREAM"));
        assert!(help.contains("Address"));
    }

    #[test]
    fn test_help_closestream() {
        let help = help_closestream();
        assert!(help.contains("CLOSESTREAM"));
        assert!(help.contains("Reason"));
    }

    #[test]
    fn test_help_add_onion() {
        let help = help_add_onion();
        assert!(help.contains("KeyType"));
        assert!(help.contains("hidden service"));
    }

    #[test]
    fn test_help_del_onion() {
        let help = help_del_onion();
        assert!(help.contains("DEL_ONION"));
        assert!(help.contains("ServiceID"));
    }

    #[test]
    fn test_help_hsfetch() {
        let help = help_hsfetch();
        assert!(help.contains("HSFETCH"));
        assert!(help.contains("descriptor"));
    }

    #[test]
    fn test_help_hspost() {
        let help = help_hspost();
        assert!(help.contains("HSPOST"));
        assert!(help.contains("DESCRIPTOR"));
    }

    #[test]
    fn test_help_resolve() {
        let help = help_resolve();
        assert!(help.contains("RESOLVE"));
        assert!(help.contains("DNS"));
        assert!(help.contains("reverse"));
    }

    #[test]
    fn test_help_takeownership() {
        let help = help_takeownership();
        assert!(help.contains("TAKEOWNERSHIP"));
        assert!(help.contains("shut down"));
    }

    #[test]
    fn test_help_protocolinfo() {
        let help = help_protocolinfo();
        assert!(help.contains("PROTOCOLINFO"));
        assert!(help.contains("authentication"));
    }

    #[test]
    fn test_normalize_mixed_case() {
        assert_eq!(normalize("GetInfo"), "GETINFO");
        assert_eq!(normalize("setConf"), "SETCONF");
    }

    #[test]
    fn test_normalize_with_multiple_spaces() {
        assert_eq!(normalize("GETINFO   version   extra"), "GETINFO");
    }

    #[test]
    fn test_normalize_slash_command() {
        assert_eq!(normalize("/EVENTS"), "EVENTS");
        assert_eq!(normalize("/events"), "EVENTS");
    }
}
