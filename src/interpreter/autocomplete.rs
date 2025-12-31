//! Tab completion for the interpreter prompt.
//!
//! This module provides autocompletion functionality for the Tor interpreter,
//! enabling tab completion of commands, options, and arguments.
//!
//! # Overview
//!
//! The [`Autocompleter`] queries Tor for available commands and options,
//! building a comprehensive list of completions including:
//!
//! - Interpreter commands (`/help`, `/events`, `/info`, etc.)
//! - Tor control commands (`GETINFO`, `GETCONF`, `SETCONF`, etc.)
//! - Command arguments (config options, event types, signals)
//! - Help topics
//!
//! # Architecture
//!
//! On initialization, the autocompleter queries Tor for:
//! - `info/names` - Available GETINFO options
//! - `config/names` - Configuration options for GETCONF/SETCONF/RESETCONF
//! - `events/names` - Event types for SETEVENTS
//! - `features/names` - Features for USEFEATURE
//! - `signal/names` - Signals for SIGNAL command
//!
//! These are combined with built-in commands to create the completion list.
//!
//! # Example
//!
//! ```rust,no_run
//! use stem_rs::Controller;
//! use stem_rs::interpreter::autocomplete::Autocompleter;
//!
//! # async fn example() -> Result<(), stem_rs::Error> {
//! let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
//! controller.authenticate(None).await?;
//!
//! let autocompleter = Autocompleter::new(&mut controller).await;
//!
//! // Get all matches for partial input
//! let matches = autocompleter.matches("GETINFO");
//! for m in matches {
//!     println!("{}", m);
//! }
//!
//! // Get specific completion by index (for readline integration)
//! if let Some(completion) = autocompleter.complete("GETINFO", 0) {
//!     println!("First match: {}", completion);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Python Stem Equivalent
//!
//! This module corresponds to Python Stem's `stem.interpreter.autocomplete` module.

use crate::controller::Controller;

/// Tab completion provider for the interpreter.
///
/// `Autocompleter` maintains a list of valid commands and provides
/// case-insensitive prefix matching for tab completion.
///
/// # Conceptual Role
///
/// The autocompleter integrates with readline-style interfaces to provide
/// interactive tab completion. It queries Tor once at initialization to
/// build a comprehensive command list.
///
/// # Thread Safety
///
/// `Autocompleter` is `Send` and `Sync` after construction, as it only
/// contains an immutable command list.
///
/// # Example
///
/// ```rust,no_run
/// use stem_rs::Controller;
/// use stem_rs::interpreter::autocomplete::Autocompleter;
///
/// # async fn example() -> Result<(), stem_rs::Error> {
/// # let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
/// # controller.authenticate(None).await?;
/// let autocompleter = Autocompleter::new(&mut controller).await;
///
/// // Case-insensitive matching
/// let matches = autocompleter.matches("getinfo");
/// assert!(matches.iter().any(|m| m.starts_with("GETINFO")));
/// # Ok(())
/// # }
/// ```
pub struct Autocompleter {
    /// List of all available commands for completion.
    commands: Vec<String>,
}

impl Autocompleter {
    /// Creates a new autocompleter by querying Tor for available commands.
    ///
    /// This queries Tor for available options and builds a comprehensive
    /// list of completions. If any query fails, fallback completions are
    /// used for that category.
    ///
    /// # Arguments
    ///
    /// * `controller` - An authenticated controller connection
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::Controller;
    /// use stem_rs::interpreter::autocomplete::Autocompleter;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// # let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// # controller.authenticate(None).await?;
    /// let autocompleter = Autocompleter::new(&mut controller).await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(controller: &mut Controller) -> Self {
        let commands = build_command_list(controller).await;
        Self { commands }
    }

    /// Returns all commands matching the given prefix.
    ///
    /// Matching is case-insensitive. The returned strings preserve their
    /// original case.
    ///
    /// # Arguments
    ///
    /// * `text` - The prefix to match against
    ///
    /// # Returns
    ///
    /// A vector of references to matching commands.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::Controller;
    /// use stem_rs::interpreter::autocomplete::Autocompleter;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// # let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// # controller.authenticate(None).await?;
    /// let autocompleter = Autocompleter::new(&mut controller).await;
    ///
    /// // Get all interpreter commands
    /// let matches = autocompleter.matches("/");
    /// assert!(matches.contains(&"/help"));
    ///
    /// // Case-insensitive matching
    /// let matches = autocompleter.matches("signal");
    /// // Returns SIGNAL commands
    /// # Ok(())
    /// # }
    /// ```
    pub fn matches(&self, text: &str) -> Vec<&str> {
        let lowercase_text = text.to_lowercase();
        self.commands
            .iter()
            .filter(|cmd| cmd.to_lowercase().starts_with(&lowercase_text))
            .map(|s| s.as_str())
            .collect()
    }

    /// Returns the completion at the given index, for readline integration.
    ///
    /// This method is designed to work with readline's `set_completer`
    /// function, which calls the completer repeatedly with increasing
    /// state values until `None` is returned.
    ///
    /// # Arguments
    ///
    /// * `text` - The prefix to match against
    /// * `state` - The index of the match to return (0-based)
    ///
    /// # Returns
    ///
    /// The completion at the given index, or `None` if the index is
    /// out of bounds.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stem_rs::Controller;
    /// use stem_rs::interpreter::autocomplete::Autocompleter;
    ///
    /// # async fn example() -> Result<(), stem_rs::Error> {
    /// # let mut controller = Controller::from_port("127.0.0.1:9051".parse()?).await?;
    /// # controller.authenticate(None).await?;
    /// let autocompleter = Autocompleter::new(&mut controller).await;
    ///
    /// // Iterate through all matches
    /// let mut state = 0;
    /// while let Some(completion) = autocompleter.complete("/", state) {
    ///     println!("{}", completion);
    ///     state += 1;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn complete(&self, text: &str, state: usize) -> Option<&str> {
        self.matches(text).get(state).copied()
    }
}

/// Builds the complete list of commands for autocompletion.
///
/// Queries Tor for available options and combines them with built-in
/// interpreter commands. Falls back to generic completions if queries fail.
async fn build_command_list(controller: &mut Controller) -> Vec<String> {
    let mut commands = vec![
        "/help".to_string(),
        "/events".to_string(),
        "/info".to_string(),
        "/python".to_string(),
        "/quit".to_string(),
        "SAVECONF".to_string(),
        "MAPADDRESS".to_string(),
        "EXTENDCIRCUIT".to_string(),
        "SETCIRCUITPURPOSE".to_string(),
        "SETROUTERPURPOSE".to_string(),
        "ATTACHSTREAM".to_string(),
        "REDIRECTSTREAM".to_string(),
        "CLOSESTREAM".to_string(),
        "CLOSECIRCUIT".to_string(),
        "QUIT".to_string(),
        "RESOLVE".to_string(),
        "PROTOCOLINFO".to_string(),
        "TAKEOWNERSHIP".to_string(),
        "AUTHCHALLENGE".to_string(),
        "DROPGUARDS".to_string(),
        "ADD_ONION NEW:BEST".to_string(),
        "ADD_ONION NEW:RSA1024".to_string(),
        "ADD_ONION NEW:ED25519-V3".to_string(),
        "ADD_ONION RSA1024:".to_string(),
        "ADD_ONION ED25519-V3:".to_string(),
        "ONION_CLIENT_AUTH_ADD".to_string(),
        "ONION_CLIENT_AUTH_REMOVE".to_string(),
        "ONION_CLIENT_AUTH_VIEW".to_string(),
        "DEL_ONION".to_string(),
        "HSFETCH".to_string(),
        "HSPOST".to_string(),
    ];

    if let Ok(info_names) = controller.get_info("info/names").await {
        for line in info_names.lines() {
            if let Some(option) = line.split(' ').next() {
                let option = option.trim_end_matches('*');
                commands.push(format!("GETINFO {}", option));
            }
        }
    } else {
        commands.push("GETINFO ".to_string());
    }

    if let Ok(config_names) = controller.get_info("config/names").await {
        for line in config_names.lines() {
            if let Some(option) = line.split(' ').next() {
                commands.push(format!("GETCONF {}", option));
                commands.push(format!("SETCONF {}", option));
                commands.push(format!("RESETCONF {}", option));
            }
        }
    } else {
        commands.push("GETCONF ".to_string());
        commands.push("SETCONF ".to_string());
        commands.push("RESETCONF ".to_string());
    }

    if let Ok(event_names) = controller.get_info("events/names").await {
        for event in event_names.split_whitespace() {
            commands.push(format!("SETEVENTS {}", event));
        }
    } else {
        commands.push("SETEVENTS ".to_string());
    }

    if let Ok(feature_names) = controller.get_info("features/names").await {
        for feature in feature_names.split_whitespace() {
            commands.push(format!("USEFEATURE {}", feature));
        }
    } else {
        commands.push("USEFEATURE ".to_string());
    }

    if let Ok(signal_names) = controller.get_info("signal/names").await {
        for signal in signal_names.split_whitespace() {
            commands.push(format!("SIGNAL {}", signal));
        }
    } else {
        commands.push("SIGNAL ".to_string());
    }

    commands.push("/help HELP".to_string());
    commands.push("/help EVENTS".to_string());
    commands.push("/help INFO".to_string());
    commands.push("/help PYTHON".to_string());
    commands.push("/help QUIT".to_string());
    commands.push("/help GETINFO".to_string());
    commands.push("/help GETCONF".to_string());
    commands.push("/help SETCONF".to_string());
    commands.push("/help RESETCONF".to_string());
    commands.push("/help SIGNAL".to_string());
    commands.push("/help SETEVENTS".to_string());
    commands.push("/help USEFEATURE".to_string());
    commands.push("/help SAVECONF".to_string());
    commands.push("/help LOADCONF".to_string());
    commands.push("/help MAPADDRESS".to_string());
    commands.push("/help POSTDESCRIPTOR".to_string());
    commands.push("/help EXTENDCIRCUIT".to_string());
    commands.push("/help SETCIRCUITPURPOSE".to_string());
    commands.push("/help CLOSECIRCUIT".to_string());
    commands.push("/help ATTACHSTREAM".to_string());
    commands.push("/help REDIRECTSTREAM".to_string());
    commands.push("/help CLOSESTREAM".to_string());
    commands.push("/help ADD_ONION".to_string());
    commands.push("/help DEL_ONION".to_string());
    commands.push("/help HSFETCH".to_string());
    commands.push("/help HSPOST".to_string());
    commands.push("/help RESOLVE".to_string());
    commands.push("/help TAKEOWNERSHIP".to_string());
    commands.push("/help PROTOCOLINFO".to_string());

    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_autocompleter() -> Autocompleter {
        Autocompleter {
            commands: vec![
                "/help".to_string(),
                "/events".to_string(),
                "/info".to_string(),
                "/python".to_string(),
                "/quit".to_string(),
                "GETINFO version".to_string(),
                "GETINFO config-file".to_string(),
                "GETCONF SocksPort".to_string(),
                "SETCONF SocksPort".to_string(),
                "SIGNAL NEWNYM".to_string(),
            ],
        }
    }

    #[test]
    fn test_matches_interpreter_commands() {
        let ac = create_test_autocompleter();
        let matches = ac.matches("/");
        assert!(matches.contains(&"/help"));
        assert!(matches.contains(&"/events"));
        assert!(matches.contains(&"/info"));
        assert!(matches.contains(&"/python"));
        assert!(matches.contains(&"/quit"));
    }

    #[test]
    fn test_matches_case_insensitive() {
        let ac = create_test_autocompleter();
        let matches = ac.matches("getinfo");
        assert!(matches.contains(&"GETINFO version"));
        assert!(matches.contains(&"GETINFO config-file"));
    }

    #[test]
    fn test_matches_partial() {
        let ac = create_test_autocompleter();
        let matches = ac.matches("/he");
        assert_eq!(matches.len(), 1);
        assert!(matches.contains(&"/help"));
    }

    #[test]
    fn test_matches_empty() {
        let ac = create_test_autocompleter();
        let matches = ac.matches("nonexistent");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_complete_first() {
        let ac = create_test_autocompleter();
        let result = ac.complete("/", 0);
        assert!(result.is_some());
    }

    #[test]
    fn test_complete_out_of_bounds() {
        let ac = create_test_autocompleter();
        let result = ac.complete("/", 100);
        assert!(result.is_none());
    }

    #[test]
    fn test_complete_sequential() {
        let ac = create_test_autocompleter();
        let matches = ac.matches("/");
        for (i, expected) in matches.iter().enumerate() {
            let result = ac.complete("/", i);
            assert_eq!(result, Some(*expected));
        }
    }
}
