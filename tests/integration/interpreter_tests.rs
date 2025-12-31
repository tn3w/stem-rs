//! Integration tests for interpreter module against a real Tor process.

use std::net::SocketAddr;

use stem_rs::controller::Controller;
use stem_rs::interpreter::ControlInterpreter;

use crate::{get_control_port, is_tor_available};

fn get_control_addr() -> SocketAddr {
    format!("127.0.0.1:{}", get_control_port()).parse().unwrap()
}

#[tokio::test]
async fn test_interpreter_help_command() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/help").await;

    assert!(result.is_ok(), "Help command failed: {:?}", result.err());
    let output = result.unwrap();
    assert!(
        output.contains("Interpreter commands include"),
        "Help should contain interpreter commands"
    );
    assert!(output.contains("/help"), "Help should mention /help");
    assert!(output.contains("/events"), "Help should mention /events");
    assert!(output.contains("/quit"), "Help should mention /quit");
}

#[tokio::test]
async fn test_interpreter_help_getinfo() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/help GETINFO").await;

    assert!(result.is_ok(), "Help GETINFO failed: {:?}", result.err());
    let output = result.unwrap();
    assert!(
        output.contains("GETINFO"),
        "Help should contain GETINFO info"
    );
}

#[tokio::test]
async fn test_interpreter_help_signal() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/help SIGNAL").await;

    assert!(result.is_ok(), "Help SIGNAL failed: {:?}", result.err());
    let output = result.unwrap();
    assert!(output.contains("RELOAD"), "Help should mention RELOAD");
    assert!(output.contains("NEWNYM"), "Help should mention NEWNYM");
}

#[tokio::test]
async fn test_interpreter_events_empty() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/events").await;

    assert!(result.is_ok(), "Events command failed: {:?}", result.err());
    let output = result.unwrap();
    assert!(output.is_empty(), "Events should be empty initially");
}

#[tokio::test]
async fn test_interpreter_events_clear() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/events clear").await;

    assert!(result.is_ok(), "Events clear failed: {:?}", result.err());
    let output = result.unwrap();
    assert!(output.contains("cleared"), "Should confirm events cleared");
}

#[tokio::test]
async fn test_interpreter_python_status() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/python").await;

    assert!(result.is_ok(), "Python status failed: {:?}", result.err());
    let output = result.unwrap();
    assert!(
        output.contains("Python support"),
        "Should show Python status"
    );
}

#[tokio::test]
async fn test_interpreter_python_enable_disable() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);

    let result = interpreter.run_command("/python disable").await;
    assert!(result.is_ok());
    assert!(result.unwrap().contains("disabled"));

    let result = interpreter.run_command("/python enable").await;
    assert!(result.is_ok());
    assert!(result.unwrap().contains("enabled"));
}

#[tokio::test]
async fn test_interpreter_python_invalid() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/python invalid").await;

    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("not recognized"));
}

#[tokio::test]
async fn test_interpreter_tor_command_getinfo() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("GETINFO version").await;

    assert!(result.is_ok(), "GETINFO failed: {:?}", result.err());
    let output = result.unwrap();
    assert!(output.contains("250"), "Should contain 250 status");
}

#[tokio::test]
async fn test_interpreter_tor_command_lowercase() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("getinfo version").await;

    assert!(
        result.is_ok(),
        "lowercase getinfo failed: {:?}",
        result.err()
    );
    let output = result.unwrap();
    assert!(output.contains("250"), "Should contain 250 status");
}

#[tokio::test]
async fn test_interpreter_unrecognized_command() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/unknown").await;

    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("isn't a recognized command"));
}

#[tokio::test]
async fn test_interpreter_empty_command() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("").await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_interpreter_whitespace_command() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("   ").await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_interpreter_multiline_command_message() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("LOADCONF").await;

    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("Multi-line"));
    assert!(output.contains("not yet implemented"));
}

#[tokio::test]
async fn test_interpreter_quit_command() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/quit").await;

    assert!(result.is_err(), "/quit should return error to signal exit");
}

#[tokio::test]
async fn test_interpreter_signal_newnym() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("SIGNAL NEWNYM").await;

    assert!(result.is_ok(), "SIGNAL NEWNYM failed: {:?}", result.err());
    let output = result.unwrap();
    assert!(output.contains("250"), "Should contain 250 OK");
}

#[tokio::test]
async fn test_interpreter_getconf() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("GETCONF SocksPort").await;

    assert!(result.is_ok(), "GETCONF failed: {:?}", result.err());
    let output = result.unwrap();
    assert!(output.contains("250"), "Should contain 250 status");
}

#[tokio::test]
async fn test_interpreter_help_setconf() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/help SETCONF").await;

    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("SETCONF"));
    assert!(output.contains("Example"));
}

#[tokio::test]
async fn test_interpreter_help_events() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/help EVENTS").await;

    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("/events"));
    assert!(output.contains("clear"));
}

#[tokio::test]
async fn test_interpreter_help_info() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/help INFO").await;

    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("/info"));
    assert!(output.contains("fingerprint"));
}

#[tokio::test]
async fn test_interpreter_help_quit() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/help QUIT").await;

    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("/quit"));
    assert!(output.contains("Terminates"));
}

#[tokio::test]
async fn test_interpreter_help_python() {
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

    let mut interpreter = ControlInterpreter::new(&mut controller);
    let result = interpreter.run_command("/help PYTHON").await;

    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("/python"));
    assert!(output.contains("enable"));
    assert!(output.contains("disable"));
}
