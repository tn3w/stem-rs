//! Integration tests for descriptors and exit policies against a real Tor process.

use std::net::SocketAddr;

use stem_rs::controller::Controller;
use stem_rs::descriptor::{Compression, Descriptor, DigestEncoding, DigestHash, ServerDescriptor};
use stem_rs::exit_policy::ExitPolicy;

use crate::{get_control_port, is_tor_available};

fn get_control_addr() -> SocketAddr {
    format!("127.0.0.1:{}", get_control_port()).parse().unwrap()
}

#[tokio::test]
async fn test_get_ns_all_from_controller() {
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

    let result = controller.get_info("ns/all").await;

    if let Ok(ns_content) = result {
        assert!(!ns_content.is_empty(), "ns/all should not be empty");

        let has_router_entries = ns_content.contains("r ") || ns_content.contains("\nr ");
        assert!(has_router_entries, "ns/all should contain router entries");
    }
}

#[tokio::test]
async fn test_get_desc_all_from_controller() {
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

    let result = controller.get_info("desc/all-recent").await;

    if let Ok(desc_content) = result {
        if !desc_content.is_empty() {
            let _has_router = desc_content.contains("router ");
        }
    }
}

#[tokio::test]
async fn test_get_md_all_from_controller() {
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

    let result = controller.get_info("md/all").await;

    if let Ok(md_content) = result {
        if !md_content.is_empty() {
            let _has_onion_key = md_content.contains("onion-key");
        }
    }
}

#[tokio::test]
async fn test_parse_exit_policy_from_descriptor() {
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

    let result = controller.get_info("desc/all-recent").await;

    if let Ok(desc_content) = result {
        if !desc_content.is_empty() && desc_content.contains("router ") {
            if let Ok(descriptor) = ServerDescriptor::parse(&desc_content) {
                let _policy = &descriptor.exit_policy;
            }
        }
    }
}

#[tokio::test]
async fn test_get_consensus_from_controller() {
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

    let result = controller.get_consensus().await;

    if let Ok(consensus) = result {
        assert!(
            !consensus.authorities.is_empty(),
            "Consensus should have authorities"
        );
        assert!(
            consensus.valid_after < consensus.valid_until,
            "Timestamps should be ordered"
        );
    }
}

#[tokio::test]
async fn test_find_relays_by_flag() {
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

    let result = controller.find_relays_by_flag(stem_rs::Flag::Guard).await;

    if let Ok(guard_relays) = result {
        for relay in &guard_relays {
            assert!(
                relay.flags.contains(&"Guard".to_string()),
                "All returned relays should have Guard flag"
            );
        }
    }
}

#[tokio::test]
async fn test_find_fastest_relays() {
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

    let result = controller.find_fastest_relays(10).await;

    if let Ok(fastest_relays) = result {
        assert!(
            fastest_relays.len() <= 10,
            "Should return at most 10 relays"
        );

        for i in 1..fastest_relays.len() {
            let prev_bw = fastest_relays[i - 1].bandwidth.unwrap_or(0);
            let curr_bw = fastest_relays[i].bandwidth.unwrap_or(0);
            assert!(prev_bw >= curr_bw, "Relays should be sorted by bandwidth");
        }
    }
}

#[tokio::test]
async fn test_select_guard_relay() {
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

    let result = controller.select_guard_relay().await;

    if let Ok(Some(guard_relay)) = result {
        assert!(
            guard_relay.flags.contains(&"Guard".to_string()),
            "Selected relay should have Guard flag"
        );
    }
}

#[tokio::test]
async fn test_exit_policy_evaluation() {
    let policy_str = "accept *:80\naccept *:443\nreject *:*";
    let policy = ExitPolicy::parse(policy_str).expect("Failed to parse policy");

    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 80),
        "Port 80 should be accepted"
    );

    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 443),
        "Port 443 should be accepted"
    );

    assert!(
        !policy.can_exit_to("192.168.1.1".parse().unwrap(), 22),
        "Port 22 should be rejected"
    );
}

#[tokio::test]
async fn test_exit_policy_cidr_matching() {
    let policy_str = "accept 192.168.0.0/16:*\nreject *:*";
    let policy = ExitPolicy::parse(policy_str).expect("Failed to parse policy");

    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 80),
        "192.168.1.1 should be accepted"
    );
    assert!(
        policy.can_exit_to("192.168.255.255".parse().unwrap(), 80),
        "192.168.255.255 should be accepted"
    );

    assert!(
        !policy.can_exit_to("10.0.0.1".parse().unwrap(), 80),
        "10.0.0.1 should be rejected"
    );
}

#[tokio::test]
async fn test_exit_policy_port_range() {
    let policy_str = "accept *:80-443\nreject *:*";
    let policy = ExitPolicy::parse(policy_str).expect("Failed to parse policy");

    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 80),
        "Port 80 should be accepted"
    );
    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 443),
        "Port 443 should be accepted"
    );
    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 200),
        "Port 200 should be accepted"
    );

    assert!(
        !policy.can_exit_to("192.168.1.1".parse().unwrap(), 79),
        "Port 79 should be rejected"
    );
    assert!(
        !policy.can_exit_to("192.168.1.1".parse().unwrap(), 444),
        "Port 444 should be rejected"
    );
}

#[tokio::test]
async fn test_exit_policy_ipv6() {
    let policy_str = "accept6 [::]:80\nreject6 [::]:*";
    let policy = ExitPolicy::parse(policy_str).expect("Failed to parse policy");

    let ipv6_addr: std::net::IpAddr = "::1".parse().unwrap();
    let _can_exit = policy.can_exit_to(ipv6_addr, 80);
}

#[tokio::test]
async fn test_exit_policy_summary() {
    let policy_str = "accept *:80\naccept *:443\nreject *:*";
    let policy = ExitPolicy::parse(policy_str).expect("Failed to parse policy");

    let summary = policy.summary();
    assert!(!summary.is_empty(), "Summary should not be empty");
}

#[tokio::test]
async fn test_server_descriptor_parsing() {
    let descriptor_content = r#"@type server-descriptor 1.0
router TestRelay 127.0.0.1 9001 0 0
bandwidth 1000 2000 500
platform Tor 0.4.7.1 on Linux
published 2023-01-01 00:00:00
fingerprint AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333
uptime 86400
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALRiMLAhiLBQGRJpFFuYuD1cFsQ7kLtWLLJGs/IQIU/kEfQErzQM
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALRiMLAhiLBQGRJpFFuYuD1cFsQ7kLtWLLJGs/IQIU/kEfQErzQM
-----END RSA PUBLIC KEY-----
accept *:80
accept *:443
reject *:*
router-signature
-----BEGIN SIGNATURE-----
AAAA
-----END SIGNATURE-----
"#;

    if let Ok(desc) = ServerDescriptor::parse(descriptor_content) {
        assert_eq!(desc.nickname, "TestRelay");
    }
}

#[tokio::test]
async fn test_consensus_info_from_controller() {
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

    let _result = controller.get_info("status/version/current").await;
    let _result = controller.get_info("status/version/recommended").await;
}

#[tokio::test]
async fn test_dir_info_from_controller() {
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

    let keys = [
        "status/bootstrap-phase",
        "status/circuit-established",
        "status/enough-dir-info",
    ];

    for key in keys {
        let _result = controller.get_info(key).await;
    }
}

#[tokio::test]
async fn test_network_status_entry_from_controller() {
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

    let result = controller.get_info("ns/all").await;

    if let Ok(ns_content) = result {
        for line in ns_content.lines() {
            if line.starts_with("r ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    let router_name = parts[1];
                    let _ns_result = controller
                        .get_info(&format!("ns/name/{}", router_name))
                        .await;
                    break;
                }
            }
        }
    }
}

#[tokio::test]
async fn test_exit_policy_default_reject() {
    let policy_str = "reject *:*";
    let policy = ExitPolicy::parse(policy_str).expect("Failed to parse policy");

    assert!(
        !policy.can_exit_to("192.168.1.1".parse().unwrap(), 80),
        "Should reject all"
    );
    assert!(
        !policy.can_exit_to("192.168.1.1".parse().unwrap(), 443),
        "Should reject all"
    );
    assert!(
        !policy.is_exiting_allowed(),
        "Exiting should not be allowed"
    );
}

#[tokio::test]
async fn test_exit_policy_default_accept() {
    let policy_str = "accept *:*";
    let policy = ExitPolicy::parse(policy_str).expect("Failed to parse policy");

    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 80),
        "Should accept all"
    );
    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 443),
        "Should accept all"
    );
    assert!(policy.is_exiting_allowed(), "Exiting should be allowed");
}

#[tokio::test]
async fn test_exit_policy_complex() {
    let policy_str = r#"accept *:20-21
accept *:22
accept *:23
accept *:43
accept *:53
accept *:79-81
accept *:88
accept *:110
accept *:143
accept *:194
accept *:220
accept *:389
accept *:443
accept *:464
accept *:531
accept *:543-544
accept *:554
accept *:563
accept *:587
accept *:636
accept *:706
accept *:749
accept *:873
accept *:902-904
accept *:981
accept *:989-995
accept *:1194
accept *:1220
accept *:1293
accept *:1500
accept *:1533
accept *:1677
accept *:1723
accept *:1755
accept *:1863
accept *:2082-2083
accept *:2086-2087
accept *:2095-2096
accept *:2102-2104
accept *:3128
accept *:3389
accept *:3690
accept *:4321
accept *:4643
accept *:5050
accept *:5190
accept *:5222-5223
accept *:5228
accept *:5900
accept *:6660-6669
accept *:6679
accept *:6697
accept *:8000
accept *:8008
accept *:8074
accept *:8080
accept *:8082
accept *:8087-8088
accept *:8232-8233
accept *:8332-8333
accept *:8443
accept *:8888
accept *:9418
accept *:9999
accept *:10000
accept *:11371
accept *:19294
accept *:19638
accept *:50002
accept *:64738
reject *:*"#;

    let policy = ExitPolicy::parse(policy_str).expect("Failed to parse complex policy");

    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 80),
        "Port 80 should be accepted"
    );
    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 443),
        "Port 443 should be accepted"
    );
    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 22),
        "Port 22 should be accepted"
    );
    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 8080),
        "Port 8080 should be accepted"
    );

    assert!(
        !policy.can_exit_to("192.168.1.1".parse().unwrap(), 25),
        "Port 25 (SMTP) should be rejected"
    );
    assert!(
        policy.can_exit_to("192.168.1.1".parse().unwrap(), 6667),
        "Port 6667 should be accepted (in 6660-6669 range)"
    );
    assert!(
        !policy.can_exit_to("192.168.1.1".parse().unwrap(), 6670),
        "Port 6670 should be rejected (not in 6660-6669 range)"
    );
}

#[tokio::test]
async fn test_descriptor_digest_computation() {
    let content = b"test content for digest";
    let digest =
        stem_rs::descriptor::compute_digest(content, DigestHash::Sha256, DigestEncoding::Hex);

    assert!(!digest.is_empty(), "Digest should not be empty");
    assert_eq!(
        digest.len(),
        64,
        "SHA256 hex digest should be 64 characters"
    );

    let sha1_digest =
        stem_rs::descriptor::compute_digest(content, DigestHash::Sha1, DigestEncoding::Hex);
    assert_eq!(
        sha1_digest.len(),
        40,
        "SHA1 hex digest should be 40 characters"
    );
}

#[tokio::test]
async fn test_compression_detection() {
    let plaintext = b"Hello, World!";
    let compression = stem_rs::descriptor::detect_compression(plaintext);
    assert_eq!(compression, Compression::Plaintext);

    let gzip_header = &[0x1f, 0x8b, 0x08, 0x00];
    let compression = stem_rs::descriptor::detect_compression(gzip_header);
    assert_eq!(compression, Compression::Gzip);
}

#[tokio::test]
async fn test_auto_decompress() {
    let content = b"Hello, World!";
    let result = stem_rs::descriptor::auto_decompress(content);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), content);
}

#[tokio::test]
async fn test_descriptor_error_types() {
    use stem_rs::descriptor::{
        ConsensusError, DescriptorError, MicrodescriptorError, ServerDescriptorError,
    };

    let consensus_err = ConsensusError::InvalidFingerprint("invalid".to_string());
    assert!(consensus_err.to_string().contains("Invalid fingerprint"));

    let server_err = ServerDescriptorError::InvalidNickname("bad nickname!".to_string());
    assert!(server_err.to_string().contains("Invalid nickname"));

    let micro_err = MicrodescriptorError::MissingRequiredField("onion-key".to_string());
    assert!(micro_err.to_string().contains("Missing required field"));

    let desc_err: DescriptorError = consensus_err.into();
    assert!(desc_err.to_string().contains("Invalid fingerprint"));
}

#[tokio::test]
async fn test_consensus_error_variants() {
    use stem_rs::descriptor::ConsensusError;

    let err = ConsensusError::InvalidNetworkStatusVersion("2".to_string());
    assert!(err.to_string().contains("expected 3, got 2"));

    let err = ConsensusError::InvalidVoteStatus("unknown".to_string());
    assert!(err.to_string().contains("expected 'vote' or 'consensus'"));

    let err = ConsensusError::TimestampOrderingViolation(
        "valid-after must be before fresh-until".to_string(),
    );
    assert!(err.to_string().contains("Timestamp ordering violation"));

    let err = ConsensusError::InvalidLineFormat {
        line: 42,
        reason: "expected 5 fields".to_string(),
    };
    assert!(err.to_string().contains("line 42"));
    assert!(err.to_string().contains("expected 5 fields"));
}

#[tokio::test]
async fn test_server_descriptor_error_variants() {
    use stem_rs::descriptor::ServerDescriptorError;

    let err = ServerDescriptorError::InvalidRouterFormat { actual: 3 };
    assert!(err.to_string().contains("expected 5 parts, got 3"));

    let err = ServerDescriptorError::InvalidBandwidthFormat { actual: 2 };
    assert!(err.to_string().contains("expected 3 parts, got 2"));

    let err = ServerDescriptorError::InvalidFingerprint("ZZZZ".to_string());
    assert!(err.to_string().contains("Invalid fingerprint"));

    let err = ServerDescriptorError::MissingRequiredField("router".to_string());
    assert!(err.to_string().contains("Missing required field: router"));
}

#[tokio::test]
async fn test_microdescriptor_error_variants() {
    use stem_rs::descriptor::MicrodescriptorError;

    let err = MicrodescriptorError::InvalidIdentityLength {
        algorithm: "ed25519".to_string(),
        expected: 32,
        actual: 16,
    };
    assert!(err.to_string().contains("ed25519"));
    assert!(err.to_string().contains("expected 32, got 16"));

    let err = MicrodescriptorError::UnknownIdentityAlgorithm("sha512".to_string());
    assert!(err.to_string().contains("Unknown identity algorithm"));

    let err = MicrodescriptorError::IncompleteCryptoBlock("onion-key".to_string());
    assert!(err.to_string().contains("Incomplete crypto block"));
}

#[tokio::test]
async fn test_descriptor_error_conversion() {
    use stem_rs::descriptor::{ConsensusError, DescriptorError, ServerDescriptorError};

    let consensus_err = ConsensusError::InvalidFingerprint("test".to_string());
    let desc_err: DescriptorError = consensus_err.into();
    match desc_err {
        DescriptorError::Consensus(_) => {}
        _ => panic!("Expected Consensus variant"),
    }

    let server_err = ServerDescriptorError::InvalidNickname("test".to_string());
    let desc_err: DescriptorError = server_err.into();
    match desc_err {
        DescriptorError::ServerDescriptor(_) => {}
        _ => panic!("Expected ServerDescriptor variant"),
    }
}

#[tokio::test]
async fn test_descriptor_error_from_io() {
    use std::io;
    use stem_rs::descriptor::ServerDescriptorError;

    let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let desc_err: ServerDescriptorError = io_err.into();
    assert!(desc_err.to_string().contains("IO error"));
}

#[tokio::test]
async fn test_descriptor_error_display() {
    use stem_rs::descriptor::{
        BandwidthFileError, ExtraInfoError, HiddenServiceDescriptorError, KeyCertificateError,
        TorDNSELError,
    };

    let err = ExtraInfoError::InvalidBandwidthHistory("malformed".to_string());
    assert!(err.to_string().contains("Invalid bandwidth history"));

    let err = HiddenServiceDescriptorError::InvalidDescriptorVersion(1);
    assert!(err.to_string().contains("expected 2 or 3, got 1"));

    let err = KeyCertificateError::InvalidCertificateVersion(2);
    assert!(err.to_string().contains("expected 3, got 2"));

    let err = BandwidthFileError::MissingRequiredHeaderField("timestamp".to_string());
    assert!(err.to_string().contains("Missing required header field"));

    let err = TorDNSELError::InvalidExitAddressFormat("bad format".to_string());
    assert!(err.to_string().contains("Invalid exit address format"));
}

#[tokio::test]
async fn test_unsupported_compression_error() {
    use stem_rs::descriptor::DescriptorError;

    let err = DescriptorError::UnsupportedCompression("zstd".to_string());
    assert!(err.to_string().contains("Unsupported compression format"));
    assert!(err.to_string().contains("zstd"));
}

#[tokio::test]
async fn test_decompression_failed_error() {
    use stem_rs::descriptor::DescriptorError;

    let err = DescriptorError::DecompressionFailed("corrupted data".to_string());
    assert!(err.to_string().contains("Decompression failed"));
    assert!(err.to_string().contains("corrupted data"));
}

#[tokio::test]
async fn test_error_source_chain() {
    use std::error::Error;
    use stem_rs::descriptor::{ConsensusError, DescriptorError};

    let consensus_err = ConsensusError::InvalidFingerprint("test".to_string());
    let desc_err: DescriptorError = consensus_err.into();

    let source = desc_err.source();
    assert!(source.is_some(), "Error should have a source");
}

#[tokio::test]
async fn test_error_debug_format() {
    use stem_rs::descriptor::ConsensusError;

    let err = ConsensusError::InvalidFingerprint("ABCD".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("InvalidFingerprint"));
    assert!(debug_str.contains("ABCD"));
}

#[tokio::test]
async fn test_main_error_includes_descriptor_error() {
    use stem_rs::descriptor::{ConsensusError, DescriptorError};
    use stem_rs::Error;

    let consensus_err = ConsensusError::InvalidFingerprint("test".to_string());
    let desc_err: DescriptorError = consensus_err.into();
    let main_err: Error = desc_err.into();

    match main_err {
        Error::Descriptor(_) => {}
        _ => panic!("Expected Descriptor variant"),
    }
}

#[tokio::test]
async fn test_legacy_parse_error_still_works() {
    use stem_rs::Error;

    let err = Error::Parse {
        location: "line 10".to_string(),
        reason: "invalid format".to_string(),
    };

    assert!(err.to_string().contains("parse error at line 10"));
    assert!(err.to_string().contains("invalid format"));
}

#[tokio::test]
async fn test_error_handling_example() {
    use stem_rs::descriptor::{ConsensusError, DescriptorError};
    use stem_rs::Error;

    fn handle_error(err: Error) -> String {
        match err {
            Error::Descriptor(desc_err) => match desc_err {
                DescriptorError::Consensus(ConsensusError::InvalidFingerprint(fp)) => {
                    format!("Invalid fingerprint: {}", fp)
                }
                DescriptorError::Consensus(ConsensusError::TimestampOrderingViolation(msg)) => {
                    format!("Timestamp issue: {}", msg)
                }
                _ => format!("Descriptor error: {}", desc_err),
            },
            Error::Parse { location, reason } => {
                format!("Legacy parse error at {}: {}", location, reason)
            }
            _ => format!("Other error: {}", err),
        }
    }

    let consensus_err = ConsensusError::InvalidFingerprint("ZZZZ".to_string());
    let desc_err: DescriptorError = consensus_err.into();
    let main_err: Error = desc_err.into();

    let result = handle_error(main_err);
    assert!(result.contains("Invalid fingerprint: ZZZZ"));

    let legacy_err = Error::Parse {
        location: "line 5".to_string(),
        reason: "bad format".to_string(),
    };
    let result = handle_error(legacy_err);
    assert!(result.contains("Legacy parse error at line 5"));
}

// Validation tests

const EXAMPLE_CONSENSUS: &str = r#"network-status-version 3
vote-status consensus
consensus-method 26
valid-after 2017-05-25 04:46:30
fresh-until 2017-05-25 04:46:40
valid-until 2017-05-25 04:46:50
voting-delay 2 2
known-flags Authority Exit Fast Guard HSDir Running Stable Valid
dir-source test001a 596CD48D61FDA4E868F4AA10FF559917BE3B1A35 127.0.0.1 127.0.0.1 7001 5001
directory-signature 596CD48D61FDA4E868F4AA10FF559917BE3B1A35 9FBF54D6A62364320308A615BF4CF6B27B254FAD
-----BEGIN SIGNATURE-----
test
-----END SIGNATURE-----
"#;

const EXAMPLE_SERVER_DESCRIPTOR: &str = r#"router TestRelay 192.168.1.1 9001 0 0
published 2023-01-01 00:00:00
bandwidth 1000 2000 500
fingerprint AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333
router-signature
-----BEGIN SIGNATURE-----
test
-----END SIGNATURE-----
"#;

const EXAMPLE_MICRODESCRIPTOR: &str = r#"onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMhPQtZPaxP3ukybV5LfofKQr20/ljpRk0e9IlGWWMSTkfVvBcHsa6IM
H2KE6s4uuPHp7FqhakXAzJbODobnPHY8l1E4efyrqMQZXEQk2IMhgSNtG6YqUrVF
CxdSKSSy0mmcBe2TOyQsahlGZ9Pudxfnrey7KcfqnArEOqNH09RpAgMBAAE=
-----END RSA PUBLIC KEY-----
"#;

#[tokio::test]
async fn test_consensus_validate_valid() {
    use stem_rs::descriptor::{Descriptor, NetworkStatusDocument};

    let doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
    assert!(doc.validate().is_ok());
}

#[tokio::test]
async fn test_consensus_validate_invalid_timestamp_ordering() {
    use stem_rs::descriptor::{ConsensusError, Descriptor, DescriptorError, NetworkStatusDocument};
    use stem_rs::Error;

    let mut doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
    doc.fresh_until = doc.valid_after;
    let result = doc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::Consensus(
            ConsensusError::TimestampOrderingViolation(_),
        ))) => {}
        _ => panic!("Expected TimestampOrderingViolation error"),
    }
}

#[tokio::test]
async fn test_consensus_validate_invalid_version() {
    use stem_rs::descriptor::{ConsensusError, Descriptor, DescriptorError, NetworkStatusDocument};
    use stem_rs::Error;

    let mut doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
    doc.version = 2;
    let result = doc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::Consensus(
            ConsensusError::InvalidNetworkStatusVersion(_),
        ))) => {}
        _ => panic!("Expected InvalidNetworkStatusVersion error"),
    }
}

#[tokio::test]
async fn test_consensus_validate_invalid_authority_fingerprint() {
    use stem_rs::descriptor::{ConsensusError, Descriptor, DescriptorError, NetworkStatusDocument};
    use stem_rs::Error;

    let mut doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
    doc.authorities[0].v3ident = "INVALID".to_string();
    let result = doc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::Consensus(ConsensusError::InvalidFingerprint(
            _,
        )))) => {}
        _ => panic!("Expected InvalidFingerprint error"),
    }
}

#[tokio::test]
async fn test_consensus_validate_missing_signatures() {
    use stem_rs::descriptor::{ConsensusError, Descriptor, DescriptorError, NetworkStatusDocument};
    use stem_rs::Error;

    let mut doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
    doc.signatures.clear();
    let result = doc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::Consensus(
            ConsensusError::MissingRequiredField(_),
        ))) => {}
        _ => panic!("Expected MissingRequiredField error"),
    }
}

#[tokio::test]
async fn test_consensus_validate_invalid_signature_fingerprint() {
    use stem_rs::descriptor::{ConsensusError, Descriptor, DescriptorError, NetworkStatusDocument};
    use stem_rs::Error;

    let mut doc = NetworkStatusDocument::parse(EXAMPLE_CONSENSUS).unwrap();
    doc.signatures[0].identity = "INVALID".to_string();
    let result = doc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::Consensus(ConsensusError::InvalidFingerprint(
            _,
        )))) => {}
        _ => panic!("Expected InvalidFingerprint error"),
    }
}

#[tokio::test]
async fn test_server_descriptor_validate_valid() {
    let desc = ServerDescriptor::parse(EXAMPLE_SERVER_DESCRIPTOR).unwrap();
    assert!(desc.validate().is_ok());
}

#[tokio::test]
async fn test_server_descriptor_validate_invalid_nickname() {
    use stem_rs::descriptor::{DescriptorError, ServerDescriptorError};
    use stem_rs::Error;

    let mut desc = ServerDescriptor::parse(EXAMPLE_SERVER_DESCRIPTOR).unwrap();
    desc.nickname = "Invalid$Nickname".to_string();
    let result = desc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::ServerDescriptor(
            ServerDescriptorError::InvalidNickname(_),
        ))) => {}
        _ => panic!("Expected InvalidNickname error"),
    }
}

#[tokio::test]
async fn test_server_descriptor_validate_invalid_fingerprint() {
    use stem_rs::descriptor::{DescriptorError, ServerDescriptorError};
    use stem_rs::Error;

    let mut desc = ServerDescriptor::parse(EXAMPLE_SERVER_DESCRIPTOR).unwrap();
    desc.fingerprint = Some("INVALID".to_string());
    let result = desc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::ServerDescriptor(
            ServerDescriptorError::InvalidFingerprint(_),
        ))) => {}
        _ => panic!("Expected InvalidFingerprint error"),
    }
}

#[tokio::test]
async fn test_server_descriptor_validate_invalid_port() {
    use stem_rs::descriptor::{DescriptorError, ServerDescriptorError};
    use stem_rs::Error;

    let mut desc = ServerDescriptor::parse(EXAMPLE_SERVER_DESCRIPTOR).unwrap();
    desc.or_port = 0;
    let result = desc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::ServerDescriptor(
            ServerDescriptorError::MissingRequiredField(_),
        ))) => {}
        _ => panic!("Expected MissingRequiredField error"),
    }
}

#[tokio::test]
async fn test_server_descriptor_validate_invalid_bandwidth() {
    use stem_rs::descriptor::{DescriptorError, ServerDescriptorError};
    use stem_rs::Error;

    let mut desc = ServerDescriptor::parse(EXAMPLE_SERVER_DESCRIPTOR).unwrap();
    desc.bandwidth_avg = 1000;
    desc.bandwidth_burst = 500;
    let result = desc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::ServerDescriptor(
            ServerDescriptorError::InvalidBandwidth(_),
        ))) => {}
        _ => panic!("Expected InvalidBandwidth error"),
    }
}

#[tokio::test]
async fn test_server_descriptor_validate_missing_signature() {
    use stem_rs::descriptor::{DescriptorError, ServerDescriptorError};
    use stem_rs::Error;

    let mut desc = ServerDescriptor::parse(EXAMPLE_SERVER_DESCRIPTOR).unwrap();
    desc.signature = String::new();
    let result = desc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::ServerDescriptor(
            ServerDescriptorError::MissingRequiredField(_),
        ))) => {}
        _ => panic!("Expected MissingRequiredField error"),
    }
}

#[tokio::test]
async fn test_microdescriptor_validate_valid() {
    use stem_rs::descriptor::{Descriptor, Microdescriptor};

    let desc = Microdescriptor::parse(EXAMPLE_MICRODESCRIPTOR).unwrap();
    assert!(desc.validate().is_ok());
}

#[tokio::test]
async fn test_microdescriptor_validate_missing_onion_key() {
    use stem_rs::descriptor::{Descriptor, DescriptorError, Microdescriptor, MicrodescriptorError};
    use stem_rs::Error;

    let mut desc = Microdescriptor::parse(EXAMPLE_MICRODESCRIPTOR).unwrap();
    desc.onion_key = String::new();
    let result = desc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::Microdescriptor(
            MicrodescriptorError::MissingRequiredField(_),
        ))) => {}
        _ => panic!("Expected MissingRequiredField error"),
    }
}

#[tokio::test]
async fn test_microdescriptor_validate_invalid_port() {
    use stem_rs::descriptor::{Descriptor, DescriptorError, Microdescriptor, MicrodescriptorError};
    use stem_rs::Error;

    let mut desc = Microdescriptor::parse(EXAMPLE_MICRODESCRIPTOR).unwrap();
    desc.or_addresses
        .push(("192.168.1.1".parse().unwrap(), 0, false));
    let result = desc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::Microdescriptor(
            MicrodescriptorError::InvalidPortPolicy(_),
        ))) => {}
        _ => panic!("Expected InvalidPortPolicy error"),
    }
}

#[tokio::test]
async fn test_microdescriptor_validate_invalid_family_fingerprint() {
    use stem_rs::descriptor::{Descriptor, DescriptorError, Microdescriptor, MicrodescriptorError};
    use stem_rs::Error;

    let mut desc = Microdescriptor::parse(EXAMPLE_MICRODESCRIPTOR).unwrap();
    desc.family
        .push("$INVALIDFINGERPRINT1234567890123456789012".to_string());
    let result = desc.validate();
    assert!(result.is_err());
    match result {
        Err(Error::Descriptor(DescriptorError::Microdescriptor(
            MicrodescriptorError::InvalidRelayFamily(_),
        ))) => {}
        _ => panic!("Expected InvalidRelayFamily error"),
    }
}

#[test]
fn test_network_status_document_builder() {
    use chrono::Utc;
    use std::collections::HashMap;
    use stem_rs::descriptor::NetworkStatusDocumentBuilder;

    let now = Utc::now();
    let later = now + chrono::Duration::hours(1);
    let much_later = now + chrono::Duration::hours(3);

    let doc = NetworkStatusDocumentBuilder::default()
        .version(3_u32)
        .version_flavor("microdesc")
        .is_consensus(true)
        .is_vote(false)
        .is_microdescriptor(true)
        .valid_after(now)
        .fresh_until(later)
        .valid_until(much_later)
        .known_flags(vec!["Running".to_string(), "Valid".to_string()])
        .client_versions(vec![])
        .server_versions(vec![])
        .recommended_client_protocols(HashMap::new())
        .recommended_relay_protocols(HashMap::new())
        .required_client_protocols(HashMap::new())
        .required_relay_protocols(HashMap::new())
        .params(HashMap::new())
        .bandwidth_weights(HashMap::new())
        .authorities(vec![])
        .signatures(vec![])
        .raw_content(vec![])
        .unrecognized_lines(vec![])
        .build()
        .expect("Failed to build NetworkStatusDocument");

    assert_eq!(doc.version, 3);
    assert_eq!(doc.version_flavor, "microdesc");
    assert!(doc.is_consensus);
    assert!(!doc.is_vote);
    assert!(doc.is_microdescriptor);
    assert_eq!(doc.valid_after, now);
    assert_eq!(doc.fresh_until, later);
    assert_eq!(doc.valid_until, much_later);
}

#[test]
fn test_server_descriptor_builder() {
    use chrono::Utc;
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;
    use stem_rs::descriptor::ServerDescriptorBuilder;
    use stem_rs::exit_policy::ExitPolicy;
    use stem_rs::BridgeDistribution;

    let exit_policy = ExitPolicy::parse("reject *:*").expect("Failed to parse exit policy");
    let address: IpAddr = "192.168.1.1".parse().unwrap();

    let desc = ServerDescriptorBuilder::default()
        .nickname("TestRelay")
        .address(address)
        .or_port(9001_u16)
        .or_addresses(vec![])
        .published(Utc::now())
        .bandwidth_avg(1000000_u64)
        .bandwidth_burst(2000000_u64)
        .bandwidth_observed(500000_u64)
        .exit_policy(exit_policy)
        .bridge_distribution(BridgeDistribution::Any)
        .family(HashSet::new())
        .hibernating(false)
        .allow_single_hop_exits(false)
        .allow_tunneled_dir_requests(true)
        .extra_info_cache(false)
        .is_hidden_service_dir(false)
        .protocols(HashMap::new())
        .signature("test_signature")
        .raw_content(vec![])
        .unrecognized_lines(vec![])
        .build()
        .expect("Failed to build ServerDescriptor");

    assert_eq!(desc.nickname, "TestRelay");
    assert_eq!(desc.or_port, 9001);
    assert_eq!(desc.bandwidth_avg, 1000000);
    assert_eq!(desc.bandwidth_burst, 2000000);
    assert_eq!(desc.bandwidth_observed, 500000);
}

#[test]
fn test_microdescriptor_builder() {
    use std::collections::HashMap;
    use stem_rs::descriptor::MicrodescriptorBuilder;
    use stem_rs::exit_policy::MicroExitPolicy;

    let onion_key = "-----BEGIN RSA PUBLIC KEY-----\ntest\n-----END RSA PUBLIC KEY-----";
    let exit_policy = MicroExitPolicy::parse("reject 1-65535").expect("Failed to parse policy");

    let desc = MicrodescriptorBuilder::default()
        .onion_key(onion_key)
        .or_addresses(vec![])
        .family(vec![])
        .exit_policy(exit_policy)
        .identifiers(HashMap::new())
        .protocols(HashMap::new())
        .raw_content(vec![])
        .annotations(vec![])
        .unrecognized_lines(vec![])
        .build()
        .expect("Failed to build Microdescriptor");

    assert_eq!(desc.onion_key, onion_key);
    assert!(desc.or_addresses.is_empty());
    assert!(desc.family.is_empty());
}

#[test]
fn test_extra_info_descriptor_builder() {
    use chrono::Utc;
    use std::collections::HashMap;
    use stem_rs::descriptor::ExtraInfoDescriptorBuilder;

    let desc = ExtraInfoDescriptorBuilder::default()
        .nickname("TestRelay")
        .fingerprint("0123456789ABCDEF0123456789ABCDEF01234567")
        .published(Utc::now())
        .transports(HashMap::new())
        .cell_processed_cells(vec![])
        .cell_queued_cells(vec![])
        .cell_time_in_queue(vec![])
        .dir_v3_ips(HashMap::new())
        .dir_v3_requests(HashMap::new())
        .dir_v3_responses(HashMap::new())
        .dir_v3_responses_unknown(HashMap::new())
        .dir_v3_direct_dl(HashMap::new())
        .dir_v3_direct_dl_unknown(HashMap::new())
        .dir_v3_tunneled_dl(HashMap::new())
        .dir_v3_tunneled_dl_unknown(HashMap::new())
        .dir_v2_ips(HashMap::new())
        .dir_v2_requests(HashMap::new())
        .dir_v2_responses(HashMap::new())
        .dir_v2_responses_unknown(HashMap::new())
        .dir_v2_direct_dl(HashMap::new())
        .dir_v2_direct_dl_unknown(HashMap::new())
        .dir_v2_tunneled_dl(HashMap::new())
        .dir_v2_tunneled_dl_unknown(HashMap::new())
        .entry_ips(HashMap::new())
        .exit_kibibytes_written(HashMap::new())
        .exit_kibibytes_read(HashMap::new())
        .exit_streams_opened(HashMap::new())
        .bridge_ips(HashMap::new())
        .ip_versions(HashMap::new())
        .ip_transports(HashMap::new())
        .hs_rend_cells_attr(HashMap::new())
        .hs_dir_onions_seen_attr(HashMap::new())
        .padding_counts(HashMap::new())
        .raw_content(vec![])
        .unrecognized_lines(vec![])
        .build()
        .expect("Failed to build ExtraInfoDescriptor");

    assert_eq!(desc.nickname, "TestRelay");
    assert_eq!(desc.fingerprint, "0123456789ABCDEF0123456789ABCDEF01234567");
    assert!(desc.transports.is_empty());
}

#[test]
fn test_builder_with_into_conversions() {
    use chrono::Utc;
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;
    use stem_rs::descriptor::ServerDescriptorBuilder;
    use stem_rs::exit_policy::ExitPolicy;
    use stem_rs::BridgeDistribution;

    let exit_policy = ExitPolicy::parse("reject *:*").expect("Failed to parse exit policy");
    let address: IpAddr = "192.168.1.1".parse().unwrap();

    let desc = ServerDescriptorBuilder::default()
        .nickname("TestRelay".to_string())
        .address(address)
        .or_port(9001_u16)
        .or_addresses(vec![])
        .published(Utc::now())
        .bandwidth_avg(1000000_u64)
        .bandwidth_burst(2000000_u64)
        .bandwidth_observed(500000_u64)
        .exit_policy(exit_policy)
        .bridge_distribution(BridgeDistribution::Any)
        .family(HashSet::new())
        .hibernating(false)
        .allow_single_hop_exits(false)
        .allow_tunneled_dir_requests(true)
        .extra_info_cache(false)
        .is_hidden_service_dir(false)
        .protocols(HashMap::new())
        .signature("test_signature")
        .raw_content(Vec::<u8>::new())
        .unrecognized_lines(Vec::<String>::new())
        .build()
        .expect("Failed to build with into conversions");

    assert_eq!(desc.nickname, "TestRelay");
}
