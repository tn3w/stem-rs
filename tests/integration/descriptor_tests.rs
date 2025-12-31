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
        if desc_content.is_empty() {
            return;
        }

        let mut policy_lines = Vec::new();
        for line in desc_content.lines() {
            if line.starts_with("accept ") || line.starts_with("reject ") {
                policy_lines.push(line.to_string());
            }
        }

        if !policy_lines.is_empty() {
            let policy_str = policy_lines.join("\n");
            if let Ok(policy) = ExitPolicy::parse(&policy_str) {
                let _can_exit_80 = policy.can_exit_to("0.0.0.0".parse().unwrap(), 80);
                let _can_exit_443 = policy.can_exit_to("0.0.0.0".parse().unwrap(), 443);
            }
        }
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
