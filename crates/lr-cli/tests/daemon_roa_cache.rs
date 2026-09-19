//! Cache-only RPKI validation through the real daemon and TCP sessions.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use lr_bgp::rtr::{self, RtrPdu, RTR_VERSION_MAX};
use lr_core::addr::Prefix;

const BIN: &str = env!("CARGO_BIN_EXE_lr-daemon");

struct Daemon {
    child: Child,
    config: PathBuf,
    log: PathBuf,
}

impl Daemon {
    fn spawn(config_text: &str, tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!("lr-roa-cache-{tag}-{}", std::process::id()));
        let config = base.with_extension("toml");
        let log = base.with_extension("log");
        std::fs::write(&config, config_text).unwrap();
        let output = std::fs::File::create(&log).unwrap();
        let child = Command::new(BIN)
            .args(["--config", config.to_str().unwrap()])
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        Self { child, config, log }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
        let _ = std::fs::remove_file(&self.log);
    }
}

fn wait_log(path: &Path, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let log = std::fs::read_to_string(path).unwrap_or_default();
        if log.contains(needle) {
            return;
        }
        assert!(Instant::now() < deadline, "missing {needle}: {log}");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn cache_only_validation_rejects_invalid_origin_and_accepts_valid_origin() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let cache_addr = listener.local_addr().unwrap();
    let cache = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let mut query = [0u8; 8];
        socket.read_exact(&mut query).unwrap();
        let mut response = Vec::new();
        for pdu in [
            RtrPdu::CacheResponse { session_id: 1 },
            RtrPdu::Ipv4Prefix {
                announce: true,
                prefix: Prefix::new_v4([203, 0, 113, 0], 24),
                max_length: 24,
                asn: 64514,
            },
            RtrPdu::Ipv4Prefix {
                announce: true,
                prefix: Prefix::new_v4([198, 51, 100, 0], 24),
                max_length: 24,
                asn: 64512,
            },
            RtrPdu::EndOfData {
                session_id: 1,
                serial: 1,
                refresh_interval: Some(60),
                retry_interval: Some(1),
                expire_interval: Some(600),
            },
        ] {
            rtr::encode(&pdu, RTR_VERSION_MAX, &mut response);
        }
        socket.write_all(&response).unwrap();
        let mut byte = [0u8; 1];
        let _ = socket.read(&mut byte);
    });
    let port = TcpListener::bind("127.0.0.1:0").unwrap();
    let bgp_addr = port.local_addr().unwrap();
    drop(port);
    let receiver = Daemon::spawn(
        &format!(
            r#"
[bgp]
local_as = 64513
peer_as = 64512
router_id = "10.0.0.2"
listen_addr = "{bgp_addr}"
local_address = "192.0.2.2"
ebgp_policy = "accept-all"
roa_validate = true
roa_invalid_action = "reject"
[bgp.rpki]
cache = "{cache_addr}"
"#
        ),
        "receiver",
    );
    wait_log(&receiver.log, "rpki: sync complete");
    let sender = Daemon::spawn(
        &format!(
            r#"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
local_address = "192.0.2.1"
networks = ["203.0.113.0/24", "198.51.100.0/24"]
ebgp_policy = "accept-all"
[[peer]]
remote = "{bgp_addr}"
peer_as = 64513
"#
        ),
        "sender",
    );
    wait_log(&receiver.log, "daemon: route installed 198.51.100.0/24");
    // Allow the remaining announcements in the established session to drain.
    thread::sleep(Duration::from_secs(1));
    let log = std::fs::read_to_string(&receiver.log).unwrap();
    assert!(
        !log.contains("daemon: route installed 203.0.113.0/24"),
        "Invalid origin must be rejected with no static ROAs: {log}"
    );
    drop(sender);
    drop(receiver);
    cache.join().unwrap();
}
