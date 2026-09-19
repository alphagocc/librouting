//! Kernel regression tests for plain IP route installation.
//!
//! Run in an isolated network namespace:
//! `unshare -Urn cargo test -p lr-osroute --test route_install_kernel -- --ignored`.

#![cfg(target_os = "linux")]

use lr_core::addr::{IpAddr, Prefix};
use lr_osroute::{OsRouteTable, RtNetlink};
use std::process::Command;

fn ip(args: &[&str]) {
    let output = Command::new("ip").args(args).output().expect("run ip");
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn setup() {
    ip(&["link", "add", "lr-route-test", "type", "dummy"]);
    ip(&["link", "set", "lr-route-test", "up"]);
    ip(&["address", "add", "192.0.2.1/24", "dev", "lr-route-test"]);
    ip(&[
        "-6",
        "address",
        "add",
        "2001:db8::1/64",
        "dev",
        "lr-route-test",
        "nodad",
    ]);
}

#[test]
#[ignore = "requires iproute2 and an isolated network namespace with CAP_NET_ADMIN"]
fn installs_new_routes_and_replaces_their_next_hops() {
    setup();
    let mut table = RtNetlink::connect().unwrap();
    for (prefix, gateway, replacement) in [
        ("198.51.100.0/24", "192.0.2.2", "192.0.2.3"),
        ("2001:db8:1::/64", "2001:db8::2", "2001:db8::3"),
    ] {
        let prefix: Prefix = prefix.parse().unwrap();
        let gateway: IpAddr = gateway.parse().unwrap();
        let replacement: IpAddr = replacement.parse().unwrap();
        table.add_route(prefix, gateway, 0).expect("create route");
        table.add_route(prefix, gateway, 0).expect("idempotent add");
        table
            .add_route(prefix, replacement, 0)
            .expect("replace next hop");
        let matching: Vec<_> = table
            .list_routes()
            .unwrap()
            .into_iter()
            .filter(|route| route.prefix == prefix)
            .collect();
        assert_eq!(matching.len(), 1, "replacement must leave one route");
        assert_eq!(matching[0].next_hop, Some(replacement));
    }
}
