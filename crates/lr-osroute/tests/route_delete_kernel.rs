//! Verify withdrawals retain routes installed by other protocols.
//!
//! Run in an isolated network namespace:
//! `unshare -Urn cargo test -p lr-osroute --test route_delete_kernel -- --ignored`.

#![cfg(target_os = "linux")]

use lr_core::addr::Prefix;
use lr_core::rib::Protocol;
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

#[test]
#[ignore = "requires iproute2 and an isolated network namespace with CAP_NET_ADMIN"]
fn withdraw_preserves_static_routes_with_the_same_prefix() {
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
    let mut table = RtNetlink::connect().unwrap();
    for (family, prefix, gateway) in [
        ("-4", "198.51.100.0/24", "192.0.2.2"),
        ("-6", "2001:db8:1::/64", "2001:db8::2"),
    ] {
        ip(&[
            family, "route", "add", prefix, "via", gateway, "proto", "static", "metric", "10",
        ]);
        ip(&[
            family, "route", "add", prefix, "via", gateway, "proto", "bgp", "metric", "20",
        ]);
        let prefix: Prefix = prefix.parse().unwrap();
        table.delete_route(prefix).expect("withdraw BGP route");
        let routes = table.list_routes().unwrap();
        assert!(
            routes
                .iter()
                .any(|route| route.prefix == prefix && route.protocol == Protocol::Static),
            "static route must survive withdrawal"
        );
        assert!(
            !routes
                .iter()
                .any(|route| route.prefix == prefix && route.protocol == Protocol::Bgp),
            "BGP route must be withdrawn"
        );
        // A repeated withdrawal must also preserve the static route when no
        // matching BGP route remains (including after a failed installation).
        let _ = table.delete_route(prefix);
        assert!(table
            .list_routes()
            .unwrap()
            .iter()
            .any(|route| route.prefix == prefix && route.protocol == Protocol::Static));
    }
}
