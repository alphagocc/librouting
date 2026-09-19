//! Default routes have no prefix octets in a Babel Update (RFC 8966).

use lr_babel::message::{NextHop, RouterId, Update};
use lr_babel::tlv::{Tlv, TlvType};
use lr_core::addr::{IpAddr, Prefix};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

fn default_update(next_hop: IpAddr, metric: u16) -> Vec<u8> {
    let ae = match next_hop {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 2,
    };
    let mut frame = lr_babel::BabelFrame::empty();
    frame.body.push(Tlv::new(
        TlvType::RouterId,
        RouterId { id: [1; 8] }.encode().to_vec(),
    ));
    frame.body.push(Tlv::new(
        TlvType::NextHop,
        NextHop {
            ae,
            address: next_hop,
        }
        .encode(),
    ));
    frame.body.push(Tlv::new(
        TlvType::Update,
        Update {
            ae,
            flags: 0,
            prefix_len: 0,
            omitted: 0,
            interval_cs: 300,
            seqno: 7,
            metric,
            prefix: Vec::new(),
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        }
        .encode(),
    ));
    lr_babel::BabelCodec::new().encode_vec(&frame).unwrap()
}

fn check_default_route(next_hop: IpAddr, prefix: Prefix) {
    let mut router = DefaultRouter::new();
    let session = router.add_session(SessionConfig::babel(next_hop)).unwrap();
    router.start_session(session).unwrap();
    router
        .feed_input(session, &default_update(next_hop, 96))
        .unwrap();
    let routes = router.rib_snapshot();
    assert_eq!(routes.len(), 1, "the default route must be installed");
    assert_eq!(routes[0].key.prefix, prefix);
    assert_eq!(routes[0].next_hop, Some(next_hop));

    // An identical announcement refreshes the route without duplicating it.
    router
        .feed_input(session, &default_update(next_hop, 96))
        .unwrap();
    assert_eq!(router.rib_len(), 1);
    router
        .feed_input(session, &default_update(next_hop, u16::MAX))
        .unwrap();
    assert!(
        router.rib_snapshot().is_empty(),
        "retraction must remove /0"
    );
}

#[test]
fn ipv4_default_route_is_installed_and_retracted() {
    check_default_route(IpAddr::V4([192, 0, 2, 1]), Prefix::new_v4([0; 4], 0));
}

#[test]
fn ipv6_default_route_is_installed_and_retracted() {
    let mut address = [0; 16];
    address[0] = 0xfe;
    address[1] = 0x80;
    address[15] = 1;
    check_default_route(IpAddr::V6(address), Prefix::new_v6([0; 16], 0));
}
