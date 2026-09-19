//! Source-specific Babel routes must retain their source in the shared RIB.

use lr_babel::message::{NextHop, RouterId, Update};
use lr_babel::tlv::{Tlv, TlvType};
use lr_core::addr::{IpAddr, Prefix};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig};

fn update(destination: Prefix, source: Option<Prefix>, metric: u16) -> Vec<u8> {
    let (ae, next_hop) = match destination.addr {
        IpAddr::V4(_) => (1, IpAddr::V4([192, 0, 2, 1])),
        IpAddr::V6(_) => (2, "fe80::1".parse().unwrap()),
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
            prefix_len: destination.prefix_len,
            omitted: 0,
            interval_cs: 300,
            seqno: 7,
            metric,
            prefix: destination.addr.octets()[..usize::from(destination.prefix_len).div_ceil(8)]
                .to_vec(),
            src_prefix_len: source.map_or(0, |p| p.prefix_len),
            src_prefix: source.map_or_else(Vec::new, |p| {
                p.addr.octets()[..usize::from(p.prefix_len).div_ceil(8)].to_vec()
            }),
        }
        .encode(),
    ));
    lr_babel::BabelCodec::new().encode_vec(&frame).unwrap()
}

fn check_distinct_sources(destination: Prefix, sources: [Prefix; 2]) {
    let mut router = DefaultRouter::new();
    let session = router
        .add_session(SessionConfig::babel("192.0.2.1".parse().unwrap()))
        .unwrap();
    router.start_session(session).unwrap();
    for source in [None, Some(sources[0]), Some(sources[1])] {
        router
            .feed_input(session, &update(destination, source, 96))
            .unwrap();
    }
    let snapshot = router.rib_snapshot();
    assert_eq!(snapshot.len(), 3, "source prefixes must not collide");
    for source in [None, Some(sources[0]), Some(sources[1])] {
        assert!(snapshot
            .iter()
            .any(|r| r.key.prefix == destination && r.key.source == source));
    }

    router
        .feed_input(session, &update(destination, Some(sources[0]), u16::MAX))
        .unwrap();
    let snapshot = router.rib_snapshot();
    assert_eq!(snapshot.len(), 2);
    assert!(snapshot.iter().any(|r| r.key.source.is_none()));
    assert!(snapshot.iter().any(|r| r.key.source == Some(sources[1])));
    assert!(snapshot.iter().all(|r| r.key.source != Some(sources[0])));
}

#[test]
fn ipv4_source_prefixes_coexist_and_withdraw_independently() {
    check_distinct_sources(
        "203.0.113.0/24".parse().unwrap(),
        [
            "198.51.100.0/24".parse().unwrap(),
            "198.51.101.0/24".parse().unwrap(),
        ],
    );
}

#[test]
fn ipv6_source_prefixes_coexist_and_withdraw_independently() {
    check_distinct_sources(
        "2001:db8:1::/48".parse().unwrap(),
        [
            "2001:db8:2::/48".parse().unwrap(),
            "2001:db8:3::/48".parse().unwrap(),
        ],
    );
}
