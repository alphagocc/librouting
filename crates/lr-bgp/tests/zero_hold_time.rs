use lr_bgp::path::{AsPath, AttrType, PathAttrFlags, PathAttribute, PathAttributes};
use lr_bgp::{BgpEvent, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

fn config(local: u32, remote: u32, id: u8) -> PeerConfig {
    PeerConfig::new(Asn(local), Asn(remote), RouterId::from_v4([10, 0, 0, id]))
}

fn establish(a: &mut BgpPeer, b: &mut BgpPeer) {
    for peer in [&mut *a, &mut *b] {
        peer.step(BgpEvent::ManualStart);
        peer.step(BgpEvent::TransportOpen);
    }
    let a_open = a.drain_outgoing();
    let b_open = b.drain_outgoing();
    a.feed_bytes(&b_open).unwrap();
    b.feed_bytes(&a_open).unwrap();
    let a_keepalive = a.drain_outgoing();
    let b_keepalive = b.drain_outgoing();
    a.feed_bytes(&b_keepalive).unwrap();
    b.feed_bytes(&a_keepalive).unwrap();
    assert!(a.is_established());
    assert!(b.is_established());
}

fn route() -> Route {
    let mut attrs = PathAttributes::new();
    let flags = PathAttrFlags::new().set_transitive(true);
    attrs.insert(PathAttribute::new(flags, AttrType::Origin, vec![0]));
    attrs.insert(PathAttribute::new(
        flags,
        AttrType::AsPath,
        AsPath::from_sequence([Asn(64500)]).encode_4(),
    ));
    attrs.insert(PathAttribute::new(
        flags,
        AttrType::NextHop,
        vec![192, 0, 2, 1],
    ));
    Route {
        key: RouteKey::new(
            Prefix::new_v4([203, 0, 113, 0], 24),
            NlriFamily::IPV4_UNICAST,
        ),
        origin: RouteOrigin { proto: 0, peer: 7 },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 1),
        next_hop: Some(IpAddr::V4([192, 0, 2, 1])),
        attributes: attrs.into(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

fn assert_no_hold_or_keepalive_timers(actions: &[lr_bgp::BgpAction]) {
    use lr_bgp::fsm::timer_ids;
    assert!(!actions.iter().any(|action| matches!(
        action,
        lr_bgp::BgpAction::SetTimer(id, _)
            if *id == timer_ids::HOLD || *id == timer_ids::KEEPALIVE
    )));
}

#[test]
fn zero_hold_time_confirms_open_and_keeps_timers_disabled() {
    for (local_hold, remote_hold) in [(0, 90), (90, 0), (0, 0)] {
        let mut local = config(64512, 64513, 1);
        local.hold_time = local_hold;
        let mut remote = config(64513, 64512, 2);
        remote.hold_time = remote_hold;
        let mut a = BgpPeer::new(local);
        let mut b = BgpPeer::new(remote);
        for peer in [&mut a, &mut b] {
            peer.step(BgpEvent::ManualStart);
            peer.step(BgpEvent::TransportOpen);
        }
        let a_open = a.drain_outgoing();
        let b_open = b.drain_outgoing();
        assert_no_hold_or_keepalive_timers(&a.feed_bytes(&b_open).unwrap());
        assert_no_hold_or_keepalive_timers(&b.feed_bytes(&a_open).unwrap());
        let a_ka = a.drain_outgoing();
        let b_ka = b.drain_outgoing();
        assert_eq!(
            a_ka.len(),
            19,
            "OPEN must be confirmed even with zero Hold Time"
        );
        assert_eq!(
            b_ka.len(),
            19,
            "OPEN must be confirmed even with zero Hold Time"
        );
        assert_no_hold_or_keepalive_timers(&a.feed_bytes(&b_ka).unwrap());
        assert_no_hold_or_keepalive_timers(&b.feed_bytes(&a_ka).unwrap());
        assert!(a.is_established() && b.is_established());
        assert_no_hold_or_keepalive_timers(&a.feed_bytes(&b_ka).unwrap());
        assert!(b.advertise(&route()));
        let actions = a.feed_bytes(&b.drain_outgoing()).unwrap();
        assert_no_hold_or_keepalive_timers(&actions);
        assert!(actions
            .iter()
            .any(|action| matches!(action, lr_bgp::BgpAction::InstallRoute(_))));
        assert!(a.step(BgpEvent::TimerKeepalive).is_empty());
        assert!(a.step(BgpEvent::TimerHoldExpired).is_empty());
        assert!(a.is_established());
        assert!(a.drain_outgoing().is_empty());
    }
}

#[test]
fn nonzero_hold_time_still_establishes() {
    let mut a = BgpPeer::new(config(64512, 64513, 1));
    let mut b = BgpPeer::new(config(64513, 64512, 2));
    establish(&mut a, &mut b);
    assert_eq!(a.negotiated_hold_time(), 90);
}
