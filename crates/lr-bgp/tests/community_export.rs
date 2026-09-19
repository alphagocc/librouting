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

#[test]
fn standard_communities_limit_session_export() {
    use lr_bgp::path::Community;
    use lr_bgp::role::PeerRole;

    for role in [
        PeerRole::Ebgp,
        PeerRole::Ibgp,
        PeerRole::ConfederationExternal,
        PeerRole::ConfederationInternal,
    ] {
        for community in [
            None,
            Some(Community::NO_EXPORT),
            Some(Community::NO_ADVERTISE),
            Some(Community::NO_EXPORT_SUBCONFED),
        ] {
            let mut cfg = config(64512, 64513, 1);
            cfg.role_override = Some(role);
            let mut a = BgpPeer::new(cfg);
            let mut b = BgpPeer::new(config(64513, 64512, 2));
            establish(&mut a, &mut b);
            let mut route = route();
            if let Some(community) = community {
                let mut attrs: PathAttributes = route.attributes.clone().into();
                attrs.insert(PathAttribute::new(
                    PathAttrFlags::new().set_optional(true).set_transitive(true),
                    AttrType::Communities,
                    community.0.to_be_bytes().to_vec(),
                ));
                route.attributes = attrs.into();
            }
            let expected = match community {
                Some(Community::NO_ADVERTISE) => false,
                Some(Community::NO_EXPORT) => role != PeerRole::Ebgp,
                Some(Community::NO_EXPORT_SUBCONFED) => role.is_internal(),
                _ => true,
            };
            assert_eq!(a.advertise(&route), expected, "{role:?}, {community:?}");
            assert_eq!(a.drain_outgoing().is_empty(), !expected);
        }
    }
}
