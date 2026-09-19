use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lr_bgp::message::update::{Nlri, Update};
use lr_bgp::path::{AsPath, AttrType, Community, PathAttrFlags, PathAttribute};
use lr_bgp::{BgpCodec, BgpEvent, BgpMessage, BgpPeer, PeerConfig};
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_core::rib::Route;
use lr_policy::{ExportHook, HookVerdict};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

fn pump(a: &mut DefaultRouter, ha: SessionHandle, b: &mut DefaultRouter, hb: SessionHandle) {
    for _ in 0..16 {
        let a_out = a.drain_output(ha);
        let b_out = b.drain_output(hb);
        if a_out.is_empty() && b_out.is_empty() {
            return;
        }
        b.feed_input(hb, &a_out).unwrap();
        a.feed_input(ha, &b_out).unwrap();
    }
    panic!("byte pump did not converge");
}

struct Transit {
    router: DefaultRouter,
    downstream: DefaultRouter,
    inbound: SessionHandle,
    outbound: SessionHandle,
    receiver: SessionHandle,
    add_path: bool,
}

impl Transit {
    fn new(add_path: bool) -> Self {
        let mut router = DefaultRouter::new();
        let mut downstream = DefaultRouter::new();
        router.set_add_path_max_paths(2);
        downstream.set_add_path_max_paths(2);
        let mut inbound_cfg =
            SessionConfig::bgp(Asn(64512), Asn(64500), RouterId::from_v4([10, 0, 0, 1]));
        let mut outbound_cfg =
            SessionConfig::bgp(Asn(64512), Asn(64513), RouterId::from_v4([10, 0, 0, 1]))
                .with_local_address(IpAddr::V4([192, 0, 2, 12]))
                .with_mrai_ms(0);
        let mut receiver_cfg =
            SessionConfig::bgp(Asn(64513), Asn(64512), RouterId::from_v4([10, 0, 0, 2]))
                .with_local_address(IpAddr::V4([192, 0, 2, 13]));
        if add_path {
            inbound_cfg = inbound_cfg.with_add_path();
            outbound_cfg = outbound_cfg.with_add_path();
            receiver_cfg = receiver_cfg.with_add_path();
        }
        let inbound = router.add_session(inbound_cfg).unwrap();
        let outbound = router.add_session(outbound_cfg).unwrap();
        let receiver = downstream.add_session(receiver_cfg).unwrap();
        let mut upstream_cfg =
            PeerConfig::new(Asn(64500), Asn(64512), RouterId::from_v4([10, 0, 0, 3]));
        upstream_cfg.add_path = add_path;
        let mut upstream = BgpPeer::new(upstream_cfg);
        upstream.step(BgpEvent::ManualStart);
        upstream.step(BgpEvent::TransportOpen);
        router.start_session(inbound).unwrap();
        for _ in 0..4 {
            router
                .feed_input(inbound, &upstream.drain_outgoing())
                .unwrap();
            upstream.feed_bytes(&router.drain_output(inbound)).unwrap();
        }
        assert!(upstream.is_established());
        router.start_session(outbound).unwrap();
        downstream.start_session(receiver).unwrap();
        pump(&mut router, outbound, &mut downstream, receiver);
        Self {
            router,
            downstream,
            inbound,
            outbound,
            receiver,
            add_path,
        }
    }

    fn update(&mut self, path_id: u32, community: Option<Community>, med: u32) {
        let mut update = Update::new();
        let flags = PathAttrFlags::new().set_transitive(true);
        update
            .attributes
            .insert(PathAttribute::new(flags, AttrType::Origin, vec![0]));
        update.attributes.insert(PathAttribute::new(
            flags,
            AttrType::AsPath,
            AsPath::from_sequence([Asn(64500)]).encode_4(),
        ));
        update.attributes.insert(PathAttribute::new(
            flags,
            AttrType::NextHop,
            vec![192, 0, 2, 1],
        ));
        update.attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true),
            AttrType::MultiExitDisc,
            med.to_be_bytes().to_vec(),
        ));
        if let Some(community) = community {
            update.attributes.insert(PathAttribute::new(
                flags.set_optional(true),
                AttrType::Communities,
                community.0.to_be_bytes().to_vec(),
            ));
        }
        update.nlri.push(Nlri::new(
            if self.add_path { path_id } else { 0 },
            Prefix::new_v4([203, 0, 113, 0], 24),
        ));
        let mut codec = BgpCodec::new().with_asn4(true);
        if self.add_path {
            codec.set_add_path(vec![NlriFamily::IPV4_UNICAST], vec![]);
        }
        let wire = codec.encode_vec(&BgpMessage::Update(update)).unwrap();
        self.router.feed_input(self.inbound, &wire).unwrap();
        pump(
            &mut self.router,
            self.outbound,
            &mut self.downstream,
            self.receiver,
        );
    }

    fn received_paths(&self) -> usize {
        self.downstream.rib_paths_snapshot().len()
    }
}

#[test]
fn learned_community_changes_withdraw_and_restore_advertisements() {
    for add_path in [false, true] {
        let mut transit = Transit::new(add_path);
        transit.update(1, Some(Community::NO_EXPORT), 0);
        assert_eq!(transit.received_paths(), 0);
        transit.update(1, None, 0);
        assert_eq!(transit.received_paths(), 1);
        if add_path {
            transit.update(2, None, 0);
            assert_eq!(transit.received_paths(), 2);
        }
        let remaining = usize::from(add_path);
        for community in [Community::NO_EXPORT, Community::NO_ADVERTISE] {
            transit.update(1, Some(community), 0);
            assert_eq!(transit.received_paths(), remaining);
            transit.update(1, None, 0);
            assert_eq!(transit.received_paths(), remaining + 1);
        }
    }
}

struct TagExport {
    enabled: Arc<AtomicBool>,
    destination: u64,
}

impl ExportHook for TagExport {
    fn on_export(&self, _route: &mut Route) -> HookVerdict {
        HookVerdict::Keep
    }

    fn on_export_to(&self, route: &mut Route, destination: u64) -> HookVerdict {
        if destination == self.destination && self.enabled.load(Ordering::Relaxed) {
            let mut attrs: lr_bgp::path::PathAttributes = route.attributes.clone().into();
            attrs.insert(PathAttribute::new(
                PathAttrFlags::new().set_optional(true).set_transitive(true),
                AttrType::Communities,
                Community::NO_EXPORT.0.to_be_bytes().to_vec(),
            ));
            route.attributes = attrs.into();
        }
        HookVerdict::Keep
    }
}

#[test]
fn export_hook_community_changes_withdraw_and_restore_advertisements() {
    let mut transit = Transit::new(false);
    let enabled = Arc::new(AtomicBool::new(false));
    transit.router.hooks_mut().export.push(Box::new(TagExport {
        enabled: Arc::clone(&enabled),
        destination: transit.outbound.0,
    }));
    transit.update(1, None, 0);
    assert_eq!(transit.received_paths(), 1);
    enabled.store(true, Ordering::Relaxed);
    transit.update(1, None, 1);
    assert_eq!(transit.received_paths(), 0);
    enabled.store(false, Ordering::Relaxed);
    transit.update(1, None, 0);
    assert_eq!(transit.received_paths(), 1);
}
