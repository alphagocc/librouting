//! Queued MRAI advertisements must reflect the latest route and export policy.

use lr_bgp::path::{AttrType, PathAttrFlags, PathAttribute, PathAttributes};
use lr_core::addr::{Asn, IpAddr, Prefix, RouterId};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Route, RouteKey};
use lr_core::time::Instant;
use lr_policy::hooks::{ExportHook, HookVerdict};
use lr_router::{DefaultRouter, RouterInstance, SessionConfig, SessionHandle};

fn pump(a: &mut DefaultRouter, ha: SessionHandle, b: &mut DefaultRouter, hb: SessionHandle) {
    for _ in 0..32 {
        let ab = a.drain_output(ha);
        let ba = b.drain_output(hb);
        if ab.is_empty() && ba.is_empty() {
            return;
        }
        if !ab.is_empty() {
            b.feed_input(hb, &ab).unwrap();
        }
        if !ba.is_empty() {
            a.feed_input(ha, &ba).unwrap();
        }
    }
    panic!("byte pump did not finish");
}

fn pair(add_path: bool) -> (DefaultRouter, SessionHandle, DefaultRouter, SessionHandle) {
    let mut a = DefaultRouter::new();
    let mut b = DefaultRouter::new();
    let config = |local, remote, id| {
        let cfg = SessionConfig::bgp(Asn(local), Asn(remote), RouterId::from_v4([10, 0, 0, id]))
            .with_local_address(IpAddr::V4([192, 0, 2, id]));
        if add_path {
            cfg.with_add_path()
        } else {
            cfg
        }
    };
    let ha = a.add_session(config(64512, 64513, 1)).unwrap();
    let hb = b.add_session(config(64513, 64512, 2)).unwrap();
    a.start_session(ha).unwrap();
    b.start_session(hb).unwrap();
    pump(&mut a, ha, &mut b, hb);
    a.set_mrai(ha, 1000).unwrap();
    (a, ha, b, hb)
}

fn originate(router: &mut DefaultRouter, med: u32) -> RouteKey {
    let mut attributes = PathAttributes::new();
    attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::Origin,
        vec![0],
    ));
    attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_transitive(true),
        AttrType::AsPath,
        Vec::new(),
    ));
    attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_optional(true),
        AttrType::MultiExitDisc,
        med.to_be_bytes().to_vec(),
    ));
    router.originate_with_attributes(
        Prefix::new_v4([203, 0, 113, 0], 24),
        NlriFamily::IPV4_UNICAST,
        Some(IpAddr::V4([192, 0, 2, 1])),
        attributes.into(),
    )
}

fn med(router: &DefaultRouter) -> u32 {
    let routes = router.rib_snapshot();
    assert_eq!(routes.len(), 1);
    let attributes: PathAttributes = routes[0].attributes.clone().into();
    attributes.med().unwrap().0
}

#[test]
fn reverting_to_advertised_route_cancels_pending_replacement() {
    for add_path in [false, true] {
        let (mut a, ha, mut b, hb) = pair(add_path);
        for value in [100, 200, 100] {
            originate(&mut a, value);
            pump(&mut a, ha, &mut b, hb);
        }
        a.tick(Instant::from_millis(1000));
        pump(&mut a, ha, &mut b, hb);
        assert_eq!(med(&a), 100);
        assert_eq!(med(&b), 100, "obsolete queued attributes must not escape");
    }
}

#[test]
fn removing_export_policy_cancels_unadvertised_pending_route() {
    for add_path in [false, true] {
        let (mut a, ha, mut b, hb) = pair(add_path);
        a.set_ebgp_requires_policy(true);
        a.set_session_policy(ha, true, true).unwrap();
        let key = originate(&mut a, 100);
        pump(&mut a, ha, &mut b, hb);
        assert_eq!(med(&b), 100);
        a.unoriginate(&key);
        pump(&mut a, ha, &mut b, hb);
        assert!(b.rib_snapshot().is_empty());
        originate(&mut a, 200);
        a.set_session_policy(ha, true, false).unwrap();
        a.tick(Instant::from_millis(1000));
        pump(&mut a, ha, &mut b, hb);
        assert!(
            b.rib_snapshot().is_empty(),
            "removed policy must cancel pending export"
        );
    }
}

struct SetMed(u32);

impl ExportHook for SetMed {
    fn on_export(&self, route: &mut Route) -> HookVerdict {
        let mut attributes: PathAttributes = route.attributes.clone().into();
        attributes.insert(PathAttribute::new(
            PathAttrFlags::new().set_optional(true),
            AttrType::MultiExitDisc,
            self.0.to_be_bytes().to_vec(),
        ));
        route.attributes = attributes.into();
        HookVerdict::Keep
    }
}

#[test]
fn route_refresh_supersedes_pending_attributes_from_old_policy() {
    for add_path in [false, true] {
        let (mut a, ha, mut b, hb) = pair(add_path);
        originate(&mut a, 100);
        pump(&mut a, ha, &mut b, hb);
        originate(&mut a, 200);
        a.hooks_mut().export.push(Box::new(SetMed(300)));
        assert!(b.request_route_refresh(hb, NlriFamily::IPV4_UNICAST));
        pump(&mut a, ha, &mut b, hb);
        assert_eq!(med(&b), 300);
        a.tick(Instant::from_millis(1000));
        pump(&mut a, ha, &mut b, hb);
        assert_eq!(
            med(&b),
            300,
            "refresh must supersede the old pending update"
        );
    }
}
