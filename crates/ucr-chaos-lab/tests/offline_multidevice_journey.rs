//! Offline / multi-device deterministic integration journeys for the existing UCR chaos lab.
use ucr_chaos_lab::*;

fn packet(id: u64, source: u16, destination: u16, route: RouteKind) -> LabPacket {
    LabPacket::new(
        PacketId(id),
        PeerId(source),
        PeerId(destination),
        route,
        format!("message-{id}").into_bytes(),
    )
}

#[test]
fn journey_offline_restart_then_delivery_to_two_devices() {
    let mut transport = ChaosTransport::with_peers(3);
    let mut pending = DurableQueueLab::new(4096);
    let first = packet(700, 0, 1, RouteKind::Direct);
    let second = packet(701, 0, 2, RouteKind::Direct);
    pending
        .persist(first.clone())
        .expect("persist first before network");
    pending
        .persist(second.clone())
        .expect("persist second before network");
    transport
        .apply(Fault::SetPeerOnline(PeerId(1), false))
        .expect("device one offline");
    transport
        .apply(Fault::SetPeerOnline(PeerId(2), false))
        .expect("device two offline");
    assert_eq!(
        transport.send(first.clone()),
        Err(ChaosError::PeerOffline(PeerId(1)))
    );
    assert_eq!(
        transport.send(second.clone()),
        Err(ChaosError::PeerOffline(PeerId(2)))
    );
    let pending = DurableQueueLab::restart_from(&pending);
    assert_eq!(
        pending.pending_count(),
        2,
        "restart must not erase either target"
    );
    transport
        .apply(Fault::SetPeerOnline(PeerId(1), true))
        .expect("reconnect first");
    transport
        .apply(Fault::SetPeerOnline(PeerId(2), true))
        .expect("reconnect second");
    let mut inbox_one = ChaosInbox::default();
    let mut inbox_two = ChaosInbox::default();
    for delivery in transport.send(first).expect("retry first") {
        assert_eq!(inbox_one.accept(delivery.packet), InboxOutcome::Accepted);
    }
    for delivery in transport.send(second).expect("retry second") {
        assert_eq!(inbox_two.accept(delivery.packet), InboxOutcome::Accepted);
    }
    assert_eq!(inbox_one.packet_ids(), vec![PacketId(700)]);
    assert_eq!(inbox_two.packet_ids(), vec![PacketId(701)]);
    // The lab queue remains pending until canonical recipient evidence is committed.
    assert_eq!(pending.pending_count(), 2);
}

#[test]
fn journey_loss_and_duplicate_retry_does_not_duplicate_user_inbox() {
    let mut transport = ChaosTransport::with_peers(2);
    let mut inbox = ChaosInbox::default();
    let outgoing = packet(702, 0, 1, RouteKind::Direct);
    transport
        .apply(Fault::DropNext)
        .expect("drop on first attempt");
    assert!(
        transport
            .send(outgoing.clone())
            .expect("lost packet")
            .is_empty()
    );
    transport
        .apply(Fault::DuplicateNext)
        .expect("duplicate retry");
    let replay = transport.send(outgoing.clone()).expect("retry delivered");
    assert_eq!(replay.len(), 2);
    assert_eq!(
        inbox.accept(replay[0].packet.clone()),
        InboxOutcome::Accepted
    );
    assert_eq!(
        inbox.accept(replay[1].packet.clone()),
        InboxOutcome::DuplicateSuppressed
    );
    assert_eq!(inbox.accept(outgoing), InboxOutcome::DuplicateSuppressed);
    assert_eq!(inbox.accepted_count(), 1);
}

#[test]
fn journey_revocation_during_offline_period_is_fail_closed() {
    let mut transport = ChaosTransport::with_peers(2);
    let mut pending = DurableQueueLab::new(1024);
    let outgoing = packet(703, 0, 1, RouteKind::Direct);
    pending
        .persist(outgoing.clone())
        .expect("local durable commit");
    transport
        .apply(Fault::SetPeerOnline(PeerId(1), false))
        .expect("offline");
    let pending = DurableQueueLab::restart_from(&pending);
    transport
        .apply(Fault::RevokePeer(PeerId(1)))
        .expect("revoke");
    transport
        .apply(Fault::SetPeerOnline(PeerId(1), true))
        .expect("network returns");
    assert_eq!(
        transport.send(outgoing),
        Err(ChaosError::PeerRevoked(PeerId(1)))
    );
    assert!(
        pending.contains(PacketId(703)),
        "do not silently discard undelivered intent"
    );
}

#[test]
fn journey_corrupt_wire_payload_never_advances_recipient_inbox() {
    let mut transport = ChaosTransport::with_peers(2);
    let mut inbox = ChaosInbox::default();
    transport.apply(Fault::CorruptNext).expect("corrupt");
    for delivery in transport
        .send(packet(704, 0, 1, RouteKind::Direct))
        .expect("wire")
    {
        assert_eq!(inbox.accept(delivery.packet), InboxOutcome::CorruptRejected);
    }
    assert_eq!(inbox.accepted_count(), 0);
}
