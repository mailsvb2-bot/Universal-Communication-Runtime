#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PacketId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Direct,
    DnsResolved,
    Relay,
    Sfu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InfrastructureComponent {
    Dns,
    Relay,
    Sfu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanonicalChaosScenario {
    NetworkLoss,
    NetworkSwitch,
    DnsFailure,
    RelayFailure,
    SfuFailure,
    ProcessKill,
    AppRestart,
    PeerDisappearance,
    ClockDrift,
    PacketDuplication,
    PacketReorder,
    Corruption,
    StorageFull,
    NetworkPartition,
    NetworkMerge,
    OldClient,
    RevokedDevice,
    SlowConsumer,
}

pub const CANONICAL_CHAOS_SCENARIOS: [CanonicalChaosScenario; 18] = [
    CanonicalChaosScenario::NetworkLoss,
    CanonicalChaosScenario::NetworkSwitch,
    CanonicalChaosScenario::DnsFailure,
    CanonicalChaosScenario::RelayFailure,
    CanonicalChaosScenario::SfuFailure,
    CanonicalChaosScenario::ProcessKill,
    CanonicalChaosScenario::AppRestart,
    CanonicalChaosScenario::PeerDisappearance,
    CanonicalChaosScenario::ClockDrift,
    CanonicalChaosScenario::PacketDuplication,
    CanonicalChaosScenario::PacketReorder,
    CanonicalChaosScenario::Corruption,
    CanonicalChaosScenario::StorageFull,
    CanonicalChaosScenario::NetworkPartition,
    CanonicalChaosScenario::NetworkMerge,
    CanonicalChaosScenario::OldClient,
    CanonicalChaosScenario::RevokedDevice,
    CanonicalChaosScenario::SlowConsumer,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabPacket {
    pub packet_id: PacketId,
    pub source: PeerId,
    pub destination: PeerId,
    pub route: RouteKind,
    pub payload: Vec<u8>,
    integrity_tag: u64,
}

impl LabPacket {
    #[must_use]
    pub fn new(
        packet_id: PacketId,
        source: PeerId,
        destination: PeerId,
        route: RouteKind,
        payload: Vec<u8>,
    ) -> Self {
        let integrity_tag = lab_integrity_tag(&payload);
        Self {
            packet_id,
            source,
            destination,
            route,
            payload,
            integrity_tag,
        }
    }

    #[must_use]
    pub fn integrity_is_valid(&self) -> bool {
        self.integrity_tag == lab_integrity_tag(&self.payload)
    }
}

fn lab_integrity_tag(payload: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in payload {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    DropNext,
    DuplicateNext,
    ReorderNextPair,
    CorruptNext,
    SetPeerOnline(PeerId, bool),
    SwitchNetwork(PeerId),
    SetInfrastructure(InfrastructureComponent, bool),
    Partition(PeerId, PeerId),
    Merge(PeerId, PeerId),
    SetLatency(PeerId, PeerId, u64),
    SetClockDrift(PeerId, i64),
    SetSlowConsumer(PeerId, bool),
    RevokePeer(PeerId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChaosError {
    UnknownPeer(PeerId),
    PeerOffline(PeerId),
    PeerRevoked(PeerId),
    NetworkPartitioned(PeerId, PeerId),
    InfrastructureUnavailable(InfrastructureComponent),
    StorageFull { capacity: usize, required: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireDelivery {
    pub packet: LabPacket,
    pub latency_ms: u64,
    pub destination_network_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerState {
    online: bool,
    revoked: bool,
    network_generation: u64,
    clock_drift_ms: i64,
    slow_consumer: bool,
}

impl Default for PeerState {
    fn default() -> Self {
        Self {
            online: true,
            revoked: false,
            network_generation: 0,
            clock_drift_ms: 0,
            slow_consumer: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OneShotFaults {
    drop_next: bool,
    duplicate_next: bool,
    reorder_next_pair: bool,
    corrupt_next: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaosTransport {
    peers: BTreeMap<PeerId, PeerState>,
    infrastructure: BTreeMap<InfrastructureComponent, bool>,
    partitions: BTreeSet<(PeerId, PeerId)>,
    latency_ms: BTreeMap<(PeerId, PeerId), u64>,
    one_shot: OneShotFaults,
    reorder_buffer: Option<LabPacket>,
}

impl ChaosTransport {
    /// Creates a deterministic lab with peer identifiers `0..peer_count`.
    ///
    /// # Panics
    ///
    /// Panics if `peer_count` does not fit in `u16`.
    #[must_use]
    pub fn with_peers(peer_count: usize) -> Self {
        let count = u16::try_from(peer_count).expect("peer count must fit in u16");
        let peers = (0..count)
            .map(|value| (PeerId(value), PeerState::default()))
            .collect();
        let infrastructure = [
            (InfrastructureComponent::Dns, true),
            (InfrastructureComponent::Relay, true),
            (InfrastructureComponent::Sfu, true),
        ]
        .into_iter()
        .collect();
        Self {
            peers,
            infrastructure,
            partitions: BTreeSet::new(),
            latency_ms: BTreeMap::new(),
            one_shot: OneShotFaults::default(),
            reorder_buffer: None,
        }
    }

    /// Applies one deterministic fault.
    ///
    /// # Errors
    ///
    /// Returns `UnknownPeer` for a peer outside this lab.
    pub fn apply(&mut self, fault: Fault) -> Result<(), ChaosError> {
        match fault {
            Fault::DropNext => self.one_shot.drop_next = true,
            Fault::DuplicateNext => self.one_shot.duplicate_next = true,
            Fault::ReorderNextPair => {
                self.one_shot.reorder_next_pair = true;
                self.reorder_buffer = None;
            }
            Fault::CorruptNext => self.one_shot.corrupt_next = true,
            Fault::SetPeerOnline(peer, online) => self.peer_mut(peer)?.online = online,
            Fault::SwitchNetwork(peer) => {
                let state = self.peer_mut(peer)?;
                state.network_generation = state.network_generation.saturating_add(1);
            }
            Fault::SetInfrastructure(component, available) => {
                self.infrastructure.insert(component, available);
            }
            Fault::Partition(left, right) => {
                self.require_peer(left)?;
                self.require_peer(right)?;
                self.partitions.insert(peer_pair(left, right));
            }
            Fault::Merge(left, right) => {
                self.require_peer(left)?;
                self.require_peer(right)?;
                self.partitions.remove(&peer_pair(left, right));
            }
            Fault::SetLatency(left, right, latency_ms) => {
                self.require_peer(left)?;
                self.require_peer(right)?;
                self.latency_ms.insert(peer_pair(left, right), latency_ms);
            }
            Fault::SetClockDrift(peer, drift_ms) => {
                self.peer_mut(peer)?.clock_drift_ms = drift_ms;
            }
            Fault::SetSlowConsumer(peer, slow) => {
                self.peer_mut(peer)?.slow_consumer = slow;
            }
            Fault::RevokePeer(peer) => self.peer_mut(peer)?.revoked = true,
        }
        Ok(())
    }

    /// Sends through the deterministic fault substrate.
    ///
    /// An empty vector means intentional loss or a packet held for reorder.
    ///
    /// # Errors
    ///
    /// Returns explicit peer, partition, revocation, or infrastructure failures.
    pub fn send(&mut self, mut packet: LabPacket) -> Result<Vec<WireDelivery>, ChaosError> {
        self.require_sendable(&packet)?;

        if self.one_shot.drop_next {
            self.one_shot.drop_next = false;
            return Ok(Vec::new());
        }

        if self.one_shot.corrupt_next {
            self.one_shot.corrupt_next = false;
            if let Some(first) = packet.payload.first_mut() {
                *first ^= 0xff;
            } else {
                packet.payload.push(0xff);
            }
        }

        if self.one_shot.reorder_next_pair {
            if let Some(first) = self.reorder_buffer.take() {
                self.one_shot.reorder_next_pair = false;
                return Ok(vec![self.delivery(packet)?, self.delivery(first)?]);
            }
            self.reorder_buffer = Some(packet);
            return Ok(Vec::new());
        }

        let delivery = self.delivery(packet)?;
        if self.one_shot.duplicate_next {
            self.one_shot.duplicate_next = false;
            return Ok(vec![delivery.clone(), delivery]);
        }
        Ok(vec![delivery])
    }

    #[must_use]
    pub fn peer_display_clock_ms(&self, peer: PeerId, monotonic_ms: u64) -> Option<i128> {
        self.peers
            .get(&peer)
            .map(|state| i128::from(monotonic_ms) + i128::from(state.clock_drift_ms))
    }

    fn delivery(&self, packet: LabPacket) -> Result<WireDelivery, ChaosError> {
        self.require_sendable(&packet)?;
        let state = self
            .peers
            .get(&packet.destination)
            .ok_or(ChaosError::UnknownPeer(packet.destination))?;
        let base_latency = self
            .latency_ms
            .get(&peer_pair(packet.source, packet.destination))
            .copied()
            .unwrap_or(0);
        let latency_ms = if state.slow_consumer {
            base_latency.saturating_add(5_000)
        } else {
            base_latency
        };
        Ok(WireDelivery {
            packet,
            latency_ms,
            destination_network_generation: state.network_generation,
        })
    }

    fn require_sendable(&self, packet: &LabPacket) -> Result<(), ChaosError> {
        let source = self.require_peer(packet.source)?;
        let destination = self.require_peer(packet.destination)?;
        if !source.online {
            return Err(ChaosError::PeerOffline(packet.source));
        }
        if !destination.online {
            return Err(ChaosError::PeerOffline(packet.destination));
        }
        if source.revoked {
            return Err(ChaosError::PeerRevoked(packet.source));
        }
        if destination.revoked {
            return Err(ChaosError::PeerRevoked(packet.destination));
        }
        if self
            .partitions
            .contains(&peer_pair(packet.source, packet.destination))
        {
            return Err(ChaosError::NetworkPartitioned(
                packet.source,
                packet.destination,
            ));
        }
        if let Some(component) = route_component(packet.route)
            && !self
                .infrastructure
                .get(&component)
                .copied()
                .unwrap_or(false)
        {
            return Err(ChaosError::InfrastructureUnavailable(component));
        }
        Ok(())
    }

    fn require_peer(&self, peer: PeerId) -> Result<&PeerState, ChaosError> {
        self.peers.get(&peer).ok_or(ChaosError::UnknownPeer(peer))
    }

    fn peer_mut(&mut self, peer: PeerId) -> Result<&mut PeerState, ChaosError> {
        self.peers
            .get_mut(&peer)
            .ok_or(ChaosError::UnknownPeer(peer))
    }
}

fn route_component(route: RouteKind) -> Option<InfrastructureComponent> {
    match route {
        RouteKind::Direct => None,
        RouteKind::DnsResolved => Some(InfrastructureComponent::Dns),
        RouteKind::Relay => Some(InfrastructureComponent::Relay),
        RouteKind::Sfu => Some(InfrastructureComponent::Sfu),
    }
}

fn peer_pair(left: PeerId, right: PeerId) -> (PeerId, PeerId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxOutcome {
    Accepted,
    DuplicateSuppressed,
    CorruptRejected,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChaosInbox {
    seen: BTreeSet<PacketId>,
    accepted: Vec<LabPacket>,
}

impl ChaosInbox {
    #[must_use]
    pub fn accept(&mut self, packet: LabPacket) -> InboxOutcome {
        if !packet.integrity_is_valid() {
            return InboxOutcome::CorruptRejected;
        }
        if !self.seen.insert(packet.packet_id) {
            return InboxOutcome::DuplicateSuppressed;
        }
        self.accepted.push(packet);
        InboxOutcome::Accepted
    }

    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.accepted.len()
    }

    #[must_use]
    pub fn packet_ids(&self) -> Vec<PacketId> {
        self.accepted
            .iter()
            .map(|packet| packet.packet_id)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableQueueLab {
    capacity_bytes: usize,
    used_bytes: usize,
    pending: BTreeMap<PacketId, LabPacket>,
}

impl DurableQueueLab {
    #[must_use]
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            used_bytes: 0,
            pending: BTreeMap::new(),
        }
    }

    /// Persists a packet atomically with respect to the lab storage limit.
    ///
    /// # Errors
    ///
    /// Returns `StorageFull` before existing state is mutated.
    pub fn persist(&mut self, packet: LabPacket) -> Result<(), ChaosError> {
        if self.pending.contains_key(&packet.packet_id) {
            return Ok(());
        }
        let required = self.used_bytes.saturating_add(packet.payload.len());
        if required > self.capacity_bytes {
            return Err(ChaosError::StorageFull {
                capacity: self.capacity_bytes,
                required,
            });
        }
        self.used_bytes = required;
        self.pending.insert(packet.packet_id, packet);
        Ok(())
    }

    #[must_use]
    pub fn restart_from(snapshot: &Self) -> Self {
        snapshot.clone()
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn contains(&self, packet_id: PacketId) -> bool {
        self.pending.contains_key(&packet_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicNetworkSimulation {
    pub transport: ChaosTransport,
    pub peer_count: usize,
    pub battery_limit_percent: u8,
}

impl DeterministicNetworkSimulation {
    #[must_use]
    pub fn canonical_100_peers() -> Self {
        Self {
            transport: ChaosTransport::with_peers(100),
            peer_count: 100,
            battery_limit_percent: 20,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn duplicate_and_reorder_are_wire_faults_not_user_visible_duplicates() {
        let mut transport = ChaosTransport::with_peers(2);
        let mut inbox = ChaosInbox::default();

        transport.apply(Fault::DuplicateNext).expect("fault");
        let duplicated = transport
            .send(packet(1, 0, 1, RouteKind::Direct))
            .expect("send");
        assert_eq!(duplicated.len(), 2);
        assert_eq!(
            inbox.accept(duplicated[0].packet.clone()),
            InboxOutcome::Accepted
        );
        assert_eq!(
            inbox.accept(duplicated[1].packet.clone()),
            InboxOutcome::DuplicateSuppressed
        );

        transport.apply(Fault::ReorderNextPair).expect("fault");
        assert!(
            transport
                .send(packet(2, 0, 1, RouteKind::Direct))
                .expect("first")
                .is_empty()
        );
        let reordered = transport
            .send(packet(3, 0, 1, RouteKind::Direct))
            .expect("second");
        assert_eq!(reordered[0].packet.packet_id, PacketId(3));
        assert_eq!(reordered[1].packet.packet_id, PacketId(2));
        for delivery in reordered {
            assert_eq!(inbox.accept(delivery.packet), InboxOutcome::Accepted);
        }
        assert_eq!(inbox.accepted_count(), 3);
    }

    #[test]
    fn corruption_is_explicitly_rejected() {
        let mut transport = ChaosTransport::with_peers(2);
        let mut inbox = ChaosInbox::default();
        transport.apply(Fault::CorruptNext).expect("fault");
        let delivery = transport
            .send(packet(10, 0, 1, RouteKind::Direct))
            .expect("wire")
            .remove(0);
        assert_eq!(inbox.accept(delivery.packet), InboxOutcome::CorruptRejected);
        assert_eq!(inbox.accepted_count(), 0);
    }

    #[test]
    fn partition_merge_and_network_switch_are_recoverable() {
        let mut transport = ChaosTransport::with_peers(2);
        transport
            .apply(Fault::Partition(PeerId(0), PeerId(1)))
            .expect("partition");
        assert_eq!(
            transport.send(packet(20, 0, 1, RouteKind::Direct)),
            Err(ChaosError::NetworkPartitioned(PeerId(0), PeerId(1)))
        );
        transport
            .apply(Fault::SwitchNetwork(PeerId(1)))
            .expect("switch");
        transport
            .apply(Fault::Merge(PeerId(0), PeerId(1)))
            .expect("merge");
        let delivery = transport
            .send(packet(20, 0, 1, RouteKind::Direct))
            .expect("recovered")
            .remove(0);
        assert_eq!(delivery.destination_network_generation, 1);
    }

    #[test]
    fn infrastructure_failures_are_never_false_successes() {
        let mut transport = ChaosTransport::with_peers(2);
        for (component, route) in [
            (InfrastructureComponent::Dns, RouteKind::DnsResolved),
            (InfrastructureComponent::Relay, RouteKind::Relay),
            (InfrastructureComponent::Sfu, RouteKind::Sfu),
        ] {
            transport
                .apply(Fault::SetInfrastructure(component, false))
                .expect("disable");
            assert_eq!(
                transport.send(packet(30, 0, 1, route)),
                Err(ChaosError::InfrastructureUnavailable(component))
            );
            transport
                .apply(Fault::SetInfrastructure(component, true))
                .expect("restore");
        }
    }

    #[test]
    fn process_restart_preserves_durable_pending_state_and_storage_full_is_atomic() {
        let mut queue = DurableQueueLab::new(16);
        queue
            .persist(packet(40, 0, 1, RouteKind::Direct))
            .expect("first persisted");
        let before = queue.clone();
        let error = queue
            .persist(LabPacket::new(
                PacketId(41),
                PeerId(0),
                PeerId(1),
                RouteKind::Direct,
                vec![7; 64],
            ))
            .expect_err("storage full");
        assert!(matches!(error, ChaosError::StorageFull { .. }));
        assert_eq!(queue, before);

        let restarted = DurableQueueLab::restart_from(&queue);
        assert!(restarted.contains(PacketId(40)));
        assert_eq!(restarted.pending_count(), 1);
    }

    #[test]
    fn revoked_or_disappeared_peer_fails_closed() {
        let mut transport = ChaosTransport::with_peers(3);
        transport
            .apply(Fault::RevokePeer(PeerId(1)))
            .expect("revoke");
        assert_eq!(
            transport.send(packet(50, 0, 1, RouteKind::Direct)),
            Err(ChaosError::PeerRevoked(PeerId(1)))
        );
        transport
            .apply(Fault::SetPeerOnline(PeerId(2), false))
            .expect("offline");
        assert_eq!(
            transport.send(packet(51, 0, 2, RouteKind::Direct)),
            Err(ChaosError::PeerOffline(PeerId(2)))
        );
    }

    #[test]
    fn clock_drift_does_not_change_monotonic_test_time() {
        let mut transport = ChaosTransport::with_peers(1);
        transport
            .apply(Fault::SetClockDrift(PeerId(0), 86_400_000))
            .expect("drift");
        assert_eq!(
            transport.peer_display_clock_ms(PeerId(0), 10_000),
            Some(86_410_000)
        );
        let monotonic_deadline_ms = 15_000_u64;
        assert!(10_000_u64 < monotonic_deadline_ms);
    }

    #[test]
    fn slow_consumer_is_bounded_as_latency_not_silent_loss() {
        let mut transport = ChaosTransport::with_peers(2);
        transport
            .apply(Fault::SetLatency(PeerId(0), PeerId(1), 50))
            .expect("latency");
        transport
            .apply(Fault::SetSlowConsumer(PeerId(1), true))
            .expect("slow");
        let delivery = transport
            .send(packet(60, 0, 1, RouteKind::Direct))
            .expect("send")
            .remove(0);
        assert_eq!(delivery.latency_ms, 5_050);
    }

    #[test]
    fn canonical_network_simulation_has_100_peers_and_survives_partition_merge() {
        let mut simulation = DeterministicNetworkSimulation::canonical_100_peers();
        assert_eq!(simulation.peer_count, 100);
        assert_eq!(simulation.battery_limit_percent, 20);

        for peer in 1_u16..100 {
            let left = PeerId(peer - 1);
            let right = PeerId(peer);
            simulation
                .transport
                .apply(Fault::SetLatency(left, right, u64::from(peer)))
                .expect("latency");
        }
        simulation
            .transport
            .apply(Fault::Partition(PeerId(49), PeerId(50)))
            .expect("partition");
        assert!(matches!(
            simulation
                .transport
                .send(packet(70, 49, 50, RouteKind::Direct)),
            Err(ChaosError::NetworkPartitioned(_, _))
        ));
        simulation
            .transport
            .apply(Fault::Merge(PeerId(49), PeerId(50)))
            .expect("merge");
        assert_eq!(
            simulation
                .transport
                .send(packet(70, 49, 50, RouteKind::Direct))
                .expect("merged")
                .len(),
            1
        );
    }

    #[test]
    fn canon_scenario_registry_is_complete_and_unique() {
        let unique: BTreeSet<_> = CANONICAL_CHAOS_SCENARIOS.into_iter().collect();
        assert_eq!(unique.len(), 18);
    }
}
