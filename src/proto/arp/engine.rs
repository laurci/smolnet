use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::{
    addr::{Ipv4Addr, MacAddr},
    proto::{
        arp::wire::{ArpFrame, ArpOperation, ArpReply, ArpRequest},
        ipv4::Ipv4Frame,
    },
    stack::tx::{TxPacket, TxQueue},
};

pub const ARP_ENTRY_TTL: Duration = Duration::from_secs(60);
pub const ARP_RETRY_INTERVAL: Duration = Duration::from_secs(1);
pub const ARP_MAX_RETRIES: u8 = 3;
pub const ARP_MAX_PENDING_FRAMES_PER_TARGET: usize = 4;
pub const ARP_MAX_PENDING_TARGETS: usize = 16;

const UNSPECIFIED_IP: Ipv4Addr = [0, 0, 0, 0];

#[derive(Debug, Clone)]
struct CacheEntry {
    mac: MacAddr,
    expires_at: Instant,
}

struct PendingEntry {
    frames: VecDeque<Ipv4Frame<'static>>,
    retries_left: u8,
    next_retry_at: Instant,
}

pub struct ArpEngine {
    local_mac: MacAddr,
    local_ip: Ipv4Addr,

    cache: HashMap<Ipv4Addr, CacheEntry>,
    pending: HashMap<Ipv4Addr, PendingEntry>,
}

impl ArpEngine {
    pub fn new(local_mac: MacAddr, local_ip: Ipv4Addr) -> ArpEngine {
        ArpEngine {
            local_mac,
            local_ip,
            cache: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    pub fn local_mac(&self) -> MacAddr {
        self.local_mac
    }

    pub fn set_local_ip(&mut self, local_ip: Ipv4Addr) {
        self.local_ip = local_ip;
    }

    pub fn lookup(&self, target: &Ipv4Addr, now: Instant) -> Option<MacAddr> {
        let entry = self.cache.get(target)?;
        if entry.expires_at <= now {
            return None;
        }

        Some(entry.mac)
    }

    pub fn learn(&mut self, ip: Ipv4Addr, mac: MacAddr, now: Instant, tx: &mut TxQueue) {
        let previous = self.cache.insert(
            ip,
            CacheEntry {
                mac,
                expires_at: now + ARP_ENTRY_TTL,
            },
        );

        match previous {
            Some(previous) if previous.mac != mac => {
                tracing::debug!(?ip, old = ?previous.mac, new = ?mac, "arp mapping changed")
            }
            Some(_) => tracing::trace!(?ip, ?mac, "arp entry refreshed"),
            None => tracing::debug!(?ip, ?mac, "arp entry learned"),
        }

        let Some(entry) = self.pending.remove(&ip) else {
            return;
        };

        tracing::debug!(
            ?ip,
            queued = entry.frames.len(),
            "arp resolved, releasing queued datagrams"
        );

        for frame in entry.frames {
            tx.push(TxPacket::Ipv4(frame));
        }
    }

    pub fn enqueue(
        &mut self,
        hop: Ipv4Addr,
        frame: Ipv4Frame<'static>,
        now: Instant,
        tx: &mut TxQueue,
    ) {
        if let Some(entry) = self.pending.get_mut(&hop) {
            if entry.frames.len() >= ARP_MAX_PENDING_FRAMES_PER_TARGET {
                tracing::warn!(?hop, "arp pending queue is full, dropping oldest datagram");
                entry.frames.pop_front();
            }

            tracing::trace!(?hop, "datagram queued behind an in-flight arp request");
            entry.frames.push_back(frame);
            return;
        }

        if self.pending.len() >= ARP_MAX_PENDING_TARGETS {
            tracing::warn!(
                ?hop,
                targets = self.pending.len(),
                "arp target table is full, dropping datagram"
            );
            return;
        }

        let mut frames = VecDeque::new();
        frames.push_back(frame);

        self.pending.insert(
            hop,
            PendingEntry {
                frames,
                retries_left: ARP_MAX_RETRIES,
                next_retry_at: now + ARP_RETRY_INTERVAL,
            },
        );

        tracing::debug!(?hop, "arp request sent");
        tx.push(self.request(hop));
    }

    pub fn process(&mut self, frame: &ArpFrame, now: Instant, tx: &mut TxQueue) {
        match &frame.operation {
            ArpOperation::Request(request) => {
                if request.sender_proto_addr() != &UNSPECIFIED_IP {
                    self.learn(
                        *request.sender_proto_addr(),
                        *request.sender_hardware_addr(),
                        now,
                        tx,
                    );
                }

                if request.target_proto_addr() != &self.local_ip {
                    tracing::trace!(
                        target = ?request.target_proto_addr(),
                        "arp request for another address"
                    );
                    return;
                }

                tracing::debug!(
                    sender = ?request.sender_proto_addr(),
                    "arp request received for our address, replying"
                );

                let reply = ArpReply::new(request, self.local_mac);
                tx.push(TxPacket::Arp(ArpFrame::new(ArpOperation::Reply(reply))));
            }
            ArpOperation::Reply(reply) => {
                tracing::debug!(
                    sender = ?reply.sender_proto_addr(),
                    mac = ?reply.sender_hardware_addr(),
                    "arp reply received"
                );

                self.learn(
                    *reply.sender_proto_addr(),
                    *reply.sender_hardware_addr(),
                    now,
                    tx,
                );
            }
        }
    }

    pub fn dispatch(&mut self, now: Instant, tx: &mut TxQueue) {
        let mut retry_targets = vec![];
        let mut unreachable_targets = vec![];

        for (target, entry) in self.pending.iter_mut() {
            if now < entry.next_retry_at {
                continue;
            }

            if entry.retries_left == 0 {
                unreachable_targets.push(*target);
                continue;
            }

            entry.retries_left -= 1;
            entry.next_retry_at = now + ARP_RETRY_INTERVAL;
            retry_targets.push(*target);
        }

        for target in unreachable_targets {
            let Some(entry) = self.pending.remove(&target) else {
                continue;
            };

            tracing::warn!(
                ?target,
                dropped = entry.frames.len(),
                "arp gave up resolving, dropping queued datagrams"
            );
        }

        for target in retry_targets {
            let retries_left = self
                .pending
                .get(&target)
                .map(|entry| entry.retries_left)
                .unwrap_or(0);

            tracing::debug!(?target, retries_left, "arp request retransmitted");
            tx.push(self.request(target));
        }

        let before = self.cache.len();
        self.cache.retain(|_, entry| entry.expires_at > now);

        let expired = before - self.cache.len();
        if expired > 0 {
            tracing::debug!(expired, "arp cache entries expired");
        }
    }

    pub fn poll_at(&self) -> Option<Instant> {
        let retries = self.pending.values().map(|entry| entry.next_retry_at);
        let expiries = self.cache.values().map(|entry| entry.expires_at);

        retries.chain(expiries).min()
    }

    fn request(&self, target: Ipv4Addr) -> TxPacket {
        let request = ArpRequest::new(self.local_mac, self.local_ip, target);
        TxPacket::Arp(ArpFrame::new(ArpOperation::Request(request)))
    }

    pub fn pending_targets(&self) -> usize {
        self.pending.len()
    }

    pub fn cached_entries(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::{
        addr::{Ipv4Addr, MacAddr},
        proto::{
            arp::{
                engine::{ARP_ENTRY_TTL, ARP_MAX_PENDING_FRAMES_PER_TARGET, ArpEngine},
                wire::{ArpFrame, ArpOperation, ArpReply, ArpRequest},
            },
            ipv4::{Ipv4Frame, Ipv4Payload},
            udp::wire::UdpFrame,
        },
        stack::tx::{TxPacket, TxQueue},
    };

    const LOCAL_MAC: MacAddr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const LOCAL_IP: Ipv4Addr = [10, 30, 0, 2];

    const PEER_MAC: MacAddr = [0x19, 0x29, 0x39, 0x49, 0x59, 0x69];
    const PEER_IP: Ipv4Addr = [10, 30, 0, 3];

    fn engine() -> ArpEngine {
        ArpEngine::new(LOCAL_MAC, LOCAL_IP)
    }

    fn datagram(dst: Ipv4Addr) -> Ipv4Frame<'static> {
        let udp = UdpFrame::new(1000, 2000, b"data".to_vec());
        Ipv4Frame::new(LOCAL_IP, dst, Ipv4Payload::Udp(udp))
    }

    fn requests_for(tx: &mut TxQueue) -> Vec<Ipv4Addr> {
        let mut targets = vec![];
        while let Some(packet) = tx.pop() {
            if let TxPacket::Arp(ArpFrame {
                operation: ArpOperation::Request(request),
            }) = packet
            {
                targets.push(*request.target_proto_addr());
            }
        }

        targets
    }

    fn reply_from(peer_ip: Ipv4Addr, peer_mac: MacAddr) -> ArpFrame {
        let request = ArpRequest::new(LOCAL_MAC, LOCAL_IP, peer_ip);
        ArpFrame::new(ArpOperation::Reply(ArpReply::new(&request, peer_mac)))
    }

    #[test]
    fn enqueue_emits_one_request_and_releases_on_reply() {
        let now = Instant::now();
        let mut engine = engine();
        let mut tx = TxQueue::default();

        engine.enqueue(PEER_IP, datagram(PEER_IP), now, &mut tx);
        engine.enqueue(PEER_IP, datagram(PEER_IP), now, &mut tx);

        assert_eq!(requests_for(&mut tx), vec![PEER_IP]);
        assert_eq!(engine.pending_targets(), 1);

        engine.process(&reply_from(PEER_IP, PEER_MAC), now, &mut tx);

        assert_eq!(engine.lookup(&PEER_IP, now), Some(PEER_MAC));
        assert_eq!(engine.pending_targets(), 0);

        let released: Vec<_> = std::iter::from_fn(|| tx.pop()).collect();
        assert_eq!(released.len(), 2);
        assert!(released.iter().all(|p| matches!(p, TxPacket::Ipv4(_))));
    }

    #[test]
    fn retries_then_gives_up() {
        let base = Instant::now();
        let mut engine = engine();
        let mut tx = TxQueue::default();

        engine.enqueue(PEER_IP, datagram(PEER_IP), base, &mut tx);
        assert_eq!(requests_for(&mut tx), vec![PEER_IP]);

        engine.dispatch(base + Duration::from_millis(500), &mut tx);
        assert_eq!(requests_for(&mut tx), Vec::<Ipv4Addr>::new());

        for second in 1..=3 {
            engine.dispatch(base + Duration::from_secs(second), &mut tx);
            assert_eq!(requests_for(&mut tx), vec![PEER_IP], "second = {second}");
            assert_eq!(engine.pending_targets(), 1);
        }

        engine.dispatch(base + Duration::from_secs(4), &mut tx);
        assert_eq!(requests_for(&mut tx), Vec::<Ipv4Addr>::new());
        assert_eq!(engine.pending_targets(), 0);
    }

    #[test]
    fn cache_entries_expire() {
        let base = Instant::now();
        let mut engine = engine();
        let mut tx = TxQueue::default();

        engine.learn(PEER_IP, PEER_MAC, base, &mut tx);
        assert_eq!(engine.lookup(&PEER_IP, base), Some(PEER_MAC));

        let almost = base + ARP_ENTRY_TTL - Duration::from_millis(1);
        assert_eq!(engine.lookup(&PEER_IP, almost), Some(PEER_MAC));

        let after = base + ARP_ENTRY_TTL;
        assert_eq!(engine.lookup(&PEER_IP, after), None);

        engine.dispatch(after, &mut tx);
        assert_eq!(engine.cached_entries(), 0);
    }

    #[test]
    fn replies_only_to_requests_for_our_address() {
        let now = Instant::now();
        let mut engine = engine();
        let mut tx = TxQueue::default();

        let elsewhere = ArpFrame::new(ArpOperation::Request(ArpRequest::new(
            PEER_MAC,
            PEER_IP,
            [10, 30, 0, 9],
        )));
        engine.process(&elsewhere, now, &mut tx);

        assert_eq!(engine.lookup(&PEER_IP, now), Some(PEER_MAC));
        assert!(tx.pop().is_none());

        let for_us = ArpFrame::new(ArpOperation::Request(ArpRequest::new(
            PEER_MAC, PEER_IP, LOCAL_IP,
        )));
        engine.process(&for_us, now, &mut tx);

        let Some(TxPacket::Arp(ArpFrame {
            operation: ArpOperation::Reply(reply),
        })) = tx.pop()
        else {
            panic!("expected an arp reply");
        };

        assert_eq!(reply.sender_hardware_addr(), &LOCAL_MAC);
        assert_eq!(reply.sender_proto_addr(), &LOCAL_IP);
        assert_eq!(reply.target_hardware_addr(), &PEER_MAC);
        assert_eq!(reply.target_proto_addr(), &PEER_IP);
    }

    #[test]
    fn pending_queue_is_bounded_per_target() {
        let now = Instant::now();
        let mut engine = engine();
        let mut tx = TxQueue::default();

        for _ in 0..(ARP_MAX_PENDING_FRAMES_PER_TARGET + 3) {
            engine.enqueue(PEER_IP, datagram(PEER_IP), now, &mut tx);
        }
        requests_for(&mut tx);

        engine.process(&reply_from(PEER_IP, PEER_MAC), now, &mut tx);

        let released: Vec<_> = std::iter::from_fn(|| tx.pop()).collect();
        assert_eq!(released.len(), ARP_MAX_PENDING_FRAMES_PER_TARGET);
    }

    #[test]
    fn poll_at_tracks_the_earliest_deadline() {
        let base = Instant::now();
        let mut engine = engine();
        let mut tx = TxQueue::default();

        assert_eq!(engine.poll_at(), None);

        engine.learn(PEER_IP, PEER_MAC, base, &mut tx);
        assert_eq!(engine.poll_at(), Some(base + ARP_ENTRY_TTL));

        engine.enqueue([10, 30, 0, 9], datagram([10, 30, 0, 9]), base, &mut tx);
        assert_eq!(engine.poll_at(), Some(base + super::ARP_RETRY_INTERVAL));
    }
}
