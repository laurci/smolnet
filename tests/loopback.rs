use std::borrow::Cow;
use std::time::{Duration, Instant};

use smolnet::{
    addr::{BROADCAST_MAC, Ipv4Addr, MacAddr},
    device::{Device, Medium, loopback::LoopbackDevice},
    proto::{
        arp::{
            engine::{ARP_ENTRY_TTL, ARP_MAX_RETRIES, ARP_RETRY_INTERVAL},
            wire::{ArpFrame, ArpOperation},
        },
        eth::{ETHER_TYPE_IPV6, EthernetFrame, EthernetPayload},
        icmp::{IcmpFrame, IcmpMessage},
        ipv4::{Ipv4Frame, Ipv4Payload},
        tcp::{
            TcpState,
            wire::{TCP_FLAG_SYN, TCP_MSS_DEFAULT, TcpFrame, TcpOption, TcpRepr},
        },
        udp::wire::UdpFrame,
    },
    stack::{Stack, StackIdentity},
};
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();
}

const ALICE_MAC: MacAddr = [0x02, 0x22, 0x33, 0x44, 0x55, 0x66];
const ALICE_IP: Ipv4Addr = [10, 30, 0, 2];

const BOB_MAC: MacAddr = [0x02, 0x29, 0x39, 0x49, 0x59, 0x69];
const BOB_IP: Ipv4Addr = [10, 30, 0, 3];

const NOBODY_IP: Ipv4Addr = [10, 30, 0, 9];

const NETMASK: Ipv4Addr = [0xff, 0xff, 0xff, 0x00];
const GATEWAY: Ipv4Addr = [10, 30, 0, 1];

const SUBNET_BROADCAST: Ipv4Addr = [10, 30, 0, 255];

fn identity(ip: Ipv4Addr) -> StackIdentity {
    StackIdentity {
        ip,
        gateway: GATEWAY,
        netmask: NETMASK,
    }
}

fn stack(ip: Ipv4Addr, medium: Medium) -> (Stack, LoopbackDevice) {
    init_tracing();

    let device = LoopbackDevice::new(medium);
    let stack = Stack::new(identity(ip), device.capabilities());

    (stack, device)
}

fn serialize(frame: &EthernetFrame<'_>) -> Vec<u8> {
    let mut bytes = vec![0u8; frame.size()];
    let size = frame.write(&mut bytes);

    bytes.truncate(size);
    bytes
}

fn to_alice(src_mac: MacAddr, dst_mac: MacAddr, payload: Ipv4Payload<'_>) -> Vec<u8> {
    let ipv4 = Ipv4Frame::new(BOB_IP, ALICE_IP, payload);
    serialize(&EthernetFrame::new(
        src_mac,
        dst_mac,
        EthernetPayload::Ipv4(ipv4),
    ))
}

type DropPolicy = Box<dyn FnMut(&[u8]) -> bool>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum From {
    Alice,
    Bob,
}

struct Net {
    alice: Stack,
    alice_device: LoopbackDevice,

    bob: Stack,
    bob_device: LoopbackDevice,

    now: Instant,

    seen: Vec<(From, Vec<u8>)>,

    drop_policy: Option<DropPolicy>,
    dropped: usize,
}

impl Net {
    fn new(medium_of: fn(MacAddr) -> Medium) -> Net {
        let (alice, alice_device) = stack(ALICE_IP, medium_of(ALICE_MAC));
        let (bob, bob_device) = stack(BOB_IP, medium_of(BOB_MAC));

        Net {
            alice,
            alice_device,
            bob,
            bob_device,
            now: Instant::now(),
            seen: vec![],
            drop_policy: None,
            dropped: 0,
        }
    }

    fn drop_frames(&mut self, policy: impl FnMut(&[u8]) -> bool + 'static) {
        self.drop_policy = Some(Box::new(policy));
    }

    fn ethernet() -> Net {
        Net::new(|mac| Medium::Ethernet { mac })
    }

    fn ip() -> Net {
        Net::new(|_| Medium::Ip)
    }

    fn advance(&mut self, duration: Duration) {
        self.now += duration;
    }

    fn pump(&mut self) -> bool {
        let from_alice = self.alice_device.drain_tx();
        let from_bob = self.bob_device.drain_tx();

        let moved = !from_alice.is_empty() || !from_bob.is_empty();

        for frame in from_alice {
            if self.should_drop(&frame) {
                continue;
            }

            self.bob_device.push_rx(&frame);
            self.seen.push((From::Alice, frame));
        }

        for frame in from_bob {
            if self.should_drop(&frame) {
                continue;
            }

            self.alice_device.push_rx(&frame);
            self.seen.push((From::Bob, frame));
        }

        moved
    }

    fn should_drop(&mut self, frame: &[u8]) -> bool {
        let Some(policy) = self.drop_policy.as_mut() else {
            return false;
        };

        if policy(frame) {
            self.dropped += 1;
            return true;
        }

        false
    }

    fn run(&mut self, total: Duration, step: Duration) {
        let mut elapsed = Duration::ZERO;

        while elapsed <= total {
            self.alice.poll(&mut self.alice_device, self.now).unwrap();
            self.bob.poll(&mut self.bob_device, self.now).unwrap();
            self.pump();

            self.now += step;
            elapsed += step;
        }
    }

    fn settle(&mut self) {
        for _ in 0..16 {
            self.alice
                .poll(&mut self.alice_device, self.now)
                .expect("alice polls cleanly");
            self.bob
                .poll(&mut self.bob_device, self.now)
                .expect("bob polls cleanly");

            if !self.pump() {
                return;
            }
        }

        panic!("network did not settle");
    }

    fn frames(&self) -> Vec<EthernetFrame<'_>> {
        self.seen
            .iter()
            .filter_map(|(_, bytes)| EthernetFrame::parse(bytes).ok())
            .collect()
    }

    fn arp_requests(&self) -> Vec<Ipv4Addr> {
        self.frames()
            .iter()
            .filter_map(|frame| match frame.payload() {
                EthernetPayload::Arp(ArpFrame {
                    operation: ArpOperation::Request(request),
                }) => Some(*request.target_proto_addr()),
                _ => None,
            })
            .collect()
    }

    fn arp_frame_count(&self) -> usize {
        self.frames()
            .iter()
            .filter(|frame| matches!(frame.payload(), EthernetPayload::Arp(_)))
            .count()
    }

    fn clear_seen(&mut self) {
        self.seen.clear();
    }
}

#[test]
fn arp_resolution_releases_the_queued_datagram() {
    let mut net = Net::ethernet();

    let bob_sock = net.bob.udp_bind(Some(7878)).unwrap();
    let alice_sock = net.alice.udp_bind(Some(4000)).unwrap();

    net.alice
        .udp_send(&alice_sock, BOB_IP, 7878, b"hello bob".to_vec());

    net.settle();

    assert_eq!(net.arp_requests(), vec![BOB_IP]);
    assert_eq!(
        net.bob.udp_recv(&bob_sock),
        Some((ALICE_IP, 4000, b"hello bob".to_vec()))
    );

    net.clear_seen();
    net.bob
        .udp_send(&bob_sock, ALICE_IP, 4000, b"hello alice".to_vec());
    net.settle();

    assert_eq!(net.arp_frame_count(), 0);
    assert_eq!(
        net.alice.udp_recv(&alice_sock),
        Some((BOB_IP, 7878, b"hello alice".to_vec()))
    );
}

#[test]
fn arp_retries_then_gives_up_on_a_silent_peer() {
    let base = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let sock = alice.udp_bind(Some(4000)).unwrap();
    alice.udp_send(&sock, NOBODY_IP, 9999, b"anyone there".to_vec());

    let mut requests = 0;

    alice.poll(&mut device, base).unwrap();
    requests += device.drain_tx().len();
    assert_eq!(requests, 1);

    alice
        .poll(&mut device, base + ARP_RETRY_INTERVAL / 2)
        .unwrap();
    assert_eq!(device.drain_tx().len(), 0);

    for attempt in 1..=u32::from(ARP_MAX_RETRIES) {
        alice
            .poll(&mut device, base + ARP_RETRY_INTERVAL * attempt)
            .unwrap();

        let sent = device.drain_tx().len();
        assert_eq!(sent, 1, "attempt = {attempt}");
        requests += sent;
    }

    assert_eq!(requests, usize::from(ARP_MAX_RETRIES) + 1);

    for attempt in 4..8 {
        alice
            .poll(&mut device, base + ARP_RETRY_INTERVAL * attempt)
            .unwrap();
        assert_eq!(device.drain_tx().len(), 0, "attempt = {attempt}");
    }
}

#[test]
fn arp_entries_expire_and_are_resolved_again() {
    let mut net = Net::ethernet();

    let bob_sock = net.bob.udp_bind(Some(7878)).unwrap();
    let alice_sock = net.alice.udp_bind(Some(4000)).unwrap();

    net.alice
        .udp_send(&alice_sock, BOB_IP, 7878, b"one".to_vec());
    net.settle();
    assert_eq!(net.arp_requests(), vec![BOB_IP]);

    net.clear_seen();
    net.alice
        .udp_send(&alice_sock, BOB_IP, 7878, b"two".to_vec());
    net.settle();
    assert_eq!(net.arp_frame_count(), 0);

    net.clear_seen();
    net.advance(ARP_ENTRY_TTL + Duration::from_secs(1));
    net.alice
        .udp_send(&alice_sock, BOB_IP, 7878, b"three".to_vec());
    net.settle();
    assert_eq!(net.arp_requests(), vec![BOB_IP]);

    assert_eq!(net.bob.udp_recv(&bob_sock).unwrap().2, b"one");
    assert_eq!(net.bob.udp_recv(&bob_sock).unwrap().2, b"two");
    assert_eq!(net.bob.udp_recv(&bob_sock).unwrap().2, b"three");
}

#[test]
fn icmp_echo_reply_mirrors_identifier_and_sequence() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let request = IcmpFrame::echo_request(0xbeef, 42, b"ping payload");
    let bytes = to_alice(BOB_MAC, ALICE_MAC, Ipv4Payload::Icmp(request));

    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();

    let sent = device.drain_tx();
    assert_eq!(sent.len(), 1);

    let reply = EthernetFrame::parse(&sent[0]).expect("reply is a valid frame");
    assert_eq!(reply.src(), &ALICE_MAC);
    assert_eq!(reply.dst(), &BOB_MAC);

    let EthernetPayload::Ipv4(ipv4) = reply.payload() else {
        panic!("expected an ipv4 reply");
    };
    assert_eq!(ipv4.src(), &ALICE_IP);
    assert_eq!(ipv4.dst(), &BOB_IP);

    let Ipv4Payload::Icmp(icmp) = ipv4.payload() else {
        panic!("expected an icmp reply");
    };
    let IcmpMessage::EchoReply { id, seq, data } = icmp.message() else {
        panic!("expected an echo reply");
    };

    assert_eq!(*id, 0xbeef);
    assert_eq!(*seq, 42);
    assert_eq!(data.as_ref(), b"ping payload");
}

#[test]
fn icmp_errors_are_parsed_rather_than_failing_the_frame() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let unreachable = IcmpFrame::new(IcmpMessage::DestUnreachable {
        code: smolnet::proto::icmp::DestUnreachableCode::Port,
        next_hop_mtu: 0,
        original: Cow::Borrowed(b"the datagram we sent"),
    });

    let bytes = to_alice(BOB_MAC, ALICE_MAC, Ipv4Payload::Icmp(unreachable));

    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();

    assert_eq!(device.drain_tx().len(), 0);

    let parsed = EthernetFrame::parse(&bytes).expect("an icmp error is a valid frame");
    let EthernetPayload::Ipv4(ipv4) = parsed.payload() else {
        panic!("expected an ipv4 datagram");
    };
    let Ipv4Payload::Icmp(icmp) = ipv4.payload() else {
        panic!("expected an icmp message");
    };

    assert!(matches!(
        icmp.message(),
        IcmpMessage::DestUnreachable { .. }
    ));
}

#[test]
fn frames_addressed_to_other_hosts_are_ignored() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let stranger: MacAddr = [0x02, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    let request = IcmpFrame::echo_request(1, 1, b"not for you");
    let bytes = to_alice(BOB_MAC, stranger, Ipv4Payload::Icmp(request));
    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();
    assert_eq!(device.drain_tx().len(), 0);

    let request = IcmpFrame::echo_request(1, 1, b"for you");
    let bytes = to_alice(BOB_MAC, ALICE_MAC, Ipv4Payload::Icmp(request));
    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();
    assert_eq!(device.drain_tx().len(), 1);
}

#[test]
fn datagrams_for_other_addresses_are_ignored() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let request = IcmpFrame::echo_request(1, 1, b"wrong ip");
    let ipv4 = Ipv4Frame::new(BOB_IP, NOBODY_IP, Ipv4Payload::Icmp(request));
    let bytes = serialize(&EthernetFrame::new(
        BOB_MAC,
        ALICE_MAC,
        EthernetPayload::Ipv4(ipv4),
    ));

    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();

    assert_eq!(device.drain_tx().len(), 0);
}

#[test]
fn broadcast_datagrams_are_accepted() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let sock = alice.udp_bind(Some(6767)).unwrap();

    for dst in [SUBNET_BROADCAST, [255, 255, 255, 255]] {
        let udp = UdpFrame::new(5000, 6767, &b"to everyone"[..]);
        let ipv4 = Ipv4Frame::new(BOB_IP, dst, Ipv4Payload::Udp(udp));
        let bytes = serialize(&EthernetFrame::new(
            BOB_MAC,
            BROADCAST_MAC,
            EthernetPayload::Ipv4(ipv4),
        ));

        device.push_rx(&bytes);
        alice.poll(&mut device, now).unwrap();

        assert_eq!(
            alice.udp_recv(&sock),
            Some((BOB_IP, 5000, b"to everyone".to_vec())),
            "dst = {dst:?}"
        );
    }
}

#[test]
fn broadcast_transmission_skips_resolution() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let sock = alice.udp_bind(Some(4000)).unwrap();
    alice.udp_send(&sock, SUBNET_BROADCAST, 6767, b"anyone home".to_vec());

    alice.poll(&mut device, now).unwrap();

    let sent = device.drain_tx();
    assert_eq!(sent.len(), 1, "went out directly, with no arp request");

    let frame = EthernetFrame::parse(&sent[0]).unwrap();
    assert_eq!(frame.dst(), &BROADCAST_MAC);

    let EthernetPayload::Ipv4(ipv4) = frame.payload() else {
        panic!("expected an ipv4 datagram");
    };
    assert_eq!(ipv4.dst(), &SUBNET_BROADCAST);
}

#[test]
fn unknown_ethertypes_and_protocols_are_ignored_quietly() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let ipv6ish = EthernetFrame::new(
        BOB_MAC,
        ALICE_MAC,
        EthernetPayload::Unknown {
            ethertype: ETHER_TYPE_IPV6,
            data: Cow::Borrowed(&[0x60; 40]),
        },
    );
    device.push_rx(&serialize(&ipv6ish));

    let ospf = Ipv4Frame::new(
        BOB_IP,
        ALICE_IP,
        Ipv4Payload::Unknown {
            protocol: 89,
            data: Cow::Borrowed(b"ospf body"),
        },
    );
    device.push_rx(&serialize(&EthernetFrame::new(
        BOB_MAC,
        ALICE_MAC,
        EthernetPayload::Ipv4(ospf),
    )));

    alice
        .poll(&mut device, now)
        .expect("neither one is an error");
    assert_eq!(device.drain_tx().len(), 0);

    let request = IcmpFrame::echo_request(1, 1, b"still here");
    let bytes = to_alice(BOB_MAC, ALICE_MAC, Ipv4Payload::Icmp(request));
    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();

    assert_eq!(device.drain_tx().len(), 1);
}

#[test]
fn malformed_input_is_rejected_without_panicking() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let request = IcmpFrame::echo_request(1, 1, b"ping");
    let valid = to_alice(BOB_MAC, ALICE_MAC, Ipv4Payload::Icmp(request));

    for len in 0..valid.len() {
        device.push_rx(&valid[..len]);
    }

    device.push_rx(&[]);
    device.push_rx(&[0xff; 60]);

    let mut bogus_length = valid.clone();
    bogus_length[16] = 0x00;
    bogus_length[17] = 0x04;
    device.push_rx(&bogus_length);

    let mut bogus_ihl = valid.clone();
    bogus_ihl[14] = 0x40;
    device.push_rx(&bogus_ihl);

    alice
        .poll(&mut device, now)
        .expect("bad input is dropped, not fatal");
    assert_eq!(device.drain_tx().len(), 0);

    let request = IcmpFrame::echo_request(1, 1, b"still here");
    let bytes = to_alice(BOB_MAC, ALICE_MAC, Ipv4Payload::Icmp(request));
    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();

    assert_eq!(device.drain_tx().len(), 1);
}

#[test]
fn tcp_syn_to_a_listening_port_gets_a_checksum_valid_syn_ack() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    alice.tcp_listen(7878).unwrap();

    let syn = TcpFrame::new(TcpRepr {
        src_port: 40000,
        dst_port: 7878,
        seq: 1000,
        flags: TCP_FLAG_SYN,
        window: 64240,
        options: &[
            TcpOption::Mss(TCP_MSS_DEFAULT),
            TcpOption::WindowScale(7),
            TcpOption::SackPermitted,
        ],
        ..Default::default()
    })
    .unwrap();

    let bytes = to_alice(BOB_MAC, ALICE_MAC, Ipv4Payload::Tcp(syn));

    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();

    let sent = device.drain_tx();
    assert_eq!(sent.len(), 1);

    let reply = EthernetFrame::parse(&sent[0]).expect("reply is a valid frame");
    let EthernetPayload::Ipv4(ipv4) = reply.payload() else {
        panic!("expected an ipv4 reply");
    };
    let Ipv4Payload::Tcp(tcp) = ipv4.payload() else {
        panic!("expected a tcp reply");
    };

    assert!(tcp.syn() && tcp.ack_flag());
    assert_eq!(tcp.src_port(), 7878);
    assert_eq!(tcp.dst_port(), 40000);
    assert_eq!(tcp.ack(), 1001);
    assert_eq!(tcp.mss(), Some(TCP_MSS_DEFAULT));
}

#[test]
fn tcp_syn_to_a_dead_port_is_reset() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let syn = TcpFrame::new(TcpRepr {
        src_port: 40000,
        dst_port: 9999,
        seq: 1000,
        flags: TCP_FLAG_SYN,
        window: 64240,
        ..Default::default()
    })
    .unwrap();

    let bytes = to_alice(BOB_MAC, ALICE_MAC, Ipv4Payload::Tcp(syn));

    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();

    let sent = device.drain_tx();
    assert_eq!(sent.len(), 1);

    let reply = EthernetFrame::parse(&sent[0]).unwrap();
    let EthernetPayload::Ipv4(ipv4) = reply.payload() else {
        panic!("expected an ipv4 reply");
    };
    let Ipv4Payload::Tcp(tcp) = ipv4.payload() else {
        panic!("expected a tcp reply");
    };

    assert!(tcp.rst());
    assert_eq!(tcp.ack(), 1001);
}

#[test]
fn tcp_connection_lifecycle_across_two_stacks() {
    let mut net = Net::ethernet();

    let listener = net.alice.tcp_listen(7878).unwrap();
    assert!(net.alice.tcp_accept(&listener).is_none());

    let client = net.bob.tcp_connect(ALICE_IP, 7878, Some(40000)).unwrap();
    assert_eq!(net.bob.tcp_state(&client), Some(TcpState::SynSent));

    net.settle();

    assert_eq!(net.bob.tcp_state(&client), Some(TcpState::Established));

    let server = net
        .alice
        .tcp_accept(&listener)
        .expect("the handshake produced a connection to accept");
    assert_eq!(net.alice.tcp_state(&server), Some(TcpState::Established));

    assert_eq!(net.bob.tcp_send(&client, b"hello from bob"), 14);
    net.settle();

    let mut buf = [0u8; 64];
    let n = net.alice.tcp_recv(&server, &mut buf);
    assert_eq!(&buf[..n], b"hello from bob");

    assert_eq!(net.alice.tcp_send(&server, b"and hello back"), 14);
    net.settle();

    let n = net.bob.tcp_recv(&client, &mut buf);
    assert_eq!(&buf[..n], b"and hello back");

    net.bob.tcp_close(&client);
    net.settle();

    assert_eq!(net.bob.tcp_state(&client), Some(TcpState::FinWait2));
    assert_eq!(net.alice.tcp_state(&server), Some(TcpState::CloseWait));
    assert!(net.alice.tcp_peer_finished(&server));

    net.alice.tcp_close(&server);
    net.settle();

    assert_eq!(
        net.alice.tcp_state(&server),
        None,
        "the server saw its fin acknowledged and is gone"
    );
    assert_eq!(net.bob.tcp_state(&client), Some(TcpState::TimeWait));

    net.advance(Duration::from_secs(61));
    net.settle();

    assert_eq!(net.bob.tcp_state(&client), None, "time-wait expired");
}

#[test]
fn tcp_carries_a_payload_larger_than_one_segment() {
    let mut net = Net::ethernet();

    let listener = net.alice.tcp_listen(7878).unwrap();
    let client = net.bob.tcp_connect(ALICE_IP, 7878, Some(40000)).unwrap();
    net.settle();

    let server = net.alice.tcp_accept(&listener).unwrap();

    let payload: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(net.bob.tcp_send(&client, &payload), payload.len());

    net.settle();

    let mut received = vec![];
    let mut buf = [0u8; 1500];
    loop {
        let n = net.alice.tcp_recv(&server, &mut buf);
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }

    assert_eq!(received, payload, "the stream reassembled in order");
}

#[test]
fn tcp_connect_to_a_dead_port_is_reset() {
    let mut net = Net::ethernet();

    let client = net.bob.tcp_connect(ALICE_IP, 9999, Some(40000)).unwrap();
    net.settle();

    assert_eq!(
        net.bob.tcp_state(&client),
        None,
        "the reset tore the connection down"
    );
}

#[test]
fn tcp_server_closing_first_walks_the_other_path() {
    let mut net = Net::ethernet();

    let listener = net.alice.tcp_listen(7878).unwrap();
    let client = net.bob.tcp_connect(ALICE_IP, 7878, Some(40000)).unwrap();
    net.settle();

    let server = net.alice.tcp_accept(&listener).unwrap();

    net.alice.tcp_close(&server);
    net.settle();

    assert_eq!(net.alice.tcp_state(&server), Some(TcpState::FinWait2));
    assert_eq!(net.bob.tcp_state(&client), Some(TcpState::CloseWait));

    net.bob.tcp_close(&client);
    net.settle();

    assert_eq!(net.bob.tcp_state(&client), None);
    assert_eq!(net.alice.tcp_state(&server), Some(TcpState::TimeWait));
}

#[test]
fn ipv4_identification_advances_per_datagram() {
    let mut net = Net::ethernet();

    let _bob_sock = net.bob.udp_bind(Some(7878)).unwrap();
    let alice_sock = net.alice.udp_bind(Some(4000)).unwrap();

    for n in 0..3 {
        net.alice.udp_send(&alice_sock, BOB_IP, 7878, vec![n as u8]);
        net.settle();
    }

    let ids: Vec<u16> = net
        .frames()
        .iter()
        .filter_map(|frame| match frame.payload() {
            EthernetPayload::Ipv4(ipv4) => Some(ipv4.identification()),
            _ => None,
        })
        .collect();

    assert!(ids.len() >= 3);
    for pair in ids.windows(2) {
        assert_eq!(
            pair[1],
            pair[0].wrapping_add(1),
            "identification should advance: {ids:?}"
        );
    }
}

#[test]
fn l3_medium_carries_datagrams_with_no_link_layer() {
    let mut net = Net::ip();

    let bob_sock = net.bob.udp_bind(Some(7878)).unwrap();
    let alice_sock = net.alice.udp_bind(Some(4000)).unwrap();

    net.alice
        .udp_send(&alice_sock, BOB_IP, 7878, b"no ethernet here".to_vec());

    net.settle();

    assert!(!net.seen.is_empty());
    for (_, bytes) in &net.seen {
        Ipv4Frame::parse(bytes).expect("frames on an L3 link are bare ipv4");
    }

    assert_eq!(
        net.bob.udp_recv(&bob_sock),
        Some((ALICE_IP, 4000, b"no ethernet here".to_vec()))
    );

    net.bob
        .udp_send(&bob_sock, ALICE_IP, 4000, b"likewise".to_vec());
    net.settle();

    assert_eq!(
        net.alice.udp_recv(&alice_sock),
        Some((BOB_IP, 7878, b"likewise".to_vec()))
    );
}

#[test]
fn l3_medium_reports_no_hardware_address() {
    let (alice, _device) = stack(ALICE_IP, Medium::Ip);

    assert_eq!(alice.capabilities().medium, Medium::Ip);
    assert_eq!(alice.capabilities().medium.mac(), None);
    assert_eq!(alice.capabilities().medium.link_header_len(), 0);
}

#[test]
fn a_blocked_device_retries_on_the_next_poll() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ip);

    let sock = alice.udp_bind(Some(4000)).unwrap();
    alice.udp_send(&sock, BOB_IP, 7878, b"queued".to_vec());

    device.set_writable(false);
    alice.poll(&mut device, now).unwrap();
    assert_eq!(device.tx_len(), 0);

    device.set_writable(true);
    alice.poll(&mut device, now).unwrap();

    let sent = device.drain_tx();
    assert_eq!(sent.len(), 1);

    let frame = Ipv4Frame::parse(&sent[0]).expect("valid ipv4 datagram");
    let Ipv4Payload::Udp(udp) = frame.payload() else {
        panic!("expected a udp datagram");
    };
    assert_eq!(udp.payload(), b"queued");
}

#[test]
fn udp_datagrams_for_unbound_ports_are_dropped() {
    let mut net = Net::ethernet();

    let alice_sock = net.alice.udp_bind(Some(4000)).unwrap();

    net.alice
        .udp_send(&alice_sock, BOB_IP, 7878, b"into the void".to_vec());

    net.settle();

    let delivered = net.frames().iter().any(|frame| {
        matches!(frame.payload(), EthernetPayload::Ipv4(ipv4)
            if matches!(ipv4.payload(), Ipv4Payload::Udp(_)))
    });
    assert!(delivered);

    let bob_sock = net.bob.udp_bind(Some(7878)).unwrap();
    assert_eq!(net.bob.udp_recv(&bob_sock), None);
}

#[test]
fn udp_checksums_survive_the_round_trip() {
    let mut net = Net::ethernet();

    let bob_sock = net.bob.udp_bind(Some(7878)).unwrap();
    let alice_sock = net.alice.udp_bind(Some(4000)).unwrap();

    for payload in [&b"a"[..], &b"ab"[..], &b"odd length payload!"[..], &[]] {
        net.alice
            .udp_send(&alice_sock, BOB_IP, 7878, payload.to_vec());
        net.settle();

        assert_eq!(
            net.bob.udp_recv(&bob_sock),
            Some((ALICE_IP, 4000, payload.to_vec())),
            "payload = {payload:?}"
        );
    }
}

#[test]
fn ipv4_options_survive_the_link() {
    let now = Instant::now();
    let (mut alice, mut device) = stack(ALICE_IP, Medium::Ethernet { mac: ALICE_MAC });

    let sock = alice.udp_bind(Some(7878)).unwrap();

    let options =
        smolnet::proto::options::Ipv4Options::from_slice(&[0x83, 0x07, 0x04, 1, 2, 3, 4, 0x00])
            .unwrap();

    let udp = UdpFrame::new(5000, 7878, &b"with options"[..]);
    let ipv4 = Ipv4Frame::new(BOB_IP, ALICE_IP, Ipv4Payload::Udp(udp)).with_options(options);
    let bytes = serialize(&EthernetFrame::new(
        BOB_MAC,
        ALICE_MAC,
        EthernetPayload::Ipv4(ipv4),
    ));

    device.push_rx(&bytes);
    alice.poll(&mut device, now).unwrap();

    assert_eq!(
        alice.udp_recv(&sock),
        Some((BOB_IP, 5000, b"with options".to_vec()))
    );
}

fn tcp_payload_len(frame: &[u8]) -> usize {
    let Ok(eth) = EthernetFrame::parse(frame) else {
        return 0;
    };
    let EthernetPayload::Ipv4(ipv4) = eth.payload() else {
        return 0;
    };
    let Ipv4Payload::Tcp(tcp) = ipv4.payload() else {
        return 0;
    };

    tcp.payload().len()
}

#[test]
fn tcp_recovers_from_a_dropped_segment() {
    let mut net = Net::ethernet();

    let listener = net.alice.tcp_listen(7878).unwrap();
    let client = net.bob.tcp_connect(ALICE_IP, 7878, Some(40000)).unwrap();
    net.settle();

    let server = net.alice.tcp_accept(&listener).unwrap();

    let mut swallowed = false;
    net.drop_frames(move |frame| {
        if !swallowed && tcp_payload_len(frame) > 0 {
            swallowed = true;
            return true;
        }

        false
    });

    let payload: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(net.bob.tcp_send(&client, &payload), payload.len());

    net.run(Duration::from_secs(5), Duration::from_millis(100));

    assert_eq!(net.dropped, 1, "exactly one segment was lost");

    let mut received = vec![];
    let mut buf = [0u8; 1500];
    loop {
        let n = net.alice.tcp_recv(&server, &mut buf);
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }

    assert_eq!(
        received, payload,
        "the retransmission filled the hole and the stream arrived intact"
    );
}

#[test]
fn tcp_recovers_from_a_dropped_handshake() {
    let mut net = Net::ethernet();

    let listener = net.alice.tcp_listen(7878).unwrap();

    let mut swallowed = false;
    net.drop_frames(move |frame| {
        let Ok(eth) = EthernetFrame::parse(frame) else {
            return false;
        };
        let EthernetPayload::Ipv4(ipv4) = eth.payload() else {
            return false;
        };
        let Ipv4Payload::Tcp(tcp) = ipv4.payload() else {
            return false;
        };

        if !swallowed && tcp.syn() && !tcp.ack_flag() {
            swallowed = true;
            return true;
        }

        false
    });

    let client = net.bob.tcp_connect(ALICE_IP, 7878, Some(40000)).unwrap();

    net.run(Duration::from_secs(3), Duration::from_millis(100));

    assert_eq!(net.dropped, 1, "the first syn was lost");
    assert_eq!(net.bob.tcp_state(&client), Some(TcpState::Established));
    assert!(net.alice.tcp_accept(&listener).is_some());
}

#[test]
fn tcp_gives_up_when_the_peer_disappears() {
    let mut net = Net::ethernet();

    let listener = net.alice.tcp_listen(7878).unwrap();
    let client = net.bob.tcp_connect(ALICE_IP, 7878, Some(40000)).unwrap();
    net.settle();

    let _server = net.alice.tcp_accept(&listener).unwrap();

    net.drop_frames(|frame| tcp_payload_len(frame) > 0);

    net.bob.tcp_send(&client, b"nobody will ever see this");
    net.run(Duration::from_secs(180), Duration::from_secs(1));

    assert!(net.dropped > 0);
    assert_eq!(
        net.bob.tcp_state(&client),
        None,
        "the sender gave up and tore the connection down"
    );
}
