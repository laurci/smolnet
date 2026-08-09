use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use thiserror::Error;

use crate::{
    addr::Ipv4Addr,
    proto::{
        ipv4::Ipv4Frame,
        tcp::{
            connection::{ConnectionKey, SegmentOutcome, TcpConnection, TcpSocketHandle, TcpState},
            wire::TcpFrame,
        },
    },
    stack::tx::TxQueue,
};

use crate::proto::tcp::connection::reset_segment;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpListenerHandle(usize);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TcpListenError {
    #[error("tcp port {0} is already being listened on")]
    AlreadyListening(u16),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TcpConnectError {
    #[error("a tcp connection from port {local_port} to {remote_port} already exists")]
    AlreadyConnected { local_port: u16, remote_port: u16 },
}

struct TcpListener {
    backlog: VecDeque<TcpSocketHandle>,
}

#[derive(Default)]
pub struct TcpEngine {
    next_handle: usize,

    connections: HashMap<ConnectionKey, TcpConnection>,
    handles: HashMap<TcpSocketHandle, ConnectionKey>,

    listeners: HashMap<u16, TcpListener>,
    listener_ports: HashMap<TcpListenerHandle, u16>,
}

impl TcpEngine {
    fn next_handle(&mut self) -> usize {
        let handle = self.next_handle;
        self.next_handle += 1;

        handle
    }

    pub fn listen(&mut self, port: u16) -> Result<TcpListenerHandle, TcpListenError> {
        if self.listeners.contains_key(&port) {
            return Err(TcpListenError::AlreadyListening(port));
        }

        let handle = TcpListenerHandle(self.next_handle());

        self.listeners.insert(
            port,
            TcpListener {
                backlog: VecDeque::new(),
            },
        );
        self.listener_ports.insert(handle, port);

        tracing::info!(port, "tcp listening");

        Ok(handle)
    }

    pub fn accept(&mut self, listener: &TcpListenerHandle) -> Option<TcpSocketHandle> {
        let port = *self.listener_ports.get(listener)?;
        let handle = self.listeners.get_mut(&port)?.backlog.pop_front()?;

        tracing::debug!(port, "tcp connection accepted");

        Some(handle)
    }

    pub fn can_accept(&self, listener: &TcpListenerHandle) -> bool {
        self.listener_ports
            .get(listener)
            .and_then(|port| self.listeners.get(port))
            .is_some_and(|listener| !listener.backlog.is_empty())
    }

    pub fn close_listener(&mut self, listener: TcpListenerHandle) {
        let Some(port) = self.listener_ports.remove(&listener) else {
            return;
        };

        self.listeners.remove(&port);

        tracing::info!(port, "tcp listener closed");
    }

    pub fn connect(
        &mut self,
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        now: Instant,
        tx: &mut TxQueue,
    ) -> Result<TcpSocketHandle, TcpConnectError> {
        let key = ConnectionKey {
            local_port,
            remote_ip,
            remote_port,
        };

        if self.connections.contains_key(&key) {
            return Err(TcpConnectError::AlreadyConnected {
                local_port,
                remote_port,
            });
        }

        tracing::info!(
            local_port,
            remote = ?remote_ip,
            remote_port,
            "tcp connecting"
        );

        let handle = TcpSocketHandle(self.next_handle());
        let connection = TcpConnection::connect(local_ip, handle, key, now, tx);

        self.connections.insert(key, connection);
        self.handles.insert(handle, key);

        Ok(handle)
    }

    pub fn process(
        &mut self,
        ipv4_frame: &Ipv4Frame<'_>,
        tcp_frame: &TcpFrame<'_>,
        local_ip: Ipv4Addr,
        now: Instant,
        tx: &mut TxQueue,
    ) {
        let key = ConnectionKey {
            local_port: tcp_frame.dst_port(),
            remote_ip: *ipv4_frame.src(),
            remote_port: tcp_frame.src_port(),
        };

        if let Some(connection) = self.connections.get_mut(&key) {
            let handle = connection.handle();

            match connection.on_segment(tcp_frame, now, tx) {
                SegmentOutcome::Established => {
                    if let Some(listener) = self.listeners.get_mut(&key.local_port) {
                        listener.backlog.push_back(handle);
                    }
                }
                SegmentOutcome::Dead => self.remove(&key),
                SegmentOutcome::None => {}
            }

            return;
        }

        if tcp_frame.syn() && !tcp_frame.ack_flag() && self.listeners.contains_key(&key.local_port)
        {
            tracing::debug!(
                local_port = key.local_port,
                remote = ?key.remote_ip,
                remote_port = key.remote_port,
                "tcp inbound connection, replying with syn-ack"
            );

            let handle = TcpSocketHandle(self.next_handle());
            let connection = TcpConnection::accept(local_ip, handle, key, tcp_frame, now, tx);

            self.connections.insert(key, connection);
            self.handles.insert(handle, key);

            return;
        }

        if !tcp_frame.rst() {
            reset_segment(local_ip, &key, tcp_frame, tx);
        }
    }

    pub fn dispatch(&mut self, now: Instant, tx: &mut TxQueue) {
        let mut finished = vec![];

        for (key, connection) in self.connections.iter_mut() {
            let alive = connection.dispatch(now, tx);

            if !alive || connection.expired(now) {
                finished.push(*key);
            }
        }

        for key in finished {
            tracing::debug!(local_port = key.local_port, "tcp connection closed");
            self.remove(&key);
        }
    }

    pub fn poll_at(&self) -> Option<Instant> {
        self.connections
            .values()
            .filter_map(TcpConnection::poll_at)
            .min()
    }

    pub fn has_work(&self) -> bool {
        self.connections.values().any(TcpConnection::has_work)
            || self
                .listeners
                .values()
                .any(|listener| !listener.backlog.is_empty())
    }

    fn remove(&mut self, key: &ConnectionKey) {
        if let Some(connection) = self.connections.remove(key) {
            self.handles.remove(&connection.handle());
        }
    }

    fn connection(&self, handle: &TcpSocketHandle) -> Option<&TcpConnection> {
        let key = self.handles.get(handle)?;
        self.connections.get(key)
    }

    fn connection_mut(&mut self, handle: &TcpSocketHandle) -> Option<&mut TcpConnection> {
        let key = self.handles.get(handle)?;
        self.connections.get_mut(key)
    }

    pub fn state(&self, handle: &TcpSocketHandle) -> Option<TcpState> {
        self.connection(handle).map(TcpConnection::state)
    }

    pub fn peer_addr(&self, handle: &TcpSocketHandle) -> Option<(Ipv4Addr, u16)> {
        self.connection(handle).map(TcpConnection::peer)
    }

    pub fn local_port(&self, handle: &TcpSocketHandle) -> Option<u16> {
        self.connection(handle).map(TcpConnection::local_port)
    }

    pub fn peer_finished(&self, handle: &TcpSocketHandle) -> bool {
        self.connection(handle)
            .is_some_and(TcpConnection::peer_finished)
    }

    pub fn can_recv(&self, handle: &TcpSocketHandle) -> bool {
        self.connection(handle).is_some_and(TcpConnection::can_recv)
    }

    pub fn recv(&mut self, handle: &TcpSocketHandle, buf: &mut [u8]) -> usize {
        self.connection_mut(handle)
            .map(|connection| connection.recv(buf))
            .unwrap_or(0)
    }

    pub fn send_capacity(&self, handle: &TcpSocketHandle) -> usize {
        self.connection(handle)
            .map(TcpConnection::send_capacity)
            .unwrap_or(0)
    }

    pub fn send(&mut self, handle: &TcpSocketHandle, data: &[u8]) -> usize {
        self.connection_mut(handle)
            .map(|connection| connection.send(data))
            .unwrap_or(0)
    }

    pub fn close(&mut self, handle: &TcpSocketHandle) {
        if let Some(connection) = self.connection_mut(handle) {
            connection.close();
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::{
        addr::Ipv4Addr,
        proto::{
            ipv4::{Ipv4Frame, Ipv4Payload},
            tcp::{
                TCP_INITIAL_WINDOW_SEGMENTS, TCP_MAX_OUT_OF_ORDER_SEGMENTS, TCP_MAX_RETRANSMITS,
                TCP_RTO_INITIAL, TCP_SEND_BUFFER, TcpSocketHandle, TcpState,
                engine::TcpEngine,
                wire::{TCP_FLAG_ACK, TCP_FLAG_PSH, TCP_FLAG_SYN, TcpFrame, TcpOption, TcpRepr},
            },
        },
        stack::tx::{TxPacket, TxQueue},
    };

    const LOCAL_IP: Ipv4Addr = [10, 30, 0, 2];
    const PEER_IP: Ipv4Addr = [10, 30, 0, 3];

    const LOCAL_PORT: u16 = 7878;
    const PEER_PORT: u16 = 40000;

    fn inbound(
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> (Ipv4Frame<'static>, TcpFrame<'static>) {
        let tcp = TcpFrame::new(TcpRepr {
            src_port: PEER_PORT,
            dst_port: LOCAL_PORT,
            seq,
            ack,
            flags,
            window: 64240,
            options: if flags & TCP_FLAG_SYN != 0 {
                &[TcpOption::Mss(1460)]
            } else {
                &[]
            },
            payload: payload.to_vec().into(),
            ..Default::default()
        })
        .unwrap();

        let ipv4 = Ipv4Frame::new(PEER_IP, LOCAL_IP, Ipv4Payload::Tcp(tcp.clone()));

        (ipv4, tcp)
    }

    fn drain(tx: &mut TxQueue) -> Vec<TcpFrame<'static>> {
        let mut segments = vec![];

        while let Some(TxPacket::Ipv4(frame)) = tx.pop() {
            if let Ipv4Payload::Tcp(tcp) = frame.into_payload() {
                segments.push(tcp);
            }
        }

        segments
    }

    struct Harness {
        engine: TcpEngine,
        tx: TxQueue,
        now: Instant,
        peer_seq: u32,
        local_seq: u32,
    }

    impl Harness {
        fn established() -> Harness {
            let mut engine = TcpEngine::default();
            let mut tx = TxQueue::default();
            let now = Instant::now();

            let listener = engine.listen(LOCAL_PORT).unwrap();

            let peer_iss = 5000;
            let (ipv4, tcp) = inbound(peer_iss, 0, TCP_FLAG_SYN, &[]);
            engine.process(&ipv4, &tcp, LOCAL_IP, now, &mut tx);

            let syn_ack = drain(&mut tx).pop().expect("syn-ack");
            assert!(syn_ack.syn() && syn_ack.ack_flag());

            let local_iss = syn_ack.seq();

            let (ipv4, tcp) = inbound(peer_iss + 1, local_iss + 1, TCP_FLAG_ACK, &[]);
            engine.process(&ipv4, &tcp, LOCAL_IP, now, &mut tx);
            drain(&mut tx);

            let handle = engine.accept(&listener).expect("connection accepted");
            assert_eq!(engine.state(&handle), Some(TcpState::Established));

            Harness {
                engine,
                tx,
                now,
                peer_seq: peer_iss + 1,
                local_seq: local_iss + 1,
            }
        }

        fn handle(&self) -> TcpSocketHandle {
            *self.engine.handles.keys().next().unwrap()
        }

        fn held_segments(&self) -> usize {
            self.engine
                .connections
                .values()
                .next()
                .map(|connection| connection.held_segments())
                .unwrap_or(0)
        }

        fn feed(&mut self, seq: u32, flags: u8, payload: &[u8]) -> Vec<TcpFrame<'static>> {
            let (ipv4, tcp) = inbound(seq, self.local_seq, flags, payload);
            self.engine
                .process(&ipv4, &tcp, LOCAL_IP, self.now, &mut self.tx);
            self.engine.dispatch(self.now, &mut self.tx);

            drain(&mut self.tx)
        }

        fn tick(&mut self, elapsed: Duration) -> Vec<TcpFrame<'static>> {
            self.now += elapsed;
            self.engine.dispatch(self.now, &mut self.tx);

            drain(&mut self.tx)
        }

        fn read(&mut self) -> Vec<u8> {
            let mut out = vec![0u8; 256];
            let n = self.engine.recv(&self.handle(), &mut out);
            out.truncate(n);

            out
        }
    }

    #[test]
    fn handshake_reaches_established() {
        let harness = Harness::established();
        assert_eq!(
            harness.engine.state(&harness.handle()),
            Some(TcpState::Established)
        );
    }

    #[test]
    fn in_order_data_is_delivered_and_acknowledged() {
        let mut harness = Harness::established();
        let peer_seq = harness.peer_seq;

        let sent = harness.feed(peer_seq, TCP_FLAG_PSH | TCP_FLAG_ACK, b"hello");

        let ack = sent.last().expect("an ack came back");
        assert_eq!(ack.ack(), peer_seq + 5);
        assert_eq!(harness.read(), b"hello");
    }

    #[test]
    fn a_segment_for_a_dead_port_is_reset() {
        let mut engine = TcpEngine::default();
        let mut tx = TxQueue::default();

        let (ipv4, tcp) = inbound(1000, 0, TCP_FLAG_SYN, &[]);
        engine.process(&ipv4, &tcp, LOCAL_IP, Instant::now(), &mut tx);

        let reset = drain(&mut tx).pop().expect("a reset came back");
        assert!(reset.rst());
        assert_eq!(reset.ack(), 1001);
    }

    #[test]
    fn out_of_order_segments_are_held_until_the_gap_closes() {
        let mut harness = Harness::established();
        let peer_seq = harness.peer_seq;

        let sent = harness.feed(peer_seq + 5, TCP_FLAG_PSH | TCP_FLAG_ACK, b"world");

        assert_eq!(
            sent.last().unwrap().ack(),
            peer_seq,
            "the ack still points at the missing byte"
        );
        assert_eq!(harness.read(), b"", "nothing is delivered out of order");
        assert_eq!(harness.held_segments(), 1);

        let sent = harness.feed(peer_seq, TCP_FLAG_PSH | TCP_FLAG_ACK, b"hello");

        assert_eq!(
            sent.last().unwrap().ack(),
            peer_seq + 10,
            "the ack jumps over both segments at once"
        );
        assert_eq!(harness.read(), b"helloworld");
        assert_eq!(harness.held_segments(), 0);
    }

    #[test]
    fn several_holes_are_filled_in_any_order() {
        let mut harness = Harness::established();
        let peer_seq = harness.peer_seq;

        harness.feed(peer_seq + 9, TCP_FLAG_ACK, b"ccc");
        harness.feed(peer_seq + 3, TCP_FLAG_ACK, b"bbb");
        harness.feed(peer_seq + 6, TCP_FLAG_ACK, b"---");
        assert_eq!(harness.read(), b"");

        let sent = harness.feed(peer_seq, TCP_FLAG_ACK, b"aaa");

        assert_eq!(sent.last().unwrap().ack(), peer_seq + 12);
        assert_eq!(harness.read(), b"aaabbb---ccc");
    }

    #[test]
    fn duplicate_and_overlapping_segments_are_absorbed() {
        let mut harness = Harness::established();
        let peer_seq = harness.peer_seq;

        harness.feed(peer_seq, TCP_FLAG_ACK, b"hello");
        assert_eq!(harness.read(), b"hello");

        let sent = harness.feed(peer_seq, TCP_FLAG_ACK, b"hello");
        assert_eq!(sent.last().unwrap().ack(), peer_seq + 5);
        assert_eq!(harness.read(), b"", "a pure retransmission adds nothing");

        let sent = harness.feed(peer_seq + 3, TCP_FLAG_ACK, b"lo!!");
        assert_eq!(sent.last().unwrap().ack(), peer_seq + 7);
        assert_eq!(harness.read(), b"!!", "only the new tail is delivered");
    }

    #[test]
    fn the_out_of_order_queue_is_bounded() {
        let mut harness = Harness::established();
        let peer_seq = harness.peer_seq;

        for index in 1..(TCP_MAX_OUT_OF_ORDER_SEGMENTS as u32 + 8) {
            harness.feed(peer_seq + index * 4, TCP_FLAG_ACK, b"....");
        }

        assert_eq!(harness.held_segments(), TCP_MAX_OUT_OF_ORDER_SEGMENTS);
    }

    #[test]
    fn unacknowledged_data_is_retransmitted() {
        let mut harness = Harness::established();
        let handle = harness.handle();

        harness.engine.send(&handle, b"needs an ack");

        let first = harness.tick(Duration::ZERO);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].payload(), b"needs an ack");

        assert!(
            harness.tick(TCP_RTO_INITIAL / 2).is_empty(),
            "nothing goes out before the timer is due"
        );

        let again = harness.tick(TCP_RTO_INITIAL);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].seq(), first[0].seq(), "same sequence number");
        assert_eq!(again[0].payload(), b"needs an ack");
    }

    #[test]
    fn acknowledged_data_is_not_retransmitted() {
        let mut harness = Harness::established();
        let handle = harness.handle();

        harness.engine.send(&handle, b"acknowledge me");
        let sent = harness.tick(Duration::ZERO);
        assert_eq!(sent.len(), 1);

        let acked = sent[0].seq() + sent[0].payload().len() as u32;
        harness.local_seq = acked;

        let peer_seq = harness.peer_seq;
        let (ipv4, tcp) = inbound(peer_seq, acked, TCP_FLAG_ACK, &[]);
        harness
            .engine
            .process(&ipv4, &tcp, LOCAL_IP, harness.now, &mut harness.tx);
        drain(&mut harness.tx);

        assert!(
            harness.tick(TCP_RTO_INITIAL * 4).is_empty(),
            "an acknowledged segment is never sent again"
        );
    }

    #[test]
    fn the_retransmit_timer_backs_off_and_eventually_gives_up() {
        let mut harness = Harness::established();
        let handle = harness.handle();

        harness.engine.send(&handle, b"into the void");
        harness.tick(Duration::ZERO);

        for attempt in 1..=u32::from(TCP_MAX_RETRANSMITS) {
            let sent = harness.tick(Duration::from_secs(120));
            assert_eq!(sent.len(), 1, "attempt {attempt} retransmits");
            assert_eq!(sent[0].payload(), b"into the void");
        }

        let last = harness.tick(Duration::from_secs(120));
        assert!(
            last.iter().any(|segment| segment.rst()),
            "giving up resets the connection"
        );
        assert_eq!(harness.engine.state(&handle), None);
    }

    #[test]
    fn a_lost_syn_is_retransmitted() {
        let mut engine = TcpEngine::default();
        let mut tx = TxQueue::default();
        let now = Instant::now();

        let handle = engine
            .connect(LOCAL_IP, PEER_PORT, PEER_IP, LOCAL_PORT, now, &mut tx)
            .unwrap();

        let first = drain(&mut tx);
        assert_eq!(first.len(), 1);
        assert!(first[0].syn());

        engine.dispatch(now + TCP_RTO_INITIAL, &mut tx);

        let again = drain(&mut tx);
        assert_eq!(again.len(), 1);
        assert!(again[0].syn());
        assert_eq!(again[0].seq(), first[0].seq());

        assert_eq!(engine.state(&handle), Some(TcpState::SynSent));
    }

    #[test]
    fn a_lost_fin_is_retransmitted() {
        let mut harness = Harness::established();
        let handle = harness.handle();

        harness.engine.close(&handle);

        let first = harness.tick(Duration::ZERO);
        assert_eq!(first.len(), 1);
        assert!(first[0].fin());

        let again = harness.tick(TCP_RTO_INITIAL);
        assert_eq!(again.len(), 1);
        assert!(again[0].fin());
        assert_eq!(again[0].seq(), first[0].seq());
    }

    #[test]
    fn the_initial_window_limits_the_first_burst() {
        let mut harness = Harness::established();
        let handle = harness.handle();

        harness.engine.send(&handle, &[0x41; 20000]);

        let burst = harness.tick(Duration::ZERO);
        let bytes: usize = burst.iter().map(|s| s.payload().len()).sum();

        assert_eq!(
            burst.len(),
            TCP_INITIAL_WINDOW_SEGMENTS,
            "slow start opens with a small window, not the peer's whole receive window"
        );
        assert_eq!(bytes, TCP_INITIAL_WINDOW_SEGMENTS * 1460);
    }

    #[test]
    fn slow_start_grows_the_window_as_acks_arrive() {
        let mut harness = Harness::established();
        let handle = harness.handle();

        harness.engine.send(&handle, &[0x41; TCP_SEND_BUFFER]);

        let first = harness.tick(Duration::ZERO);
        let first_bytes: usize = first.iter().map(|s| s.payload().len()).sum();

        let acked = first.last().unwrap().seq() + first.last().unwrap().payload().len() as u32;
        harness.local_seq = acked;

        let peer_seq = harness.peer_seq;
        let (ipv4, tcp) = inbound(peer_seq, acked, TCP_FLAG_ACK, &[]);
        harness
            .engine
            .process(&ipv4, &tcp, LOCAL_IP, harness.now, &mut harness.tx);
        drain(&mut harness.tx);

        harness.engine.send(&handle, &[0x41; TCP_SEND_BUFFER]);

        let second = harness.tick(Duration::ZERO);
        let second_bytes: usize = second.iter().map(|s| s.payload().len()).sum();

        assert!(
            second_bytes > first_bytes,
            "the window opened: {first_bytes} bytes then {second_bytes}"
        );
    }

    #[test]
    fn three_duplicate_acks_trigger_a_fast_retransmit() {
        let mut harness = Harness::established();
        let handle = harness.handle();

        harness.engine.send(&handle, &[0x41; 20000]);

        let burst = harness.tick(Duration::ZERO);
        let lost = burst.first().unwrap().seq();

        let peer_seq = harness.peer_seq;

        assert!(
            harness.feed(peer_seq, TCP_FLAG_ACK, &[]).is_empty(),
            "one duplicate ack is not enough"
        );
        assert!(
            harness.feed(peer_seq, TCP_FLAG_ACK, &[]).is_empty(),
            "two duplicate acks are not enough"
        );

        let resent = harness.feed(peer_seq, TCP_FLAG_ACK, &[]);

        assert!(
            !resent.is_empty(),
            "the third duplicate ack retransmits without waiting for the timer"
        );
        assert_eq!(
            resent.first().unwrap().seq(),
            lost,
            "it resends from the hole"
        );
    }

    #[test]
    fn a_timeout_collapses_the_window_to_one_segment() {
        let mut harness = Harness::established();
        let handle = harness.handle();

        harness.engine.send(&handle, &[0x41; 20000]);

        let burst = harness.tick(Duration::ZERO);
        assert_eq!(burst.len(), TCP_INITIAL_WINDOW_SEGMENTS);

        let after_timeout = harness.tick(TCP_RTO_INITIAL);

        assert_eq!(
            after_timeout.len(),
            1,
            "a timeout is treated as serious congestion: back to one segment"
        );
        assert_eq!(after_timeout[0].seq(), burst[0].seq());
    }

    #[test]
    fn the_send_window_caps_what_goes_out() {
        let mut harness = Harness::established();
        let handle = harness.handle();

        assert_eq!(harness.engine.send(&handle, &[0x41; 4096]), 4096);

        let segments = harness.tick(Duration::ZERO);
        assert!(!segments.is_empty());

        for segment in &segments {
            assert!(segment.payload().len() <= 1460);
        }

        let total: usize = segments.iter().map(|s| s.payload().len()).sum();
        assert_eq!(total, 4096);
    }
}
