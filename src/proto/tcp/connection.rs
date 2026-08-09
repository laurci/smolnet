use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::{
    addr::Ipv4Addr,
    proto::{
        ipv4::{Ipv4Frame, Ipv4Payload},
        tcp::{
            congestion::Congestion,
            rtt::RoundTrip,
            seq,
            wire::{
                TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
                TCP_MSS_DEFAULT, TcpFrame, TcpOption, TcpRepr,
            },
        },
    },
    stack::tx::{TxPacket, TxQueue},
};

pub const TCP_RECV_WINDOW: u16 = 8192;
pub const TCP_SEND_BUFFER: usize = 8192;
pub const TCP_TIME_WAIT: Duration = Duration::from_secs(60);
pub const TCP_MSS_FLOOR: u16 = 536;
pub const TCP_MAX_RETRANSMITS: u8 = 5;
pub const TCP_MAX_OUT_OF_ORDER_SEGMENTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    fn sends_stream(&self) -> bool {
        matches!(
            self,
            TcpState::Established
                | TcpState::CloseWait
                | TcpState::FinWait1
                | TcpState::Closing
                | TcpState::LastAck
        )
    }

    fn accepts_writes(&self) -> bool {
        matches!(self, TcpState::Established | TcpState::CloseWait)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpSocketHandle(pub(super) usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ConnectionKey {
    pub(super) local_port: u16,
    pub(super) remote_ip: Ipv4Addr,
    pub(super) remote_port: u16,
}

pub(super) enum SegmentOutcome {
    None,
    Established,
    Dead,
}

fn negotiated_mss(tcp: &TcpFrame<'_>) -> u16 {
    tcp.mss().unwrap_or(TCP_MSS_FLOOR).min(TCP_MSS_DEFAULT)
}

#[allow(clippy::too_many_arguments)]
fn emit(
    local_ip: Ipv4Addr,
    key: &ConnectionKey,
    seq: u32,
    ack: u32,
    flags: u8,
    options: &[TcpOption<'_>],
    payload: Vec<u8>,
    tx: &mut TxQueue,
) {
    let repr = TcpRepr {
        src_port: key.local_port,
        dst_port: key.remote_port,
        seq,
        ack,
        flags,
        window: TCP_RECV_WINDOW,
        urgent_ptr: 0,
        options,
        payload: payload.into(),
    };

    let frame = match TcpFrame::new(repr) {
        Ok(frame) => frame,
        Err(e) => {
            tracing::warn!("could not build tcp segment: {e}");
            return;
        }
    };

    tracing::trace!(
        local_port = key.local_port,
        remote = ?key.remote_ip,
        remote_port = key.remote_port,
        seq,
        ack,
        flags = format_args!("{flags:#010b}"),
        payload = frame.payload().len(),
        "tcp segment sent"
    );

    let ipv4 = Ipv4Frame::new(local_ip, key.remote_ip, Ipv4Payload::Tcp(frame));
    tx.push(TxPacket::Ipv4(ipv4.into_owned()));
}

/// Answers a segment that belongs to no socket. There is no connection to hold
/// state, so everything comes from the offending segment itself.
pub(super) fn reset_segment(
    local_ip: Ipv4Addr,
    key: &ConnectionKey,
    tcp: &TcpFrame<'_>,
    tx: &mut TxQueue,
) {
    let (seq, ack, flags) = if tcp.ack_flag() {
        (tcp.ack(), 0, TCP_FLAG_RST)
    } else {
        let segment_len = tcp.payload().len() as u32 + u32::from(tcp.syn()) + u32::from(tcp.fin());

        (
            0,
            tcp.seq().wrapping_add(segment_len),
            TCP_FLAG_RST | TCP_FLAG_ACK,
        )
    };

    tracing::debug!(
        local_port = key.local_port,
        remote = ?key.remote_ip,
        remote_port = key.remote_port,
        "tcp resetting segment for a port with no socket"
    );

    emit(local_ip, key, seq, ack, flags, &[], vec![], tx);
}

pub(super) struct TcpConnection {
    local_ip: Ipv4Addr,
    handle: TcpSocketHandle,
    key: ConnectionKey,

    state: TcpState,

    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u16,
    snd_mss: u16,
    fin_seq: Option<u32>,

    rcv_nxt: u32,
    peer_fin_seq: Option<u32>,

    rx_buffer: VecDeque<u8>,
    send_buffer: VecDeque<u8>,
    out_of_order: Vec<(u32, Vec<u8>)>,

    round_trip: RoundTrip,
    congestion: Congestion,
    retransmit_at: Option<Instant>,
    retransmits: u8,

    needs_ack: bool,
    peer_finished: bool,
    close_requested: bool,

    time_wait_until: Option<Instant>,
}

impl TcpConnection {
    fn new(
        local_ip: Ipv4Addr,
        handle: TcpSocketHandle,
        key: ConnectionKey,
        state: TcpState,
    ) -> TcpConnection {
        let iss: u32 = rand::random();

        TcpConnection {
            local_ip,
            handle,
            key,
            state,
            iss,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_wnd: TCP_RECV_WINDOW,
            snd_mss: TCP_MSS_FLOOR,
            fin_seq: None,
            rcv_nxt: 0,
            peer_fin_seq: None,
            rx_buffer: VecDeque::new(),
            send_buffer: VecDeque::new(),
            out_of_order: vec![],
            round_trip: RoundTrip::new(),
            congestion: Congestion::new(TCP_MSS_FLOOR as usize),
            retransmit_at: None,
            retransmits: 0,
            needs_ack: false,
            peer_finished: false,
            close_requested: false,
            time_wait_until: None,
        }
    }

    /// Opens a connection, putting the syn on the wire.
    pub(super) fn connect(
        local_ip: Ipv4Addr,
        handle: TcpSocketHandle,
        key: ConnectionKey,
        now: Instant,
        tx: &mut TxQueue,
    ) -> TcpConnection {
        let mut connection = TcpConnection::new(local_ip, handle, key, TcpState::SynSent);

        emit(
            local_ip,
            &key,
            connection.iss,
            0,
            TCP_FLAG_SYN,
            &[TcpOption::Mss(TCP_MSS_DEFAULT)],
            vec![],
            tx,
        );

        connection.arm_retransmit(now);

        connection
    }

    /// Answers an inbound syn, putting the syn-ack on the wire.
    pub(super) fn accept(
        local_ip: Ipv4Addr,
        handle: TcpSocketHandle,
        key: ConnectionKey,
        syn: &TcpFrame<'_>,
        now: Instant,
        tx: &mut TxQueue,
    ) -> TcpConnection {
        let mut connection = TcpConnection::new(local_ip, handle, key, TcpState::SynReceived);

        connection.rcv_nxt = syn.seq().wrapping_add(1);
        connection.snd_wnd = syn.window();
        connection.set_mss(negotiated_mss(syn));

        emit(
            local_ip,
            &key,
            connection.iss,
            connection.rcv_nxt,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            &[TcpOption::Mss(TCP_MSS_DEFAULT)],
            vec![],
            tx,
        );

        connection.arm_retransmit(now);

        connection
    }

    pub(super) fn handle(&self) -> TcpSocketHandle {
        self.handle
    }

    pub(super) fn state(&self) -> TcpState {
        self.state
    }

    pub(super) fn peer_finished(&self) -> bool {
        self.peer_finished
    }

    pub(super) fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    #[cfg(test)]
    pub(super) fn held_segments(&self) -> usize {
        self.out_of_order.len()
    }

    fn set_mss(&mut self, mss: u16) {
        self.snd_mss = mss;
        self.congestion.on_mss(mss as usize);
    }

    fn arm_retransmit(&mut self, now: Instant) {
        self.retransmit_at = Some(now + self.round_trip.rto());
    }

    fn transition(&mut self, next: TcpState) {
        tracing::debug!(
            local_port = self.key.local_port,
            remote = ?self.key.remote_ip,
            remote_port = self.key.remote_port,
            from = ?self.state,
            to = ?next,
            "tcp state transition"
        );

        self.state = next;
    }

    fn enter_time_wait(&mut self, now: Instant) {
        self.transition(TcpState::TimeWait);
        self.time_wait_until = Some(now + TCP_TIME_WAIT);
        self.retransmit_at = None;
    }

    fn flight(&self) -> usize {
        self.snd_nxt.wrapping_sub(self.snd_una) as usize
    }

    pub(super) fn on_segment(
        &mut self,
        tcp: &TcpFrame<'_>,
        now: Instant,
        tx: &mut TxQueue,
    ) -> SegmentOutcome {
        tracing::trace!(
            local_port = self.key.local_port,
            state = ?self.state,
            seq = tcp.seq(),
            ack = tcp.ack(),
            flags = format_args!("{:#010b}", tcp.flags()),
            payload = tcp.payload().len(),
            "tcp segment received"
        );

        if tcp.rst() {
            tracing::debug!(
                local_port = self.key.local_port,
                "tcp connection reset by peer"
            );
            self.transition(TcpState::Closed);
            return SegmentOutcome::Dead;
        }

        match self.state {
            TcpState::SynSent => self.on_syn_sent(tcp, now, tx),
            TcpState::SynReceived => self.on_syn_received(tcp, now),
            _ => self.on_synchronized(tcp, now),
        }
    }

    fn on_syn_sent(
        &mut self,
        tcp: &TcpFrame<'_>,
        now: Instant,
        tx: &mut TxQueue,
    ) -> SegmentOutcome {
        if !tcp.syn() || !tcp.ack_flag() {
            tracing::debug!("tcp ignoring segment that is not a syn-ack while connecting");
            return SegmentOutcome::None;
        }

        if tcp.ack() != self.snd_nxt {
            tracing::debug!(
                expected = self.snd_nxt,
                got = tcp.ack(),
                "tcp syn-ack acknowledges the wrong sequence, resetting"
            );

            emit(
                self.local_ip,
                &self.key,
                tcp.ack(),
                0,
                TCP_FLAG_RST,
                &[],
                vec![],
                tx,
            );

            return SegmentOutcome::Dead;
        }

        self.rcv_nxt = tcp.seq().wrapping_add(1);
        self.snd_wnd = tcp.window();
        self.set_mss(negotiated_mss(tcp));
        self.needs_ack = true;

        self.acknowledge(tcp.ack(), now);
        self.transition(TcpState::Established);

        SegmentOutcome::None
    }

    fn on_syn_received(&mut self, tcp: &TcpFrame<'_>, now: Instant) -> SegmentOutcome {
        if !tcp.ack_flag() || tcp.ack() != self.snd_nxt {
            tracing::debug!("tcp ignoring segment that does not complete the handshake");
            return SegmentOutcome::None;
        }

        self.acknowledge(tcp.ack(), now);
        self.transition(TcpState::Established);

        self.on_synchronized(tcp, now);

        SegmentOutcome::Established
    }

    fn acknowledge(&mut self, ack: u32, now: Instant) {
        if !seq::gt(ack, self.snd_una) || !seq::leq(ack, self.snd_nxt) {
            return;
        }

        let acked = ack.wrapping_sub(self.snd_una) as usize;
        let data_acked = acked.min(self.send_buffer.len());

        self.send_buffer.drain(..data_acked);
        self.snd_una = ack;

        self.round_trip.take_sample(ack, now);
        self.congestion
            .on_new_ack(data_acked, self.snd_mss as usize);

        self.retransmits = 0;
        self.retransmit_at = if seq::lt(self.snd_una, self.snd_nxt) {
            Some(now + self.round_trip.rto())
        } else {
            None
        };
    }

    fn is_duplicate_ack(&self, tcp: &TcpFrame<'_>) -> bool {
        tcp.ack_flag()
            && tcp.payload().is_empty()
            && !tcp.syn()
            && !tcp.fin()
            && tcp.ack() == self.snd_una
            && seq::lt(self.snd_una, self.snd_nxt)
    }

    fn on_duplicate_ack(&mut self, now: Instant) {
        let flight = self.flight();

        if !self
            .congestion
            .on_duplicate_ack(self.snd_mss as usize, flight)
        {
            return;
        }

        tracing::debug!(
            local_port = self.key.local_port,
            acks = self.congestion.duplicate_acks(),
            "tcp fast retransmit"
        );

        self.snd_nxt = self.snd_una;
        self.round_trip.discard_sample();
        self.arm_retransmit(now);
    }

    fn on_synchronized(&mut self, tcp: &TcpFrame<'_>, now: Instant) -> SegmentOutcome {
        if self.is_duplicate_ack(tcp) {
            self.on_duplicate_ack(now);
        } else if tcp.ack_flag() {
            self.acknowledge(tcp.ack(), now);
        }

        self.snd_wnd = tcp.window();

        let segment_len = tcp.payload().len() + usize::from(tcp.fin());
        if segment_len > 0 {
            self.accept_segment(tcp.seq(), tcp.payload(), tcp.fin());
            self.needs_ack = true;
        }

        let fin_acked = self
            .fin_seq
            .is_some_and(|fin_seq| seq::gt(self.snd_una, fin_seq));

        match self.state {
            TcpState::Established => {
                if self.peer_finished {
                    self.transition(TcpState::CloseWait);
                }
            }
            TcpState::FinWait1 => {
                if fin_acked && self.peer_finished {
                    self.enter_time_wait(now);
                } else if fin_acked {
                    self.transition(TcpState::FinWait2);
                } else if self.peer_finished {
                    self.transition(TcpState::Closing);
                }
            }
            TcpState::FinWait2 => {
                if self.peer_finished {
                    self.enter_time_wait(now);
                }
            }
            TcpState::Closing => {
                if fin_acked {
                    self.enter_time_wait(now);
                }
            }
            TcpState::LastAck => {
                if fin_acked {
                    self.transition(TcpState::Closed);
                    return SegmentOutcome::Dead;
                }
            }
            TcpState::TimeWait => {
                self.time_wait_until = Some(now + TCP_TIME_WAIT);
            }
            _ => {}
        }

        SegmentOutcome::None
    }

    fn accept_segment(&mut self, segment_seq: u32, payload: &[u8], fin: bool) {
        if fin {
            self.peer_fin_seq = Some(segment_seq.wrapping_add(payload.len() as u32));
        }

        let end = segment_seq.wrapping_add(payload.len() as u32);

        if seq::geq(
            segment_seq,
            self.rcv_nxt.wrapping_add(TCP_RECV_WINDOW as u32),
        ) {
            tracing::debug!(seq = segment_seq, "tcp segment falls outside the window");
            return;
        }

        if !payload.is_empty() {
            if seq::leq(segment_seq, self.rcv_nxt) {
                if seq::gt(end, self.rcv_nxt) {
                    let skip = self.rcv_nxt.wrapping_sub(segment_seq) as usize;
                    self.push_received(&payload[skip..]);
                    self.drain_out_of_order();
                }
            } else {
                self.buffer_out_of_order(segment_seq, payload);
            }
        }

        if self.peer_fin_seq == Some(self.rcv_nxt) && !self.peer_finished {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.peer_finished = true;

            tracing::debug!(
                local_port = self.key.local_port,
                "tcp peer finished sending"
            );
        }
    }

    fn push_received(&mut self, payload: &[u8]) -> usize {
        let room = TCP_RECV_WINDOW as usize - self.rx_buffer.len();
        let len = payload.len().min(room);

        if len < payload.len() {
            tracing::debug!(
                len = payload.len(),
                room,
                "tcp receive buffer is full, leaving the rest unacknowledged"
            );
        }

        self.rx_buffer.extend(&payload[..len]);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(len as u32);

        len
    }

    fn buffer_out_of_order(&mut self, segment_seq: u32, payload: &[u8]) {
        if self
            .out_of_order
            .iter()
            .any(|(stored, _)| *stored == segment_seq)
        {
            return;
        }

        if self.out_of_order.len() >= TCP_MAX_OUT_OF_ORDER_SEGMENTS {
            tracing::debug!(
                seq = segment_seq,
                "tcp out of order queue is full, dropping the segment"
            );
            return;
        }

        tracing::debug!(
            seq = segment_seq,
            expected = self.rcv_nxt,
            len = payload.len(),
            "tcp holding an out of order segment"
        );

        self.out_of_order.push((segment_seq, payload.to_vec()));
    }

    fn drain_out_of_order(&mut self) {
        loop {
            let found = self.out_of_order.iter().position(|(stored, data)| {
                seq::leq(*stored, self.rcv_nxt)
                    && seq::gt(stored.wrapping_add(data.len() as u32), self.rcv_nxt)
            });

            let Some(index) = found else {
                break;
            };

            let (stored, data) = self.out_of_order.remove(index);
            let skip = self.rcv_nxt.wrapping_sub(stored) as usize;

            tracing::debug!(
                seq = stored,
                len = data.len() - skip,
                "tcp releasing a held segment now that the gap is filled"
            );

            if self.push_received(&data[skip..]) == 0 {
                break;
            }
        }

        let rcv_nxt = self.rcv_nxt;
        self.out_of_order
            .retain(|(stored, data)| seq::gt(stored.wrapping_add(data.len() as u32), rcv_nxt));
    }

    fn retransmit(&mut self, now: Instant, tx: &mut TxQueue) -> bool {
        self.retransmits += 1;

        if self.retransmits > TCP_MAX_RETRANSMITS {
            tracing::warn!(
                local_port = self.key.local_port,
                remote = ?self.key.remote_ip,
                remote_port = self.key.remote_port,
                "tcp giving up after {TCP_MAX_RETRANSMITS} retransmissions"
            );

            emit(
                self.local_ip,
                &self.key,
                self.snd_nxt,
                self.rcv_nxt,
                TCP_FLAG_RST,
                &[],
                vec![],
                tx,
            );

            return false;
        }

        let flight = self.flight();
        self.congestion.on_timeout(self.snd_mss as usize, flight);

        self.round_trip.back_off();
        self.arm_retransmit(now);

        tracing::debug!(
            local_port = self.key.local_port,
            state = ?self.state,
            attempt = self.retransmits,
            rto_ms = self.round_trip.rto().as_millis(),
            "tcp retransmitting"
        );

        match self.state {
            TcpState::SynSent => emit(
                self.local_ip,
                &self.key,
                self.iss,
                0,
                TCP_FLAG_SYN,
                &[TcpOption::Mss(TCP_MSS_DEFAULT)],
                vec![],
                tx,
            ),
            TcpState::SynReceived => emit(
                self.local_ip,
                &self.key,
                self.iss,
                self.rcv_nxt,
                TCP_FLAG_SYN | TCP_FLAG_ACK,
                &[TcpOption::Mss(TCP_MSS_DEFAULT)],
                vec![],
                tx,
            ),
            _ => self.snd_nxt = self.snd_una,
        }

        true
    }

    pub(super) fn dispatch(&mut self, now: Instant, tx: &mut TxQueue) -> bool {
        if let Some(deadline) = self.retransmit_at
            && now >= deadline
            && seq::lt(self.snd_una, self.snd_nxt)
            && !self.retransmit(now, tx)
        {
            return false;
        }

        let mut sent = false;

        if self.state.sends_stream() {
            sent |= self.send_pending_data(now, tx);
            sent |= self.send_pending_fin(tx);
        }

        if self.needs_ack && !sent {
            emit(
                self.local_ip,
                &self.key,
                self.snd_nxt,
                self.rcv_nxt,
                TCP_FLAG_ACK,
                &[],
                vec![],
                tx,
            );
            sent = true;
        }

        if sent {
            self.needs_ack = false;
        }

        if seq::lt(self.snd_una, self.snd_nxt) && self.retransmit_at.is_none() {
            self.arm_retransmit(now);
        }

        true
    }

    fn send_pending_data(&mut self, now: Instant, tx: &mut TxQueue) -> bool {
        let mut sent = false;

        loop {
            let offset = self.flight();
            if offset >= self.send_buffer.len() {
                break;
            }

            let window = (self.snd_wnd as usize).min(self.congestion.window());
            let allowed = window.saturating_sub(offset);
            let available = self.send_buffer.len() - offset;
            let len = available.min(self.snd_mss as usize).min(allowed);

            if len == 0 {
                break;
            }

            // a partial segment is only worth sending when it is all that is left,
            // otherwise we would be spending a packet on a sliver of window
            if len < self.snd_mss as usize && len < available {
                break;
            }

            let payload: Vec<u8> = self
                .send_buffer
                .iter()
                .skip(offset)
                .take(len)
                .copied()
                .collect();

            emit(
                self.local_ip,
                &self.key,
                self.snd_nxt,
                self.rcv_nxt,
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                &[],
                payload,
                tx,
            );

            self.snd_nxt = self.snd_nxt.wrapping_add(len as u32);
            self.round_trip.start_sample(self.snd_nxt, now);
            sent = true;
        }

        sent
    }

    fn send_pending_fin(&mut self, tx: &mut TxQueue) -> bool {
        let Some(fin_seq) = self.fin_seq else {
            return false;
        };

        if self.snd_nxt != fin_seq {
            return false;
        }

        emit(
            self.local_ip,
            &self.key,
            fin_seq,
            self.rcv_nxt,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            &[],
            vec![],
            tx,
        );

        self.snd_nxt = fin_seq.wrapping_add(1);

        match self.state {
            TcpState::Established => self.transition(TcpState::FinWait1),
            TcpState::CloseWait => self.transition(TcpState::LastAck),
            _ => {}
        }

        true
    }

    pub(super) fn poll_at(&self) -> Option<Instant> {
        match (self.time_wait_until, self.retransmit_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (deadline, None) | (None, deadline) => deadline,
        }
    }

    pub(super) fn expired(&self, now: Instant) -> bool {
        match self.state {
            TcpState::Closed => true,
            TcpState::TimeWait => self.time_wait_until.is_some_and(|until| now >= until),
            _ => false,
        }
    }

    pub(super) fn has_work(&self) -> bool {
        !self.rx_buffer.is_empty()
            || !self.send_buffer.is_empty()
            || self.needs_ack
            || (self.close_requested && self.fin_seq.is_none())
    }

    pub(super) fn recv(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len().min(self.rx_buffer.len());
        for (slot, byte) in buf.iter_mut().zip(self.rx_buffer.drain(..len)) {
            *slot = byte;
        }

        len
    }

    pub(super) fn send_capacity(&self) -> usize {
        if !self.state.accepts_writes() || self.close_requested {
            return 0;
        }

        TCP_SEND_BUFFER - self.send_buffer.len()
    }

    pub(super) fn send(&mut self, data: &[u8]) -> usize {
        if !self.state.accepts_writes() || self.close_requested {
            tracing::debug!(state = ?self.state, "tcp send on a socket that cannot send");
            return 0;
        }

        let len = data.len().min(self.send_capacity());
        self.send_buffer.extend(&data[..len]);

        len
    }

    pub(super) fn close(&mut self) {
        if self.close_requested {
            return;
        }

        tracing::debug!(
            local_port = self.key.local_port,
            state = ?self.state,
            "tcp close requested"
        );

        self.close_requested = true;

        if matches!(self.state, TcpState::SynSent) {
            self.transition(TcpState::Closed);
            return;
        }

        self.fin_seq = Some(self.snd_una.wrapping_add(self.send_buffer.len() as u32));
    }
}
