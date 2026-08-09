use std::time::Instant;

use crate::{
    addr::Ipv4Addr,
    proto::{
        ipv4::{Ipv4Frame, Ipv4Payload},
        tcp::wire::{TCP_FLAG_ACK, TCP_FLAG_SYN, TCP_MSS_DEFAULT, TcpFrame, TcpOption, TcpRepr},
    },
    stack::tx::{TxPacket, TxQueue},
};

const TCP_STUB_WINDOW: u16 = 5000;
const TCP_STUB_ISS: u32 = 10245;

#[derive(Default)]
pub struct TcpEngine {}

impl TcpEngine {
    pub fn process(
        &mut self,
        ipv4_frame: &Ipv4Frame<'_>,
        tcp_frame: &TcpFrame<'_>,
        local_ip: Ipv4Addr,
        tx: &mut TxQueue,
    ) {
        tracing::debug!(
            src = ?ipv4_frame.src(),
            src_port = tcp_frame.src_port(),
            dst_port = tcp_frame.dst_port(),
            seq = tcp_frame.seq(),
            ack = tcp_frame.ack(),
            flags = format_args!("{:#010b}", tcp_frame.flags()),
            window = tcp_frame.window(),
            payload = tcp_frame.payload().len(),
            "tcp segment received"
        );

        if let Some(mss) = tcp_frame.mss() {
            tracing::trace!(
                mss,
                window_scale = tcp_frame.window_scale(),
                sack_permitted = tcp_frame.sack_permitted(),
                "tcp peer options"
            );
        }

        let reply = TcpFrame::new(TcpRepr {
            src_port: tcp_frame.dst_port(),
            dst_port: tcp_frame.src_port(),
            seq: TCP_STUB_ISS,
            ack: tcp_frame.seq().wrapping_add(1),
            flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
            window: TCP_STUB_WINDOW,
            options: &[TcpOption::Mss(TCP_MSS_DEFAULT)],
            ..Default::default()
        });

        let reply = match reply {
            Ok(reply) => reply,
            Err(e) => {
                tracing::warn!("could not build tcp reply: {e}");
                return;
            }
        };

        tracing::debug!(
            dst = ?ipv4_frame.src(),
            ack = reply.ack(),
            "tcp replying with a stub syn-ack"
        );

        let frame = Ipv4Frame::new(local_ip, *ipv4_frame.src(), Ipv4Payload::Tcp(reply));

        tx.push(TxPacket::Ipv4(frame.into_owned()));
    }

    pub fn poll_at(&self) -> Option<Instant> {
        None
    }

    pub fn dispatch(&mut self, _now: Instant, _tx: &mut TxQueue) {}

    pub fn has_work(&self) -> bool {
        false
    }
}
