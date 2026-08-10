use std::time::Instant;

use thiserror::Error;

use crate::{
    addr::MacAddr,
    device::Medium,
    proto::{
        eth::{self, EthernetFrame, EthernetFrameParseError, EthernetPayload},
        icmp::IcmpFrame,
        ipv4::{Ipv4Frame, Ipv4FrameParseError, Ipv4Payload},
    },
    stack::{Stack, tx::TxPacket},
};

#[derive(Debug, Error)]
pub enum StackRxError {
    #[error("ethernet frame parse error:\n{0}")]
    EthernetFrameParseError(EthernetFrameParseError),

    #[error("ipv4 frame parse error:\n{0}")]
    Ipv4FrameParseError(Ipv4FrameParseError),
}

impl Stack {
    pub(crate) fn process_frame(&mut self, bytes: &[u8], now: Instant) -> Result<(), StackRxError> {
        match self.capabilities.medium {
            Medium::Ethernet { mac } => {
                let frame =
                    EthernetFrame::parse(bytes).map_err(StackRxError::EthernetFrameParseError)?;

                if !eth::accepts_dst(frame.dst(), &mac) {
                    tracing::trace!(dst = ?frame.dst(), "dropping frame addressed to another host");
                    return Ok(());
                }

                tracing::trace!(
                    src = ?frame.src(),
                    dst = ?frame.dst(),
                    ethertype = format_args!("{:#06x}", frame.ethertype()),
                    len = bytes.len(),
                    "ethernet frame received"
                );

                let src_mac = *frame.src();

                match frame.payload() {
                    EthernetPayload::Arp(arp_frame) => {
                        if let Some(arp) = self.arp.as_mut() {
                            arp.process(arp_frame, now, &mut self.tx);
                        }
                    }
                    EthernetPayload::Ipv4(ipv4_frame) => {
                        self.learn_from_link(&src_mac, ipv4_frame, now);
                        self.process_ipv4(ipv4_frame, now);
                    }
                    EthernetPayload::Unknown { ethertype, data } => {
                        tracing::debug!(
                            ethertype = format_args!("{ethertype:#06x}"),
                            len = data.len(),
                            "ignoring frame with an unhandled ethertype"
                        );
                    }
                }
            }
            Medium::Ip => {
                let frame = Ipv4Frame::parse(bytes).map_err(StackRxError::Ipv4FrameParseError)?;

                tracing::trace!(len = bytes.len(), "ipv4 datagram received");
                self.process_ipv4(&frame, now);
            }
        }

        Ok(())
    }

    fn learn_from_link(&mut self, src_mac: &MacAddr, ipv4_frame: &Ipv4Frame<'_>, now: Instant) {
        let src_ip = *ipv4_frame.src();

        if self.identity.next_hop(&src_ip) != src_ip {
            return;
        }

        let Some(arp) = self.arp.as_mut() else {
            return;
        };

        arp.learn(src_ip, *src_mac, now, &mut self.tx);
    }

    fn process_ipv4(&mut self, frame: &Ipv4Frame<'_>, now: Instant) {
        if !self.identity.accepts_dst(frame.dst()) {
            tracing::trace!(
                dst = ?frame.dst(),
                "dropping ipv4 datagram addressed to another host"
            );
            return;
        }

        tracing::trace!(
            src = ?frame.src(),
            dst = ?frame.dst(),
            protocol = frame.protocol(),
            ttl = frame.ttl(),
            len = frame.size(),
            "ipv4 datagram accepted"
        );

        match frame.payload() {
            Ipv4Payload::Icmp(icmp_frame) => self.process_icmp(frame, icmp_frame),
            Ipv4Payload::Udp(udp_frame) => self.udp.process(frame, udp_frame),
            Ipv4Payload::Tcp(tcp_frame) => {
                self.tcp
                    .process(frame, tcp_frame, self.identity.ip, now, &mut self.tx)
            }
            Ipv4Payload::Unknown { protocol, data } => {
                tracing::debug!(
                    protocol,
                    len = data.len(),
                    "ignoring datagram with an unhandled ipv4 protocol"
                );
            }
        }
    }

    fn process_icmp(&mut self, frame: &Ipv4Frame<'_>, icmp_frame: &IcmpFrame<'_>) {
        let Some(reply) = icmp_frame.echo_reply() else {
            tracing::debug!(
                src = ?frame.src(),
                type_ = icmp_frame.message().type_(),
                code = icmp_frame.message().code(),
                "icmp message needs no reply"
            );
            return;
        };

        tracing::debug!(dst = ?frame.src(), "icmp echo request answered");

        let reply = Ipv4Frame::new(self.identity.ip, *frame.src(), Ipv4Payload::Icmp(reply));

        self.tx.push(TxPacket::Ipv4(reply.into_owned()));
    }
}
