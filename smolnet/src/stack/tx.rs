use std::{collections::VecDeque, time::Instant};

use net_header::NetHeader;

use crate::{
    addr::{BROADCAST_MAC, Ipv4Addr, MacAddr},
    device::{Device, DeviceError, MAX_FRAME_SIZE, Medium},
    proto::{
        arp::wire::ArpFrame,
        eth::{ETHER_TYPE_ARP, ETHER_TYPE_IPV4, EthernetHeader},
        ipv4::Ipv4Frame,
    },
    stack::Stack,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TxPacket {
    Ipv4(Ipv4Frame<'static>),
    Arp(ArpFrame),
}

impl TxPacket {
    pub fn ethertype(&self) -> u16 {
        match self {
            TxPacket::Ipv4(_) => ETHER_TYPE_IPV4,
            TxPacket::Arp(_) => ETHER_TYPE_ARP,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            TxPacket::Ipv4(frame) => frame.size(),
            TxPacket::Arp(frame) => frame.size(),
        }
    }

    pub fn write(&self, bytes: &mut [u8]) -> usize {
        match self {
            TxPacket::Ipv4(frame) => frame.write(bytes),
            TxPacket::Arp(frame) => frame.write(bytes),
        }
    }
}

#[derive(Debug, Default)]
pub struct TxQueue {
    queue: VecDeque<TxPacket>,
}

impl TxQueue {
    pub fn push(&mut self, packet: TxPacket) {
        self.queue.push_back(packet);
    }

    pub fn push_front(&mut self, packet: TxPacket) {
        self.queue.push_front(packet);
    }

    pub fn pop(&mut self) -> Option<TxPacket> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

enum LinkResolution {
    Bare,
    Ready(MacAddr),
    Deferred(Ipv4Addr),
    Drop,
}

impl Stack {
    fn resolve_link(&self, packet: &TxPacket, now: Instant) -> LinkResolution {
        let Medium::Ethernet { .. } = self.capabilities.medium else {
            return match packet {
                TxPacket::Ipv4(_) => LinkResolution::Bare,
                TxPacket::Arp(_) => LinkResolution::Drop,
            };
        };

        let Some(arp) = self.arp.as_ref() else {
            return LinkResolution::Drop;
        };

        match packet {
            TxPacket::Arp(frame) => LinkResolution::Ready(frame.link_dst()),
            TxPacket::Ipv4(frame) if self.identity.is_broadcast(frame.dst()) => {
                LinkResolution::Ready(BROADCAST_MAC)
            }
            TxPacket::Ipv4(frame) => {
                let hop = self.identity.next_hop(frame.dst());

                match arp.lookup(&hop, now) {
                    Some(mac) => LinkResolution::Ready(mac),
                    None => LinkResolution::Deferred(hop),
                }
            }
        }
    }

    pub(crate) fn flush_tx<D: Device + ?Sized>(
        &mut self,
        device: &mut D,
        now: Instant,
    ) -> Result<(), DeviceError> {
        let mut buffer = [0u8; MAX_FRAME_SIZE];

        let medium = self.capabilities.medium;
        let max_frame_size = self.capabilities.max_frame_size();

        while let Some(mut packet) = self.tx.pop() {
            let link_dst = match self.resolve_link(&packet, now) {
                LinkResolution::Bare => None,
                LinkResolution::Ready(dst) => Some(dst),
                LinkResolution::Deferred(hop) => {
                    let TxPacket::Ipv4(frame) = packet else {
                        continue;
                    };

                    tracing::trace!(
                        dst = ?frame.dst(),
                        ?hop,
                        "next hop unresolved, deferring to arp"
                    );

                    if let Some(arp) = self.arp.as_mut() {
                        arp.enqueue(hop, frame, now, &mut self.tx);
                    }

                    continue;
                }
                LinkResolution::Drop => {
                    tracing::warn!(
                        ?medium,
                        "dropping packet that cannot be framed for the medium"
                    );
                    continue;
                }
            };

            let total = medium.link_header_len() + packet.size();
            if total > max_frame_size {
                tracing::warn!(total, max_frame_size, "dropping oversized frame");
                continue;
            }

            if let TxPacket::Ipv4(frame) = &mut packet {
                frame.set_identification(self.next_ipv4_id());
            }

            let offset = match (medium, link_dst) {
                (Medium::Ethernet { mac }, Some(dst)) => {
                    EthernetHeader::new(mac, dst, packet.ethertype()).write(&mut buffer)
                }
                _ => 0,
            };

            let size = offset + packet.write(&mut buffer[offset..]);

            match device.write_frame(&buffer[..size]) {
                Ok(()) => {
                    tracing::trace!(
                        ethertype = format_args!("{:#06x}", packet.ethertype()),
                        ?link_dst,
                        size,
                        "frame transmitted"
                    );
                }
                Err(DeviceError::WouldBlock) => {
                    tracing::debug!(
                        queued = self.tx.len() + 1,
                        "device is not writable, retrying on the next poll"
                    );
                    self.tx.push_front(packet);
                    break;
                }
                Err(e) => {
                    self.tx.push_front(packet);
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}
