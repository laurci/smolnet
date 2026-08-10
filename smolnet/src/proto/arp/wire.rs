use net_header::{NetHeader, parse::HeaderParseError};
use thiserror::Error;

use crate::{
    addr::{BROADCAST_MAC, Ipv4Addr, MacAddr, UNSPECIFIED_MAC},
    proto::eth::ETHER_TYPE_IPV4,
};

pub const ARP_OPERATION_REQUEST: u16 = 1;
pub const ARP_OPERATION_REPLY: u16 = 2;

pub const ARP_H_TYPE_ETHERNET: u16 = 1;

#[derive(NetHeader, Clone, Debug, PartialEq, Eq)]
#[header(name = "arp")]
pub struct ArpHeader {
    h_type: u16,
    p_type: u16,

    h_addr_len: u8,
    p_addr_len: u8,

    operation: u16,

    sender_h_addr: [u8; 6],
    sender_p_addr: [u8; 4],

    target_h_addr: [u8; 6],
    target_p_addr: [u8; 4],
}

#[derive(Debug, Error)]
pub enum ArpFrameParseError {
    #[error("failed to parse arp header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error(
        "unsupported or invalid arp hardware type (expected = {ARP_H_TYPE_ETHERNET}; found = {0})"
    )]
    UnsupportedHardwareType(u16),

    #[error(
        "unsupported or invalid arp proto type (expected = ETHER_TYPE_IPV4 ({ETHER_TYPE_IPV4}); found = {0})"
    )]
    UnsupportedProtoType(u16),

    #[error("unsupported or invalid arp hardware addr len (expected = 6; found = {0})")]
    UnsupportedHardwareAddrLen(u8),

    #[error("unsupported or invalid arp proto addr len (expected = 4; found = {0})")]
    UnsupportedProtoAddrLen(u8),

    #[error("unknown arp operation 0x{0:x}")]
    UnknownArpOperation(u16),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ArpOperation {
    Request(ArpRequest),
    Reply(ArpReply),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArpFrame {
    pub operation: ArpOperation,
}

impl ArpFrame {
    pub fn parse(bytes: &[u8]) -> Result<Self, ArpFrameParseError> {
        let header = ArpHeader::from_bytes(bytes).map_err(ArpFrameParseError::HeaderParseError)?;

        if header.h_type != ARP_H_TYPE_ETHERNET {
            return Err(ArpFrameParseError::UnsupportedHardwareType(header.h_type));
        }

        if header.p_type != ETHER_TYPE_IPV4 {
            return Err(ArpFrameParseError::UnsupportedProtoType(header.p_type));
        }

        if header.h_addr_len != size_of::<MacAddr>() as u8 {
            return Err(ArpFrameParseError::UnsupportedHardwareAddrLen(
                header.h_addr_len,
            ));
        }

        if header.p_addr_len != size_of::<Ipv4Addr>() as u8 {
            return Err(ArpFrameParseError::UnsupportedProtoAddrLen(
                header.p_addr_len,
            ));
        }

        let operation = match header.operation {
            ARP_OPERATION_REQUEST => ArpOperation::Request(ArpRequest { header }),
            ARP_OPERATION_REPLY => ArpOperation::Reply(ArpReply { header }),
            unknown_value => return Err(ArpFrameParseError::UnknownArpOperation(unknown_value)),
        };

        Ok(ArpFrame { operation })
    }

    pub fn new(operation: ArpOperation) -> Self {
        ArpFrame { operation }
    }

    pub fn write(&self, bytes: &mut [u8]) -> usize {
        let header = match &self.operation {
            ArpOperation::Request(request) => &request.header,
            ArpOperation::Reply(reply) => &reply.header,
        };

        header.write(bytes)
    }

    pub fn size(&self) -> usize {
        ArpHeader::SIZE
    }

    pub fn link_dst(&self) -> MacAddr {
        match &self.operation {
            ArpOperation::Request(_) => BROADCAST_MAC,
            ArpOperation::Reply(reply) => *reply.target_hardware_addr(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArpRequest {
    header: ArpHeader,
}

impl ArpRequest {
    pub fn new(
        sender_hardware_addr: MacAddr,
        sender_proto_addr: Ipv4Addr,
        target_proto_addr: Ipv4Addr,
    ) -> ArpRequest {
        let header = ArpHeader {
            h_type: ARP_H_TYPE_ETHERNET,
            p_type: ETHER_TYPE_IPV4,

            h_addr_len: size_of::<MacAddr>() as u8,
            p_addr_len: size_of::<Ipv4Addr>() as u8,

            operation: ARP_OPERATION_REQUEST,

            sender_h_addr: sender_hardware_addr,
            sender_p_addr: sender_proto_addr,

            target_h_addr: UNSPECIFIED_MAC,
            target_p_addr: target_proto_addr,
        };

        ArpRequest { header }
    }

    pub fn sender_hardware_addr(&self) -> &MacAddr {
        &self.header.sender_h_addr
    }

    pub fn sender_proto_addr(&self) -> &Ipv4Addr {
        &self.header.sender_p_addr
    }

    pub fn target_proto_addr(&self) -> &Ipv4Addr {
        &self.header.target_p_addr
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArpReply {
    header: ArpHeader,
}

impl ArpReply {
    pub fn new(request: &ArpRequest, sender_hardware_addr: MacAddr) -> Self {
        let header = ArpHeader {
            h_type: ARP_H_TYPE_ETHERNET,
            p_type: ETHER_TYPE_IPV4,

            h_addr_len: size_of::<MacAddr>() as u8,
            p_addr_len: size_of::<Ipv4Addr>() as u8,

            operation: ARP_OPERATION_REPLY,

            sender_h_addr: sender_hardware_addr,
            sender_p_addr: request.header.target_p_addr,

            target_h_addr: request.header.sender_h_addr,
            target_p_addr: request.header.sender_p_addr,
        };

        ArpReply { header }
    }

    pub fn sender_hardware_addr(&self) -> &MacAddr {
        &self.header.sender_h_addr
    }

    pub fn sender_proto_addr(&self) -> &Ipv4Addr {
        &self.header.sender_p_addr
    }

    pub fn target_hardware_addr(&self) -> &MacAddr {
        &self.header.target_h_addr
    }

    pub fn target_proto_addr(&self) -> &Ipv4Addr {
        &self.header.target_p_addr
    }
}

#[cfg(test)]
mod test {
    use net_header::NetHeader;

    use crate::{
        addr::BROADCAST_MAC,
        proto::{
            arp::wire::{ArpFrame, ArpHeader, ArpOperation, ArpReply, ArpRequest},
            eth::{EthernetFrame, EthernetHeader, EthernetPayload},
        },
    };

    #[test]
    fn ethernet_arp_e2e() {
        let alice_mac = [0, 1, 2, 3, 4, 5];
        let alice_ip = [0xa, 0xb, 0xc, 0xd];

        let bob_mac = [6, 7, 8, 9, 10, 11];
        let bob_ip = [0xe, 0xf, 0xe, 0xf];

        let sent_frame = EthernetFrame::new(
            alice_mac,
            bob_mac,
            EthernetPayload::Arp(ArpFrame::new(ArpOperation::Request(ArpRequest::new(
                alice_mac, alice_ip, bob_ip,
            )))),
        );

        let mut sent_bytes = [0u8; EthernetHeader::SIZE + ArpHeader::SIZE];
        let sent_size = sent_frame.write(&mut sent_bytes);
        assert_eq!(sent_size, sent_bytes.len());

        let recv_frame = EthernetFrame::parse(&sent_bytes).unwrap();
        assert_eq!(sent_frame, recv_frame);

        let EthernetPayload::Arp(ArpFrame {
            operation: ArpOperation::Request(arp_request),
        }) = recv_frame.into_payload()
        else {
            panic!("req recv_frame is invalid");
        };

        let arp_reply = ArpReply::new(&arp_request, bob_mac);
        let sent_frame = EthernetFrame::new(
            bob_mac,
            alice_mac,
            EthernetPayload::Arp(ArpFrame::new(ArpOperation::Reply(arp_reply))),
        );

        let mut sent_bytes = [0u8; EthernetHeader::SIZE + ArpHeader::SIZE];
        let sent_size = sent_frame.write(&mut sent_bytes);
        assert_eq!(sent_size, sent_bytes.len());

        let recv_frame = EthernetFrame::parse(&sent_bytes).unwrap();
        assert_eq!(sent_frame, recv_frame);

        let EthernetPayload::Arp(ArpFrame {
            operation: ArpOperation::Reply(_arp_reply),
        }) = recv_frame.into_payload()
        else {
            panic!("reply recv_frame is invalid");
        };
    }

    #[test]
    fn link_dst() {
        let alice_mac = [0, 1, 2, 3, 4, 5];
        let bob_mac = [6, 7, 8, 9, 10, 11];

        let request = ArpRequest::new(alice_mac, [10, 0, 0, 1], [10, 0, 0, 2]);
        let request_frame = ArpFrame::new(ArpOperation::Request(request.clone()));
        assert_eq!(request_frame.link_dst(), BROADCAST_MAC);

        let reply_frame = ArpFrame::new(ArpOperation::Reply(ArpReply::new(&request, bob_mac)));
        assert_eq!(reply_frame.link_dst(), alice_mac);
    }

    #[test]
    fn rejects_truncated_frame() {
        let request = ArpRequest::new([0, 1, 2, 3, 4, 5], [10, 0, 0, 1], [10, 0, 0, 2]);
        let frame = ArpFrame::new(ArpOperation::Request(request));

        let mut bytes = [0u8; ArpHeader::SIZE];
        let size = frame.write(&mut bytes);

        for len in 0..size {
            assert!(ArpFrame::parse(&bytes[..len]).is_err(), "len = {len}");
        }
    }
}
