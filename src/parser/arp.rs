use net_header::{NetHeader, parse::HeaderParseError, write::HeaderWriteError};
use thiserror::Error;

use crate::{
    addr::{Ipv4Addr, MacAddr},
    parser::ethernet::ETHER_TYPE_IPV4,
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
        let header =
            ArpHeader::from_bytes(bytes).map_err(|e| ArpFrameParseError::HeaderParseError(e))?;

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
            ARP_OPERATION_REQUEST => {
                let request = ArpRequest { header };
                ArpOperation::Request(request)
            }
            ARP_OPERATION_REPLY => {
                let reply = ArpReply { header };
                ArpOperation::Reply(reply)
            }
            unknown_value => return Err(ArpFrameParseError::UnknownArpOperation(unknown_value)),
        };

        let frame = ArpFrame { operation };

        Ok(frame)
    }

    pub fn new(operation: ArpOperation) -> Self {
        ArpFrame { operation }
    }

    pub fn write(self, bytes: &mut [u8]) -> Result<usize, HeaderWriteError> {
        let header = match self.operation {
            ArpOperation::Request(req) => req.header,
            ArpOperation::Reply(reply) => reply.header,
        };

        let size = header.write(bytes)?;

        Ok(size)
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

            target_h_addr: [0u8; 6],
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

    use crate::parser::{
        arp::{ArpFrame, ArpHeader, ArpOperation, ArpReply, ArpRequest},
        ethernet::{EthernetFrame, EthernetHeader, EthernetPayload},
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
            EthernetPayload::Arp(ArpFrame::new(super::ArpOperation::Request(
                ArpRequest::new(alice_mac, alice_ip, bob_ip),
            ))),
        );

        let mut sent_bytes = [0u8; EthernetHeader::SIZE + ArpHeader::SIZE];
        let sent_size = sent_frame.clone().write(&mut sent_bytes).unwrap();
        assert_eq!(sent_size, sent_bytes.len());

        let recv_frame = EthernetFrame::parse(&sent_bytes).unwrap();
        assert_eq!(sent_frame, recv_frame);

        let EthernetPayload::Arp(ArpFrame {
            operation: ArpOperation::Request(arp_request),
        }) = recv_frame.payload.clone()
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
        let sent_size = sent_frame.clone().write(&mut sent_bytes).unwrap();
        assert_eq!(sent_size, sent_bytes.len());

        let recv_frame = EthernetFrame::parse(&sent_bytes).unwrap();
        assert_eq!(sent_frame, recv_frame);

        let EthernetPayload::Arp(ArpFrame {
            operation: ArpOperation::Reply(_arp_reply),
        }) = recv_frame.payload.clone()
        else {
            panic!("reply recv_frame is invalid");
        };
    }
}
