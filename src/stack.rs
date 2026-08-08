use std::collections::VecDeque;

use thiserror::Error;

use crate::{
    addr::{Ipv4Addr, MacAddr},
    device::{Device, DeviceError, MAX_FRAME_SIZE},
    handler::{
        arp::{self, ArpCache},
        ipv4,
    },
    parser::ethernet::{EthernetFrame, EthernetFrameParseEerror, EthernetPayload},
};

#[derive(Debug, Error)]
pub enum StackError {
    #[error("device reported error while processing frame:\n{0}")]
    DeviceError(DeviceError),
}

#[derive(Debug, Error)]
pub enum StackFrameProcessError {
    #[error("frame parse error:\n{0}")]
    EthernetFrameParseEerror(EthernetFrameParseEerror),
}

#[derive(Debug)]
pub struct StackIdentity {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
}

pub struct Stack {
    identity: StackIdentity,
    arp_cache: ArpCache,
    egress_queue: VecDeque<Vec<u8>>,
}

impl Stack {
    pub fn new(identity: StackIdentity) -> Stack {
        let arp_cache = ArpCache::default();

        Stack {
            identity,
            arp_cache,
            egress_queue: VecDeque::new(),
        }
    }

    pub fn poll<D: Device>(&mut self, device: &mut D) -> Result<(), StackError> {
        let mut read_buf = [0u8; MAX_FRAME_SIZE];

        let output = loop {
            match device.read_frame(&mut read_buf) {
                Ok(size) => {
                    let frame = &read_buf[..size];
                    if let Err(e) = self.process_frame(frame) {
                        tracing::warn!("error while processing frame: {e}");
                    }
                }
                Err(DeviceError::WouldBlock) => {
                    break Ok(());
                }
                Err(device_error) => {
                    break Err(StackError::DeviceError(device_error));
                }
            }
        };

        if let Err(flush_error) = self.flush_egress(device) {
            if output.is_err() {
                tracing::warn!("device error while flushing egress queue {flush_error}");
            } else {
                return Err(StackError::DeviceError(flush_error));
            }
        }

        output
    }

    fn flush_egress<D: Device>(&mut self, device: &mut D) -> Result<(), DeviceError> {
        while let Some(frame) = self.egress_queue.pop_front() {
            match device.write_frame(&frame) {
                Err(DeviceError::WouldBlock) => {
                    self.egress_queue.push_front(frame);
                    break;
                }
                Err(e) => {
                    self.egress_queue.push_front(frame);
                    return Err(e);
                }
                Ok(_) => {}
            }
        }
        Ok(())
    }

    pub fn has_pending_egress(&self) -> bool {
        self.egress_queue.len() > 0
    }

    fn queue_egress_frame(&mut self, frame: &[u8]) {
        self.egress_queue.push_back(frame.to_owned());
    }

    fn queue_egress_eth_frame(&mut self, frame: EthernetFrame) {
        let mut write_buf = [0u8; MAX_FRAME_SIZE];

        let size = frame.write(&mut write_buf);
        debug_assert!(size.is_ok(), "failed to serialize eth frame for egress");
        let size = size.expect("failed to serialize eth frame for egress");

        self.queue_egress_frame(&write_buf[..size]);
    }

    pub fn process_frame(&mut self, frame: &[u8]) -> Result<(), StackFrameProcessError> {
        let eth_frame = EthernetFrame::parse(frame)
            .map_err(|e| StackFrameProcessError::EthernetFrameParseEerror(e))?;

        match &eth_frame.payload {
            EthernetPayload::Arp(arp_frame) => {
                if let Some(frame) =
                    arp::process_frame(&self.identity, &mut self.arp_cache, arp_frame)
                {
                    let frame = eth_frame.reply(&self.identity, EthernetPayload::Arp(frame));
                    self.queue_egress_eth_frame(frame);
                }
            }
            EthernetPayload::Ipv4(ipv4_frame) => {
                let frames = ipv4::process_frame(&self.identity, ipv4_frame);
                for frame in frames {
                    let frame = eth_frame.reply(&self.identity, EthernetPayload::Ipv4(frame));
                    self.queue_egress_eth_frame(frame);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        addr::MacAddr,
        device::mock::MockDevice,
        parser::{
            arp::{ArpFrame, ArpOperation, ArpRequest},
            ethernet::{EthernetFrame, EthernetPayload},
        },
        stack::{Stack, StackIdentity},
    };

    const ALICE_IDENTITY: StackIdentity = StackIdentity {
        mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        ip: [10, 30, 0, 2],
    };

    const BOB_IDENTITY: StackIdentity = StackIdentity {
        mac: [0x19, 0x29, 0x39, 0x49, 0x59, 0x69],
        ip: [10, 30, 0, 3],
    };

    const BROADCAST_MAC: MacAddr = [0xff; 6];

    #[test]
    fn arp_e2e() {
        let mut alice_device = MockDevice::new();
        let mut alice_stack = Stack::new(ALICE_IDENTITY);

        let mut bob_device = MockDevice::new();
        let mut bob_stack = Stack::new(BOB_IDENTITY);

        let arp_req_frame = EthernetFrame::new(
            ALICE_IDENTITY.mac,
            BROADCAST_MAC,
            EthernetPayload::Arp(ArpFrame::new(ArpOperation::Request(ArpRequest::new(
                ALICE_IDENTITY.mac,
                ALICE_IDENTITY.ip,
                BOB_IDENTITY.ip,
            )))),
        );

        bob_device.push_rx_eth_frame(&arp_req_frame);

        bob_stack
            .poll(&mut bob_device)
            .expect("bob stack should poll successfully");

        assert_eq!(
            bob_stack.arp_cache.lookup(&ALICE_IDENTITY.ip),
            Some(&ALICE_IDENTITY.mac)
        );

        let out_frame = bob_device
            .pop_tx_frame()
            .expect("bob should have a frame ready to send");

        let reply_frame =
            EthernetFrame::parse(&out_frame).expect("reply frame should be valid eth frame");
        assert_eq!(reply_frame.src(), &BOB_IDENTITY.mac);
        assert_eq!(reply_frame.dst(), &ALICE_IDENTITY.mac);

        alice_device.push_rx_frame(&out_frame);

        alice_stack
            .poll(&mut alice_device)
            .expect("bob stack should poll successfully");

        assert_eq!(
            alice_stack.arp_cache.lookup(&BOB_IDENTITY.ip),
            Some(&BOB_IDENTITY.mac)
        );
    }
}
