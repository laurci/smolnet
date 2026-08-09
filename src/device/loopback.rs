use std::{collections::VecDeque, time::Duration};

use crate::{
    device::{Device, DeviceCapabilities, DeviceError, MAX_FRAME_SIZE, Medium},
    proto::{eth::EthernetFrame, ipv4::Ipv4Frame},
};

pub struct LoopbackDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,

    capabilities: DeviceCapabilities,

    writable: bool,
}

impl LoopbackDevice {
    pub fn new(medium: Medium) -> LoopbackDevice {
        LoopbackDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            capabilities: DeviceCapabilities::new(medium),
            writable: true,
        }
    }

    pub fn with_mtu(mut self, mtu: usize) -> LoopbackDevice {
        self.capabilities.mtu = mtu;
        self
    }

    pub fn push_rx(&mut self, bytes: &[u8]) {
        self.rx.push_back(bytes.to_owned());
    }

    pub fn push_rx_eth_frame(&mut self, frame: &EthernetFrame) {
        let mut buffer = [0u8; MAX_FRAME_SIZE];
        let size = frame.write(&mut buffer);
        self.push_rx(&buffer[..size]);
    }

    pub fn push_rx_ipv4_frame(&mut self, frame: &Ipv4Frame) {
        let mut buffer = [0u8; MAX_FRAME_SIZE];
        let size = frame.write(&mut buffer);
        self.push_rx(&buffer[..size]);
    }

    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx.drain(..).collect()
    }

    pub fn tx_len(&self) -> usize {
        self.tx.len()
    }

    pub fn rx_len(&self) -> usize {
        self.rx.len()
    }

    pub fn set_writable(&mut self, writable: bool) {
        self.writable = writable;
    }
}

impl Device for LoopbackDevice {
    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities
    }

    fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError> {
        let Some(frame) = self.rx.pop_front() else {
            return Err(DeviceError::WouldBlock);
        };

        if data.len() < frame.len() {
            return Err(DeviceError::BufferTooSmall {
                need: frame.len(),
                got: data.len(),
            });
        }

        data[..frame.len()].copy_from_slice(&frame);

        Ok(frame.len())
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), DeviceError> {
        if !self.writable {
            tracing::trace!("loopback device is not writable");
            return Err(DeviceError::WouldBlock);
        }

        tracing::trace!(len = data.len(), "wrote frame to loopback");
        self.tx.push_back(data.to_owned());

        Ok(())
    }

    fn wait(
        &mut self,
        _timeout: Option<Duration>,
        _wait_writable: bool,
    ) -> Result<(), DeviceError> {
        Ok(())
    }
}
