use std::collections::VecDeque;

use crate::{
    device::{Device, DeviceError, MAX_FRAME_SIZE},
    parser::ethernet::EthernetFrame,
};

pub struct MockDevice {
    rx_buffer: VecDeque<Vec<u8>>,
    tx_buffer: VecDeque<Vec<u8>>,
}

impl MockDevice {
    pub fn new() -> MockDevice {
        MockDevice {
            rx_buffer: VecDeque::new(),
            tx_buffer: VecDeque::new(),
        }
    }
}

impl MockDevice {
    pub fn push_rx_frame(&mut self, data: &[u8]) {
        self.rx_buffer.push_back(data.to_owned());
    }

    pub fn push_rx_eth_frame(&mut self, frame: &EthernetFrame) {
        let mut buffer = [0u8; MAX_FRAME_SIZE];
        let size = frame
            .clone()
            .write(&mut buffer)
            .expect("failed to serialize ethernet frame");
        self.push_rx_frame(&buffer[..size]);
    }

    pub fn pop_tx_frame(&mut self) -> Option<Vec<u8>> {
        self.tx_buffer.pop_front()
    }
}

impl Device for MockDevice {
    fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError> {
        let Some(frame) = self.rx_buffer.pop_front() else {
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
        let frame = data.to_owned();
        self.tx_buffer.push_back(frame);
        Ok(())
    }

    fn wait(
        &mut self,
        _timeout: Option<std::time::Duration>,
        _wait_writable: bool,
    ) -> Result<(), DeviceError> {
        Ok(())
    }
}
