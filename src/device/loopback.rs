use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use crate::{
    device::{Device, DeviceCapabilities, DeviceError, MAX_FRAME_SIZE, Medium},
    proto::{eth::EthernetFrame, ipv4::Ipv4Frame},
};

#[derive(Default)]
struct Wire {
    queue: Mutex<VecDeque<Vec<u8>>>,
    waker: Mutex<Option<Waker>>,
}

impl Wire {
    fn push(&self, frame: Vec<u8>) {
        self.queue.lock().unwrap().push_back(frame);

        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    fn pop(&self) -> Option<Vec<u8>> {
        self.queue.lock().unwrap().pop_front()
    }

    fn drain(&self) -> Vec<Vec<u8>> {
        self.queue.lock().unwrap().drain(..).collect()
    }

    fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.len() > 0 {
            return Poll::Ready(());
        }

        *self.waker.lock().unwrap() = Some(cx.waker().clone());

        if self.len() > 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

pub struct LoopbackDevice {
    rx: Arc<Wire>,
    tx: Arc<Wire>,

    capabilities: DeviceCapabilities,

    writable: bool,
}

impl LoopbackDevice {
    pub fn new(medium: Medium) -> LoopbackDevice {
        LoopbackDevice {
            rx: Arc::new(Wire::default()),
            tx: Arc::new(Wire::default()),
            capabilities: DeviceCapabilities::new(medium),
            writable: true,
        }
    }

    pub fn pair(left: Medium, right: Medium) -> (LoopbackDevice, LoopbackDevice) {
        let one = Arc::new(Wire::default());
        let two = Arc::new(Wire::default());

        (
            LoopbackDevice {
                rx: one.clone(),
                tx: two.clone(),
                capabilities: DeviceCapabilities::new(left),
                writable: true,
            },
            LoopbackDevice {
                rx: two,
                tx: one,
                capabilities: DeviceCapabilities::new(right),
                writable: true,
            },
        )
    }

    pub fn with_mtu(mut self, mtu: usize) -> LoopbackDevice {
        self.capabilities.mtu = mtu;
        self
    }

    pub fn push_rx(&mut self, bytes: &[u8]) {
        self.rx.push(bytes.to_owned());
    }

    pub fn push_rx_eth_frame(&mut self, frame: &EthernetFrame<'_>) {
        let mut buffer = [0u8; MAX_FRAME_SIZE];
        let size = frame.write(&mut buffer);
        self.push_rx(&buffer[..size]);
    }

    pub fn push_rx_ipv4_frame(&mut self, frame: &Ipv4Frame<'_>) {
        let mut buffer = [0u8; MAX_FRAME_SIZE];
        let size = frame.write(&mut buffer);
        self.push_rx(&buffer[..size]);
    }

    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop()
    }

    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx.drain()
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
        let Some(frame) = self.rx.pop() else {
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
        self.tx.push(data.to_owned());

        Ok(())
    }

    fn poll_readable(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.rx.poll_ready(cx).map(Ok)
    }

    fn poll_writable(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
