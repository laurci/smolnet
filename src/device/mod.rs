pub mod loopback;

#[cfg(all(target_os = "linux", feature = "tuntap"))]
pub mod tap;
#[cfg(all(target_os = "linux", feature = "tuntap"))]
pub mod tun;

#[cfg(all(target_os = "linux", feature = "tuntap"))]
mod tuntap;

use std::io;
use std::task::{Context, Poll};

use net_header::NetHeader;
use thiserror::Error;

use crate::{addr::MacAddr, proto::eth::EthernetHeader};

pub const MAX_FRAME_SIZE: usize = 2048;

pub const DEFAULT_MTU: usize = 1500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Medium {
    Ethernet { mac: MacAddr },
    Ip,
}

impl Medium {
    pub fn mac(&self) -> Option<MacAddr> {
        match self {
            Medium::Ethernet { mac } => Some(*mac),
            Medium::Ip => None,
        }
    }

    pub fn link_header_len(&self) -> usize {
        match self {
            Medium::Ethernet { .. } => EthernetHeader::SIZE,
            Medium::Ip => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceCapabilities {
    pub medium: Medium,
    pub mtu: usize,
}

impl DeviceCapabilities {
    pub fn new(medium: Medium) -> DeviceCapabilities {
        DeviceCapabilities {
            medium,
            mtu: DEFAULT_MTU,
        }
    }

    pub fn max_frame_size(&self) -> usize {
        (self.medium.link_header_len() + self.mtu).min(MAX_FRAME_SIZE)
    }
}

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("device io:\n{0}")]
    Io(Box<dyn std::error::Error + Send + Sync>),

    #[error("device read would block caller")]
    WouldBlock,

    #[error("provided output buffer is not big enough (need = {need}; got = {got})")]
    BufferTooSmall { need: usize, got: usize },
}

pub trait Device {
    fn capabilities(&self) -> DeviceCapabilities;

    fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError>;
    fn write_frame(&mut self, data: &[u8]) -> Result<(), DeviceError>;

    fn poll_readable(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}
