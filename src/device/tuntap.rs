use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::task::{Context, Poll, ready};

use nix::fcntl::{OFlag, open};
use nix::libc;
use nix::sys::stat::Mode;
use thiserror::Error;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::device::{DeviceCapabilities, DeviceError};

pub const IFF_TUN: libc::c_short = 0x0001;
pub const IFF_TAP: libc::c_short = 0x0002;
pub const IFF_NO_PI: libc::c_short = 0x1000;

const IFNAMSIZ: usize = 16;

#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

nix::ioctl_write_int!(tun_set_iff, b'T', 202);

#[derive(Debug, Error)]
pub enum TunTapOpenError {
    #[error("invalid tun/tap interface name {0}")]
    InvalidInterfaceName(String),

    #[error("failed to open tun/tap device:\n{0}")]
    Io(nix::Error),

    #[error("failed to register the tun/tap device with the reactor:\n{0}")]
    Reactor(std::io::Error),
}

pub struct TunTapDevice {
    file: AsyncFd<File>,
    capabilities: DeviceCapabilities,
}

impl TunTapDevice {
    pub fn open(
        interface_name: &str,
        flags: libc::c_short,
        capabilities: DeviceCapabilities,
    ) -> Result<TunTapDevice, TunTapOpenError> {
        if interface_name.len() >= IFNAMSIZ {
            return Err(TunTapOpenError::InvalidInterfaceName(
                interface_name.to_owned(),
            ));
        }

        let fd: OwnedFd = open(
            "/dev/net/tun",
            OFlag::O_RDWR | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(TunTapOpenError::Io)?;

        let mut ifr = IfReq {
            name: [0; IFNAMSIZ],
            flags,
            _pad: [0; 22],
        };
        ifr.name[..interface_name.len()].copy_from_slice(interface_name.as_bytes());

        unsafe {
            tun_set_iff(fd.as_raw_fd(), &ifr as *const IfReq as u64).map_err(TunTapOpenError::Io)?
        };

        let file = AsyncFd::with_interest(File::from(fd), Interest::READABLE | Interest::WRITABLE)
            .map_err(TunTapOpenError::Reactor)?;

        Ok(TunTapDevice { file, capabilities })
    }

    pub fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities
    }

    pub fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError> {
        loop {
            match self.file.get_mut().read(data) {
                Ok(n) => {
                    tracing::trace!(len = n, "read frame from tun/tap");
                    return Ok(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(DeviceError::WouldBlock);
                }
                Err(e) => return Err(DeviceError::Io(Box::new(e))),
            }
        }
    }

    pub fn write_frame(&mut self, data: &[u8]) -> Result<(), DeviceError> {
        loop {
            match self.file.get_mut().write(data) {
                Ok(n) => {
                    debug_assert_eq!(n, data.len(), "tun/tap wrote partial frame");
                    tracing::trace!(len = n, "wrote frame to tun/tap");
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue, // EINTR: retry
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tracing::debug!("tun/tap transmit queue is full");
                    return Err(DeviceError::WouldBlock); // queue full: caller re-queues
                }
                Err(e) => return Err(DeviceError::Io(Box::new(e))),
            }
        }
    }

    pub fn poll_readable(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut guard = ready!(self.file.poll_read_ready_mut(cx))?;
        guard.clear_ready();

        Poll::Ready(Ok(()))
    }

    pub fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut guard = ready!(self.file.poll_write_ready_mut(cx))?;
        guard.clear_ready();

        Poll::Ready(Ok(()))
    }
}
