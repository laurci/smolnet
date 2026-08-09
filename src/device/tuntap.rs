use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::Duration;

use nix::fcntl::{OFlag, open};
use nix::libc;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::stat::Mode;
use thiserror::Error;

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
}

pub struct TunTapDevice {
    file: File,
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

        Ok(TunTapDevice {
            file: fd.into(),
            capabilities,
        })
    }

    pub fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities
    }

    pub fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError> {
        loop {
            match self.file.read(data) {
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
            match self.file.write(data) {
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

    pub fn wait(
        &mut self,
        timeout: Option<Duration>,
        wait_writable: bool,
    ) -> Result<(), DeviceError> {
        let mut events = PollFlags::POLLIN;
        if wait_writable {
            events |= PollFlags::POLLOUT;
        }

        let timeout = match timeout {
            None => PollTimeout::NONE,
            Some(d) => {
                let ms = d.as_millis().max(1);
                PollTimeout::try_from(ms).unwrap_or(PollTimeout::MAX)
            }
        };

        let mut fds = [PollFd::new(self.file.as_fd(), events)];
        match poll(&mut fds, timeout) {
            Ok(_) | Err(nix::errno::Errno::EINTR) => Ok(()),
            Err(e) => Err(DeviceError::Io(Box::new(e))),
        }
    }
}
