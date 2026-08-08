use std::fs::File;
use std::io::{Read, Write};

use crate::device::{Device, DeviceError};

use nix::fcntl::{OFlag, open};
use nix::libc;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::stat::Mode;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use thiserror::Error;

const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

nix::ioctl_write_int!(tun_set_iff, b'T', 202);

#[derive(Debug, Error)]
pub enum TapDeviceOpenError {
    #[error("invalid tap interface name {0}")]
    InvalidInterfaceName(String),

    #[error("failed to open tap device:\n{0}")]
    Io(nix::Error),
}

pub struct TapDevice {
    file: File,
}

impl TapDevice {
    pub fn open(interface_name: &str) -> Result<TapDevice, TapDeviceOpenError> {
        if interface_name.len() >= IFNAMSIZ {
            return Err(TapDeviceOpenError::InvalidInterfaceName(
                interface_name.to_owned(),
            ));
        }

        let fd: OwnedFd = open(
            "/dev/net/tun",
            OFlag::O_RDWR | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| TapDeviceOpenError::Io(e))?;

        let mut ifr = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TAP | IFF_NO_PI,
            _pad: [0; 22],
        };
        ifr.name[..interface_name.len()].copy_from_slice(interface_name.as_bytes());

        unsafe {
            tun_set_iff(fd.as_raw_fd(), &ifr as *const IfReq as u64)
                .map_err(|e| TapDeviceOpenError::Io(e))?
        };

        Ok(TapDevice { file: fd.into() })
    }
}

impl Device for TapDevice {
    fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError> {
        loop {
            match self.file.read(data) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(DeviceError::WouldBlock);
                }
                Err(e) => return Err(DeviceError::Io(Box::new(e))),
            }
        }
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), DeviceError> {
        loop {
            match self.file.write(data) {
                Ok(n) => {
                    debug_assert_eq!(n, data.len(), "TAP wrote partial frame");
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue, // EINTR: retry
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(DeviceError::WouldBlock); // queue full: caller re-queues
                }
                Err(e) => return Err(DeviceError::Io(Box::new(e))),
            }
        }
    }

    fn wait(
        &mut self,
        timeout: Option<std::time::Duration>,
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
