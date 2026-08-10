use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::task::{Context, Poll, ready};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::libc;
use nix::sys::socket::{
    AddressFamily, SockFlag, SockProtocol, SockType, SysControlAddr, connect, getsockopt, socket,
    sockopt::UtunIfname,
};
use nix::sys::uio::{readv, writev};
use thiserror::Error;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::device::{Device, DeviceCapabilities, DeviceError, Medium};

pub const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

const FAMILY_SIZE: usize = 4;

const AF_INET_PREFIX: [u8; FAMILY_SIZE] = (libc::AF_INET as u32).to_be_bytes();

#[derive(Debug, Error)]
pub enum UtunOpenError {
    #[error("failed to open a kernel control socket:\n{0}")]
    Socket(nix::Error),

    #[error("failed to resolve the {UTUN_CONTROL_NAME} kernel control:\n{0}")]
    Control(nix::Error),

    #[error("failed to attach to the utun control (are you root?):\n{0}")]
    Attach(nix::Error),

    #[error("failed to read back the interface name:\n{0}")]
    Name(nix::Error),

    #[error("failed to make the utun socket non blocking:\n{0}")]
    NonBlocking(nix::Error),

    #[error("failed to register the utun socket with the reactor:\n{0}")]
    Reactor(std::io::Error),
}

pub struct UtunDevice {
    socket: AsyncFd<OwnedFd>,
    name: String,
    capabilities: DeviceCapabilities,
}

impl UtunDevice {
    pub fn open(unit: Option<u32>, mtu: usize) -> Result<UtunDevice, UtunOpenError> {
        let fd = socket(
            AddressFamily::System,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::KextControl,
        )
        .map_err(UtunOpenError::Socket)?;

        let address = SysControlAddr::from_name(
            fd.as_raw_fd(),
            UTUN_CONTROL_NAME,
            unit.map(|unit| unit + 1).unwrap_or(0),
        )
        .map_err(UtunOpenError::Control)?;

        connect(fd.as_raw_fd(), &address).map_err(UtunOpenError::Attach)?;

        let name = getsockopt(&fd, UtunIfname)
            .map_err(UtunOpenError::Name)?
            .to_string_lossy()
            .into_owned();

        fcntl(fd.as_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .map_err(UtunOpenError::NonBlocking)?;

        let capabilities = DeviceCapabilities {
            medium: Medium::Ip,
            mtu,
        };

        tracing::info!(interface = name, mtu, "utun device opened");

        let socket = AsyncFd::with_interest(fd, Interest::READABLE | Interest::WRITABLE)
            .map_err(UtunOpenError::Reactor)?;

        Ok(UtunDevice {
            socket,
            name,
            capabilities,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Device for UtunDevice {
    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities
    }

    fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError> {
        let mut family = [0u8; FAMILY_SIZE];

        loop {
            let mut slices = [IoSliceMut::new(&mut family), IoSliceMut::new(data)];

            match readv(&self.socket, &mut slices) {
                Ok(read) if read < FAMILY_SIZE => {
                    tracing::debug!(read, "discarding a runt utun packet");
                    continue;
                }
                Ok(read) => {
                    if family != AF_INET_PREFIX {
                        tracing::trace!(?family, "discarding a non ipv4 utun packet");
                        continue;
                    }

                    let len = read - FAMILY_SIZE;
                    tracing::trace!(len, "read packet from utun");

                    return Ok(len);
                }
                Err(nix::Error::EINTR) => continue,
                Err(nix::Error::EWOULDBLOCK) => return Err(DeviceError::WouldBlock),
                Err(e) => return Err(DeviceError::Io(Box::new(e))),
            }
        }
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), DeviceError> {
        let slices = [IoSlice::new(&AF_INET_PREFIX), IoSlice::new(data)];

        loop {
            match writev(&self.socket, &slices) {
                Ok(written) => {
                    debug_assert_eq!(written, data.len() + FAMILY_SIZE);
                    tracing::trace!(len = data.len(), "wrote packet to utun");

                    return Ok(());
                }
                Err(nix::Error::EINTR) => continue,
                Err(nix::Error::EWOULDBLOCK) => {
                    tracing::debug!("utun transmit queue is full");
                    return Err(DeviceError::WouldBlock);
                }
                Err(e) => return Err(DeviceError::Io(Box::new(e))),
            }
        }
    }

    fn poll_readable(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut guard = ready!(self.socket.poll_read_ready_mut(cx))?;
        guard.clear_ready();

        Poll::Ready(Ok(()))
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut guard = ready!(self.socket.poll_write_ready_mut(cx))?;
        guard.clear_ready();

        Poll::Ready(Ok(()))
    }
}
