pub mod tcp;
pub mod udp;

mod shared;

use std::future::poll_fn;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use crate::{
    device::{Device, DeviceCapabilities},
    net::{
        shared::Shared,
        tcp::{TcpListener, TcpStream},
        udp::UdpSocket,
    },
    stack::{Stack, StackIdentity},
};

pub use crate::proto::tcp::TcpState;

#[derive(Clone)]
pub struct Net {
    shared: Arc<Shared>,
}

pub struct Driver<D> {
    shared: Arc<Shared>,
    device: D,
}

pub fn build<D: Device>(identity: StackIdentity, device: D) -> (Net, Driver<D>) {
    let capabilities = device.capabilities();
    let stack = Stack::new(identity, capabilities);
    let shared = Shared::new(stack);

    (
        Net {
            shared: shared.clone(),
        },
        Driver { shared, device },
    )
}

impl Net {
    pub fn capabilities(&self) -> DeviceCapabilities {
        self.shared.lock().stack.capabilities()
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.shared.lock().stack.identity().ip)
    }

    pub fn tcp_listen(&self, port: u16) -> io::Result<TcpListener> {
        let handle = self
            .shared
            .lock()
            .stack
            .tcp_listen(port)
            .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e))?;

        Ok(TcpListener::new(self.shared.clone(), handle, port))
    }

    pub async fn tcp_connect(&self, addr: Ipv4Addr, port: u16) -> io::Result<TcpStream> {
        TcpStream::connect(self.shared.clone(), addr, port).await
    }

    pub fn udp_bind(&self, port: Option<u16>) -> io::Result<UdpSocket> {
        let handle = self
            .shared
            .lock()
            .stack
            .udp_bind(port)
            .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e))?;

        Ok(UdpSocket::new(self.shared.clone(), handle))
    }
}

impl<D: Device> Driver<D> {
    pub async fn run(mut self) -> io::Result<()> {
        let result = self.run_inner().await;

        self.shared.shutdown();

        result
    }

    async fn run_inner(&mut self) -> io::Result<()> {
        loop {
            let (deadline, wants_writable) = {
                let mut inner = self.shared.lock();

                inner
                    .stack
                    .poll(&mut self.device, Instant::now())
                    .map_err(io::Error::other)?;

                inner.wake_ready();

                (inner.stack.poll_at(), inner.stack.has_pending_tx())
            };

            let timer = async {
                match deadline {
                    Some(deadline) => {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await
                    }
                    None => std::future::pending().await,
                }
            };

            let device = &mut self.device;
            let shared = &self.shared;

            let device_ready = poll_fn(|cx| {
                if let Poll::Ready(result) = device.poll_readable(cx) {
                    return Poll::Ready(result);
                }

                if wants_writable && let Poll::Ready(result) = device.poll_writable(cx) {
                    return Poll::Ready(result);
                }

                Poll::Pending
            });

            tokio::select! {
                result = device_ready => result?,
                _ = timer => {}
                _ = shared.driver.notified() => {}
            }
        }
    }
}
