use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::{net::shared::Shared, proto::udp::engine::UdpSocketHandle};

pub struct UdpSocket {
    shared: Arc<Shared>,
    handle: UdpSocketHandle,
}

impl UdpSocket {
    pub(crate) fn new(shared: Arc<Shared>, handle: UdpSocketHandle) -> UdpSocket {
        UdpSocket { shared, handle }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    pub fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut inner = self.shared.lock();

        if let Some((addr, port, payload)) = inner.stack.udp_recv(&self.handle) {
            let len = payload.len().min(buf.len());
            buf[..len].copy_from_slice(&payload[..len]);

            let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(addr), port));

            return Poll::Ready(Ok((len, peer)));
        }

        inner
            .wakers
            .udp_readable
            .insert(self.handle, cx.waker().clone());

        Poll::Pending
    }

    pub fn send_to(&self, buf: &[u8], addr: Ipv4Addr, port: u16) -> io::Result<usize> {
        self.shared
            .lock()
            .stack
            .udp_send(&self.handle, addr.octets(), port, buf.to_vec());

        self.shared.wake_driver();

        Ok(buf.len())
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.shared.lock().stack.udp_close(self.handle);
        self.shared.wake_driver();
    }
}
