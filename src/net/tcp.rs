use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    net::shared::Shared,
    proto::tcp::{TcpListenerHandle, TcpSocketHandle, TcpState},
};

fn broken_pipe() -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}

pub struct TcpListener {
    shared: Arc<Shared>,
    handle: TcpListenerHandle,
    local: SocketAddrV4,
}

impl std::fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpListener")
            .field("local", &self.local)
            .finish()
    }
}

impl TcpListener {
    pub(crate) fn new(shared: Arc<Shared>, handle: TcpListenerHandle, port: u16) -> TcpListener {
        let ip = Ipv4Addr::from(shared.lock().stack.identity().ip);

        TcpListener {
            shared,
            handle,
            local: SocketAddrV4::new(ip, port),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.local)
    }

    pub async fn accept(&self) -> io::Result<TcpStream> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }

    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<TcpStream>> {
        let mut inner = self.shared.lock();

        if let Some(handle) = inner.stack.tcp_accept(&self.handle) {
            let peer = inner
                .stack
                .tcp_peer_addr(&handle)
                .map(|(ip, port)| SocketAddrV4::new(Ipv4Addr::from(ip), port))
                .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

            return Poll::Ready(Ok(TcpStream {
                shared: self.shared.clone(),
                handle,
                local: self.local,
                peer,
            }));
        }

        inner
            .wakers
            .accepting
            .insert(self.handle, cx.waker().clone());

        Poll::Pending
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.shared.lock().stack.tcp_close_listener(self.handle);
    }
}

pub struct TcpStream {
    shared: Arc<Shared>,
    handle: TcpSocketHandle,
    local: SocketAddrV4,
    peer: SocketAddrV4,
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpStream")
            .field("local", &self.local)
            .field("peer", &self.peer)
            .finish()
    }
}

impl TcpStream {
    pub(crate) async fn connect(
        shared: Arc<Shared>,
        addr: Ipv4Addr,
        port: u16,
    ) -> io::Result<TcpStream> {
        let (handle, local_ip) = {
            let mut inner = shared.lock();

            let handle = inner
                .stack
                .tcp_connect(addr.octets(), port, None)
                .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, e))?;

            (handle, Ipv4Addr::from(inner.stack.identity().ip))
        };

        shared.wake_driver();

        let settled = poll_fn(|cx| {
            let mut inner = shared.lock();

            match inner.stack.tcp_state(&handle) {
                Some(TcpState::SynSent) => {
                    inner.wakers.connecting.insert(handle, cx.waker().clone());
                    Poll::Pending
                }
                state => Poll::Ready(state),
            }
        })
        .await;

        match settled {
            None | Some(TcpState::Closed) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "tcp connection was refused or reset",
                ));
            }
            Some(_) => {}
        }

        let local_port = shared
            .lock()
            .stack
            .tcp_local_addr(&handle)
            .map(|(_, port)| port)
            .unwrap_or(0);

        Ok(TcpStream {
            shared,
            handle,
            local: SocketAddrV4::new(local_ip, local_port),
            peer: SocketAddrV4::new(addr, port),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.local)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.peer)
    }

    pub fn state(&self) -> Option<TcpState> {
        self.shared.lock().stack.tcp_state(&self.handle)
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.shared.lock();

        let read = inner
            .stack
            .tcp_recv(&self.handle, buf.initialize_unfilled());

        if read > 0 {
            buf.advance(read);
            drop(inner);

            self.shared.wake_driver();

            return Poll::Ready(Ok(()));
        }

        match inner.stack.tcp_state(&self.handle) {
            None => return Poll::Ready(Ok(())),
            Some(_) if inner.stack.tcp_peer_finished(&self.handle) => {
                return Poll::Ready(Ok(()));
            }
            Some(_) => {}
        }

        inner
            .wakers
            .readable
            .insert(self.handle, cx.waker().clone());

        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut inner = self.shared.lock();

        let written = inner.stack.tcp_send(&self.handle, buf);
        if written > 0 {
            drop(inner);
            self.shared.wake_driver();

            return Poll::Ready(Ok(written));
        }

        match inner.stack.tcp_state(&self.handle) {
            Some(TcpState::Established) | Some(TcpState::CloseWait) => {}
            _ => return Poll::Ready(Err(broken_pipe())),
        }

        inner
            .wakers
            .writable
            .insert(self.handle, cx.waker().clone());

        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.wake_driver();

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.lock().stack.tcp_close(&self.handle);
        self.shared.wake_driver();

        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.shared.lock().stack.tcp_close(&self.handle);
        self.shared.wake_driver();
    }
}
