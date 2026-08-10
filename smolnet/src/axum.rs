use std::io;
use std::net::SocketAddr;

use crate::net::tcp::{TcpListener, TcpStream};

#[derive(Debug)]
pub struct Listener(TcpListener);

impl From<TcpListener> for Listener {
    fn from(listener: TcpListener) -> Self {
        Listener(listener)
    }
}

impl From<Listener> for TcpListener {
    fn from(listener: Listener) -> Self {
        listener.0
    }
}

impl AsRef<TcpListener> for Listener {
    fn as_ref(&self) -> &TcpListener {
        &self.0
    }
}

impl axum::serve::Listener for Listener {
    type Io = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let stream = loop {
            match self.0.accept().await {
                Ok(stream) => break stream,
                Err(e) => tracing::error!(error = %e, "tcp accept"),
            }
        };

        let peer = stream.peer_addr();

        (stream, peer)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.0.local_addr())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddr(pub SocketAddr);

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<PeerAddr> for SocketAddr {
    fn from(peer: PeerAddr) -> SocketAddr {
        peer.0
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, Listener>>
    for PeerAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, Listener>) -> Self {
        PeerAddr(*stream.remote_addr())
    }
}
