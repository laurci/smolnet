use std::io;
use std::net::SocketAddr;

use tokio::net::{ToSocketAddrs, UdpSocket};

use crate::{
    id::NodeId,
    wire::{Datagram, ENDPOINT_SIZE, HEADER_SIZE, MessageType, as_ipv4_endpoint, encode_endpoint},
};

const REFLECTOR_BUFFER: usize = 256;

pub struct Reflector {
    socket: UdpSocket,
    node: NodeId,
}

impl Reflector {
    pub async fn bind(addr: impl ToSocketAddrs) -> io::Result<Reflector> {
        let socket = UdpSocket::bind(addr).await?;

        tracing::info!(local = %socket.local_addr()?, "reflector bound");

        Ok(Reflector {
            socket,
            node: NodeId::random(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    pub async fn run(self) -> io::Result<()> {
        let mut inbound = [0u8; REFLECTOR_BUFFER];
        let mut outbound = [0u8; HEADER_SIZE + ENDPOINT_SIZE];

        loop {
            let (size, from) = self.socket.recv_from(&mut inbound).await?;

            let datagram = match Datagram::parse(&inbound[..size]) {
                Ok(datagram) => datagram,
                Err(e) => {
                    tracing::debug!(%from, "ignoring datagram: {e}");
                    continue;
                }
            };

            if datagram.message != MessageType::Probe {
                tracing::debug!(%from, message = ?datagram.message, "ignoring non probe");
                continue;
            }

            let Some(endpoint) = as_ipv4_endpoint(from) else {
                tracing::debug!(%from, "cannot reflect a non ipv4 endpoint");
                continue;
            };

            let payload = encode_endpoint(endpoint);
            let reply = Datagram::new(
                MessageType::Reflection,
                datagram.network,
                self.node,
                &payload[..],
            );

            let len = reply.write(&mut outbound);
            self.socket.send_to(&outbound[..len], from).await?;

            tracing::info!(
                %from,
                network = %datagram.network,
                node = ?datagram.sender,
                "reflected endpoint"
            );
        }
    }
}
