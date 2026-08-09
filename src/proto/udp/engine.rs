use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use thiserror::Error;

use crate::{
    addr::Ipv4Addr,
    proto::{
        ipv4::{Ipv4Frame, Ipv4Payload},
        udp::wire::UdpFrame,
    },
    stack::tx::{TxPacket, TxQueue},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpSocketHandle(usize);

pub type UdpDatagram = (Ipv4Addr, u16, Vec<u8>);

struct UdpSocket {
    local_port: u16,

    rx_queue: VecDeque<UdpDatagram>,
    tx_queue: VecDeque<UdpDatagram>,
}

impl UdpSocket {
    fn new(local_port: u16) -> UdpSocket {
        UdpSocket {
            local_port,
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpSocketBindError {
    #[error("udp port {0} already in use")]
    AlreadyBound(u16),
}

#[derive(Default)]
pub struct UdpEngine {
    next_handle: usize,
    sockets: HashMap<u16, UdpSocket>,
    handle_ports: HashMap<usize, u16>,
}

impl UdpEngine {
    pub fn bind(&mut self, port: u16) -> Result<UdpSocketHandle, UdpSocketBindError> {
        if self.sockets.contains_key(&port) {
            return Err(UdpSocketBindError::AlreadyBound(port));
        }

        let handle = self.next_handle;
        self.next_handle += 1;

        self.sockets.insert(port, UdpSocket::new(port));
        self.handle_ports.insert(handle, port);

        tracing::info!(port, handle, "udp socket bound");

        Ok(UdpSocketHandle(handle))
    }

    pub fn is_bound(&self, port: u16) -> bool {
        self.sockets.contains_key(&port)
    }

    pub fn dispatch(&mut self, local_ip: Ipv4Addr, tx: &mut TxQueue) {
        for socket in self.sockets.values_mut() {
            while let Some((dst_addr, dst_port, payload)) = socket.tx_queue.pop_front() {
                tracing::trace!(
                    src_port = socket.local_port,
                    ?dst_addr,
                    dst_port,
                    len = payload.len(),
                    "udp datagram queued for transmission"
                );

                let udp_frame = UdpFrame::new(socket.local_port, dst_port, payload);
                let ipv4_frame = Ipv4Frame::new(local_ip, dst_addr, Ipv4Payload::Udp(udp_frame));

                tx.push(TxPacket::Ipv4(ipv4_frame));
            }
        }
    }

    pub fn poll_at(&self) -> Option<Instant> {
        None
    }

    pub fn process(&mut self, ipv4_frame: &Ipv4Frame<'_>, udp_frame: &UdpFrame<'_>) {
        let Some(socket) = self.sockets.get_mut(&udp_frame.dst_port()) else {
            tracing::debug!(
                src = ?ipv4_frame.src(),
                dst_port = udp_frame.dst_port(),
                "dropping udp datagram for an unbound port"
            );
            return;
        };

        tracing::trace!(
            src = ?ipv4_frame.src(),
            src_port = udp_frame.src_port(),
            dst_port = udp_frame.dst_port(),
            len = udp_frame.payload().len(),
            "udp datagram delivered to socket"
        );

        socket.rx_queue.push_back((
            *ipv4_frame.src(),
            udp_frame.src_port(),
            udp_frame.payload().to_vec(),
        ));
    }

    pub fn has_work(&self) -> bool {
        self.sockets
            .values()
            .any(|socket| !socket.rx_queue.is_empty() || !socket.tx_queue.is_empty())
    }

    fn socket_mut(&mut self, handle: &UdpSocketHandle) -> Option<&mut UdpSocket> {
        let port = *self.handle_ports.get(&handle.0)?;
        self.sockets.get_mut(&port)
    }

    pub fn recv(&mut self, handle: &UdpSocketHandle) -> Option<UdpDatagram> {
        self.socket_mut(handle)?.rx_queue.pop_front()
    }

    pub fn send(
        &mut self,
        handle: &UdpSocketHandle,
        dst_addr: Ipv4Addr,
        dst_port: u16,
        payload: Vec<u8>,
    ) {
        let id = handle.0;
        let Some(socket) = self.socket_mut(handle) else {
            tracing::warn!("couldn't find socket for handle {id} while attempting write");
            return;
        };

        socket.tx_queue.push_back((dst_addr, dst_port, payload));
    }

    pub fn close(&mut self, handle: UdpSocketHandle) {
        let Some(port) = self.handle_ports.remove(&handle.0) else {
            tracing::warn!("couldn't find socket for handle {} while closing", handle.0);
            return;
        };

        self.sockets.remove(&port);

        tracing::info!(port, handle = handle.0, "udp socket closed");
    }
}

#[cfg(test)]
mod test {
    use crate::{
        proto::{
            ipv4::{Ipv4Frame, Ipv4Payload},
            udp::{
                engine::{UdpEngine, UdpSocketBindError},
                wire::UdpFrame,
            },
        },
        stack::tx::{TxPacket, TxQueue},
    };

    const LOCAL_IP: [u8; 4] = [10, 30, 0, 2];
    const PEER_IP: [u8; 4] = [10, 30, 0, 3];

    fn inbound(dst_port: u16) -> (Ipv4Frame<'static>, UdpFrame<'static>) {
        let udp = UdpFrame::new(4000, dst_port, b"ping".to_vec());
        let ipv4 = Ipv4Frame::new(PEER_IP, LOCAL_IP, Ipv4Payload::Udp(udp.clone()));

        (ipv4, udp)
    }

    #[test]
    fn double_bind_is_rejected() {
        let mut engine = UdpEngine::default();

        engine.bind(7878).expect("first bind succeeds");
        assert_eq!(
            engine.bind(7878),
            Err(UdpSocketBindError::AlreadyBound(7878))
        );
    }

    #[test]
    fn delivers_to_bound_port_only() {
        let mut engine = UdpEngine::default();
        let handle = engine.bind(7878).unwrap();

        let (ipv4, udp) = inbound(7878);
        engine.process(&ipv4, &udp);

        assert_eq!(
            engine.recv(&handle),
            Some((PEER_IP, 4000, b"ping".to_vec()))
        );
        assert_eq!(engine.recv(&handle), None);

        let (ipv4, udp) = inbound(9999);
        engine.process(&ipv4, &udp);
        assert!(!engine.has_work());
    }

    #[test]
    fn dispatch_emits_ipv4_packets() {
        let mut engine = UdpEngine::default();
        let handle = engine.bind(7878).unwrap();

        engine.send(&handle, PEER_IP, 9000, b"pong".to_vec());
        assert!(engine.has_work());

        let mut tx = TxQueue::default();
        engine.dispatch(LOCAL_IP, &mut tx);

        assert!(!engine.has_work());

        let Some(TxPacket::Ipv4(frame)) = tx.pop() else {
            panic!("expected one ipv4 packet");
        };
        assert_eq!(frame.src(), &LOCAL_IP);
        assert_eq!(frame.dst(), &PEER_IP);

        let Ipv4Payload::Udp(udp) = frame.payload() else {
            panic!("expected a udp payload");
        };
        assert_eq!(udp.src_port(), 7878);
        assert_eq!(udp.dst_port(), 9000);
        assert_eq!(udp.payload(), b"pong");
    }

    #[test]
    fn close_releases_the_port() {
        let mut engine = UdpEngine::default();

        let handle = engine.bind(7878).unwrap();
        assert!(engine.is_bound(7878));

        engine.close(handle);
        assert!(!engine.is_bound(7878));

        engine.bind(7878).expect("port is free again after close");
    }
}
