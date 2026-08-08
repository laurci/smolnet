use std::collections::{HashMap, VecDeque};

use thiserror::Error;

use crate::{
    addr::Ipv4Addr,
    parser::{ipv4::Ipv4Frame, udp::UdpFrame},
    stack::StackIdentity,
};

#[derive(Clone, Copy)]
pub struct UdpSocketHandle(usize);

struct UdpSocket {
    local_port: u16,

    rx_queue: VecDeque<(Ipv4Addr, u16, Vec<u8>)>,
    tx_queue: VecDeque<(Ipv4Addr, u16, Vec<u8>)>,
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
    current_handle: usize,
    sockets: HashMap<u16, UdpSocket>,
    handle_ports: HashMap<usize, u16>,
}

impl UdpEngine {
    pub fn bind(&mut self, port: u16) -> Result<UdpSocketHandle, UdpSocketBindError> {
        if self.sockets.contains_key(&port) {
            return Err(UdpSocketBindError::AlreadyBound(port));
        }

        let handle = self.current_handle;
        self.current_handle += 1;

        let socket = UdpSocket::new(port);

        self.sockets.insert(port, socket);
        self.handle_ports.insert(handle, port);

        Ok(UdpSocketHandle(handle))
    }

    pub fn drain_tx_queues(&mut self) -> HashMap<Ipv4Addr, Vec<UdpFrame>> {
        let mut result: HashMap<Ipv4Addr, Vec<UdpFrame>> = HashMap::new();
        for handle in self.sockets.values_mut() {
            if handle.tx_queue.len() == 0 {
                continue;
            }

            while let Some(tx) = handle.tx_queue.pop_front() {
                let frame = UdpFrame::new(handle.local_port, tx.1, tx.2);

                if let Some(frames) = result.get_mut(&tx.0) {
                    frames.push(frame);
                } else {
                    result.insert(tx.0, vec![frame]);
                }
            }
        }

        result
    }

    pub fn has_work(&self) -> bool {
        for socket in self.sockets.values() {
            if socket.rx_queue.len() > 0 || socket.tx_queue.len() > 0 {
                return true;
            }
        }

        false
    }

    fn resolve_socket_from_handle_mut(
        &mut self,
        handle: &UdpSocketHandle,
    ) -> Option<&mut UdpSocket> {
        let Some(port) = self.handle_ports.get(&handle.0) else {
            return None;
        };

        self.sockets.get_mut(port)
    }

    pub fn recv(&mut self, handle: &UdpSocketHandle) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        let Some(socket) = self.resolve_socket_from_handle_mut(handle) else {
            return None;
        };

        socket.rx_queue.pop_front()
    }

    pub fn send(
        &mut self,
        handle: &UdpSocketHandle,
        dst_addr: Ipv4Addr,
        dst_port: u16,
        payload: Vec<u8>,
    ) {
        let Some(socket) = self.resolve_socket_from_handle_mut(handle) else {
            tracing::warn!(
                "couldn't find socket for handle {} while attempting write",
                handle.0
            );
            return;
        };

        socket.tx_queue.push_back((dst_addr, dst_port, payload));
    }
}

pub fn process_frame(
    _identity: &StackIdentity,
    udp_engine: &mut UdpEngine,
    ipv4_frame: &Ipv4Frame,
    udp_frame: &UdpFrame,
) {
    if let Some(handle) = udp_engine.sockets.get_mut(&udp_frame.dst_port()) {
        handle.rx_queue.push_back((
            ipv4_frame.src().clone(),
            udp_frame.src_port(),
            udp_frame.payload.clone(),
        ));
    }
}
