pub mod rx;
pub mod tx;

use std::time::Instant;

use thiserror::Error;

use crate::{
    addr::Ipv4Addr,
    device::{Device, DeviceCapabilities, DeviceError, MAX_FRAME_SIZE, Medium},
    proto::{
        arp::engine::ArpEngine,
        tcp::{
            TcpConnectError, TcpEngine, TcpListenError, TcpListenerHandle, TcpSocketHandle,
            TcpState,
        },
        udp::engine::{UdpDatagram, UdpEngine, UdpSocketBindError, UdpSocketHandle},
    },
    stack::tx::TxQueue,
};

const EPHEMERAL_PORT_START: u16 = 50000;
const EPHEMERAL_PORT_END: u16 = 60999;

pub const IPV4_BROADCAST: Ipv4Addr = [255, 255, 255, 255];

#[derive(Debug, Error)]
pub enum StackError {
    #[error("device reported error while processing frame:\n{0}")]
    DeviceError(DeviceError),
}

#[derive(Debug, Clone, Copy)]
pub struct StackIdentity {
    pub ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

impl StackIdentity {
    pub fn next_hop(&self, dst: &Ipv4Addr) -> Ipv4Addr {
        let netmask_value = u32::from_be_bytes(self.netmask);
        let ip_value = u32::from_be_bytes(self.ip);
        let dst_value = u32::from_be_bytes(*dst);

        if dst_value & netmask_value == ip_value & netmask_value {
            return *dst;
        }

        self.gateway
    }

    pub fn subnet_broadcast(&self) -> Ipv4Addr {
        let netmask_value = u32::from_be_bytes(self.netmask);
        let ip_value = u32::from_be_bytes(self.ip);

        (ip_value | !netmask_value).to_be_bytes()
    }

    pub fn is_broadcast(&self, dst: &Ipv4Addr) -> bool {
        dst == &IPV4_BROADCAST || dst == &self.subnet_broadcast()
    }

    pub fn accepts_dst(&self, dst: &Ipv4Addr) -> bool {
        dst == &self.ip || self.is_broadcast(dst)
    }
}

pub struct Stack {
    pub(crate) identity: StackIdentity,

    pub(crate) capabilities: DeviceCapabilities,

    pub(crate) arp: Option<ArpEngine>,
    pub(crate) udp: UdpEngine,
    pub(crate) tcp: TcpEngine,

    pub(crate) tx: TxQueue,

    next_ephemeral_port: u16,
    next_ipv4_id: u16,
}

impl Stack {
    pub fn new(identity: StackIdentity, capabilities: DeviceCapabilities) -> Stack {
        let arp = match capabilities.medium {
            Medium::Ethernet { mac } => Some(ArpEngine::new(mac, identity.ip)),
            Medium::Ip => None,
        };

        tracing::info!(
            ip = ?identity.ip,
            gateway = ?identity.gateway,
            netmask = ?identity.netmask,
            medium = ?capabilities.medium,
            mtu = capabilities.mtu,
            arp = arp.is_some(),
            "stack created"
        );

        Stack {
            identity,

            capabilities,

            arp,
            udp: UdpEngine::default(),
            tcp: TcpEngine::default(),

            tx: TxQueue::default(),

            next_ephemeral_port: rand::random_range(EPHEMERAL_PORT_START..=EPHEMERAL_PORT_END),
            next_ipv4_id: rand::random(),
        }
    }

    pub fn identity(&self) -> &StackIdentity {
        &self.identity
    }

    pub fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities
    }

    pub fn poll<D: Device + ?Sized>(
        &mut self,
        device: &mut D,
        now: Instant,
    ) -> Result<(), StackError> {
        let mut read_buf = [0u8; MAX_FRAME_SIZE];

        let outcome = loop {
            match device.read_frame(&mut read_buf) {
                Ok(size) => {
                    if let Err(e) = self.process_frame(&read_buf[..size], now) {
                        tracing::debug!(len = size, "discarding malformed frame: {e}");
                    }
                }
                Err(DeviceError::WouldBlock) => break Ok(()),
                Err(device_error) => break Err(StackError::DeviceError(device_error)),
            }
        };

        if let Some(arp) = self.arp.as_mut() {
            arp.dispatch(now, &mut self.tx);
        }
        self.udp.dispatch(self.identity.ip, &mut self.tx);
        self.tcp.dispatch(now, &mut self.tx);

        if let Err(flush_error) = self.flush_tx(device, now) {
            if outcome.is_err() {
                tracing::warn!("device error while flushing egress queue: {flush_error}");
            } else {
                return Err(StackError::DeviceError(flush_error));
            }
        }

        outcome
    }

    pub fn poll_at(&self) -> Option<Instant> {
        [
            self.arp.as_ref().and_then(ArpEngine::poll_at),
            self.udp.poll_at(),
            self.tcp.poll_at(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn wait<D: Device + ?Sized>(
        &mut self,
        device: &mut D,
        now: Instant,
    ) -> Result<(), StackError> {
        if self.has_work() {
            return Ok(());
        }

        let timeout = self
            .poll_at()
            .map(|deadline| deadline.saturating_duration_since(now));

        let wait_writable = !self.tx.is_empty();

        device
            .wait(timeout, wait_writable)
            .map_err(StackError::DeviceError)
    }

    fn has_work(&self) -> bool {
        !self.tx.is_empty() || self.udp.has_work() || self.tcp.has_work()
    }

    fn alloc_ephemeral_port(&mut self) -> u16 {
        self.next_ephemeral_port += 1;
        if self.next_ephemeral_port > EPHEMERAL_PORT_END {
            self.next_ephemeral_port = EPHEMERAL_PORT_START;
        };

        self.next_ephemeral_port
    }

    pub(crate) fn next_ipv4_id(&mut self) -> u16 {
        let id = self.next_ipv4_id;
        self.next_ipv4_id = self.next_ipv4_id.wrapping_add(1);

        id
    }

    pub fn udp_bind(&mut self, port: Option<u16>) -> Result<UdpSocketHandle, UdpSocketBindError> {
        let port = port.unwrap_or_else(|| self.alloc_ephemeral_port());
        self.udp.bind(port).inspect_err(|e| {
            tracing::warn!(port, "udp bind failed: {e}");
        })
    }

    pub fn udp_recv(&mut self, handle: &UdpSocketHandle) -> Option<UdpDatagram> {
        self.udp.recv(handle)
    }

    pub fn udp_send(
        &mut self,
        handle: &UdpSocketHandle,
        dst_addr: Ipv4Addr,
        dst_port: u16,
        payload: Vec<u8>,
    ) {
        self.udp.send(handle, dst_addr, dst_port, payload);
    }

    pub fn udp_close(&mut self, handle: UdpSocketHandle) {
        self.udp.close(handle);
    }

    pub fn tcp_listen(&mut self, port: u16) -> Result<TcpListenerHandle, TcpListenError> {
        self.tcp.listen(port)
    }

    pub fn tcp_accept(&mut self, listener: &TcpListenerHandle) -> Option<TcpSocketHandle> {
        self.tcp.accept(listener)
    }

    pub fn tcp_close_listener(&mut self, listener: TcpListenerHandle) {
        self.tcp.close_listener(listener);
    }

    pub fn tcp_connect(
        &mut self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        local_port: Option<u16>,
    ) -> Result<TcpSocketHandle, TcpConnectError> {
        let local_port = local_port.unwrap_or_else(|| self.alloc_ephemeral_port());

        self.tcp.connect(
            self.identity.ip,
            local_port,
            remote_ip,
            remote_port,
            Instant::now(),
            &mut self.tx,
        )
    }

    pub fn tcp_state(&self, handle: &TcpSocketHandle) -> Option<TcpState> {
        self.tcp.state(handle)
    }

    pub fn tcp_can_recv(&self, handle: &TcpSocketHandle) -> bool {
        self.tcp.can_recv(handle)
    }

    pub fn tcp_peer_finished(&self, handle: &TcpSocketHandle) -> bool {
        self.tcp.peer_finished(handle)
    }

    pub fn tcp_recv(&mut self, handle: &TcpSocketHandle, buf: &mut [u8]) -> usize {
        self.tcp.recv(handle, buf)
    }

    pub fn tcp_send_capacity(&self, handle: &TcpSocketHandle) -> usize {
        self.tcp.send_capacity(handle)
    }

    pub fn tcp_send(&mut self, handle: &TcpSocketHandle, data: &[u8]) -> usize {
        self.tcp.send(handle, data)
    }

    pub fn tcp_close(&mut self, handle: &TcpSocketHandle) {
        self.tcp.close(handle);
    }
}

#[cfg(test)]
mod test {
    use crate::stack::StackIdentity;

    const IDENTITY: StackIdentity = StackIdentity {
        ip: [10, 30, 0, 2],
        netmask: [0xff, 0xff, 0xff, 0x00],
        gateway: [10, 30, 0, 1],
    };

    #[test]
    fn next_hop() {
        assert_eq!(IDENTITY.next_hop(&[10, 30, 0, 5]), [10, 30, 0, 5]);
        assert_eq!(IDENTITY.next_hop(&[8, 8, 8, 8]), IDENTITY.gateway);
        assert_eq!(IDENTITY.next_hop(&[10, 30, 0, 255]), [10, 30, 0, 255]);
        assert_eq!(IDENTITY.next_hop(&[10, 30, 1, 0]), IDENTITY.gateway);
    }

    #[test]
    fn accepted_destinations() {
        assert!(IDENTITY.accepts_dst(&[10, 30, 0, 2]));
        assert!(IDENTITY.accepts_dst(&[255, 255, 255, 255]));
        assert!(IDENTITY.accepts_dst(&[10, 30, 0, 255]));

        assert!(!IDENTITY.accepts_dst(&[10, 30, 0, 3]));
        assert!(!IDENTITY.accepts_dst(&[10, 30, 1, 255]));
    }

    #[test]
    fn subnet_broadcast() {
        assert_eq!(IDENTITY.subnet_broadcast(), [10, 30, 0, 255]);

        let sixteen = StackIdentity {
            netmask: [0xff, 0xff, 0x00, 0x00],
            ..IDENTITY
        };
        assert_eq!(sixteen.subnet_broadcast(), [10, 30, 255, 255]);
    }
}
