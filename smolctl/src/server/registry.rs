use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use smolmesh::{NetworkId, NodeId};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::proto::{PeerGone, PeerState, ServerMessage, server_message};

pub const DEFAULT_SUBNET: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 0);

pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

const FIRST_HOST: u32 = 2;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("network {0} has no addresses left")]
    Exhausted(NetworkId),
}

#[derive(Debug, Clone)]
pub struct Member {
    pub node: NodeId,
    pub ip: Ipv4Addr,
    pub endpoints: Vec<SocketAddr>,
    pub online: bool,
}

impl Member {
    fn to_state(&self) -> PeerState {
        PeerState {
            node: self.node.to_string(),
            ip: self.ip.to_string(),
            endpoints: self.endpoints.iter().map(SocketAddr::to_string).collect(),
            online: self.online,
        }
    }
}

struct Network {
    subnet: Ipv4Addr,
    netmask: Ipv4Addr,
    members: HashMap<NodeId, Member>,
    streams: HashMap<NodeId, mpsc::Sender<ServerMessage>>,
}

impl Network {
    fn new(subnet: Ipv4Addr, netmask: Ipv4Addr) -> Network {
        Network {
            subnet,
            netmask,
            members: HashMap::new(),
            streams: HashMap::new(),
        }
    }

    fn allocate(&self, network: NetworkId) -> Result<Ipv4Addr, RegistryError> {
        let base = u32::from(self.subnet) & u32::from(self.netmask);
        let broadcast = base | !u32::from(self.netmask);

        let taken: Vec<u32> = self.members.values().map(|m| u32::from(m.ip)).collect();

        (base + FIRST_HOST..broadcast)
            .find(|candidate| !taken.contains(candidate))
            .map(Ipv4Addr::from)
            .ok_or(RegistryError::Exhausted(network))
    }
}

#[derive(Clone)]
pub struct Registry {
    networks: Arc<Mutex<HashMap<NetworkId, Network>>>,
    subnet: Ipv4Addr,
    netmask: Ipv4Addr,
}

pub struct Joined {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub peers: Vec<PeerState>,
    pub updates: mpsc::Receiver<ServerMessage>,
}

impl Registry {
    pub fn new(subnet: Ipv4Addr, netmask: Ipv4Addr) -> Registry {
        Registry {
            networks: Arc::new(Mutex::new(HashMap::new())),
            subnet,
            netmask,
        }
    }

    pub fn join(
        &self,
        network: NetworkId,
        node: NodeId,
        capacity: usize,
    ) -> Result<Joined, RegistryError> {
        let mut networks = self.networks.lock().unwrap();

        let entry = networks
            .entry(network)
            .or_insert_with(|| Network::new(self.subnet, self.netmask));

        let ip = match entry.members.get(&node) {
            Some(member) => member.ip,
            None => entry.allocate(network)?,
        };

        let member = entry.members.entry(node).or_insert_with(|| Member {
            node,
            ip,
            endpoints: vec![],
            online: false,
        });

        member.online = true;
        let state = member.to_state();

        let peers: Vec<PeerState> = entry
            .members
            .values()
            .filter(|member| member.node != node)
            .map(Member::to_state)
            .collect();

        let (sender, updates) = mpsc::channel(capacity);
        entry.streams.insert(node, sender);

        let netmask = entry.netmask;

        broadcast(entry, node, server_message::Body::Peer(state));

        tracing::info!(%network, %ip, node = ?node, peers = peers.len(), "node joined");

        Ok(Joined {
            ip,
            netmask,
            peers,
            updates,
        })
    }

    pub fn publish(&self, network: NetworkId, node: NodeId, endpoints: Vec<SocketAddr>) {
        let mut networks = self.networks.lock().unwrap();

        let Some(entry) = networks.get_mut(&network) else {
            return;
        };

        let Some(member) = entry.members.get_mut(&node) else {
            return;
        };

        if member.endpoints == endpoints {
            return;
        }

        member.endpoints = endpoints;
        let state = member.to_state();

        tracing::info!(
            %network,
            ip = %member.ip,
            endpoints = ?member.endpoints,
            "node published its endpoints"
        );

        broadcast(entry, node, server_message::Body::Peer(state));
    }

    pub fn leave(&self, network: NetworkId, node: NodeId) {
        let mut networks = self.networks.lock().unwrap();

        let Some(entry) = networks.get_mut(&network) else {
            return;
        };

        entry.streams.remove(&node);

        let Some(member) = entry.members.get_mut(&node) else {
            return;
        };

        member.online = false;
        member.endpoints.clear();

        tracing::info!(%network, ip = %member.ip, "node left");

        broadcast(
            entry,
            node,
            server_message::Body::Gone(PeerGone {
                node: node.to_string(),
            }),
        );
    }
}

fn broadcast(network: &mut Network, origin: NodeId, body: server_message::Body) {
    let message = ServerMessage { body: Some(body) };

    network.streams.retain(|node, stream| {
        if *node == origin {
            return true;
        }

        match stream.try_send(message.clone()) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(node = ?node, "control stream is backed up, dropping update");
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    });
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use smolmesh::{NetworkId, NodeId};

    use crate::{
        proto::server_message,
        server::registry::{DEFAULT_NETMASK, DEFAULT_SUBNET, Registry},
    };

    fn registry() -> Registry {
        Registry::new(DEFAULT_SUBNET, DEFAULT_NETMASK)
    }

    #[test]
    fn addresses_are_handed_out_in_order() {
        let registry = registry();
        let network = NetworkId::random();

        let first = registry.join(network, NodeId::random(), 8).unwrap();
        let second = registry.join(network, NodeId::random(), 8).unwrap();

        assert_eq!(first.ip, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(second.ip, Ipv4Addr::new(10, 77, 0, 3));
        assert_eq!(first.netmask, DEFAULT_NETMASK);
    }

    #[test]
    fn a_node_keeps_its_address_across_reconnects() {
        let registry = registry();
        let network = NetworkId::random();
        let node = NodeId::random();

        let first = registry.join(network, node, 8).unwrap();
        registry.leave(network, node);

        let other = registry.join(network, NodeId::random(), 8).unwrap();
        let again = registry.join(network, node, 8).unwrap();

        assert_eq!(again.ip, first.ip, "the address is sticky");
        assert_ne!(other.ip, first.ip);
    }

    #[test]
    fn networks_are_isolated_from_each_other() {
        let registry = registry();

        let first = registry
            .join(NetworkId::random(), NodeId::random(), 8)
            .unwrap();
        let second = registry
            .join(NetworkId::random(), NodeId::random(), 8)
            .unwrap();

        assert_eq!(
            first.ip, second.ip,
            "each network has its own address space"
        );
        assert!(first.peers.is_empty());
        assert!(second.peers.is_empty());
    }

    #[test]
    fn a_joining_node_sees_the_existing_roster() {
        let registry = registry();
        let network = NetworkId::random();

        let alice = NodeId::random();
        registry.join(network, alice, 8).unwrap();

        let bob = registry.join(network, NodeId::random(), 8).unwrap();

        assert_eq!(bob.peers.len(), 1);
        assert_eq!(bob.peers[0].node, alice.to_string());
        assert_eq!(bob.peers[0].ip, "10.77.0.2");
    }

    #[tokio::test]
    async fn a_join_is_announced_to_everyone_else() {
        let registry = registry();
        let network = NetworkId::random();

        let mut alice = registry.join(network, NodeId::random(), 8).unwrap();
        let bob = NodeId::random();
        registry.join(network, bob, 8).unwrap();

        let update = alice.updates.recv().await.unwrap();

        let Some(server_message::Body::Peer(state)) = update.body else {
            panic!("expected a peer update");
        };

        assert_eq!(state.node, bob.to_string());
        assert!(state.online);
    }

    #[tokio::test]
    async fn published_endpoints_reach_the_other_members() {
        let registry = registry();
        let network = NetworkId::random();

        let mut alice = registry.join(network, NodeId::random(), 8).unwrap();
        let bob = NodeId::random();
        registry.join(network, bob, 8).unwrap();

        let _ = alice.updates.recv().await.unwrap();

        registry.publish(network, bob, vec!["203.0.113.7:51820".parse().unwrap()]);

        let update = alice.updates.recv().await.unwrap();

        let Some(server_message::Body::Peer(state)) = update.body else {
            panic!("expected a peer update");
        };

        assert_eq!(state.endpoints, vec!["203.0.113.7:51820"]);
    }

    #[tokio::test]
    async fn a_departure_is_announced() {
        let registry = registry();
        let network = NetworkId::random();

        let mut alice = registry.join(network, NodeId::random(), 8).unwrap();
        let bob = NodeId::random();
        registry.join(network, bob, 8).unwrap();

        let _ = alice.updates.recv().await.unwrap();

        registry.leave(network, bob);

        let update = alice.updates.recv().await.unwrap();

        let Some(server_message::Body::Gone(gone)) = update.body else {
            panic!("expected a departure");
        };

        assert_eq!(gone.node, bob.to_string());
    }

    #[tokio::test]
    async fn a_node_does_not_hear_about_itself() {
        let registry = registry();
        let network = NetworkId::random();

        let node = NodeId::random();
        let mut joined = registry.join(network, node, 8).unwrap();

        registry.publish(network, node, vec!["203.0.113.7:51820".parse().unwrap()]);

        assert!(
            joined.updates.try_recv().is_err(),
            "a node's own state change is not echoed back to it"
        );
    }
}
