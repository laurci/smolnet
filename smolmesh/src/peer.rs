use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use crate::id::NodeId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub node: NodeId,
    pub ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
}

impl Peer {
    pub fn new(node: NodeId, ip: Ipv4Addr) -> Peer {
        Peer {
            node,
            ip,
            endpoint: None,
        }
    }

    pub fn with_endpoint(mut self, endpoint: SocketAddr) -> Peer {
        self.endpoint = Some(endpoint);
        self
    }
}

#[derive(Default)]
struct Table {
    by_node: HashMap<NodeId, Peer>,
    by_ip: HashMap<Ipv4Addr, NodeId>,
}

impl Table {
    fn insert(&mut self, peer: Peer) -> Option<Peer> {
        if let Some(holder) = self.by_ip.get(&peer.ip).copied()
            && holder != peer.node
        {
            tracing::warn!(
                ip = %peer.ip,
                evicted = ?holder,
                claimed_by = ?peer.node,
                "overlay address reassigned to another node"
            );

            if let Some(evicted) = self.by_node.remove(&holder) {
                self.by_ip.remove(&evicted.ip);
            }
        }

        let previous = self.by_node.insert(peer.node, peer.clone());

        if let Some(previous) = previous.as_ref()
            && previous.ip != peer.ip
        {
            self.by_ip.remove(&previous.ip);
        }

        self.by_ip.insert(peer.ip, peer.node);

        previous
    }

    fn remove(&mut self, node: &NodeId) -> Option<Peer> {
        let peer = self.by_node.remove(node)?;
        self.by_ip.remove(&peer.ip);

        Some(peer)
    }
}

#[derive(Clone, Default)]
pub struct Peers {
    table: Arc<Mutex<Table>>,
}

impl Peers {
    pub fn new() -> Peers {
        Peers::default()
    }

    pub fn insert(&self, peer: Peer) -> Option<Peer> {
        self.table.lock().unwrap().insert(peer)
    }

    pub fn remove(&self, node: &NodeId) -> Option<Peer> {
        self.table.lock().unwrap().remove(node)
    }

    pub fn get(&self, node: &NodeId) -> Option<Peer> {
        self.table.lock().unwrap().by_node.get(node).cloned()
    }

    pub fn by_ip(&self, ip: &Ipv4Addr) -> Option<Peer> {
        let table = self.table.lock().unwrap();
        let node = table.by_ip.get(ip)?;

        table.by_node.get(node).cloned()
    }

    pub fn route(&self, ip: &Ipv4Addr) -> Option<SocketAddr> {
        self.by_ip(ip)?.endpoint
    }

    pub fn endpoints(&self) -> Vec<SocketAddr> {
        self.table
            .lock()
            .unwrap()
            .by_node
            .values()
            .filter_map(|peer| peer.endpoint)
            .collect()
    }

    pub fn learn_endpoint(&self, node: &NodeId, endpoint: SocketAddr) -> bool {
        let mut table = self.table.lock().unwrap();

        let Some(peer) = table.by_node.get_mut(node) else {
            return false;
        };

        if peer.endpoint == Some(endpoint) {
            return false;
        }

        peer.endpoint = Some(endpoint);

        true
    }

    pub fn replace_all(&self, peers: impl IntoIterator<Item = Peer>) {
        let mut table = self.table.lock().unwrap();
        let known = std::mem::take(&mut *table);

        for mut peer in peers {
            if peer.endpoint.is_none()
                && let Some(previous) = known.by_node.get(&peer.node)
            {
                peer.endpoint = previous.endpoint;
            }

            table.insert(peer);
        }
    }

    pub fn list(&self) -> Vec<Peer> {
        self.table
            .lock()
            .unwrap()
            .by_node
            .values()
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.table.lock().unwrap().by_node.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FromIterator<Peer> for Peers {
    fn from_iter<T: IntoIterator<Item = Peer>>(peers: T) -> Peers {
        let table = Peers::default();
        table.replace_all(peers);

        table
    }
}

impl std::fmt::Debug for Peers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.list()).finish()
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, SocketAddr};

    use crate::{
        id::NodeId,
        peer::{Peer, Peers},
    };

    fn endpoint(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn routing_needs_a_known_endpoint() {
        let node = NodeId::random();
        let ip = Ipv4Addr::new(10, 30, 0, 3);

        let peers = Peers::new();
        peers.insert(Peer::new(node, ip));

        assert_eq!(
            peers.route(&ip),
            None,
            "a peer without an endpoint is unreachable"
        );

        peers.learn_endpoint(&node, endpoint(4001));

        assert_eq!(peers.route(&ip), Some(endpoint(4001)));
        assert_eq!(peers.route(&Ipv4Addr::new(10, 30, 0, 9)), None);
    }

    #[test]
    fn learning_reports_whether_the_endpoint_moved() {
        let node = NodeId::random();

        let peers = Peers::new();
        peers.insert(Peer::new(node, Ipv4Addr::new(10, 30, 0, 3)));

        assert!(peers.learn_endpoint(&node, endpoint(4001)));
        assert!(!peers.learn_endpoint(&node, endpoint(4001)));
        assert!(peers.learn_endpoint(&node, endpoint(4002)));

        assert!(!peers.learn_endpoint(&NodeId::random(), endpoint(4003)));
    }

    #[test]
    fn moving_a_peer_to_a_new_address_clears_the_old_route() {
        let node = NodeId::random();
        let old = Ipv4Addr::new(10, 30, 0, 3);
        let new = Ipv4Addr::new(10, 30, 0, 4);

        let peers = Peers::new();
        peers.insert(Peer::new(node, old).with_endpoint(endpoint(4001)));
        peers.insert(Peer::new(node, new).with_endpoint(endpoint(4001)));

        assert_eq!(peers.route(&old), None);
        assert_eq!(peers.route(&new), Some(endpoint(4001)));
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn one_node_owns_an_overlay_address() {
        let first = NodeId::random();
        let second = NodeId::random();
        let ip = Ipv4Addr::new(10, 30, 0, 3);

        let peers = Peers::new();
        peers.insert(Peer::new(first, ip).with_endpoint(endpoint(4001)));
        peers.insert(Peer::new(second, ip).with_endpoint(endpoint(4002)));

        assert_eq!(peers.len(), 1);
        assert_eq!(peers.get(&first), None);
        assert_eq!(peers.route(&ip), Some(endpoint(4002)));
    }

    #[test]
    fn removing_a_peer_clears_both_indexes() {
        let node = NodeId::random();
        let ip = Ipv4Addr::new(10, 30, 0, 3);

        let peers = Peers::new();
        peers.insert(Peer::new(node, ip).with_endpoint(endpoint(4001)));

        assert!(peers.remove(&node).is_some());
        assert!(peers.remove(&node).is_none());

        assert_eq!(peers.route(&ip), None);
        assert!(peers.is_empty());
    }

    #[test]
    fn replacing_the_roster_keeps_learned_endpoints() {
        let stays = NodeId::random();
        let leaves = NodeId::random();
        let joins = NodeId::random();

        let peers = Peers::new();
        peers.insert(Peer::new(stays, Ipv4Addr::new(10, 30, 0, 3)));
        peers.insert(Peer::new(leaves, Ipv4Addr::new(10, 30, 0, 4)));

        peers.learn_endpoint(&stays, endpoint(4001));
        peers.learn_endpoint(&leaves, endpoint(4002));

        peers.replace_all([
            Peer::new(stays, Ipv4Addr::new(10, 30, 0, 3)),
            Peer::new(joins, Ipv4Addr::new(10, 30, 0, 5)),
        ]);

        assert_eq!(peers.len(), 2);
        assert_eq!(
            peers.route(&Ipv4Addr::new(10, 30, 0, 3)),
            Some(endpoint(4001)),
            "a punched endpoint outlives a roster refresh"
        );
        assert_eq!(peers.get(&leaves), None);
        assert_eq!(peers.get(&joins).unwrap().endpoint, None);
    }

    #[test]
    fn a_roster_refresh_takes_a_known_endpoint_over_a_learned_one() {
        let node = NodeId::random();
        let ip = Ipv4Addr::new(10, 30, 0, 3);

        let peers = Peers::new();
        peers.insert(Peer::new(node, ip));
        peers.learn_endpoint(&node, endpoint(4001));

        peers.replace_all([Peer::new(node, ip).with_endpoint(endpoint(4002))]);

        assert_eq!(peers.route(&ip), Some(endpoint(4002)));
    }

    #[test]
    fn endpoints_skips_unreachable_peers() {
        let peers = Peers::from_iter([
            Peer::new(NodeId::random(), Ipv4Addr::new(10, 30, 0, 3)).with_endpoint(endpoint(4001)),
            Peer::new(NodeId::random(), Ipv4Addr::new(10, 30, 0, 4)),
        ]);

        assert_eq!(peers.endpoints(), vec![endpoint(4001)]);
    }

    #[test]
    fn the_table_is_shared_between_clones() {
        let peers = Peers::new();
        let handle = peers.clone();

        handle.insert(Peer::new(NodeId::random(), Ipv4Addr::new(10, 30, 0, 3)));

        assert_eq!(peers.len(), 1);
    }
}
