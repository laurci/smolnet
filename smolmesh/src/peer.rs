use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use crate::id::NodeId;

/// The overlay's top level domain.
pub const ZONE: &str = "smol";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub node: NodeId,
    pub ip: Ipv4Addr,
    /// Where we believe this peer answers. Starts as a guess and is corrected
    /// to whichever address it actually spoke to us from.
    pub endpoint: Option<SocketAddr>,
    /// Every address the peer published. A peer behind the same nat as us, or
    /// on this very machine, is only reachable on one of the later ones.
    pub candidates: Vec<SocketAddr>,
    pub key: Option<crate::keys::PublicKey>,
    pub name: Option<String>,
}

impl Peer {
    pub fn new(node: NodeId, ip: Ipv4Addr) -> Peer {
        Peer {
            key: None,
            name: None,
            node,
            ip,
            endpoint: None,
            candidates: vec![],
        }
    }

    pub fn with_endpoint(mut self, endpoint: SocketAddr) -> Peer {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn with_candidates(mut self, candidates: Vec<SocketAddr>) -> Peer {
        self.endpoint = self.endpoint.or_else(|| candidates.first().copied());
        self.candidates = candidates;
        self
    }

    /// Everywhere worth trying, best guess first and never empty when we know
    /// of anywhere at all.
    pub fn reachable_at(&self) -> Vec<SocketAddr> {
        let mut all: Vec<SocketAddr> = self.endpoint.into_iter().collect();

        for candidate in &self.candidates {
            if !all.contains(candidate) {
                all.push(*candidate);
            }
        }

        all
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

    /// Resolve `<name>.smol`, or a bare `<name>`, to a peer's overlay address.
    /// Matching is case insensitive because dns is.
    pub fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let wanted = name.trim_end_matches('.').to_ascii_lowercase();
        let label = wanted
            .strip_suffix(&format!(".{ZONE}"))
            .unwrap_or(&wanted)
            .to_owned();

        let table = self.table.lock().unwrap();

        table
            .by_node
            .values()
            .find(|peer| peer.name.as_deref() == Some(label.as_str()))
            .map(|peer| peer.ip)
    }

    pub fn named(&self) -> Vec<(String, Ipv4Addr)> {
        let table = self.table.lock().unwrap();

        table
            .by_node
            .values()
            .filter_map(|peer| Some((peer.name.clone()?, peer.ip)))
            .collect()
    }

    pub fn for_ip(&self, ip: &Ipv4Addr) -> Option<Peer> {
        let table = self.table.lock().unwrap();
        let node = table.by_ip.get(ip)?;

        table.by_node.get(node).cloned()
    }

    /// Peers we can both reach and encrypt to: an endpoint and a published key.
    pub fn reachable(&self) -> Vec<(SocketAddr, crate::keys::PublicKey)> {
        let table = self.table.lock().unwrap();

        table
            .by_node
            .values()
            .filter_map(|peer| Some((peer.endpoint?, peer.key?)))
            .collect()
    }

    pub fn by_key(&self, key: &crate::keys::PublicKey) -> Option<Peer> {
        let table = self.table.lock().unwrap();

        table
            .by_node
            .values()
            .find(|peer| peer.key.as_ref() == Some(key))
            .cloned()
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
    #[test]
    fn a_name_resolves_with_or_without_the_zone() {
        use crate::peer::{Peer, Peers};
        use std::net::Ipv4Addr;

        let peers: Peers = Peers::default();

        let mut laptop = Peer::new(crate::id::NodeId::random(), Ipv4Addr::new(10, 1, 2, 3));
        laptop.name = Some("laptop".to_owned());

        peers.replace_all([laptop]);

        assert_eq!(peers.resolve("laptop.smol"), Some(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(peers.resolve("laptop"), Some(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(
            peers.resolve("LAPTOP.SMOL"),
            Some(Ipv4Addr::new(10, 1, 2, 3)),
            "dns lookups are case insensitive"
        );
        assert_eq!(
            peers.resolve("laptop.smol."),
            Some(Ipv4Addr::new(10, 1, 2, 3)),
            "a fully qualified name ends in a dot"
        );

        assert_eq!(peers.resolve("desktop.smol"), None);
        assert_eq!(peers.resolve("laptop.example.com"), None);
    }

    #[test]
    fn an_unnamed_peer_is_not_resolvable() {
        use crate::peer::{Peer, Peers};
        use std::net::Ipv4Addr;

        let peers: Peers = Peers::default();
        peers.replace_all([Peer::new(crate::id::NodeId::random(), Ipv4Addr::new(10, 1, 2, 4))]);

        assert!(peers.named().is_empty());
        assert_eq!(peers.resolve("anything.smol"), None);
    }

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
    fn every_published_address_is_worth_trying() {
        let peer = Peer::new(NodeId::random(), Ipv4Addr::new(10, 0, 0, 2))
            .with_candidates(vec![endpoint(4001), endpoint(4002)]);

        assert_eq!(
            peer.endpoint,
            Some(endpoint(4001)),
            "the first published address is the opening guess"
        );
        assert_eq!(peer.reachable_at(), vec![endpoint(4001), endpoint(4002)]);
    }

    #[test]
    fn the_address_that_answered_is_tried_first_and_only_once() {
        let mut peer = Peer::new(NodeId::random(), Ipv4Addr::new(10, 0, 0, 2))
            .with_candidates(vec![endpoint(4001), endpoint(4002)]);

        peer.endpoint = Some(endpoint(4002));

        assert_eq!(
            peer.reachable_at(),
            vec![endpoint(4002), endpoint(4001)],
            "what worked leads, and nothing is asked twice"
        );
    }

    #[test]
    fn a_peer_we_know_nowhere_to_reach_has_nowhere_to_try() {
        let peer = Peer::new(NodeId::random(), Ipv4Addr::new(10, 0, 0, 2));

        assert!(peer.reachable_at().is_empty());
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
