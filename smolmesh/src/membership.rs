use std::net::Ipv4Addr;

use smolnet::stack::StackIdentity;

use crate::{
    id::{NetworkId, NodeId},
    peer::Peer,
};

pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub network: NetworkId,
    pub node: NodeId,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub peers: Vec<Peer>,
    /// This device's unique name, so it can answer for itself under the zone.
    pub name: Option<String>,
}

impl Membership {
    pub fn new(network: NetworkId, node: NodeId, ip: Ipv4Addr) -> Membership {
        Membership {
            network,
            node,
            ip,
            netmask: DEFAULT_NETMASK,
            peers: vec![],
            name: None,
        }
    }

    pub fn with_netmask(mut self, netmask: Ipv4Addr) -> Membership {
        self.netmask = netmask;
        self
    }

    pub fn with_peer(mut self, peer: Peer) -> Membership {
        self.peers.push(peer);
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Membership {
        self.name = Some(name.into());
        self
    }

    pub fn with_peers(mut self, peers: impl IntoIterator<Item = Peer>) -> Membership {
        self.peers.extend(peers);
        self
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) | !u32::from(self.netmask))
    }

    pub fn stack_identity(&self) -> StackIdentity {
        StackIdentity {
            ip: self.ip.octets(),
            gateway: Ipv4Addr::UNSPECIFIED.octets(),
            netmask: self.netmask.octets(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use crate::{
        id::{NetworkId, NodeId},
        membership::Membership,
        peer::Peer,
    };

    fn membership() -> Membership {
        Membership::new(
            NetworkId::random(),
            NodeId::random(),
            Ipv4Addr::new(10, 30, 0, 2),
        )
    }

    #[test]
    fn the_default_netmask_is_a_slash_twenty_four() {
        assert_eq!(membership().broadcast(), Ipv4Addr::new(10, 30, 0, 255));
    }

    #[test]
    fn a_wider_netmask_widens_the_broadcast_address() {
        let membership = membership().with_netmask(Ipv4Addr::new(255, 255, 0, 0));

        assert_eq!(membership.broadcast(), Ipv4Addr::new(10, 30, 255, 255));
    }

    #[test]
    fn a_mesh_has_no_gateway() {
        let identity = membership().stack_identity();

        assert_eq!(identity.ip, [10, 30, 0, 2]);
        assert_eq!(identity.netmask, [255, 255, 255, 0]);
        assert_eq!(identity.gateway, [0, 0, 0, 0]);
    }

    #[test]
    fn peers_accumulate() {
        let membership = membership()
            .with_peer(Peer::new(NodeId::random(), Ipv4Addr::new(10, 30, 0, 3)))
            .with_peers([
                Peer::new(NodeId::random(), Ipv4Addr::new(10, 30, 0, 4)),
                Peer::new(NodeId::random(), Ipv4Addr::new(10, 30, 0, 5)),
            ]);

        assert_eq!(membership.peers.len(), 3);
    }
}
