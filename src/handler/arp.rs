use std::collections::HashMap;

use crate::{
    addr::{Ipv4Addr, MacAddr},
    parser::arp::{ArpFrame, ArpOperation, ArpReply},
    stack::StackIdentity,
};

#[derive(Default)]
pub struct ArpCache {
    map: HashMap<Ipv4Addr, MacAddr>,
}

impl ArpCache {
    pub fn learn(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.map.insert(ip, mac);
    }

    pub fn lookup(&self, target: &Ipv4Addr) -> Option<&MacAddr> {
        self.map.get(target)
    }

    /// Avoid using this. Is quite slow; needs a second cache to optimize reverse lookup (if needed)
    pub fn reverse_lookup(&self, target: &MacAddr) -> Option<&Ipv4Addr> {
        let pair = self.map.iter().find(|(_, mac)| mac == &target);
        pair.map(|(key, _)| key)
    }
}

pub fn process_frame(
    identity: &StackIdentity,
    cache: &mut ArpCache,
    arp_frame: &ArpFrame,
) -> Option<ArpFrame> {
    match &arp_frame.operation {
        ArpOperation::Request(request) => {
            cache.learn(
                *request.sender_proto_addr(),
                *request.sender_hardware_addr(),
            );

            if request.target_proto_addr() != &identity.ip {
                return None;
            }

            let reply = ArpReply::new(request, identity.mac);
            return Some(ArpFrame::new(ArpOperation::Reply(reply)));
        }
        ArpOperation::Reply(reply) => {
            cache.learn(*reply.sender_proto_addr(), *reply.sender_hardware_addr());
        }
    }

    None
}
