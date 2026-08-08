use crate::{
    handler::icmp,
    parser::ipv4::{Ipv4Frame, Ipv4Payload},
    stack::StackIdentity,
};

pub fn process_frame(identity: &StackIdentity, ipv4_frame: &Ipv4Frame) -> Vec<Ipv4Frame> {
    let mut reply_queue = vec![];
    if ipv4_frame.dst() != &identity.ip {
        return reply_queue;
    }

    // TODO: match and dispatch on payload type
    let Ipv4Payload::ICMP(icmp) = &ipv4_frame.payload;
    if let Some(frame) = icmp::process_icmp_frame(identity, icmp) {
        let frame = ipv4_frame.reply(identity, Ipv4Payload::ICMP(frame));
        reply_queue.push(frame);
    }

    return reply_queue;
}
