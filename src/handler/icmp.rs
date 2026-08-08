use crate::{
    parser::icmp::{IcmpFrame, IcmpType},
    stack::StackIdentity,
};

pub fn process_frame(_identity: &StackIdentity, icmp_frame: &IcmpFrame) -> Option<IcmpFrame> {
    if icmp_frame.type_() != &IcmpType::EchoRequest {
        return None;
    }

    let reply_frame = IcmpFrame::new(IcmpType::EchoReply, &icmp_frame.payload);
    return Some(reply_frame);
}
