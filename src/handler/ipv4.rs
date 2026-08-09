use crate::{
    handler::{
        icmp,
        udp::{self, UdpEngine},
    },
    parser::{
        ipv4::{Ipv4Frame, Ipv4Payload},
        tcp::TcpSegment,
    },
    stack::StackIdentity,
};

pub fn process_frame(
    identity: &StackIdentity,
    udp_engine: &mut UdpEngine,
    ipv4_frame: &Ipv4Frame,
) -> Vec<Ipv4Frame> {
    let mut reply_queue = vec![];
    if ipv4_frame.dst() != &identity.ip {
        return reply_queue;
    }

    match &ipv4_frame.payload {
        Ipv4Payload::ICMP(icmp) => {
            if let Some(frame) = icmp::process_frame(identity, &icmp) {
                let frame = ipv4_frame.reply(identity, Ipv4Payload::ICMP(frame));
                reply_queue.push(frame);
            }
        }

        Ipv4Payload::UDP(udp) => {
            udp::process_frame(identity, udp_engine, &ipv4_frame, &udp);
        }

        Ipv4Payload::TCP(tcp) => {
            tracing::info!("tcp frame passed checksum {:?}", tcp);

            let frame = tcp.reply(
                5000,
                TcpSegment::SynAck {
                    iss: 10245,
                    ack: tcp.seq() + 1,
                },
            );
            let frame = ipv4_frame.reply(identity, Ipv4Payload::TCP(frame));

            reply_queue.push(frame);
        }
    }

    return reply_queue;
}
