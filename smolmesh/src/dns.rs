use std::net::{Ipv4Addr, SocketAddr};

use hickory_server::Server;
use hickory_server::proto::op::{Header, HeaderCounts, Metadata, MessageType, ResponseCode};
use hickory_server::proto::rr::{RData, Record, RecordType, rdata};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::peer::{Peers, ZONE};

/// Peers come and go, so an answer is only good for a moment.
pub const RECORD_TTL: u32 = 5;

/// Answers `<name>.smol` from the peer table and hands everything else to the
/// resolver the host already uses.
#[derive(Clone)]
pub struct Zone {
    peers: Peers,
    upstream: Option<hickory_resolver::TokioResolver>,
    /// This device's own name, so it can resolve itself.
    local: Option<(String, Ipv4Addr)>,
}

impl Zone {
    pub fn new(peers: Peers) -> Zone {
        let upstream = hickory_resolver::TokioResolver::builder_tokio()
            .ok()
            .and_then(|builder| builder.build().ok());

        if upstream.is_none() {
            tracing::warn!("no host resolver found, only .{ZONE} names will resolve");
        }

        Zone {
            peers,
            upstream,
            local: None,
        }
    }

    pub fn with_self(mut self, name: impl Into<String>, ip: Ipv4Addr) -> Zone {
        self.local = Some((name.into(), ip));
        self
    }

    /// Resolve a name inside our zone. Returns None when the name is ours to
    /// answer but nothing holds it, so the caller can say NXDOMAIN rather than
    /// leaking the query upstream.
    pub fn lookup(&self, name: &str) -> Option<Ipv4Addr> {
        let wanted = name.trim_end_matches('.').to_ascii_lowercase();
        let label = wanted.strip_suffix(&format!(".{ZONE}")).unwrap_or(&wanted);

        if let Some((ours, ip)) = &self.local
            && ours == label
        {
            return Some(*ip);
        }

        self.peers.resolve(label)
    }

    pub fn owns(name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();

        name == ZONE || name.ends_with(&format!(".{ZONE}"))
    }
}

fn answering(request: &Metadata, code: ResponseCode) -> Metadata {
    let mut metadata = Metadata::response_from_request(request);
    metadata.response_code = code;
    metadata.authoritative = true;

    metadata
}

/// Only reached when writing the reply itself failed, so the caller is already
/// gone; the value simply has to be something well formed.
fn gave_up(metadata: &Metadata) -> ResponseInfo {
    ResponseInfo::from(Header {
        metadata: answering(metadata, ResponseCode::ServFail),
        counts: HeaderCounts::default(),
    })
}

#[async_trait::async_trait]
impl RequestHandler for Zone {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> ResponseInfo {
        let Ok(info) = request.request_info() else {
            let fallback = Metadata::new(0, MessageType::Response, hickory_server::proto::op::OpCode::Query);
            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.error_msg(&fallback, ResponseCode::FormErr);

            return responder
                .send_response(response)
                .await
                .unwrap_or_else(|_| gave_up(&fallback));
        };

        let metadata = *info.metadata;
        let name = info.query.name().to_string();
        let kind = info.query.query_type();
        let label = info.query.name().clone();

        if !Zone::owns(&name) {
            return self.forward(request, &metadata, name, kind, responder).await;
        }

        let builder = MessageResponseBuilder::from_message_request(request);

        let found = self.lookup(&name);

        let answers: Vec<Record> = match (kind, found) {
            (RecordType::A, Some(ip)) => vec![Record::from_rdata(
                label.into(),
                RECORD_TTL,
                RData::A(rdata::A(ip)),
            )],

            // We are ipv4 only. NXDOMAIN on AAAA makes many resolvers treat the
            // whole name as missing and stall before trying A, so answer with an
            // empty success: the name exists, it simply has no AAAA.
            (_, Some(_)) => vec![],

            (_, None) => {
                let response = builder.error_msg(&metadata, ResponseCode::NXDomain);

                return responder
                    .send_response(response)
                    .await
                    .unwrap_or_else(|_| gave_up(&metadata));
            }
        };

        let response = builder.build(
            answering(&metadata, ResponseCode::NoError),
            answers.iter(),
            &[],
            &[],
            &[],
        );

        responder
            .send_response(response)
            .await
            .unwrap_or_else(|_| gave_up(&metadata))
    }
}

impl Zone {
    async fn forward<R: ResponseHandler>(
        &self,
        request: &Request,
        metadata: &Metadata,
        name: String,
        kind: RecordType,
        mut responder: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);

        let Some(upstream) = &self.upstream else {
            let response = builder.error_msg(metadata, ResponseCode::ServFail);

            return responder
                .send_response(response)
                .await
                .unwrap_or_else(|_| gave_up(metadata));
        };

        match upstream.lookup_ip(name.clone()).await {
            Ok(found) => {
                let wanted: Vec<Record> = found
                    .iter()
                    .filter_map(|ip| match (ip, kind) {
                        (std::net::IpAddr::V4(ip), RecordType::A) => Some(RData::A(rdata::A(ip))),
                        (std::net::IpAddr::V6(ip), RecordType::AAAA) => {
                            Some(RData::AAAA(rdata::AAAA(ip)))
                        }
                        _ => None,
                    })
                    .filter_map(|data| {
                        hickory_server::proto::rr::Name::from_utf8(&name)
                            .ok()
                            .map(|name| Record::from_rdata(name, RECORD_TTL, data))
                    })
                    .collect();

                let answers = wanted;

                let response = builder.build(
                    answering(metadata, ResponseCode::NoError),
                    answers.iter(),
                    &[],
                    &[],
                    &[],
                );

                responder
                    .send_response(response)
                    .await
                    .unwrap_or_else(|_| gave_up(metadata))
            }
            Err(e) => {
                tracing::debug!("upstream lookup failed: {e}");

                let response = builder.error_msg(metadata, ResponseCode::NXDomain);

                responder
                    .send_response(response)
                    .await
                    .unwrap_or_else(|_| gave_up(metadata))
            }
        }
    }
}

/// Bind a resolver for this network. Every node answers the same address
/// locally, so `<subnet>.1` means "ask the daemon on this machine".
pub async fn serve(zone: Zone, listen: SocketAddr) -> std::io::Result<()> {
    let socket = tokio::net::UdpSocket::bind(listen).await?;

    tracing::info!(%listen, "resolver listening for .{ZONE} names");

    let mut server = Server::new(zone);
    server.register_socket(socket);

    server
        .block_until_done()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// The address that answers dns for a network: the first host address, which
/// the allocator never hands to a device.
pub fn resolver_address(subnet: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from((u32::from(subnet) & u32::from(netmask)) | 1)
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use crate::dns::{Zone, resolver_address};
    use crate::peer::{Peer, Peers};

    fn zone() -> Zone {
        let peers: Peers = Peers::default();

        let mut laptop = Peer::new(crate::id::NodeId::random(), Ipv4Addr::new(10, 9, 8, 7));
        laptop.name = Some("laptop".to_owned());

        peers.replace_all([laptop]);

        Zone::new(peers).with_self("thisbox", Ipv4Addr::new(10, 9, 8, 2))
    }

    #[test]
    fn the_resolver_lives_at_the_first_address_in_the_network() {
        assert_eq!(
            resolver_address(Ipv4Addr::new(10, 133, 214, 0), Ipv4Addr::new(255, 255, 255, 0)),
            Ipv4Addr::new(10, 133, 214, 1)
        );

        // and it is never a device address, which start at .2
        assert_ne!(
            resolver_address(Ipv4Addr::new(10, 1, 2, 0), Ipv4Addr::new(255, 255, 255, 0)),
            Ipv4Addr::new(10, 1, 2, 2)
        );
    }

    #[test]
    fn only_our_zone_is_ours_to_answer() {
        assert!(Zone::owns("laptop.smol"));
        assert!(Zone::owns("laptop.smol."));
        assert!(Zone::owns("LAPTOP.SMOL"));
        assert!(Zone::owns("smol"));

        assert!(!Zone::owns("example.com"));
        assert!(!Zone::owns("smol.example.com"));
        assert!(!Zone::owns("notsmol"));
    }

    #[test]
    fn a_peer_and_this_device_both_resolve() {
        let zone = zone();

        assert_eq!(zone.lookup("laptop.smol"), Some(Ipv4Addr::new(10, 9, 8, 7)));
        assert_eq!(zone.lookup("laptop"), Some(Ipv4Addr::new(10, 9, 8, 7)));
        assert_eq!(
            zone.lookup("thisbox.smol"),
            Some(Ipv4Addr::new(10, 9, 8, 2)),
            "a device can always find itself"
        );

        assert_eq!(zone.lookup("nobody.smol"), None);
    }
}

impl Zone {
    /// Answer a raw query without a socket, for callers that already hold the
    /// datagram — the seccomp supervisor intercepts the target's traffic to
    /// port 53 and never lets it reach a real resolver.
    ///
    /// Returns None when the query is not ours to answer, so the caller can let
    /// it go to the host's resolver instead of guessing.
    pub fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        use hickory_server::proto::op::{Message, MessageType, ResponseCode};

        let request = Message::from_vec(query).ok()?;
        let asked = request.queries.first()?;
        let name = asked.name().to_string();

        if !Zone::owns(&name) {
            return None;
        }

        let mut response = Message::response(request.metadata.id, request.metadata.op_code);

        response.queries = request.queries.clone();
        response.metadata.message_type = MessageType::Response;
        response.metadata.authoritative = true;
        response.metadata.recursion_desired = request.metadata.recursion_desired;

        match (asked.query_type(), self.lookup(&name)) {
            (RecordType::A, Some(ip)) => {
                response.add_answer(Record::from_rdata(
                    asked.name().clone(),
                    RECORD_TTL,
                    RData::A(rdata::A(ip)),
                ));
            }

            // The name exists but has no address of this kind. Saying NXDOMAIN
            // here would make the caller give up on the name entirely.
            (_, Some(_)) => {}

            (_, None) => response.metadata.response_code = ResponseCode::NXDomain,
        }

        response.to_vec().ok()
    }
}

#[cfg(test)]
mod answer_test {
    use std::net::Ipv4Addr;

    use crate::dns::Zone;
    use crate::peer::{Peer, Peers};

    fn zone() -> Zone {
        let peers: Peers = Peers::default();

        let mut laptop = Peer::new(crate::id::NodeId::random(), Ipv4Addr::new(10, 9, 8, 7));
        laptop.name = Some("laptop".to_owned());
        peers.replace_all([laptop]);

        Zone::new(peers)
    }

    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut out = vec![0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }

        out.push(0);
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x01]);

        out
    }

    #[test]
    fn a_known_name_is_answered_with_its_address() {
        let answer = zone().answer(&query("laptop.smol", 1)).expect("ours to answer");

        assert_eq!(&answer[..2], &[0xab, 0xcd], "the id is carried back");
        assert_eq!(answer[2] & 0x80, 0x80, "it is a response");
        assert_eq!(answer[3] & 0x0f, 0, "with no error");
        assert!(
            answer.windows(4).any(|w| w == [10, 9, 8, 7]),
            "and carries the overlay address"
        );
    }

    #[test]
    fn an_unknown_name_in_our_zone_is_refused_here_not_upstream() {
        let answer = zone().answer(&query("nobody.smol", 1)).expect("still ours");

        assert_eq!(answer[3] & 0x0f, 3, "nxdomain");
    }

    #[test]
    fn aaaa_for_a_known_name_is_empty_rather_than_missing() {
        let answer = zone().answer(&query("laptop.smol", 28)).expect("ours");

        assert_eq!(answer[3] & 0x0f, 0, "no error");
        assert_eq!(
            u16::from_be_bytes([answer[6], answer[7]]),
            0,
            "no answers, but the name exists"
        );
    }

    #[test]
    fn anything_outside_the_zone_is_left_to_the_host() {
        assert!(
            zone().answer(&query("ntp.google.com", 1)).is_none(),
            "we must not answer for names that are not ours"
        );
        assert!(zone().answer(b"not a dns packet").is_none());
    }
}
