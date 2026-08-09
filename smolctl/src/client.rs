use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use smolmesh::{Membership, MeshDevice, MeshHandle, NodeId, Observed, Peer, Peers};
use smolnet::net::{Driver, Net};
use thiserror::Error;
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::mpsc;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::metadata::MetadataValue;
use tonic::transport::Endpoint;
use tonic::{Request, Streaming};

use crate::proto::{
    ClientMessage, Endpoints, ServerMessage, control_client::ControlClient, server_message,
};

pub const PROBE_INTERVAL: Duration = Duration::from_secs(20);

pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

const OUTBOUND_CAPACITY: usize = 16;

pub const DEFAULT_STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun1.l.google.com:19302"];

#[derive(Debug, Clone)]
pub struct JoinConfig {
    pub control: String,
    pub token: String,
    pub bind: SocketAddr,
    pub stun: Vec<String>,
}

impl JoinConfig {
    pub fn new(control: impl Into<String>, token: impl Into<String>) -> JoinConfig {
        JoinConfig {
            control: control.into(),
            token: token.into(),
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            stun: DEFAULT_STUN_SERVERS.map(str::to_owned).to_vec(),
        }
    }

    pub fn bind(mut self, bind: SocketAddr) -> JoinConfig {
        self.bind = bind;
        self
    }

    pub fn stun(mut self, servers: Vec<String>) -> JoinConfig {
        self.stun = servers;
        self
    }
}

#[derive(Debug, Error)]
pub enum JoinError {
    #[error("control endpoint {0} is not a valid uri")]
    Endpoint(String),

    #[error("could not reach the control server:\n{0}")]
    Connect(tonic::transport::Error),

    #[error("the control server rejected the session:\n{0}")]
    Rejected(tonic::Status),

    #[error("the control stream closed before sending a welcome")]
    NoWelcome,

    #[error("the control server sent a malformed welcome")]
    MalformedWelcome,

    #[error("the control server advertised no reflector")]
    NoReflector,

    #[error("could not resolve the reflector address {0}")]
    Reflector(String),

    #[error("could not open the mesh socket:\n{0}")]
    Socket(std::io::Error),

    #[error("the bearer token is not valid metadata")]
    Token,
}

pub struct Session {
    net: Net,
    driver: Driver<MeshDevice>,
    handle: MeshHandle,
    peers: Peers,
    membership: Membership,
    reflector: SocketAddr,
    inbound: Streaming<ServerMessage>,
    outbound: mpsc::Sender<ClientMessage>,
    candidates: HashMap<NodeId, Vec<SocketAddr>>,
    stun: Vec<String>,
}

impl Session {
    pub async fn join(config: JoinConfig) -> Result<Session, JoinError> {
        let endpoint = Endpoint::from_shared(config.control.clone())
            .map_err(|_| JoinError::Endpoint(config.control.clone()))?;

        let channel = endpoint.connect().await.map_err(JoinError::Connect)?;
        let mut client = ControlClient::new(channel);

        let (outbound, requests) = mpsc::channel(OUTBOUND_CAPACITY);

        let mut request = Request::new(ReceiverStream::new(requests));
        let bearer = format!("Bearer {}", config.token);

        request.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from(bearer).map_err(|_| JoinError::Token)?,
        );

        let response = client.session(request).await.map_err(JoinError::Rejected)?;
        let mut inbound = response.into_inner();

        let welcome = match inbound.next().await {
            Some(Ok(ServerMessage {
                body: Some(server_message::Body::Welcome(welcome)),
            })) => welcome,
            Some(Err(e)) => return Err(JoinError::Rejected(e)),
            _ => return Err(JoinError::NoWelcome),
        };

        let network = welcome
            .network
            .parse()
            .map_err(|_| JoinError::MalformedWelcome)?;
        let node = welcome
            .node
            .parse()
            .map_err(|_| JoinError::MalformedWelcome)?;
        let ip: Ipv4Addr = welcome
            .ip
            .parse()
            .map_err(|_| JoinError::MalformedWelcome)?;
        let netmask: Ipv4Addr = welcome
            .netmask
            .parse()
            .map_err(|_| JoinError::MalformedWelcome)?;

        if welcome.reflector.is_empty() {
            return Err(JoinError::NoReflector);
        }

        let reflector = lookup_host(&welcome.reflector)
            .await
            .map_err(|_| JoinError::Reflector(welcome.reflector.clone()))?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| JoinError::Reflector(welcome.reflector.clone()))?;

        let mut candidates = HashMap::new();
        let mut roster = vec![];

        for state in &welcome.peers {
            if let Some((peer, endpoints)) = decode_peer(state) {
                candidates.insert(peer.node, endpoints);
                roster.push(peer);
            }
        }

        let membership = Membership::new(network, node, ip)
            .with_netmask(netmask)
            .with_peers(roster);

        tracing::info!(
            %network,
            %ip,
            %netmask,
            %reflector,
            peers = membership.peers.len(),
            "joined the network"
        );

        let (device, handle) = MeshDevice::bind(config.bind, &membership)
            .await
            .map_err(JoinError::Socket)?;

        let peers = handle.peers();
        let (net, driver) = smolnet::net::build(membership.stack_identity(), device);

        Ok(Session {
            net,
            driver,
            handle,
            peers,
            membership,
            reflector,
            inbound,
            outbound,
            candidates,
            stun: config.stun,
        })
    }

    pub fn net(&self) -> Net {
        self.net.clone()
    }

    pub fn handle(&self) -> MeshHandle {
        self.handle.clone()
    }

    pub fn peers(&self) -> Peers {
        self.peers.clone()
    }

    pub fn membership(&self) -> &Membership {
        &self.membership
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.membership.ip
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        let Session {
            driver,
            handle,
            peers,
            reflector,
            mut inbound,
            outbound,
            mut candidates,
            stun,
            ..
        } = self;

        let mut stack = tokio::spawn(driver.run());

        let local = local_candidate(reflector, handle.local_addr()?).await;
        let mut observed = handle.observe();

        let mut probe = tokio::time::interval(PROBE_INTERVAL);
        let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);

        loop {
            tokio::select! {
                _ = probe.tick() => {
                    if let Err(e) = handle.probe(reflector).await {
                        tracing::warn!("could not probe the reflector: {e}");
                    }

                    discover(&handle, &stun).await;
                }
                _ = keepalive.tick() => punch(&handle, &candidates).await,
                changed = observed.changed() => {
                    if changed.is_err() {
                        break;
                    }

                    publish(&outbound, handle.observed(), local).await;
                }
                message = inbound.next() => {
                    match message {
                        Some(Ok(message)) => {
                            if apply(&peers, &mut candidates, message) {
                                punch(&handle, &candidates).await;
                            }
                        }
                        Some(Err(e)) => {
                            tracing::warn!("control stream failed: {e}");
                            break;
                        }
                        None => {
                            tracing::info!("the control server closed the session");
                            break;
                        }
                    }
                }
                result = &mut stack => {
                    return result.unwrap_or_else(|e| Err(std::io::Error::other(e)));
                }
            }
        }

        stack.abort();

        Ok(())
    }
}

fn decode_peer(state: &crate::proto::PeerState) -> Option<(Peer, Vec<SocketAddr>)> {
    let node: NodeId = state.node.parse().ok()?;
    let ip: Ipv4Addr = state.ip.parse().ok()?;

    let endpoints: Vec<SocketAddr> = state
        .endpoints
        .iter()
        .filter_map(|endpoint| endpoint.parse().ok())
        .collect();

    let mut peer = Peer::new(node, ip);
    peer.endpoint = endpoints.first().copied();

    Some((peer, endpoints))
}

fn apply(
    peers: &Peers,
    candidates: &mut HashMap<NodeId, Vec<SocketAddr>>,
    message: ServerMessage,
) -> bool {
    match message.body {
        Some(server_message::Body::Peer(state)) => {
            let Some((mut peer, endpoints)) = decode_peer(&state) else {
                tracing::warn!(node = state.node, "ignoring a malformed peer update");
                return false;
            };

            if let Some(known) = peers.get(&peer.node)
                && known.endpoint.is_some()
            {
                peer.endpoint = known.endpoint;
            }

            tracing::info!(
                ip = %peer.ip,
                endpoints = ?endpoints,
                online = state.online,
                "peer updated"
            );

            candidates.insert(peer.node, endpoints);
            peers.insert(peer);

            true
        }
        Some(server_message::Body::Gone(gone)) => {
            let Ok(node) = gone.node.parse::<NodeId>() else {
                return false;
            };

            candidates.remove(&node);

            if let Some(peer) = peers.remove(&node) {
                tracing::info!(ip = %peer.ip, "peer left");
            }

            false
        }
        _ => false,
    }
}

async fn punch(handle: &MeshHandle, candidates: &HashMap<NodeId, Vec<SocketAddr>>) {
    for endpoints in candidates.values() {
        for endpoint in endpoints {
            if let Err(e) = handle.keepalive(*endpoint).await {
                tracing::debug!(%endpoint, "keepalive failed: {e}");
            }
        }
    }
}

async fn discover(handle: &MeshHandle, servers: &[String]) {
    for server in servers {
        let mut resolved = match lookup_host(server).await {
            Ok(resolved) => resolved,
            Err(e) => {
                tracing::debug!(server, "could not resolve the stun server: {e}");
                continue;
            }
        };

        let Some(address) = resolved.find(SocketAddr::is_ipv4) else {
            continue;
        };

        if let Err(e) = handle.stun(address).await {
            tracing::debug!(%address, "could not send a stun request: {e}");
        }
    }
}

async fn publish(
    outbound: &mpsc::Sender<ClientMessage>,
    observed: Observed,
    local: Option<SocketAddr>,
) {
    let mut candidates: Vec<String> = vec![];

    for endpoint in observed.candidates().chain(local) {
        let encoded = endpoint.to_string();

        if !candidates.contains(&encoded) {
            candidates.push(encoded);
        }
    }

    if candidates.is_empty() {
        return;
    }

    tracing::info!(?candidates, "publishing our endpoints");

    let message = ClientMessage {
        body: Some(crate::proto::client_message::Body::Endpoints(Endpoints {
            candidates,
        })),
    };

    if outbound.send(message).await.is_err() {
        tracing::warn!("could not publish endpoints, the control stream is gone");
    }
}

async fn local_candidate(reflector: SocketAddr, bound: SocketAddr) -> Option<SocketAddr> {
    let probe = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    probe.connect(reflector).await.ok()?;

    let address = probe.local_addr().ok()?.ip();

    if address.is_loopback() && !reflector.ip().is_loopback() {
        return None;
    }

    Some(SocketAddr::new(address, bound.port()))
}
