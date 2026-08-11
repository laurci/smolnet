use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use smolmesh::keys::Keypair;
use smolmesh::{Membership, MeshDevice, MeshHandle, NodeId, Observed, Peer, Peers};
use smolnet::net::{Driver, Net};
use thiserror::Error;
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tonic::{Request, Streaming};

use crate::proto::{
    ClientMessage, Endpoints, ServerMessage, control_client::ControlClient, server_message,
};

pub const PROBE_INTERVAL: Duration = Duration::from_secs(20);

pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

const OUTBOUND_CAPACITY: usize = 16;

pub const DEFAULT_STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun1.l.google.com:19302"];

/// What a node needs to mint itself a fresh join token.
///
/// A token is short lived and names one device. Neither the day it expires nor
/// the device being removed can be recovered by retrying the token, so a node
/// keeps the credential that earned it and asks again.
#[derive(Debug, Clone)]
pub struct Renewal {
    pub api: String,
    pub key: String,
    pub node: String,
    pub device: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JoinConfig {
    pub control: String,
    pub token: String,
    pub bind: SocketAddr,
    pub stun: Vec<String>,
    pub hostname: Option<String>,
    pub version: Option<String>,
    pub keys: Option<Keypair>,
    /// The control port's certificate, learned over the console's https api.
    /// With one, that certificate is the only one this node will accept; with
    /// none, an https control url is checked against the usual public roots.
    pub ca: Option<String>,

    pub renew: Option<Renewal>,
}

fn plausible(name: String) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_owned();

    // DHCP often hands macs a reverse resolved address as their hostname; an
    // address is never a useful device name, so keep looking.
    if name.is_empty() || name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    Some(name)
}

#[cfg(target_os = "macos")]
fn preferred_name() -> Option<String> {
    for key in ["LocalHostName", "ComputerName"] {
        let output = std::process::Command::new("scutil")
            .args(["--get", key])
            .output()
            .ok()?;

        if output.status.success()
            && let Ok(text) = String::from_utf8(output.stdout)
            && let Some(name) = plausible(text)
        {
            return Some(name);
        }
    }

    None
}

#[cfg(not(target_os = "macos"))]
fn preferred_name() -> Option<String> {
    None
}

pub fn discovered_hostname() -> Option<String> {
    if let Some(name) = preferred_name() {
        return Some(name);
    }

    if let Ok(name) = std::env::var("HOSTNAME")
        && let Some(name) = plausible(name)
    {
        return Some(name);
    }

    let mut buffer = [0u8; 256];

    let read = unsafe {
        libc::gethostname(buffer.as_mut_ptr() as *mut libc::c_char, buffer.len() - 1)
    };

    let from_kernel = if read == 0 {
        let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(0);

        std::str::from_utf8(&buffer[..end])
            .ok()
            .map(str::to_owned)
            .and_then(plausible)
    } else {
        None
    };

    from_kernel.or_else(|| {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .and_then(plausible)
    })
}

#[cfg(test)]
mod hostname_test {
    use crate::client::plausible;

    #[test]
    fn an_address_is_never_accepted_as_a_device_name() {
        assert_eq!(plausible("192.168.1.135".to_owned()), None);
        assert_eq!(plausible("10.0.0.1".to_owned()), None);
        assert_eq!(plausible("fe80::1".to_owned()), None);
        assert_eq!(plausible("  ".to_owned()), None);
    }

    #[test]
    fn a_real_name_survives_trimming() {
        assert_eq!(
            plausible("  Laurcis-Mac.local.  ".to_owned()).as_deref(),
            Some("Laurcis-Mac.local")
        );
    }
}

pub fn running_os() -> &'static str {
    std::env::consts::OS
}

impl JoinConfig {
    pub fn new(control: impl Into<String>, token: impl Into<String>) -> JoinConfig {
        JoinConfig {
            control: control.into(),
            token: token.into(),
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            stun: DEFAULT_STUN_SERVERS.map(str::to_owned).to_vec(),
            hostname: None,
            version: None,
            keys: None,
            ca: None,
            renew: None,
        }
    }

    pub fn renew(mut self, renewal: Renewal) -> JoinConfig {
        self.renew = Some(renewal);
        self
    }

    pub fn ca(mut self, ca: Option<String>) -> JoinConfig {
        self.ca = ca;
        self
    }

    /// A binary mode device passes the key pair it keeps beside its device id;
    /// a library mode device leaves this unset and gets a fresh one per process.
    pub fn keys(mut self, keys: Keypair) -> JoinConfig {
        self.keys = Some(keys);
        self
    }

    pub fn hostname(mut self, hostname: impl Into<String>) -> JoinConfig {
        self.hostname = Some(hostname.into());
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> JoinConfig {
        self.version = Some(version.into());
        self
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

/// One attempt at opening the control stream. Factored out of `join` so the
/// session can redial with the same credentials when the stream drops.
async fn dial(
    config: &JoinConfig,
) -> Result<(mpsc::Sender<ClientMessage>, Streaming<ServerMessage>), JoinError> {
    let mut endpoint = Endpoint::from_shared(config.control.clone())
        .map_err(|_| JoinError::Endpoint(config.control.clone()))?
        // A nat that forgets the connection leaves the stream half open: the
        // server is gone but nothing ever arrives to say so, and a node can sit
        // for hours believing it is still on the roster. Ping often enough to
        // turn that silence into an error the reconnect loop can act on.
        .http2_keep_alive_interval(CONTROL_KEEPALIVE)
        .keep_alive_timeout(CONTROL_KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(CONTROL_KEEPALIVE));

    if config.control.starts_with("https://") {
        let mut tls = ClientTlsConfig::new().with_enabled_roots();

        if let Some(pem) = &config.ca {
            // The server signs for itself, so the only thing that makes this
            // connection meaningful is that the certificate is byte for byte
            // the one the console handed us. The name in it is a fixed label,
            // not a claim about the host.
            tls = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(pem))
                .domain_name(crate::server::tls::CONTROL_NAME);
        }

        endpoint = endpoint.tls_config(tls).map_err(JoinError::Connect)?;
    }

    let channel = endpoint.connect().await.map_err(JoinError::Connect)?;
    let mut client = ControlClient::new(channel);

    let (outbound, requests) = mpsc::channel(OUTBOUND_CAPACITY);

    let mut request = Request::new(ReceiverStream::new(requests));
    let bearer = format!("Bearer {}", config.token);

    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(bearer).map_err(|_| JoinError::Token)?,
    );

    let hello = ClientMessage {
        body: Some(crate::proto::client_message::Body::Hello(
            crate::proto::Hello {
                hostname: config
                    .hostname
                    .clone()
                    .or_else(discovered_hostname)
                    .unwrap_or_default(),
                os: running_os().to_owned(),
                version: config
                    .version
                    .clone()
                    .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned()),
                public_key: config
                    .keys
                    .as_ref()
                    .map(|keys| keys.public().to_string())
                    .unwrap_or_default(),
            },
        )),
    };

    let _ = outbound.send(hello).await;

    let response = client.session(request).await.map_err(JoinError::Rejected)?;

    Ok((outbound, response.into_inner()))
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

/// How often to ping the control server over an idle stream.
pub const CONTROL_KEEPALIVE: Duration = Duration::from_secs(20);

/// How long a ping may go unanswered before the stream counts as gone.
pub const CONTROL_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub const RECONNECT_MIN: Duration = Duration::from_secs(1);
pub const RECONNECT_MAX: Duration = Duration::from_secs(30);

pub struct Control {
    handle: MeshHandle,
    peers: Peers,
    reflector: SocketAddr,
    inbound: Streaming<ServerMessage>,
    outbound: mpsc::Sender<ClientMessage>,
    candidates: HashMap<NodeId, Vec<SocketAddr>>,
    stun: Vec<String>,
    config: JoinConfig,
}

impl Control {
    pub async fn run(self) -> Result<(), std::io::Error> {
        let Control {
            handle,
            peers,
            reflector,
            mut inbound,
            mut outbound,
            mut candidates,
            stun,
            mut config,
        } = self;

        let local = local_candidate(reflector, handle.local_addr()?).await;
        let mut observed = handle.observe();

        let mut probe = tokio::time::interval(PROBE_INTERVAL);
        let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
        let mut backoff = RECONNECT_MIN;

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

                            match reconnect(&mut config, &mut backoff).await {
                                Some((sender, stream)) => {
                                    outbound = sender;
                                    inbound = stream;

                                    publish(&outbound, handle.observed(), local).await;
                                }
                                None => {
                                    return Err(std::io::Error::other(
                                        "the control session cannot be restored, so start over",
                                    ));
                                }
                            }
                        }
                        None => {
                            tracing::info!("the control server closed the session, reconnecting");

                            match reconnect(&mut config, &mut backoff).await {
                                Some((sender, stream)) => {
                                    outbound = sender;
                                    inbound = stream;

                                    publish(&outbound, handle.observed(), local).await;
                                }
                                None => {
                                    return Err(std::io::Error::other(
                                        "the control session cannot be restored, so start over",
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

pub struct Joined {
    pub membership: Membership,
    pub device: MeshDevice,
    pub handle: MeshHandle,
    pub peers: Peers,
    pub control: Control,
}

impl Joined {
    pub fn into_session(self) -> Session {
        let Joined {
            membership,
            device,
            handle,
            peers,
            control,
        } = self;

        let (net, driver) = smolnet::net::build(membership.stack_identity(), device);

        Session {
            net,
            driver,
            handle,
            peers,
            membership,
            control,
        }
    }

    pub async fn join(mut config: JoinConfig) -> Result<Joined, JoinError> {
        // A library mode caller passes no key pair, so make one for this process
        // and keep it in memory only; peers learn it through the control plane.
        if config.keys.is_none() {
            config.keys = Some(Keypair::generate().map_err(|_| JoinError::Token)?);
        }

        let (outbound, mut inbound) = dial(&config).await?;

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

        let mut membership = Membership::new(network, node, ip)
            .with_netmask(netmask)
            .with_peers(roster);

        if !welcome.name.is_empty() {
            membership = membership.with_name(welcome.name.clone());
        }

        tracing::info!(
            %network,
            %ip,
            %netmask,
            %reflector,
            peers = membership.peers.len(),
            "joined the network"
        );

        let keys = config.keys.clone().expect("filled in above");

        let (device, handle) = MeshDevice::bind(config.bind, &membership, keys)
            .await
            .map_err(JoinError::Socket)?;

        let peers = handle.peers();

        Ok(Joined {
            membership,
            device,
            handle: handle.clone(),
            peers: peers.clone(),
            control: Control {
                handle,
                peers,
                reflector,
                inbound,
                outbound,
                candidates,
                stun: config.stun.clone(),
                config,
            },
        })
    }
}

pub struct Session {
    net: Net,
    driver: Driver<MeshDevice>,
    handle: MeshHandle,
    peers: Peers,
    membership: Membership,
    control: Control,
}

impl Session {
    /// Resolve a name against the mesh. Only `.smol` names and bare peer names
    /// live here; anything else belongs to the host's resolver.
    pub fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        self.peers.resolve(name)
    }

    /// Connect to `host:port`. A peer is dialled over the overlay; anything else
    /// falls back to the host's own network, since the mesh has no route off
    /// itself yet.
    pub async fn connect(&self, target: &str) -> std::io::Result<Stream> {
        let (host, port) = split_target(target)
            .ok_or_else(|| std::io::Error::other(format!("{target} is not host:port")))?;

        if let Some(ip) = self.peers.resolve(host) {
            tracing::debug!(host, %ip, "connecting over the mesh");

            return self
                .net
                .tcp_connect(ip, port)
                .await
                .map(Stream::Mesh)
                .map_err(|e| std::io::Error::other(e.to_string()));
        }

        if let Ok(ip) = host.parse::<Ipv4Addr>()
            && self.peers.for_ip(&ip).is_some()
        {
            return self
                .net
                .tcp_connect(ip, port)
                .await
                .map(Stream::Mesh)
                .map_err(|e| std::io::Error::other(e.to_string()));
        }

        tracing::debug!(host, "not on the mesh, dialling with host networking");

        tokio::net::TcpStream::connect((host, port))
            .await
            .map(Stream::Host)
    }

    pub async fn join(config: JoinConfig) -> Result<Session, JoinError> {
        Joined::join(config).await.map(Joined::into_session)
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
            driver, control, ..
        } = self;

        let mut running = JoinSet::new();
        running.spawn(driver.run());
        running.spawn(control.run());

        match running.join_next().await {
            Some(result) => result.unwrap_or_else(|e| Err(std::io::Error::other(e))),
            None => Ok(()),
        }
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

    let mut peer = Peer::new(node, ip).with_candidates(endpoints.clone());

    // Without the peer's static key there is no way to encrypt to it, and there
    // is no plaintext fallback, so a peer that has not published one is simply
    // unreachable until it does.
    peer.key = state.public_key.parse().ok();
    peer.name = (!state.name.is_empty()).then(|| state.name.clone());

    if peer.key.is_none() && !state.public_key.is_empty() {
        tracing::warn!(node = state.node, "peer published an unreadable public key");
    }

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
                name = ?peer.name,
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

/// The mesh keeps running while the control plane is away; only the roster goes
/// stale. Redial forever with a capped backoff rather than taking the node down.
async fn reconnect(
    config: &mut JoinConfig,
    backoff: &mut Duration,
) -> Option<(mpsc::Sender<ClientMessage>, Streaming<ServerMessage>)> {
    loop {
        tracing::info!(after = ?*backoff, "reconnecting to the control server");
        tokio::time::sleep(*backoff).await;

        match dial(config).await {
            Ok(opened) => {
                tracing::info!("the control stream is back");
                *backoff = RECONNECT_MIN;

                return Some(opened);
            }
            Err(e) => {
                tracing::warn!("could not reconnect: {e}");

                if !renewed(config).await {
                    return None;
                }

                *backoff = (*backoff * 2).min(RECONNECT_MAX);
            }
        }
    }
}

/// Whether a renewed token still names the device this node has been running as.
/// A different one means the old device is gone and this is a new machine as far
/// as the mesh is concerned, holding an address that is no longer its own.
fn still_us(renewal: &Renewal, issued: &Issued) -> bool {
    renewal
        .device
        .as_ref()
        .is_none_or(|was| was == &issued.device)
}

/// Mint a fresh join token before the next attempt. Returns false when this node
/// is no longer the device it was, which no amount of reconnecting can mend:
/// its address has moved, and starting over is the only honest answer.
async fn renewed(config: &mut JoinConfig) -> bool {
    let Some(renewal) = config.renew.clone() else {
        return true;
    };

    let issued = match exchange(
        &renewal.api,
        &renewal.key,
        &renewal.node,
        renewal.device.as_deref(),
        renewal.name.as_deref(),
        false,
        false,
    )
    .await
    {
        Ok(issued) => issued,
        Err(e) => {
            tracing::warn!("could not renew the join token: {e}");
            return true;
        }
    };

    if !still_us(&renewal, &issued) {
        tracing::error!(
            was = ?renewal.device,
            now = %issued.device,
            "this machine is a different device than it was, and its address with it"
        );

        return false;
    }

    tracing::info!("minted a fresh join token");

    config.token = issued.token;

    if issued.ca.is_some() {
        config.ca = issued.ca;
    }

    true
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

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("could not reach the control server:\n{0}")]
    Unreachable(reqwest::Error),

    #[error("the control server refused the key: {0}")]
    Refused(String),

    #[error("the control server sent a reply we could not read:\n{0}")]
    Malformed(reqwest::Error),
}

#[derive(Debug, Clone)]
pub struct Issued {
    pub token: String,
    pub device: String,
    pub ip: String,
    /// What the server settled on calling this device, which is not always what
    /// the caller suggested.
    pub name: String,
    pub ca: Option<String>,
}

pub async fn exchange(
    api: &str,
    key: &str,
    node: &str,
    device: Option<&str>,
    name: Option<&str>,
    // exact: the caller named the device by hand. A hostname derived name is
    // only a suggestion, and the server may hand back a numbered variant.
    exact: bool,
    ephemeral: bool,
) -> Result<Issued, ExchangeError> {
    let body = serde_json::json!({
        "key": key,
        "node": node,
        "exact": exact,
        "device": device,
        "name": name,
        "ephemeral": ephemeral,
    });

    let response = reqwest::Client::new()
        .post(format!("{}/token", api.trim_end_matches('/')))
        .json(&body)
        .send()
        .await
        .map_err(ExchangeError::Unreachable)?;

    if !response.status().is_success() {
        let detail = response
            .text()
            .await
            .unwrap_or_else(|_| "no detail".to_owned());

        return Err(ExchangeError::Refused(detail));
    }

    let issued: serde_json::Value = response.json().await.map_err(ExchangeError::Malformed)?;

    Ok(Issued::read(&issued))
}

impl Issued {
    fn read(body: &serde_json::Value) -> Issued {
        Issued {
            token: body["token"].as_str().unwrap_or_default().to_owned(),
            device: body["device"].as_str().unwrap_or_default().to_owned(),
            ip: body["ip"].as_str().unwrap_or_default().to_owned(),
            name: body["name"].as_str().unwrap_or_default().to_owned(),
            // A server with no certificate to offer leaves this out, and the
            // node falls back to checking an https control url the ordinary way.
            ca: body["ca"]
                .as_str()
                .filter(|pem| !pem.is_empty())
                .map(str::to_owned),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Connect {
    pub code: String,
    pub secret: String,
    pub url: String,
}

pub async fn start_connect(api: &str) -> Result<Connect, ExchangeError> {
    let response = reqwest::Client::new()
        .post(format!("{}/connect", api.trim_end_matches('/')))
        .send()
        .await
        .map_err(ExchangeError::Unreachable)?;

    if !response.status().is_success() {
        return Err(ExchangeError::Refused(
            response.text().await.unwrap_or_default(),
        ));
    }

    let body: serde_json::Value = response.json().await.map_err(ExchangeError::Malformed)?;

    Ok(Connect {
        code: body["code"].as_str().unwrap_or_default().to_owned(),
        secret: body["secret"].as_str().unwrap_or_default().to_owned(),
        url: body["url"].as_str().unwrap_or_default().to_owned(),
    })
}

pub async fn claim_connect(api: &str, connect: &Connect) -> Result<Option<String>, ExchangeError> {
    let response = reqwest::Client::new()
        .post(format!("{}/connect/claim", api.trim_end_matches('/')))
        .json(&serde_json::json!({ "code": connect.code, "secret": connect.secret }))
        .send()
        .await
        .map_err(ExchangeError::Unreachable)?;

    if response.status() == reqwest::StatusCode::ACCEPTED {
        return Ok(None);
    }

    if !response.status().is_success() {
        return Err(ExchangeError::Refused(
            response.text().await.unwrap_or_default(),
        ));
    }

    let body: serde_json::Value = response.json().await.map_err(ExchangeError::Malformed)?;

    Ok(body["key"].as_str().map(str::to_owned))
}

pub async fn verify(api: &str, key: &str) -> Result<String, ExchangeError> {
    let response = reqwest::Client::new()
        .post(format!("{}/verify", api.trim_end_matches('/')))
        .json(&serde_json::json!({ "key": key }))
        .send()
        .await
        .map_err(ExchangeError::Unreachable)?;

    if !response.status().is_success() {
        return Err(ExchangeError::Refused(
            response.text().await.unwrap_or_default(),
        ));
    }

    let body: serde_json::Value = response.json().await.map_err(ExchangeError::Malformed)?;

    Ok(body["account"].as_str().unwrap_or_default().to_owned())
}

/// A connection that may live on the mesh or on the host's own network.
///
/// The overlay only knows how to reach peers, so anything outside it has no
/// route through our stack. Rather than dropping those packets and leaving the
/// caller to time out, a name that is not on the mesh is dialled with ordinary
/// host networking. Exit nodes would change this later.
pub enum Stream {
    Mesh(smolnet::net::tcp::TcpStream),
    Host(tokio::net::TcpStream),
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Mesh(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Stream::Host(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Mesh(stream) => std::pin::Pin::new(stream).poll_write(cx, data),
            Stream::Host(stream) => std::pin::Pin::new(stream).poll_write(cx, data),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Mesh(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Stream::Host(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Mesh(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Stream::Host(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Stream {
    pub fn on_mesh(&self) -> bool {
        matches!(self, Stream::Mesh(_))
    }
}

/// Split `host:port`, where host may be a `.smol` name, a bare peer name, or an
/// address.
fn split_target(target: &str) -> Option<(&str, u16)> {
    let (host, port) = target.rsplit_once(':')?;

    Some((host, port.parse().ok()?))
}

#[cfg(test)]
mod issued_test {
    use crate::client::Issued;

    #[test]
    fn a_certificate_comes_back_with_the_token() {
        let issued = Issued::read(&serde_json::json!({
            "token": "jwt",
            "device": "dev1",
            "ip": "10.0.0.2",
            "ca": "-----BEGIN CERTIFICATE-----",
        }));

        assert_eq!(issued.device, "dev1");
        assert_eq!(issued.ca.as_deref(), Some("-----BEGIN CERTIFICATE-----"));

        let named = Issued::read(&serde_json::json!({
            "device": "dev1",
            "name": "laptop-1",
        }));

        assert_eq!(
            named.name, "laptop-1",
            "the name the server settled on, not the one that was asked for"
        );
    }

    #[test]
    fn no_certificate_is_not_an_empty_one() {
        for body in [
            serde_json::json!({"token": "jwt", "device": "d", "ip": "10.0.0.2"}),
            serde_json::json!({"token": "jwt", "device": "d", "ip": "10.0.0.2", "ca": ""}),
        ] {
            assert!(
                Issued::read(&body).ca.is_none(),
                "an absent certificate must not become a pin nothing can match"
            );
        }
    }
}

#[cfg(test)]
mod renewal_test {
    use crate::client::{Issued, Renewal, still_us};

    fn renewal(device: Option<&str>) -> Renewal {
        Renewal {
            api: "https://control/api".to_owned(),
            key: "smol_key".to_owned(),
            node: "node".to_owned(),
            device: device.map(str::to_owned),
            name: Some("laptop".to_owned()),
        }
    }

    fn issued(device: &str) -> Issued {
        Issued {
            token: "jwt".to_owned(),
            device: device.to_owned(),
            ip: "10.0.0.2".to_owned(),
            name: "laptop".to_owned(),
            ca: None,
        }
    }

    #[test]
    fn a_fresh_token_for_the_same_device_carries_on() {
        assert!(still_us(&renewal(Some("dev1")), &issued("dev1")));
    }

    #[test]
    fn a_token_for_another_device_means_starting_over() {
        assert!(
            !still_us(&renewal(Some("dev1")), &issued("dev2")),
            "the address moved with the device, and no reconnect can mend that"
        );
    }

    #[test]
    fn a_node_that_never_had_a_device_takes_what_it_is_given() {
        assert!(still_us(&renewal(None), &issued("dev9")));
    }
}
