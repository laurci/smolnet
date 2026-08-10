pub mod http;
pub mod registry;
pub mod store;

use std::net::SocketAddr;
use std::pin::Pin;

use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status, Streaming};

use crate::{
    proto::{
        ClientMessage, ServerMessage, Welcome, client_message,
        control_server::{Control, ControlServer},
        server_message,
    },
    server::registry::Registry,
    server::http::Presence,
    server::store::Store,
    token::{self, Identity},
};

const STREAM_CAPACITY: usize = 64;

pub struct ControlService {
    registry: Registry,
    store: Option<Store>,
    presence: Option<tokio::sync::broadcast::Sender<Presence>>,
    secret: Vec<u8>,
    reflector: String,
}

impl ControlService {
    pub fn new(registry: Registry, secret: Vec<u8>, reflector: String) -> ControlService {
        ControlService {
            registry,
            store: None,
            presence: None,
            secret,
            reflector,
        }
    }

    pub fn with_store(mut self, store: Store) -> ControlService {
        self.store = Some(store);
        self
    }

    pub fn with_presence(
        mut self,
        presence: tokio::sync::broadcast::Sender<Presence>,
    ) -> ControlService {
        self.presence = Some(presence);
        self
    }

    pub fn into_server(self) -> ControlServer<ControlService> {
        ControlServer::new(self)
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<Identity, Status> {
        let header = request
            .metadata()
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;

        let value = header
            .to_str()
            .map_err(|_| Status::unauthenticated("authorization metadata is not valid ascii"))?;

        let token = value
            .strip_prefix("Bearer ")
            .ok_or_else(|| Status::unauthenticated("authorization must be a bearer token"))?;

        token::verify(&self.secret, token)
            .map_err(|e| Status::unauthenticated(format!("token rejected: {e}")))
    }
}

type SessionStream = Pin<Box<dyn Stream<Item = Result<ServerMessage, Status>> + Send>>;

#[tonic::async_trait]
impl Control for ControlService {
    type SessionStream = SessionStream;

    async fn session(
        &self,
        request: Request<Streaming<ClientMessage>>,
    ) -> Result<Response<SessionStream>, Status> {
        let identity = self.authenticate(&request)?;
        let remote = request.remote_addr();

        let mut advertised = None;

        let leased = match &self.store {
            Some(store) => {
                let device = store
                    .device(&identity.device)
                    .await
                    .map_err(|e| Status::unauthenticated(format!("unknown device: {e}")))?;

                store
                    .mark(&device.id, true)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;

                announce(&self.presence, &device, true);

                let dropped =
                    self.registry
                        .evict_stale_nodes(identity.network, identity.node, device.ip);

                if dropped > 0 {
                    tracing::info!(dropped, ip = %device.ip, "reclaimed the address from earlier sessions");
                }

                advertised = device.public_key.clone();

                Some(device.ip)
            }
            None => None,
        };

        let joined = self
            .registry
            .join(
                identity.network,
                identity.node,
                leased,
                advertised,
                STREAM_CAPACITY,
            )
            .map_err(|e| Status::resource_exhausted(e.to_string()))?;

        tracing::info!(
            network = %identity.network,
            node = ?identity.node,
            ip = %joined.ip,
            remote = ?remote,
            "control session opened"
        );

        let welcome = ServerMessage {
            body: Some(server_message::Body::Welcome(Welcome {
                network: identity.network.to_string(),
                node: identity.node.to_string(),
                ip: joined.ip.to_string(),
                netmask: joined.netmask.to_string(),
                reflector: self.reflector.clone(),
                peers: joined.peers,
                device: identity.device.clone(),
                hostname: String::new(),
            })),
        };

        let (outbound, receiver) = mpsc::channel(STREAM_CAPACITY);

        outbound
            .send(Ok(welcome))
            .await
            .map_err(|_| Status::internal("could not send the welcome"))?;

        let mut updates = joined.updates;
        let forward = outbound.clone();

        tokio::spawn(async move {
            while let Some(update) = updates.recv().await {
                if forward.send(Ok(update)).await.is_err() {
                    break;
                }
            }
        });

        let registry = self.registry.clone();
        let store = self.store.clone();
        let presence = self.presence.clone();
        let device = identity.device.clone();
        let mut inbound = request.into_inner();

        tokio::spawn(async move {
            while let Some(message) = inbound.next().await {
                match message {
                    Ok(ClientMessage {
                        body: Some(client_message::Body::Endpoints(endpoints)),
                    }) => {
                        let parsed: Vec<SocketAddr> = endpoints
                            .candidates
                            .iter()
                            .filter_map(|candidate| candidate.parse().ok())
                            .collect();

                        registry.publish(identity.network, identity.node, parsed);
                    }
                    Ok(ClientMessage {
                        body: Some(client_message::Body::Hello(hello)),
                    }) => {
                        if !hello.public_key.is_empty()
                            && registry.set_key(
                                identity.network,
                                identity.node,
                                hello.public_key.clone(),
                            )
                        {
                            tracing::info!(
                                node = %identity.node,
                                "published this device's live static key to its peers"
                            );
                        }

                        if let Some(store) = &store {
                            let _ = store
                                .describe(
                                    &device,
                                    Some(hello.hostname.as_str()).filter(|text| !text.is_empty()),
                                    Some(hello.os.as_str()).filter(|text| !text.is_empty()),
                                    Some(hello.version.as_str()).filter(|text| !text.is_empty()),
                                    Some(hello.public_key.as_str()).filter(|text| !text.is_empty()),
                                )
                                .await;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::debug!(node = ?identity.node, "control stream failed: {e}");
                        break;
                    }
                }
            }

            registry.leave(identity.network, identity.node);

            if let Some(store) = &store {
                let _ = store.mark(&device, false).await;

                if let Ok(gone) = store.device(&device).await {
                    announce(&presence, &gone, false);
                }

                let _ = store.release(&device).await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

fn announce(
    presence: &Option<tokio::sync::broadcast::Sender<Presence>>,
    device: &crate::server::store::Device,
    online: bool,
) {
    let Some(presence) = presence else {
        return;
    };

    let _ = presence.send(Presence {
        device: device.id.clone(),
        name: device.name.clone(),
        hostname: device.hostname.clone(),
        ip: device.ip.to_string(),
        online,
    });
}
