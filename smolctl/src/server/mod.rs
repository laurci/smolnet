pub mod registry;

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
    token::{self, Identity},
};

const STREAM_CAPACITY: usize = 64;

pub struct ControlService {
    registry: Registry,
    secret: Vec<u8>,
    reflector: String,
}

impl ControlService {
    pub fn new(registry: Registry, secret: Vec<u8>, reflector: String) -> ControlService {
        ControlService {
            registry,
            secret,
            reflector,
        }
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

        let joined = self
            .registry
            .join(identity.network, identity.node, STREAM_CAPACITY)
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
                    Ok(_) => {}
                    Err(e) => {
                        tracing::debug!(node = ?identity.node, "control stream failed: {e}");
                        break;
                    }
                }
            }

            registry.leave(identity.network, identity.node);
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}
