pub mod client;
pub mod server;
pub mod token;

pub mod proto {
    tonic::include_proto!("smolctl.v1");
}

pub use crate::{
    client::{Control, JoinConfig, JoinError, Joined, Session},
    server::{ControlService, registry::Registry},
    token::{Identity, TokenError},
};
