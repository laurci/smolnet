use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};

use smolmesh::{Membership, MeshDevice, MeshHandle, NetworkId, NodeId, Peer};
use smolnet::net::Net;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::spawn;
use tracing_subscriber::EnvFilter;

const ECHO_PORT: u16 = 7777;

struct Node {
    net: Net,
    handle: MeshHandle,
    id: NodeId,
    ip: Ipv4Addr,
    endpoint: SocketAddr,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("mesh_hello=info,smolmesh=info,smolnet=warn")),
        )
        .init();
}

async fn join(network: NetworkId, ip: Ipv4Addr) -> Result<Node, Box<dyn Error>> {
    let id = NodeId::random();
    let membership = Membership::new(network, id, ip);

    let (device, handle) = MeshDevice::bind(
        "127.0.0.1:0",
        &membership,
        smolmesh::keys::Keypair::generate()?,
    )
    .await?;
    let endpoint = handle.local_addr()?;

    let (net, driver) = smolnet::net::build(membership.stack_identity(), device);
    spawn(driver.run());

    let listener = net.tcp_listen(ECHO_PORT)?;

    spawn(async move {
        while let Ok(socket) = listener.accept().await {
            spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(socket);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    Ok(Node {
        net,
        handle,
        id,
        ip,
        endpoint,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let network = NetworkId::random();
    tracing::info!(%network, "forming a mesh");

    let mut nodes = vec![];
    for last in 2..=4u8 {
        nodes.push(join(network, Ipv4Addr::new(10, 30, 0, last)).await?);
    }

    let roster: Vec<Peer> = nodes
        .iter()
        .map(|node| Peer::new(node.id, node.ip).with_endpoint(node.endpoint))
        .collect();

    tracing::info!(
        peers = roster.len(),
        "handing every node the roster a coordination server would publish"
    );

    for node in &nodes {
        node.handle
            .peers()
            .replace_all(roster.iter().filter(|p| p.node != node.id).cloned());
    }

    for client in &nodes {
        for server in &nodes {
            if client.id == server.id {
                continue;
            }

            let mut stream = client.net.tcp_connect(server.ip, ECHO_PORT).await?;

            let message = format!("hello from {}", client.ip);
            stream.write_all(message.as_bytes()).await?;

            let mut echo = vec![0u8; message.len()];
            stream.read_exact(&mut echo).await?;

            tracing::info!(
                from = %client.ip,
                to = %server.ip,
                over = %server.endpoint,
                reply = %String::from_utf8_lossy(&echo),
                "round trip"
            );
        }
    }

    tracing::info!("every node reached every other node over udp");

    Ok(())
}
