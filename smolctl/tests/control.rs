use std::net::Ipv4Addr;
use std::time::Duration;

use smolctl::{
    ControlService, JoinConfig, JoinError, Registry, Session,
    server::registry::{DEFAULT_NETMASK, DEFAULT_SUBNET},
    token::{self, DEFAULT_TTL, Identity},
};
use smolmesh::{NetworkId, NodeId, Reflector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

const SECRET: &[u8] = b"a shared secret that only the control plane knows";
const ECHO_PORT: u16 = 7777;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();
}

struct Control {
    url: String,
}

async fn control() -> Control {
    init_tracing();

    let reflector = Reflector::bind("127.0.0.1:0").await.unwrap();
    let advertise = reflector.local_addr().unwrap().to_string();
    tokio::spawn(reflector.run());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());

    let registry = Registry::new(DEFAULT_SUBNET, DEFAULT_NETMASK);
    let service = ControlService::new(registry, SECRET.to_vec(), advertise);

    tokio::spawn(
        Server::builder()
            .add_service(service.into_server())
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );

    Control { url }
}

fn token_for(network: NetworkId, node: NodeId) -> String {
    token::mint(SECRET, Identity { network, node }, DEFAULT_TTL)
        .unwrap()
        .0
}

async fn join(control: &Control, network: NetworkId) -> Session {
    let token = token_for(network, NodeId::random());

    tokio::time::timeout(
        Duration::from_secs(10),
        Session::join(
            JoinConfig::new(control.url.clone(), token)
                .bind("127.0.0.1:0".parse().unwrap())
                .stun(vec![]),
        ),
    )
    .await
    .expect("the join did not time out")
    .expect("the join succeeded")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_is_assigned_an_address_from_the_control_server() {
    let control = control().await;
    let network = NetworkId::random();

    let first = join(&control, network).await;
    let second = join(&control, network).await;

    assert_eq!(first.ipv4_addr(), Ipv4Addr::new(10, 30, 0, 2));
    assert_eq!(second.ipv4_addr(), Ipv4Addr::new(10, 30, 0, 3));

    assert_eq!(
        second.membership().peers.len(),
        1,
        "the second node is told about the first"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_signed_with_another_secret_is_refused() {
    let control = control().await;

    let token = token::mint(
        b"the wrong secret",
        Identity {
            network: NetworkId::random(),
            node: NodeId::random(),
        },
        DEFAULT_TTL,
    )
    .unwrap()
    .0;

    let result = Session::join(JoinConfig::new(control.url.clone(), token)).await;

    assert!(
        matches!(result, Err(JoinError::Rejected(_))),
        "an unsigned node cannot join"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_without_a_token_is_refused() {
    let control = control().await;

    let result = Session::join(JoinConfig::new(control.url.clone(), "not-a-jwt")).await;

    assert!(matches!(result, Err(JoinError::Rejected(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_discover_each_other_and_carry_tcp() {
    let control = control().await;
    let network = NetworkId::random();

    let server = join(&control, network).await;
    let client = join(&control, network).await;

    let server_ip = server.ipv4_addr();
    let server_net = server.net();
    let client_net = client.net();

    let listener = server_net.tcp_listen(ECHO_PORT).unwrap();

    tokio::spawn(async move {
        while let Ok(socket) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(socket);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    tokio::spawn(server.run());
    tokio::spawn(client.run());

    let mut stream = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(stream) = client_net.tcp_connect(server_ip, ECHO_PORT).await {
                break stream;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the nodes found each other");

    stream.write_all(b"over the overlay").await.unwrap();

    let mut echo = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echo))
        .await
        .expect("the echo came back")
        .unwrap();

    assert_eq!(&echo, b"over the overlay");
}

#[tokio::test(flavor = "multi_thread")]
async fn endpoints_are_discovered_by_reflection_and_shared() {
    let control = control().await;
    let network = NetworkId::random();

    let first = join(&control, network).await;
    let second = join(&control, network).await;

    let first_handle = first.handle();
    let second_peers = second.peers();
    let first_node = first_handle.node();

    tokio::spawn(first.run());
    tokio::spawn(second.run());

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if second_peers
                .get(&first_node)
                .and_then(|peer| peer.endpoint)
                .is_some()
            {
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the second node learned where the first one lives");

    assert_eq!(
        first_handle.observed().reflected,
        Some(first_handle.local_addr().unwrap()),
        "the reflector told us the address our socket sends from"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_departing_node_is_removed_from_the_roster() {
    let control = control().await;
    let network = NetworkId::random();

    let first = join(&control, network).await;
    let second = join(&control, network).await;

    let first_peers = first.peers();
    let second_node = second.handle().node();

    tokio::spawn(first.run());
    let leaving = tokio::spawn(second.run());

    tokio::time::timeout(Duration::from_secs(10), async {
        while first_peers.get(&second_node).is_none() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the first node saw the second join");

    leaving.abort();

    tokio::time::timeout(Duration::from_secs(10), async {
        while first_peers.get(&second_node).is_some() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the first node saw the second leave");
}

#[tokio::test(flavor = "multi_thread")]
async fn nodes_on_different_networks_never_see_each_other() {
    let control = control().await;

    let first = join(&control, NetworkId::random()).await;
    let second = join(&control, NetworkId::random()).await;

    assert!(first.membership().peers.is_empty());
    assert!(second.membership().peers.is_empty());

    let first_peers = first.peers();

    tokio::spawn(first.run());
    tokio::spawn(second.run());

    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(
        first_peers.is_empty(),
        "a separate network id is a separate mesh"
    );
}
