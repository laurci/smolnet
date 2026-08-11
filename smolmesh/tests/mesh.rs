use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use smolmesh::{Membership, MeshDevice, MeshHandle, NetworkId, NodeId, Peer, Reflector};
use smolnet::{
    net::Net,
    proto::{
        ipv4::{Ipv4Frame, Ipv4Payload},
        udp::wire::UdpFrame,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

const ECHO_PORT: u16 = 7878;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();
}

struct Node {
    net: Net,
    handle: MeshHandle,
    id: NodeId,
    ip: Ipv4Addr,
    endpoint: SocketAddr,
    key: smolmesh::keys::PublicKey,
}

async fn mesh(size: usize) -> (NetworkId, Vec<Node>) {
    mesh_with(size, None).await
}

async fn mesh_with(size: usize, rekey: Option<Duration>) -> (NetworkId, Vec<Node>) {
    init_tracing();

    let network = NetworkId::random();
    let mut nodes = vec![];

    for index in 0..size {
        let id = NodeId::random();
        let ip = Ipv4Addr::new(10, 30, 0, 2 + index as u8);

        let membership = Membership::new(network, id, ip);

        let keys = smolmesh::keys::Keypair::generate().unwrap();
        let key = keys.public();

        let (mut device, handle) = MeshDevice::bind("127.0.0.1:0", &membership, keys)
            .await
            .unwrap();

        if let Some(after) = rekey {
            device.rekey_after(after);
        }

        let endpoint = handle.local_addr().unwrap();

        let (net, driver) = smolnet::net::build(membership.stack_identity(), device);
        tokio::spawn(driver.run());

        nodes.push(Node {
            net,
            handle,
            id,
            ip,
            endpoint,
            key,
        });
    }

    // The control plane is what distributes static keys in production; here the
    // roster carries them so a session can be established.
    let roster: Vec<Peer> = nodes
        .iter()
        .map(|node| {
            let mut peer = Peer::new(node.id, node.ip).with_endpoint(node.endpoint);
            peer.key = Some(node.key);
            peer
        })
        .collect();

    for node in &nodes {
        node.handle
            .peers()
            .replace_all(roster.iter().filter(|p| p.node != node.id).cloned());
    }

    (network, nodes)
}

fn spawn_echo(net: &Net, port: u16) {
    let listener = net.tcp_listen(port).unwrap();

    tokio::spawn(async move {
        loop {
            let socket = listener.accept().await.unwrap();

            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(socket);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
}

fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, body: &[u8]) -> Vec<u8> {
    let frame = Ipv4Frame::new(
        src.octets(),
        dst.octets(),
        Ipv4Payload::Udp(UdpFrame::new(4000, dst_port, body)),
    );

    let mut bytes = vec![0u8; frame.size()];
    frame.write(&mut bytes);

    bytes
}

async fn send_datagram(
    socket: &UdpSocket,
    to: SocketAddr,
    network: NetworkId,
    sender: NodeId,
    packet: &[u8],
) {
    let datagram =
        smolmesh::wire::Datagram::new(
            smolmesh::wire::MessageType::Keepalive,
            network,
            sender,
            packet,
        );

    let mut bytes = vec![0u8; datagram.size()];
    datagram.write(&mut bytes);

    socket.send_to(&bytes, to).await.unwrap();
}

async fn assert_no_delivery(net: &Net, port: u16) {
    let socket = net.udp_bind(Some(port)).unwrap();
    let mut buf = [0u8; 128];

    let result = tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buf)).await;

    assert!(result.is_err(), "the datagram should never have arrived");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_node_reaches_every_other_node() {
    let (_, nodes) = mesh(3).await;

    for node in &nodes {
        spawn_echo(&node.net, ECHO_PORT);
    }

    for client in &nodes {
        for server in &nodes {
            if client.id == server.id {
                continue;
            }

            let mut stream = tokio::time::timeout(
                Duration::from_secs(5),
                client.net.tcp_connect(server.ip, ECHO_PORT),
            )
            .await
            .unwrap_or_else(|_| panic!("{} -> {} connected", client.ip, server.ip))
            .unwrap();

            let message = format!("{} to {}", client.ip, server.ip);
            stream.write_all(message.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; message.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
                .await
                .expect("the echo came back")
                .unwrap();

            assert_eq!(buf, message.as_bytes());
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_stream_survives_the_overlay_mtu() {
    let (_, nodes) = mesh(2).await;

    spawn_echo(&nodes[0].net, ECHO_PORT);

    let payload: Vec<u8> = (0..192 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    let stream = nodes[1]
        .net
        .tcp_connect(nodes[0].ip, ECHO_PORT)
        .await
        .unwrap();

    let (mut reader, mut writer) = tokio::io::split(stream);

    let sender = tokio::spawn(async move {
        writer.write_all(&payload).await.unwrap();
        writer.shutdown().await.unwrap();
    });

    let mut received = vec![];
    tokio::time::timeout(Duration::from_secs(30), reader.read_to_end(&mut received))
        .await
        .expect("the transfer did not time out")
        .unwrap();

    sender.await.unwrap();

    assert_eq!(received, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_datagram_from_an_unknown_node_is_dropped() {
    let (network, nodes) = mesh(2).await;

    let outsider = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = udp_packet(nodes[1].ip, nodes[0].ip, ECHO_PORT, b"let me in");

    send_datagram(
        &outsider,
        nodes[0].endpoint,
        network,
        NodeId::random(),
        &packet,
    )
    .await;

    assert_no_delivery(&nodes[0].net, ECHO_PORT).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_datagram_for_another_network_is_dropped() {
    let (_, nodes) = mesh(2).await;

    let outsider = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = udp_packet(nodes[1].ip, nodes[0].ip, ECHO_PORT, b"wrong network");

    send_datagram(
        &outsider,
        nodes[0].endpoint,
        NetworkId::random(),
        nodes[1].id,
        &packet,
    )
    .await;

    assert_no_delivery(&nodes[0].net, ECHO_PORT).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_cannot_spoof_another_peers_address() {
    let (network, nodes) = mesh(3).await;

    let outsider = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = udp_packet(nodes[2].ip, nodes[0].ip, ECHO_PORT, b"not mine to send");

    send_datagram(&outsider, nodes[0].endpoint, network, nodes[1].id, &packet).await;

    assert_no_delivery(&nodes[0].net, ECHO_PORT).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_is_refused_even_from_a_known_peer() {
    let (network, nodes) = mesh(2).await;

    let socket = nodes[0].net.udp_bind(Some(ECHO_PORT)).unwrap();

    let outsider = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = udp_packet(nodes[1].ip, nodes[0].ip, ECHO_PORT, b"hello neighbour");

    // Exactly what used to be delivered: a well formed datagram naming a peer
    // the receiver knows. There is no plaintext path any more, so it is dropped.
    send_datagram(&outsider, nodes[0].endpoint, network, nodes[1].id, &packet).await;

    let mut buf = [0u8; 128];

    assert!(
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .is_err(),
        "unencrypted traffic must never reach the stack"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_reach_each_other_over_an_encrypted_session() {
    let (_network, nodes) = mesh(2).await;

    let listener = nodes[0].net.udp_bind(Some(ECHO_PORT)).unwrap();
    let sender = nodes[1].net.udp_bind(None).unwrap();

    let mut buf = [0u8; 128];

    // The first packet triggers the handshake and is held, not lost, so a
    // single send is enough once the session comes up.
    sender
        .send_to(b"sealed and delivered", nodes[0].ip, ECHO_PORT)
        .unwrap();

    let (len, from) = tokio::time::timeout(Duration::from_secs(10), listener.recv_from(&mut buf))
        .await
        .expect("the encrypted datagram arrived")
        .unwrap();

    assert_eq!(&buf[..len], b"sealed and delivered");
    assert_eq!(from.ip(), std::net::IpAddr::V4(nodes[1].ip));
}


#[tokio::test(flavor = "multi_thread")]
async fn a_session_finds_the_candidate_that_answers() {
    let (_, nodes) = mesh(2).await;

    // Somewhere that takes datagrams and never replies, which is how a peer
    // behind our own nat looks when we aim at the address stun gave it.
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead = blackhole.local_addr().unwrap();

    let peers = nodes[1].handle.peers();
    let mut peer =
        Peer::new(nodes[0].id, nodes[0].ip).with_candidates(vec![dead, nodes[0].endpoint]);
    peer.key = Some(nodes[0].key);
    peers.insert(peer);

    assert_eq!(
        peers.route(&nodes[0].ip),
        Some(dead),
        "the first candidate is the one we would have used on its own"
    );

    let listener = nodes[0].net.udp_bind(Some(ECHO_PORT)).unwrap();
    let sender = nodes[1].net.udp_bind(None).unwrap();

    sender
        .send_to(b"round the back", nodes[0].ip, ECHO_PORT)
        .unwrap();

    let mut buf = [0u8; 128];
    let (len, _) = tokio::time::timeout(Duration::from_secs(10), listener.recv_from(&mut buf))
        .await
        .expect("a working candidate carried it")
        .unwrap();

    assert_eq!(&buf[..len], b"round the back");
    assert_eq!(
        peers.route(&nodes[0].ip),
        Some(nodes[0].endpoint),
        "and the address that answered is the one we keep"
    );
}

/// Sessions are replaced while they are in use, so a peer that restarts is not
/// stuck behind a session only one side still has. Nothing may be dropped while
/// that happens.
#[tokio::test(flavor = "multi_thread")]
async fn traffic_survives_a_session_being_replaced_underneath_it() {
    let (_, nodes) = mesh_with(2, Some(Duration::from_millis(150))).await;

    let listener = nodes[0].net.udp_bind(Some(ECHO_PORT)).unwrap();
    let sender = nodes[1].net.udp_bind(None).unwrap();

    const SENT: usize = 40;

    let receiving = tokio::spawn(async move {
        let mut seen = vec![];
        let mut buf = [0u8; 128];

        while seen.len() < SENT {
            let Ok(Ok((len, _))) =
                tokio::time::timeout(Duration::from_secs(5), listener.recv_from(&mut buf)).await
            else {
                break;
            };

            seen.push(String::from_utf8_lossy(&buf[..len]).to_string());
        }

        seen
    });

    for number in 0..SENT {
        sender
            .send_to(format!("packet {number}").as_bytes(), nodes[0].ip, ECHO_PORT)
            .unwrap();

        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let seen = receiving.await.unwrap();

    assert_eq!(
        seen.len(),
        SENT,
        "every packet must arrive across the rekeys, not just the ones between them"
    );

    for number in 0..SENT {
        assert!(seen.contains(&format!("packet {number}")), "packet {number} went missing");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keepalive_teaches_an_endpoint_without_carrying_traffic() {
    let (_, nodes) = mesh(2).await;

    let peers = nodes[0].handle.peers();
    peers.insert(Peer::new(nodes[1].id, nodes[1].ip));

    assert_eq!(peers.route(&nodes[1].ip), None);

    nodes[1].handle.keepalive(nodes[0].endpoint).await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), async {
        while peers.route(&nodes[1].ip).is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the keepalive taught the endpoint");

    assert_eq!(peers.route(&nodes[1].ip), Some(nodes[1].endpoint));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_packet_for_an_unreachable_address_is_dropped_without_killing_the_link() {
    let (_, nodes) = mesh(2).await;

    let sender = nodes[0].net.udp_bind(Some(4100)).unwrap();
    sender
        .send_to(b"nobody home", Ipv4Addr::new(10, 30, 0, 200), 9999)
        .unwrap();

    spawn_echo(&nodes[1].net, ECHO_PORT);

    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        nodes[0].net.tcp_connect(nodes[1].ip, ECHO_PORT),
    )
    .await
    .expect("the link still works")
    .unwrap();

    stream.write_all(b"still here").await.unwrap();

    let mut buf = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("the echo came back")
        .unwrap();

    assert_eq!(&buf, b"still here");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broadcast_reaches_every_peer() {
    let (_, nodes) = mesh(3).await;

    let listeners: Vec<_> = nodes[1..]
        .iter()
        .map(|node| node.net.udp_bind(Some(4200)).unwrap())
        .collect();

    let sender = nodes[0].net.udp_bind(Some(4201)).unwrap();

    for listener in &listeners {
        let mut buf = [0u8; 64];

        let received = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                sender
                    .send_to(b"anyone there", Ipv4Addr::new(10, 30, 0, 255), 4200)
                    .unwrap();

                if let Ok(Ok(received)) =
                    tokio::time::timeout(Duration::from_millis(200), listener.recv_from(&mut buf))
                        .await
                {
                    break received;
                }
            }
        })
        .await
        .expect("the broadcast arrived");

        assert_eq!(&buf[..received.0], b"anyone there");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_overlay_mtu_is_advertised_to_the_stack() {
    let (_, nodes) = mesh(1).await;

    assert_eq!(nodes[0].net.capabilities().mtu, smolmesh::MESH_MTU);
    assert_eq!(
        nodes[0].net.capabilities().medium,
        smolnet::device::Medium::Ip
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reflector_reports_the_endpoint_it_observes() {
    let (_, nodes) = mesh(1).await;

    let reflector = Reflector::bind("127.0.0.1:0").await.unwrap();
    let address = reflector.local_addr().unwrap();
    tokio::spawn(reflector.run());

    let mut observed = nodes[0].handle.observe();
    assert!(observed.borrow().is_empty());

    nodes[0].handle.probe(address).await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), observed.changed())
        .await
        .expect("the reflection came back")
        .unwrap();

    assert_eq!(
        observed.borrow().reflected,
        Some(nodes[0].endpoint),
        "the reflector saw the address our mesh socket sends from"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_answers_a_probe_like_a_reflector() {
    let (_, nodes) = mesh(2).await;

    let mut observed = nodes[0].handle.observe();
    nodes[0].handle.probe(nodes[1].endpoint).await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), observed.changed())
        .await
        .expect("the peer answered the probe")
        .unwrap();

    assert_eq!(observed.borrow().reflected, Some(nodes[0].endpoint));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reflection_for_another_network_is_ignored() {
    let (_, nodes) = mesh(1).await;

    let outsider = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = smolmesh::wire::encode_endpoint("1.2.3.4:5678".parse().unwrap());

    let datagram = smolmesh::wire::Datagram::new(
        smolmesh::wire::MessageType::Reflection,
        NetworkId::random(),
        NodeId::random(),
        &payload[..],
    );

    let mut bytes = vec![0u8; datagram.size()];
    datagram.write(&mut bytes);
    outsider.send_to(&bytes, nodes[0].endpoint).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(nodes[0].handle.observed().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_resolver_answers_names_from_the_peer_table() {
    use smolmesh::dns::{Zone, serve};
    use smolmesh::peer::{Peer, Peers};

    init_tracing();

    let peers: Peers = Peers::default();

    let mut laptop = Peer::new(NodeId::random(), Ipv4Addr::new(10, 9, 8, 7));
    laptop.name = Some("laptop".to_owned());
    peers.replace_all([laptop]);

    let zone = Zone::new(peers).with_self("thisbox", Ipv4Addr::new(10, 9, 8, 2));

    let bound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    drop(bound);

    tokio::spawn(async move {
        let _ = serve(zone, listen).await;
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // a minimal query for laptop.smol A, built by hand so the test does not
    // depend on the same library it is checking
    let query: Vec<u8> = {
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["laptop", "smol"] {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        out
    };

    client.send_to(&query, listen).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("the resolver answered")
        .unwrap();

    let reply = &buf[..len];

    assert_eq!(&reply[..2], &[0x12, 0x34], "the reply carries our query id");
    assert_eq!(reply[2] & 0x80, 0x80, "it is a response");
    assert_eq!(reply[3] & 0x0f, 0, "with no error");
    assert!(u16::from_be_bytes([reply[6], reply[7]]) >= 1, "and at least one answer");

    assert!(
        reply.windows(4).any(|w| w == [10, 9, 8, 7]),
        "the answer carries the peer's overlay address"
    );
}
