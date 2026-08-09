use std::net::Ipv4Addr;
use std::time::Duration;

use smolnet::{
    addr::MacAddr,
    device::{Medium, loopback::LoopbackDevice},
    net::{Net, TcpState},
    stack::StackIdentity,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALICE_MAC: MacAddr = [0x02, 0x22, 0x33, 0x44, 0x55, 0x66];
const BOB_MAC: MacAddr = [0x02, 0x29, 0x39, 0x49, 0x59, 0x69];

const ALICE_IP: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 2);
const BOB_IP: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 3);

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();
}

fn identity(ip: Ipv4Addr) -> StackIdentity {
    StackIdentity {
        ip: ip.octets(),
        gateway: [10, 30, 0, 1],
        netmask: [0xff, 0xff, 0xff, 0x00],
    }
}

fn linked_pair() -> (Net, Net) {
    init_tracing();

    let (alice_device, bob_device) = LoopbackDevice::pair(
        Medium::Ethernet { mac: ALICE_MAC },
        Medium::Ethernet { mac: BOB_MAC },
    );

    let (alice, alice_driver) = smolnet::net::build(identity(ALICE_IP), alice_device);
    let (bob, bob_driver) = smolnet::net::build(identity(BOB_IP), bob_device);

    tokio::spawn(alice_driver.run());
    tokio::spawn(bob_driver.run());

    (alice, bob)
}

#[tokio::test]
async fn tcp_echo_round_trip() {
    let (alice, bob) = linked_pair();

    let listener = alice.tcp_listen(7878).unwrap();

    tokio::spawn(async move {
        let socket = listener.accept().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(socket);

        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
    });

    let mut client = tokio::time::timeout(Duration::from_secs(5), bob.tcp_connect(ALICE_IP, 7878))
        .await
        .expect("connect did not time out")
        .expect("connect succeeded");

    assert_eq!(client.peer_addr().to_string(), "10.30.0.2:7878");

    client.write_all(b"hello from bob\n").await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("read did not time out")
        .unwrap();

    assert_eq!(&buf[..n], b"hello from bob\n");
}

#[tokio::test]
async fn tcp_stream_reads_zero_when_the_peer_closes() {
    let (alice, bob) = linked_pair();

    let listener = alice.tcp_listen(7878).unwrap();

    tokio::spawn(async move {
        let mut socket = listener.accept().await.unwrap();

        socket.write_all(b"bye").await.unwrap();
        socket.shutdown().await.unwrap();
    });

    let mut client = bob.tcp_connect(ALICE_IP, 7878).await.unwrap();

    let mut received = vec![];
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut received))
        .await
        .expect("read_to_end did not time out")
        .unwrap();

    assert_eq!(received, b"bye");
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_carries_a_large_stream() {
    let (alice, bob) = linked_pair();

    let listener = alice.tcp_listen(7878).unwrap();

    tokio::spawn(async move {
        let socket = listener.accept().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(socket);

        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
    });

    let payload: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    let client = bob.tcp_connect(ALICE_IP, 7878).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(client);

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

    assert_eq!(received.len(), expected.len());
    assert_eq!(received, expected);
}

#[tokio::test]
async fn tcp_connect_to_a_dead_port_is_refused() {
    let (_alice, bob) = linked_pair();

    let result = tokio::time::timeout(Duration::from_secs(5), bob.tcp_connect(ALICE_IP, 9999))
        .await
        .expect("the refusal did not time out");

    assert!(result.is_err(), "connecting to a closed port must fail");
}

#[tokio::test]
async fn many_connections_are_served_concurrently() {
    let (alice, bob) = linked_pair();

    let listener = alice.tcp_listen(7878).unwrap();

    tokio::spawn(async move {
        loop {
            let socket = listener.accept().await.unwrap();

            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(socket);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    let mut clients = vec![];
    for index in 0..16u8 {
        let bob = bob.clone();

        clients.push(tokio::spawn(async move {
            let mut client = bob.tcp_connect(ALICE_IP, 7878).await.unwrap();
            let message = vec![index; 128];

            client.write_all(&message).await.unwrap();

            let mut buf = vec![0u8; 128];
            client.read_exact(&mut buf).await.unwrap();

            assert_eq!(buf, message);
        }));
    }

    for client in clients {
        tokio::time::timeout(Duration::from_secs(20), client)
            .await
            .expect("every connection completed")
            .unwrap();
    }
}

#[tokio::test]
async fn udp_round_trip() {
    let (alice, bob) = linked_pair();

    let server = alice.udp_bind(Some(7878)).unwrap();
    let client = bob.udp_bind(Some(4000)).unwrap();

    client.send_to(b"ping", ALICE_IP, 7878).unwrap();

    let mut buf = [0u8; 64];
    let (n, peer) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
        .await
        .expect("the datagram arrived")
        .unwrap();

    assert_eq!(&buf[..n], b"ping");
    assert_eq!(peer.to_string(), "10.30.0.3:4000");

    server.send_to(b"pong", BOB_IP, 4000).unwrap();

    let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("the reply arrived")
        .unwrap();

    assert_eq!(&buf[..n], b"pong");
}

#[tokio::test]
async fn a_listener_reports_its_address() {
    let (alice, _bob) = linked_pair();

    let listener = alice.tcp_listen(8080).unwrap();

    assert_eq!(listener.local_addr().to_string(), "10.30.0.2:8080");
    assert_eq!(alice.ipv4_addr(), ALICE_IP);
}

#[tokio::test]
async fn a_closed_stream_reports_its_state() {
    let (alice, bob) = linked_pair();

    let listener = alice.tcp_listen(7878).unwrap();
    tokio::spawn(async move {
        let socket = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(socket);
    });

    let mut client = bob.tcp_connect(ALICE_IP, 7878).await.unwrap();
    assert_eq!(client.state(), Some(TcpState::Established));

    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("the close was observed")
        .unwrap();

    assert_eq!(n, 0, "dropping the peer's stream closes ours");
}
