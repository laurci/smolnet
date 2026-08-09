use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};

use smolnet::{device::tap::TapDevice, stack::StackIdentity};
use tokio::task::spawn;
use tracing_subscriber::EnvFilter;

const LISTEN_PORT: u16 = 7878;

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("udp_echo=info,smolnet=info")),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let identity = StackIdentity {
        ip: Ipv4Addr::new(10, 30, 0, 2).octets(),
        gateway: Ipv4Addr::new(10, 30, 0, 1).octets(),
        netmask: [0xff, 0xff, 0xff, 0x00],
    };

    let device = TapDevice::open("tap0", [0x02, 0xde, 0xad, 0xbe, 0xef, 0x02])?;

    let (net, driver) = smolnet::net::build(identity, device);
    spawn(driver.run());

    let socket = net.udp_bind(Some(LISTEN_PORT))?;
    tracing::info!(port = LISTEN_PORT, "listening");

    let mut buf = [0u8; 1500];

    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;

        let text = String::from_utf8_lossy(&buf[..n]);
        tracing::info!(%peer, "echoing {} bytes: {}", n, text.trim());

        let SocketAddr::V4(peer) = peer else {
            continue;
        };

        socket.send_to(&buf[..n], *peer.ip(), peer.port())?;
    }
}
