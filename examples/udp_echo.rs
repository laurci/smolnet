#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddr};

#[cfg(target_os = "linux")]
use smolnet::{device::tap::TapDevice, stack::StackIdentity};
#[cfg(target_os = "linux")]
use tokio::task::spawn;
#[cfg(target_os = "linux")]
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "linux")]
const LISTEN_PORT: u16 = 7878;

#[cfg(target_os = "linux")]
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("udp_echo=info,smolnet=info")),
        )
        .init();
}

#[cfg(target_os = "linux")]
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("udp_echo needs a tun/tap device, which only exists on linux");
}
