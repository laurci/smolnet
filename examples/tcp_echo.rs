use std::error::Error;
use std::net::Ipv4Addr;

use smolnet::{device::tap::TapDevice, stack::StackIdentity};
use tokio::task::spawn;
use tracing_subscriber::EnvFilter;

const LISTEN_PORT: u16 = 7878;

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tcp_echo=info,smolnet=info")),
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

    let listener = net.tcp_listen(LISTEN_PORT)?;
    tracing::info!(addr = %listener.local_addr(), "listening");

    loop {
        let conn = listener.accept().await?;

        spawn(async move {
            let peer = conn.peer_addr();
            tracing::info!(%peer, "accepted connection");

            let (mut reader, mut writer) = tokio::io::split(conn);

            match tokio::io::copy(&mut reader, &mut writer).await {
                Ok(bytes) => tracing::info!(%peer, bytes, "remote hung up"),
                Err(e) => tracing::error!(%peer, error = %e),
            }
        });
    }
}
