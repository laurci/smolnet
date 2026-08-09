use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Duration;

use smolnet::{device::tap::TapDevice, stack::StackIdentity};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::task::spawn;
use tracing_subscriber::EnvFilter;

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 5);
const SERVER_PORT: u16 = 7777;
const MESSAGE: &str = "hello from smolnet";

const TIMEOUT: Duration = Duration::from_secs(5);

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tcp_client=info,smolnet=info")),
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

    let conn = tokio::time::timeout(TIMEOUT, net.tcp_connect(SERVER, SERVER_PORT)).await??;
    tracing::info!(peer = %conn.peer_addr(), "connected");

    let mut conn = BufReader::new(conn);

    conn.write_all(format!("{MESSAGE}\n").as_bytes()).await?;
    conn.flush().await?;

    let mut line = String::new();
    tokio::time::timeout(TIMEOUT, conn.read_line(&mut line)).await??;

    conn.shutdown().await?;

    println!("{}", line.trim_end());

    Ok(())
}
