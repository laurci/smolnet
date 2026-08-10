#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use smolnet::{device::tap::TapDevice, stack::StackIdentity};
#[cfg(target_os = "linux")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(target_os = "linux")]
use tokio::task::spawn;
#[cfg(target_os = "linux")]
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "linux")]
const SERVER: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 5);
#[cfg(target_os = "linux")]
const SERVER_PORT: u16 = 7777;
#[cfg(target_os = "linux")]
const MESSAGE: &str = "hello from smolnet";

#[cfg(target_os = "linux")]
const TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tcp_client=info,smolnet=info")),
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp_client needs a tun/tap device, which only exists on linux");
}
