#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_os = "linux")]
use axum::{
    Router,
    extract::{ConnectInfo, State},
    response::IntoResponse,
    routing::get,
};
#[cfg(target_os = "linux")]
use smolnet::{axum::PeerAddr, device::tap::TapDevice, stack::StackIdentity};
#[cfg(target_os = "linux")]
use tokio::task::spawn;
#[cfg(target_os = "linux")]
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "linux")]
const LISTEN_PORT: u16 = 8080;

#[cfg(target_os = "linux")]
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("axum_hello=info,smolnet=info")),
        )
        .init();
}

#[cfg(target_os = "linux")]
async fn index(
    State(visits): State<Arc<AtomicUsize>>,
    ConnectInfo(peer): ConnectInfo<PeerAddr>,
) -> impl IntoResponse {
    let visit = visits.fetch_add(1, Ordering::Relaxed) + 1;

    tracing::info!(%peer, visit, "serving index");

    format!("Hello, world! You are visitor {visit} from {peer}.\n")
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

    let listener = net.tcp_listen(LISTEN_PORT)?;
    tracing::info!(url = %format!("http://{}/", listener.local_addr()), "serving");

    let router = Router::new()
        .route("/", get(index))
        .with_state(Arc::new(AtomicUsize::new(0)));

    let listener = smolnet::axum::Listener::from(listener);

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<PeerAddr>(),
    )
    .await?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("axum_hello needs a tun/tap device, which only exists on linux");
}
