use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use clap::Parser;
use smolctl::{JoinConfig, Session};
use smolmesh::Peers;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(about = "join a smolmesh network and talk to a peer over tcp")]
struct Args {
    #[arg(long, env = "SMOLCTL_CONTROL")]
    control: String,

    #[arg(long, env = "SMOLCTL_TOKEN", hide_env_values = true)]
    token: String,

    #[arg(long)]
    peer: Option<Ipv4Addr>,

    #[arg(long, default_value_t = 7777)]
    port: u16,

    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,

    #[arg(long)]
    stun: Vec<String>,

    #[arg(long, default_value_t = 60)]
    timeout: u64,
}

async fn wait_for_peer(peers: &Peers, wanted: Option<Ipv4Addr>) -> Ipv4Addr {
    loop {
        let reachable: Vec<Ipv4Addr> = peers
            .list()
            .into_iter()
            .filter(|peer| peer.endpoint.is_some())
            .map(|peer| peer.ip)
            .collect();

        match wanted {
            Some(wanted) if reachable.contains(&wanted) => return wanted,
            None if !reachable.is_empty() => return reachable[0],
            _ => {}
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("mesh_client=info,smolctl=info,smolmesh=info")),
        )
        .init();

    let session = Session::join({
        let mut config = JoinConfig::new(args.control, args.token).bind(args.bind);

        if !args.stun.is_empty() {
            config = config.stun(args.stun);
        }

        config
    })
    .await?;

    let net = session.net();
    let peers = session.peers();
    let address = session.ipv4_addr();

    tracing::info!(%address, "waiting for a reachable peer");

    let control = tokio::spawn(session.run());

    let peer = tokio::time::timeout(
        Duration::from_secs(args.timeout),
        wait_for_peer(&peers, args.peer),
    )
    .await
    .map_err(|_| "no peer became reachable in time")?;

    tracing::info!(%peer, port = args.port, "connecting");

    let mut stream = tokio::time::timeout(
        Duration::from_secs(args.timeout),
        net.tcp_connect(peer, args.port),
    )
    .await
    .map_err(|_| "the connection attempt timed out")??;

    tracing::info!(%peer, "connected, type a line and press enter");

    let mut input = BufReader::new(tokio::io::stdin()).lines();
    let mut buffer = [0u8; 2048];

    loop {
        tokio::select! {
            line = input.next_line() => {
                let Some(mut line) = line? else { break };
                line.push('\n');

                stream.write_all(line.as_bytes()).await?;
            }
            read = stream.read(&mut buffer) => {
                match read? {
                    0 => {
                        tracing::info!("the peer closed the connection");
                        break;
                    }
                    len => {
                        print!("{}", String::from_utf8_lossy(&buffer[..len]));
                        std::io::Write::flush(&mut std::io::stdout())?;
                    }
                }
            }
        }
    }

    control.abort();

    Ok(())
}
