use std::error::Error;
use std::net::SocketAddr;

use clap::Parser;
use smolctl::{JoinConfig, Session};
use tokio::io::AsyncWriteExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(about = "serve a stream of zeros over the overlay, for throughput testing")]
struct Args {
    #[arg(long, env = "SMOLCTL_CONTROL")]
    control: String,

    #[arg(long, env = "SMOLCTL_TOKEN", hide_env_values = true)]
    token: String,

    #[arg(long, default_value_t = 9000)]
    port: u16,

    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("blast=info")),
        )
        .init();

    let session = Session::join(JoinConfig::new(args.control, args.token).bind(args.bind)).await?;

    let net = session.net();
    let listener = net.tcp_listen(args.port)?;

    tracing::info!(address = %session.ipv4_addr(), port = args.port, "blasting");

    tokio::spawn(async move {
        while let Ok(mut socket) = listener.accept().await {
            tokio::spawn(async move {
                let block = vec![0x5au8; 64 * 1024];

                loop {
                    if socket.write_all(&block).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    session.run().await?;

    Ok(())
}
