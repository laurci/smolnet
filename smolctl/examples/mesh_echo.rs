use std::error::Error;
use std::net::SocketAddr;

use clap::Parser;
use smolctl::{JoinConfig, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(about = "join a smolmesh network and echo tcp on it")]
struct Args {
    #[arg(long, env = "SMOLCTL_CONTROL")]
    control: String,

    #[arg(long, env = "SMOLCTL_TOKEN", hide_env_values = true)]
    token: String,

    #[arg(long, default_value_t = 7777)]
    port: u16,

    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,

    #[arg(long)]
    stun: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("mesh_echo=info,smolctl=info,smolmesh=info")),
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
    let address = session.ipv4_addr();

    let listener = net.tcp_listen(args.port)?;

    tracing::info!(%address, port = args.port, "echoing on the overlay");

    tokio::spawn(async move {
        loop {
            let socket = match listener.accept().await {
                Ok(socket) => socket,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    continue;
                }
            };

            let peer = socket.peer_addr();
            tracing::info!(%peer, "connection accepted");

            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(socket);
                let mut buffer = [0u8; 2048];

                loop {
                    match reader.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(len) => {
                            tracing::info!(
                                %peer,
                                message = %String::from_utf8_lossy(&buffer[..len]).trim_end(),
                                "echoing"
                            );

                            if writer.write_all(&buffer[..len]).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(%peer, "read failed: {e}");
                            break;
                        }
                    }
                }

                tracing::info!(%peer, "connection closed");
            });
        }
    });

    session.run().await?;

    Ok(())
}
