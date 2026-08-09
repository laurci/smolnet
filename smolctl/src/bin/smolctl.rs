use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};

use clap::{Parser, Subcommand};
use smolctl::{
    ControlService, Registry,
    server::registry::{DEFAULT_NETMASK, DEFAULT_SUBNET},
    token::{self, DEFAULT_TTL, Identity},
};
use smolmesh::{NetworkId, NodeId, Reflector};
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "smolctl", about = "control plane for smolmesh networks")]
struct Cli {
    #[arg(long, env = "SMOLCTL_SECRET", hide_env_values = true, global = true)]
    secret: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Mint(Mint),
    Serve(Serve),
    Network(Network),
}

#[derive(Parser)]
#[command(about = "mint a join token for a node")]
struct Mint {
    #[arg(long)]
    network: String,

    #[arg(long)]
    node: Option<String>,

    #[arg(long, default_value_t = DEFAULT_TTL)]
    ttl: u64,
}

#[derive(Parser)]
#[command(about = "run the control server and endpoint reflector")]
struct Serve {
    #[arg(long, default_value = "0.0.0.0:8989")]
    listen: SocketAddr,

    #[arg(long, default_value = "0.0.0.0:8989")]
    reflect: SocketAddr,

    #[arg(long)]
    advertise: String,

    #[arg(long, default_value_t = DEFAULT_SUBNET)]
    subnet: Ipv4Addr,

    #[arg(long, default_value_t = DEFAULT_NETMASK)]
    netmask: Ipv4Addr,
}

#[derive(Parser)]
#[command(about = "generate identifiers")]
struct Network {
    #[arg(long, default_value_t = 1)]
    nodes: usize,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("smolctl=info,smolmesh=info")),
        )
        .init();
}

fn secret(cli: &Cli) -> Result<Vec<u8>, Box<dyn Error>> {
    cli.secret
        .as_ref()
        .map(|secret| secret.as_bytes().to_vec())
        .ok_or_else(|| "set SMOLCTL_SECRET or pass --secret".into())
}

async fn mint(cli: &Cli, args: &Mint) -> Result<(), Box<dyn Error>> {
    let identity = Identity {
        network: args.network.parse()?,
        node: match &args.node {
            Some(node) => node.parse()?,
            None => NodeId::random(),
        },
    };

    let (jwt, claims) = token::mint(&secret(cli)?, identity, args.ttl)?;

    println!("network {}", identity.network);
    println!("node    {}", identity.node);
    println!("expires {}", claims.exp);
    println!();
    println!("{jwt}");

    Ok(())
}

async fn serve(cli: &Cli, args: &Serve) -> Result<(), Box<dyn Error>> {
    let secret = secret(cli)?;

    let reflector = Reflector::bind(args.reflect).await?;
    tokio::spawn(async move {
        if let Err(e) = reflector.run().await {
            tracing::error!("reflector stopped: {e}");
        }
    });

    let registry = Registry::new(args.subnet, args.netmask);
    let service = ControlService::new(registry, secret, args.advertise.clone());

    tracing::info!(
        listen = %args.listen,
        reflect = %args.reflect,
        advertise = %args.advertise,
        subnet = %args.subnet,
        netmask = %args.netmask,
        "control server starting"
    );

    Server::builder()
        .add_service(service.into_server())
        .serve_with_shutdown(args.listen, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;

    Ok(())
}

fn network(args: &Network) {
    println!("network {}", NetworkId::random());

    for _ in 0..args.nodes {
        println!("node    {}", NodeId::random());
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Mint(args) => {
            mint(&cli, args).await?;
        }
        Command::Serve(args) => {
            init_tracing();
            serve(&cli, args).await?;
        }
        Command::Network(args) => network(args),
    }

    Ok(())
}
