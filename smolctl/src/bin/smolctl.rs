use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};

use clap::{Parser, Subcommand};
use smolctl::{
    ControlService, Registry,
    server::registry::{DEFAULT_NETMASK, DEFAULT_SUBNET},
    token::{self, DEFAULT_TTL, Identity},
};
use smolmesh::{NetworkId, NodeId, Reflector};
use tonic::transport::{Server, ServerTlsConfig};
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

    #[arg(long)]
    device: Option<String>,

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

    #[arg(long, default_value = "0.0.0.0:3000")]
    console: SocketAddr,

    #[arg(long, default_value = "smolctl.db")]
    database: String,

    #[arg(long)]
    assets: Option<String>,
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
        device: args.device.clone().unwrap_or_else(|| "dev".to_owned()),
    };

    let (jwt, claims) = token::mint(&secret(cli)?, identity.clone(), args.ttl)?;

    println!("network {}", identity.network);
    println!("node    {}", identity.node);
    println!("device  {}", identity.device);
    println!("expires {}", claims.exp);
    println!();
    println!("{jwt}");

    Ok(())
}

async fn serve(cli: &Cli, args: &Serve) -> Result<(), Box<dyn Error>> {
    let secret = secret(cli)?;

    let store = smolctl::server::store::Store::open(&args.database).await?;

    match store.reset_presence().await {
        Ok(0) => {}
        Ok(cleared) => tracing::info!(cleared, "cleared stale presence from the last run"),
        Err(e) => tracing::warn!("could not clear stale presence: {e}"),
    }

    let material = smolctl::server::tls::Material::load_or_create(beside(&args.database))?;

    let (console, presence) = smolctl::server::http::Console::new(
        store.clone(),
        secret.clone(),
        std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
        std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default(),
        std::env::var("SMOL_PUBLIC_URL").unwrap_or_else(|_| format!("http://{}", args.console)),
        args.assets.clone().map(std::path::PathBuf::from),
        material.certificate.clone(),
    );

    {
        let console = console.clone();
        let listen = args.console;

        tokio::spawn(async move {
            if let Err(e) = smolctl::server::http::serve(console, listen).await {
                tracing::error!("console stopped: {e}");
            }
        });
    }

    let reflector = Reflector::bind(args.reflect).await?;
    tokio::spawn(async move {
        if let Err(e) = reflector.run().await {
            tracing::error!("reflector stopped: {e}");
        }
    });

    let registry = Registry::new(args.subnet, args.netmask);
    let service = ControlService::new(registry, secret, args.advertise.clone())
        .with_store(store)
        .with_presence(presence);

    tracing::info!(
        listen = %args.listen,
        reflect = %args.reflect,
        advertise = %args.advertise,
        subnet = %args.subnet,
        netmask = %args.netmask,
        certificate = %material.fingerprint(),
        "control server starting"
    );

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(material.identity()))?
        // Nodes hold this stream open for days behind home routers. Ping it so
        // a connection the network quietly dropped is noticed on both ends
        // instead of leaving a node listed as online long after it is gone.
        .http2_keepalive_interval(Some(smolctl::client::CONTROL_KEEPALIVE))
        .http2_keepalive_timeout(Some(smolctl::client::CONTROL_KEEPALIVE_TIMEOUT))
        .tcp_keepalive(Some(smolctl::client::CONTROL_KEEPALIVE))
        .add_service(service.into_server())
        .serve_with_shutdown(args.listen, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;

    Ok(())
}

/// Keep the control certificate next to the database: both are this server's
/// state, and both have to outlive a restart.
fn beside(database: &str) -> &std::path::Path {
    let parent = std::path::Path::new(database).parent();

    match parent {
        Some(directory) if !directory.as_os_str().is_empty() => directory,
        _ => std::path::Path::new("."),
    }
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
