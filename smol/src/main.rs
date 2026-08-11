mod config;
mod service;

use std::error::Error;
use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use service::Service;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "smol",
    about = "join a smolmesh network and run programs on it",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "store the control server and join token for this machine")]
    Login(Login),

    #[command(about = "install and start the mesh daemon")]
    Start(Start),

    #[command(about = "stop the mesh daemon")]
    Stop,

    #[command(about = "restart the mesh daemon")]
    Restart,

    #[command(about = "show whether the mesh daemon is running")]
    Status,

    #[command(about = "follow the mesh daemon logs")]
    Logs(Logs),

    #[command(about = "remove the mesh daemon from this machine")]
    Uninstall,

    #[command(about = "run a program with its sockets served by the mesh")]
    Run(Run),

    #[command(hide = true, name = "__daemon")]
    Daemon(Daemon),
}

#[derive(Parser)]
struct Login {
    #[arg(long, env = "SMOLCTL_CONTROL")]
    control: Option<String>,

    #[arg(long, env = "SMOL_AUTH_KEY", hide_env_values = true)]
    key: Option<String>,

    #[arg(long, help = "what to call this machine (defaults to its hostname)")]
    name: Option<String>,
}

#[derive(Parser)]
struct Start {
    #[arg(long)]
    control: Option<String>,

    #[arg(long, hide_env_values = true)]
    token: Option<String>,
}

#[derive(Parser)]
struct Logs {
    #[arg(short, long)]
    follow: bool,
}

#[derive(Parser)]
struct Daemon {
    #[arg(long, env = "SMOLCTL_CONTROL")]
    control: Option<String>,

    #[arg(long, env = "SMOL_AUTH_KEY", hide_env_values = true)]
    token: Option<String>,

    #[arg(long)]
    name: Option<String>,

    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,

    #[arg(long)]
    interface: Option<String>,

    #[arg(long, default_value_t = smolmesh::MESH_MTU)]
    mtu: usize,

    #[arg(long)]
    stun: Vec<String>,

    #[arg(long)]
    no_configure: bool,
}

#[derive(Parser)]
struct Run {
    #[arg(long)]
    control: Option<String>,

    #[arg(long, hide_env_values = true)]
    token: Option<String>,

    #[arg(long)]
    name: Option<String>,

    #[arg(long)]
    workdir: Option<std::path::PathBuf>,

    #[arg(long)]
    allow_io_uring: bool,

    #[arg(last = true, required = true)]
    command: Vec<String>,
}

async fn browser_login(api: &str) -> Result<String, Box<dyn Error>> {
    let connect = smolctl::client::start_connect(api).await?;

    println!();
    println!("  Open this in your browser:");
    println!();
    println!("      {}", connect.url);
    println!();
    println!("  and confirm the code:  {}", connect.code);
    println!();

    let _ = std::process::Command::new(if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    })
    .arg(&connect.url)
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .spawn();

    print!("  waiting");
    use std::io::Write;
    let _ = std::io::stdout().flush();

    for _ in 0..150 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        match smolctl::client::claim_connect(api, &connect).await {
            Ok(Some(key)) => {
                println!(" authorized");
                return Ok(key);
            }
            Ok(None) => {
                print!(".");
                let _ = std::io::stdout().flush();
            }
            Err(e) => {
                println!();
                return Err(e.into());
            }
        }
    }

    println!();

    Err("timed out waiting for the browser to authorize this machine".into())
}

fn tracing_for(filter: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)))
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Login(args) => {
            let mut config = config::load();

            if let Some(control) = args.control {
                config.control = control;
            }

            if config.control.is_empty() {
                return Err(
                    "no control server known: reinstall with `sudo ./install.sh <host>:<port>` \
                     or pass --control"
                        .into(),
                );
            }

            let control = config.control.clone();

            let key = match args.key {
                Some(key) => key,
                None => browser_login(&control).await?,
            };

            let account = smolctl::client::verify(&control, &key).await?;

            let chosen = args.name.is_some();

            let name = args
                .name
                .or_else(smolctl::client::discovered_hostname)
                .unwrap_or_else(|| "unnamed".to_owned());

            let node = smolmesh::NodeId::random().to_string();

            let issued = smolctl::client::exchange(
                &control,
                &key,
                &node,
                config::known_device(false).as_deref(),
                Some(&name),
                chosen,
                false,
            )
            .await?;

            config.key = key;

            config::save(&config)?;
            config::remember_device(false, &issued.device)?;

            println!();
            println!("signed in as {account}");
            println!("this machine is {} at {}", name, issued.ip);
            println!("saved to {}", config::path().display());
            println!();
            println!("now run: sudo smol start");
        }

        Command::Start(args) => {
            let config = config::resolve(args.control, args.token)?;
            let service = Service::located()?;

            service.install(
                &config.control,
                &config.key,
                config::known_device(false).as_deref(),
            )?;
            service.start()?;

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let state = service.status()?;

            if state != "active" {
                return Err(format!(
                    "the daemon did not stay up (it is {state}); see `smol logs`"
                )
                .into());
            }

            println!("the mesh daemon is {state}");
        }

        Command::Stop => {
            Service::located()?.stop()?;
            println!("stopped");
        }

        Command::Restart => {
            Service::located()?.restart()?;
            println!("restarted");
        }

        Command::Status => {
            println!("{}", Service::located()?.status()?);
        }

        Command::Logs(args) => {
            Service::located()?.logs(args.follow)?;
        }

        Command::Uninstall => {
            Service::located()?.uninstall()?;
            println!("removed");
        }

        Command::Daemon(args) => {
            tracing_for("smol=info,smolnode=info,smolctl=info,smolmesh=info");

            let config = config::resolve(args.control, args.token)?;

            let node_id = smolmesh::NodeId::random().to_string();
            let device = config::known_device(true);

            // With a device of its own the name is settled and never resent. On
            // a machine that has none, offer what the machine calls itself so
            // the first start lands on a named device rather than an anonymous
            // one; `--name` makes that a demand rather than a suggestion.
            let chosen = args.name.is_some();
            let name = args
                .name
                .clone()
                .or_else(|| device.is_none().then(smolctl::client::discovered_hostname).flatten());

            let issued = smolctl::client::exchange(
                &config.control,
                &config.key,
                &node_id,
                device.as_deref(),
                name.as_deref(),
                chosen,
                false,
            )
            .await?;

            config::remember_device(true, &issued.device)?;

            let mesh = config
                .mesh_url()
                .ok_or("no mesh endpoint known: reinstall with `sudo ./install.sh <host>:<port>`")?;

            tracing::info!(device = %issued.device, ip = %issued.ip, "exchanged the auth key for a join token");

            let mut node = smolnode::NodeConfig::new(mesh, issued.token);

            node.ca = issued.ca;
            node.keys = Some(config::keys_for(true, &issued.device)?);
            node.bind = args.bind;
            node.interface = args.interface;
            node.mtu = args.mtu;
            node.stun = args.stun;
            node.configure_interface = !args.no_configure;

            smolnode::run(node).await?;
        }

        Command::Run(args) => {
            run_program(args).await?;
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_program(args: Run) -> Result<(), Box<dyn Error>> {
    tracing_for("smol=info,smolrun=info,smolnet=warn");

    let config = config::resolve(args.control, args.token)?;

    let ephemeral = args.name.is_none();
    let node_id = smolmesh::NodeId::random().to_string();

    let issued = smolctl::client::exchange(
        &config.control,
        &config.key,
        &node_id,
        None,
        args.name.as_deref(),
        true,
        ephemeral,
    )
    .await?;

    let mesh = config
        .mesh_url()
        .ok_or("no mesh endpoint known: reinstall with `sudo ./install.sh <host>:<port>`")?;

    tracing::info!(
        device = %issued.device,
        ip = %issued.ip,
        ephemeral,
        "exchanged the auth key for a join token"
    );

    let mut run = smolrun::RunConfig::new(args.command);

    run.control = Some(mesh);
    run.token = Some(issued.token);
    run.ca = issued.ca;

    // A throwaway device is gone the moment this exits, so its key has nothing
    // to outlive; a named one is the same device every run and keeps its own.
    if !ephemeral {
        run.keys = Some(config::keys_for(false, &issued.device)?);
    }
    run.workdir = args.workdir;
    run.allow_io_uring = args.allow_io_uring;

    smolrun::run(run).await
}

#[cfg(not(target_os = "linux"))]
async fn run_program(_: Run) -> Result<(), Box<dyn Error>> {
    Err("smol run needs seccomp, which is linux only; use smol start on this platform".into())
}
