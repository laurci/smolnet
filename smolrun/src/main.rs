mod fdpass;
mod mem;
mod notify;
mod seccomp;
mod supervisor;

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use clap::Parser;
use smolctl::{JoinConfig, Joined};
use smolnet::net::Net;
use smolnet::{addr::MacAddr, device::tap::TapDevice, stack::StackIdentity};
use supervisor::Supervisor;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "smolrun",
    about = "run an unmodified program with its tcp sockets served by smolnet"
)]
struct Args {
    #[arg(long, default_value = "tap0")]
    tap: String,

    #[arg(long, env = "SMOLCTL_CONTROL")]
    control: Option<String>,

    #[arg(long, env = "SMOLCTL_TOKEN", hide_env_values = true)]
    token: Option<String>,

    #[arg(long, default_value = "10.30.0.2")]
    ip: Ipv4Addr,

    #[arg(long, default_value = "255.255.255.0")]
    netmask: Ipv4Addr,

    #[arg(long, default_value = "10.30.0.1")]
    gateway: Ipv4Addr,

    #[arg(long, default_value = "02:de:ad:be:ef:11")]
    mac: String,

    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn parse_mac(text: &str) -> Result<MacAddr, String> {
    let parts: Vec<&str> = text.split(':').collect();

    if parts.len() != 6 {
        return Err(format!("{text} is not a mac address"));
    }

    let mut mac = [0u8; 6];

    for (slot, part) in mac.iter_mut().zip(parts) {
        *slot = u8::from_str_radix(part, 16).map_err(|_| format!("{text} is not a mac address"))?;
    }

    Ok(mac)
}

fn spawn(command: &[String]) -> io::Result<(std::process::Child, OwnedFd, OwnedFd)> {
    let (ours, theirs) = fdpass::pair()?;
    let handover = theirs.as_fd().try_clone_to_owned()?;
    let filter = seccomp::program(seccomp::INTERCEPTED);

    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);

    unsafe {
        child.pre_exec(move || {
            seccomp::set_no_new_privs()?;

            let listener = seccomp::install(&filter)?;
            fdpass::send(handover.as_fd(), listener.as_fd())?;

            Ok(())
        });
    }

    let child = child.spawn()?;
    drop(theirs);

    let listener = fdpass::recv(ours.as_fd())?;

    Ok((child, listener, ours))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("smolrun=info,smolnet=warn")),
        )
        .init();

    let (net, address) = match (&args.control, &args.token) {
        (Some(control), Some(token)) => {
            let session = Joined::join(JoinConfig::new(control.clone(), token.clone()))
                .await?
                .into_session();

            let net = session.net();
            let address = session.ipv4_addr();

            tokio::spawn(session.run());

            (net, address)
        }
        _ => {
            let identity = StackIdentity {
                ip: args.ip.octets(),
                gateway: args.gateway.octets(),
                netmask: args.netmask.octets(),
            };

            let device = TapDevice::open(&args.tap, parse_mac(&args.mac)?)?;
            let (net, driver): (Net, _) = smolnet::net::build(identity, device);
            tokio::spawn(driver.run());

            (net, args.ip)
        }
    };

    let (mut child, listener, _gate) = spawn(&args.command)?;
    let pid = child.id();

    tracing::info!(
        pid,
        program = %args.command[0],
        ip = %address,
        "supervising, its sockets now live on the smolnet stack"
    );

    let supervisor = Supervisor::new(listener, pid, net, tokio::runtime::Handle::current())?;
    std::thread::spawn(move || supervisor.run());

    let status = tokio::task::spawn_blocking(move || child.wait()).await??;

    tracing::info!(?status, "target exited");

    std::process::exit(status.code().unwrap_or(0));
}
