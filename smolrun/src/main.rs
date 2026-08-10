mod fdpass;
mod mem;
mod notify;
mod seccomp;
mod supervisor;
mod wake;

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

    #[arg(long)]
    workdir: Option<std::path::PathBuf>,

    #[arg(long)]
    allow_io_uring: bool,

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

struct Handover {
    listener: OwnedFd,
    pid: u32,
    gate: OwnedFd,
    exit: tokio::sync::oneshot::Receiver<io::Result<std::process::ExitStatus>>,
}

fn spawn(command: &[String], workdir: Option<&std::path::Path>) -> io::Result<Handover> {
    let (ours, theirs) = fdpass::pair()?;
    let handover = theirs.as_fd().try_clone_to_owned()?;
    let filter = seccomp::program(seccomp::INTERCEPTED, seccomp::BY_DESCRIPTOR);

    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);

    if let Some(workdir) = workdir {
        child.current_dir(workdir);
    }

    unsafe {
        child.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(io::Error::last_os_error());
            }

            seccomp::set_no_new_privs()?;

            let listener = seccomp::install(&filter)?;
            fdpass::send(handover.as_fd(), listener.as_fd(), std::process::id())?;

            Ok(())
        });
    }

    let (report, exit) = tokio::sync::oneshot::channel();

    std::thread::spawn(move || {
        drop(theirs);

        let outcome = match child.spawn() {
            Ok(mut started) => started.wait(),
            Err(e) => Err(e),
        };

        let _ = report.send(outcome);
    });

    let (listener, pid) = fdpass::recv(ours.as_fd())?;

    Ok(Handover {
        listener,
        pid,
        gate: ours,
        exit,
    })
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

    let (net, address, netmask) = match (&args.control, &args.token) {
        (Some(control), Some(token)) => {
            let session = Joined::join(JoinConfig::new(control.clone(), token.clone()))
                .await?
                .into_session();

            let net = session.net();
            let address = session.ipv4_addr();
            let netmask = session.membership().netmask;

            tokio::spawn(session.run());

            (net, address, netmask)
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

            (net, args.ip, args.netmask)
        }
    };

    let handover = spawn(&args.command, args.workdir.as_deref())?;
    let pid = handover.pid;
    let _gate = handover.gate;

    tracing::info!(
        pid,
        program = %args.command[0],
        ip = %address,
        "supervising, its sockets now live on the smolnet stack"
    );

    let supervisor = Supervisor::new(
        handover.listener,
        pid,
        net,
        tokio::runtime::Handle::current(),
        (address, netmask),
        args.allow_io_uring,
    )?;
    std::thread::spawn(move || supervisor.run());

    let group = pid as libc::pid_t;

    let stop = move || {
        tracing::info!(pid, "taking the target down with us");

        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    };

    let status = tokio::select! {
        outcome = handover.exit => outcome.map_err(|_| io::Error::other("the target was never started"))??,
        _ = tokio::signal::ctrl_c() => {
            stop();
            return Ok(());
        }
    };

    stop();

    tracing::info!(?status, "target exited");

    std::process::exit(status.code().unwrap_or(0));
}
