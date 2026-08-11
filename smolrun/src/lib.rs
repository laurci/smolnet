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

use smolctl::{JoinConfig, Joined};
use smolnet::net::Net;
use smolnet::{addr::MacAddr, device::tap::TapDevice, stack::StackIdentity};
use supervisor::Supervisor;

pub struct RunConfig {
    pub tap: String,
    pub control: Option<String>,
    pub token: Option<String>,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mac: String,
    pub workdir: Option<std::path::PathBuf>,
    pub allow_io_uring: bool,
    pub ca: Option<String>,
    pub keys: Option<smolmesh::keys::Keypair>,
    pub renew: Option<smolctl::client::Renewal>,
    pub command: Vec<String>,
}

impl RunConfig {
    pub fn new(command: Vec<String>) -> RunConfig {
        RunConfig {
            tap: "tap0".to_owned(),
            control: None,
            token: None,
            ip: Ipv4Addr::new(10, 30, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 30, 0, 1),
            mac: "02:de:ad:be:ef:11".to_owned(),
            workdir: None,
            allow_io_uring: false,
            ca: None,
            keys: None,
            renew: None,
            command,
        }
    }
}

struct Terminal {
    ours: libc::pid_t,
    handed: bool,
}

impl Terminal {
    fn hand_over(group: libc::pid_t) -> Terminal {
        let ours = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };

        if ours < 0 {
            return Terminal {
                ours: 0,
                handed: false,
            };
        }

        // tcsetpgrp from a background group raises SIGTTOU at us; ignore it for
        // the duration or we stop ourselves while trying to hand the job over.
        let previous = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
        let handed = unsafe { libc::tcsetpgrp(libc::STDIN_FILENO, group) } == 0;
        unsafe { libc::signal(libc::SIGTTOU, previous) };

        if handed {
            tracing::debug!(group, "handed the terminal to the target");
        }

        Terminal { ours, handed }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if !self.handed {
            return;
        }

        unsafe {
            let previous = libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            libc::tcsetpgrp(libc::STDIN_FILENO, self.ours);
            libc::signal(libc::SIGTTOU, previous);
        }
    }
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

pub async fn run(args: RunConfig) -> Result<(), Box<dyn std::error::Error>> {
    if args.command.is_empty() {
        return Err("no command to run".into());
    }

    let (net, address, netmask, zone) = match (&args.control, &args.token) {
        (Some(control), Some(token)) => {
            let mut joining = JoinConfig::new(control.clone(), token.clone()).ca(args.ca.clone());

            if let Some(keys) = args.keys.clone() {
                joining = joining.keys(keys);
            }

            if let Some(renewal) = args.renew.clone() {
                joining = joining.renew(renewal);
            }

            let session = Joined::join(joining).await?.into_session();

            let net = session.net();
            let address = session.ipv4_addr();
            let netmask = session.membership().netmask;

            let zone = smolmesh::dns::Zone::new(session.peers()).with_self(
                session
                    .membership()
                    .name
                    .clone()
                    .unwrap_or_else(|| "this".to_owned()),
                address,
            );

            tokio::spawn(session.run());

            (net, address, netmask, Some(zone))
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

            (net, args.ip, args.netmask, None)
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

    let mut supervisor = Supervisor::new(
        handover.listener,
        pid,
        net,
        tokio::runtime::Handle::current(),
        (address, netmask),
        args.allow_io_uring,
    )?;

    if let Some(zone) = zone {
        supervisor = supervisor.with_resolver(zone);
    }

    std::thread::spawn(move || supervisor.run());

    let group = pid as libc::pid_t;

    // The target runs in its own process group so we can take its children down
    // with it. That also makes it a background group, and a background process
    // reading the terminal is stopped with SIGTTIN, so hand it the terminal the
    // way a shell hands it to a job.
    let terminal = Terminal::hand_over(group);

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
            drop(terminal);

            return Ok(());
        }
    };

    stop();

    tracing::info!(?status, "target exited");

    // process::exit skips destructors, so give the terminal back by hand
    drop(terminal);

    std::process::exit(status.code().unwrap_or(0));
}
