use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;

use clap::Parser;
use smolctl::{JoinConfig, Joined};
use smolmesh::{MESH_MTU, forward};
use smolnet::device::Device;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "smolnode",
    about = "join a smolmesh network and expose it as a local tun interface"
)]
struct Args {
    #[arg(long, env = "SMOLCTL_CONTROL")]
    control: String,

    #[arg(long, env = "SMOLCTL_TOKEN", hide_env_values = true)]
    token: String,

    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,

    #[arg(long)]
    interface: Option<String>,

    #[arg(long, default_value_t = MESH_MTU)]
    mtu: usize,

    #[arg(long)]
    stun: Vec<String>,

    #[arg(long)]
    no_configure: bool,
}

fn run(command: &str, arguments: &[&str]) -> Result<(), Box<dyn Error>> {
    tracing::info!(command, ?arguments, "configuring the interface");

    let output = Command::new(command).args(arguments).output()?;

    if !output.status.success() {
        return Err(format!(
            "{command} {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn configure(
    interface: &str,
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: usize,
) -> Result<(), Box<dyn Error>> {
    let prefix = u32::from(netmask).count_ones();
    let address = format!("{ip}/{prefix}");
    let mtu = mtu.to_string();

    run("ip", &["addr", "replace", &address, "dev", interface])?;
    run("ip", &["link", "set", "dev", interface, "mtu", &mtu, "up"])?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn configure(
    interface: &str,
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: usize,
) -> Result<(), Box<dyn Error>> {
    let ip = ip.to_string();
    let netmask = netmask.to_string();
    let mtu = mtu.to_string();

    let network = Ipv4Addr::from(
        u32::from(ip.parse::<Ipv4Addr>()?) & u32::from(netmask.parse::<Ipv4Addr>()?),
    );
    let prefix = u32::from(netmask.parse::<Ipv4Addr>()?).count_ones();
    let subnet = format!("{network}/{prefix}");

    run(
        "ifconfig",
        &[interface, &ip, &ip, "netmask", &netmask, "mtu", &mtu, "up"],
    )?;
    run(
        "route",
        &["-n", "add", "-net", &subnet, "-interface", interface],
    )?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn open_tunnel(
    interface: Option<&str>,
    mtu: usize,
) -> Result<(impl Device, String), Box<dyn Error>> {
    use smolnet::device::tun::TunDevice;

    let name = interface.unwrap_or("smolmesh0").to_owned();
    let device = TunDevice::open(&name, mtu)?;

    Ok((device, name))
}

#[cfg(target_os = "macos")]
fn open_tunnel(
    interface: Option<&str>,
    mtu: usize,
) -> Result<(impl Device, String), Box<dyn Error>> {
    use smolnet::device::utun::UtunDevice;

    let unit = interface
        .and_then(|name| name.strip_prefix("utun"))
        .and_then(|unit| unit.parse().ok());

    let device = UtunDevice::open(unit, mtu)?;
    let name = device.name().to_owned();

    Ok((device, name))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_tunnel(_: Option<&str>, _: usize) -> Result<(impl Device, String), Box<dyn Error>> {
    Err::<(smolnet::device::loopback::LoopbackDevice, String), _>(
        "smolnode needs a tun interface, which this platform does not provide".into(),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("smolnode=info,smolctl=info,smolmesh=info")),
        )
        .init();

    let mut config = JoinConfig::new(args.control, args.token).bind(args.bind);

    if !args.stun.is_empty() {
        config = config.stun(args.stun);
    }

    let joined = Joined::join(config).await?;

    let ip = joined.membership.ip;
    let netmask = joined.membership.netmask;

    let (mut tunnel, interface) = open_tunnel(args.interface.as_deref(), args.mtu)?;

    if args.no_configure {
        tracing::warn!(interface, %ip, "skipping interface configuration as asked");
    } else {
        configure(&interface, ip, netmask, args.mtu)?;
    }

    tracing::info!(
        interface,
        %ip,
        %netmask,
        mtu = args.mtu,
        "the mesh is up, bind your services to this address"
    );

    let mut mesh = joined.device;
    let control = tokio::spawn(joined.control.run());

    let result = tokio::select! {
        result = forward(&mut tunnel, &mut mesh) => result,
        result = control => result.unwrap_or_else(|e| Err(std::io::Error::other(e))),
    };

    Ok(result?)
}
