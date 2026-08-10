use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;

use smolctl::{JoinConfig, Joined};
use smolmesh::{MESH_MTU, forward};
use smolnet::device::Device;

pub struct NodeConfig {
    pub control: String,
    pub token: String,
    pub bind: SocketAddr,
    pub interface: Option<String>,
    pub mtu: usize,
    pub stun: Vec<String>,
    pub configure_interface: bool,
}

impl NodeConfig {
    pub fn new(control: impl Into<String>, token: impl Into<String>) -> NodeConfig {
        NodeConfig {
            control: control.into(),
            token: token.into(),
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            interface: None,
            mtu: MESH_MTU,
            stun: Vec::new(),
            configure_interface: true,
        }
    }
}

fn shell(command: &str, arguments: &[&str]) -> Result<(), Box<dyn Error>> {
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

    shell("ip", &["addr", "replace", &address, "dev", interface])?;
    shell("ip", &["link", "set", "dev", interface, "mtu", &mtu, "up"])?;

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

    shell(
        "ifconfig",
        &[interface, &ip, &ip, "netmask", &netmask, "mtu", &mtu, "up"],
    )?;
    if let Err(e) = shell(
        "route",
        &["-n", "add", "-net", &subnet, "-interface", interface],
    ) {
        tracing::warn!("could not add the subnet route, it may already exist: {e}");
    }

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

pub async fn run(config: NodeConfig) -> Result<(), Box<dyn Error>> {
    let mut joining = JoinConfig::new(config.control, config.token).bind(config.bind);

    if !config.stun.is_empty() {
        joining = joining.stun(config.stun);
    }

    let joined = Joined::join(joining).await?;

    let ip = joined.membership.ip;
    let netmask = joined.membership.netmask;

    let (mut tunnel, interface) = open_tunnel(config.interface.as_deref(), config.mtu)?;

    if config.configure_interface {
        configure(&interface, ip, netmask, config.mtu)?;
    } else {
        tracing::warn!(interface, %ip, "skipping interface configuration as asked");
    }

    tracing::info!(
        interface,
        %ip,
        %netmask,
        mtu = config.mtu,
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
