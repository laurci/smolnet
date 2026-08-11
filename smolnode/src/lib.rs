use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;

use smolctl::{JoinConfig, Joined};
use smolmesh::{MESH_MTU, forward};
use smolmesh::peer::ZONE;

/// Where the resolver listens when it cannot take a whole address of its own.
#[cfg(target_os = "macos")]
const RESOLVER_PORT: u16 = 5354;
use smolnet::device::Device;

pub struct NodeConfig {
    pub control: String,
    pub token: String,
    pub bind: SocketAddr,
    pub interface: Option<String>,
    pub mtu: usize,
    pub stun: Vec<String>,
    pub configure_interface: bool,
    pub serve_dns: bool,
    pub ca: Option<String>,
    pub keys: Option<smolmesh::keys::Keypair>,
    pub renew: Option<smolctl::client::Renewal>,
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
            serve_dns: true,
            ca: None,
            keys: None,
            renew: None,
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

/// Claim the network's first host address and point the system resolver at it
/// for our zone only. Every node answers this same address locally, so the
/// configuration is identical on every machine.
/// Point this machine's resolver at the mesh, and say where the resolver should
/// then listen. The two are one decision: each platform has its own way of
/// sending a zone somewhere, and the address that works follows from it.
#[cfg(target_os = "linux")]
fn configure_dns(interface: &str, resolver: Ipv4Addr) -> Result<SocketAddr, Box<dyn Error>> {
    let resolver_address = resolver;

    // Adding the address to the link is what makes it local, so a query for it
    // is delivered here rather than routed down the tunnel.
    shell("ip", &["addr", "replace", &format!("{resolver}/32"), "dev", interface])?;

    // resolved is the common case; without it the operator has to point their
    // own resolver at us, so a failure here is worth saying out loud but is not
    // fatal to the mesh itself.
    let resolver = resolver.to_string();

    if let Err(e) = shell("resolvectl", &["dns", interface, &resolver]) {
        return Err(format!("could not hand resolved our address: {e}").into());
    }

    shell("resolvectl", &["domain", interface, &format!("~{ZONE}")])?;

    Ok(SocketAddr::from((resolver_address, 53)))
}

/// A tunnel address is the wrong place for a resolver on macos: utun is point
/// to point, an alias on it never gets a local route, and the route covering the
/// overlay then sends the query down the tunnel to a peer that does not exist.
/// Loopback is unambiguously here, needs no alias and no route, and leaves port
/// 53 to whatever else on the machine wants it.
#[cfg(target_os = "macos")]
fn configure_dns(_: &str, _: Ipv4Addr) -> Result<SocketAddr, Box<dyn Error>> {
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, RESOLVER_PORT));

    // macos has no resolved; a file per domain under /etc/resolver is the
    // supported way to send one zone somewhere else, port and all.
    std::fs::create_dir_all("/etc/resolver")?;
    std::fs::write(
        format!("/etc/resolver/{ZONE}"),
        format!("nameserver {}\nport {RESOLVER_PORT}\n", Ipv4Addr::LOCALHOST),
    )?;

    Ok(listen)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn configure_dns(_: &str, _: Ipv4Addr) -> Result<SocketAddr, Box<dyn Error>> {
    Err("dns configuration is only implemented for linux and macos".into())
}

pub async fn run(config: NodeConfig) -> Result<(), Box<dyn Error>> {
    let mut joining = JoinConfig::new(config.control, config.token)
        .bind(config.bind)
        .ca(config.ca);

    if let Some(keys) = config.keys {
        joining = joining.keys(keys);
    }

    if let Some(renewal) = config.renew {
        joining = joining.renew(renewal);
    }

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

    let resolver = smolmesh::dns::resolver_address(ip, netmask);

    if config.serve_dns {
        match configure_dns(&interface, resolver) {
            Ok(listen) => {
                let zone = smolmesh::dns::Zone::new(joined.peers.clone())
                    .with_self(
                        joined
                            .membership
                            .name
                            .clone()
                            .unwrap_or_else(|| "this".to_owned()),
                        ip,
                    );

                tokio::spawn(async move {
                    if let Err(e) = smolmesh::dns::serve(zone, listen).await {
                        tracing::error!("the resolver stopped: {e}");
                    }
                });

                tracing::info!(%listen, "names under .{ZONE} resolve through this machine");
            }
            Err(e) => tracing::warn!("not serving dns: {e}"),
        }
    }

    let mut mesh = joined.device;
    let control = tokio::spawn(joined.control.run());

    let result = tokio::select! {
        result = forward(&mut tunnel, &mut mesh) => result,
        result = control => result.unwrap_or_else(|e| Err(std::io::Error::other(e))),
    };

    Ok(result?)
}
