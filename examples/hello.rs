use std::error::Error;
use std::time::Instant;

use smolnet::{
    device::{Device, tap::TapDevice},
    stack::{Stack, StackIdentity},
};
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("smolnet=info")),
        )
        .init();
}

fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();

    let identity = StackIdentity {
        ip: [10, 30, 0, 2],
        gateway: [10, 30, 0, 1],
        netmask: [0xff, 0xff, 0xff, 0x00],
    };

    let mut device = TapDevice::open("tap0", [0x02, 0xde, 0xad, 0xbe, 0xef, 0x02])?;

    let mut stack = Stack::new(identity, device.capabilities());

    let sock = stack.udp_bind(7878.into())?;

    loop {
        stack.poll(&mut device, Instant::now())?;

        while let Some((addr, port, data)) = stack.udp_recv(&sock) {
            let text = String::from_utf8_lossy(&data);
            let reply = format!("reply: {}\n", text.trim());
            stack.udp_send(&sock, addr, port, reply.into_bytes());
        }

        stack.wait(&mut device, Instant::now())?;
    }
}
