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
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("ntp=info,smolnet=info")),
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

    let sock = stack.udp_bind(None)?;

    let mut req_ntp = [0u8; 48];
    req_ntp[0] = 0x1b;

    stack.udp_send(&sock, [162, 159, 200, 1], 123, req_ntp.to_vec());

    loop {
        stack.poll(&mut device, Instant::now())?;

        while let Some((addr, port, data)) = stack.udp_recv(&sock) {
            // we could parse ntp time here.
            tracing::info!("udp recv {:?} {} {:?}", addr, port, data);
        }

        stack.wait(&mut device, Instant::now())?;
    }
}
