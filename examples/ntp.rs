use std::error::Error;

use smolnet::{
    device::tap::TapDevice,
    stack::{Stack, StackIdentity},
};

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().init();

    let identity = StackIdentity {
        mac: [0x02, 0xde, 0xad, 0xbe, 0xef, 0x02],
        ip: [10, 30, 0, 2],
        gateway: [10, 30, 0, 1],
        netmask: [0xff, 0xff, 0xff, 0x00],
    };

    let mut device = TapDevice::open("tap0")?;

    let mut stack = Stack::new(identity);

    let sock = stack.udp_bind(55674)?;

    let mut req_ntp = [0u8; 48];
    req_ntp[0] = 0x1b;

    stack.udp_send(&sock, [162, 159, 200, 1], 123, req_ntp.to_vec());

    loop {
        stack.poll(&mut device)?;

        while let Some((addr, port, data)) = stack.udp_recv(&sock) {
            tracing::info!("udp recv {:?} {} {:?}", addr, port, data);
        }

        stack.wait(&mut device)?;
    }
}
