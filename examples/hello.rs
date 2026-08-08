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

    let sock = stack.udp_bind(7878.into())?;

    loop {
        stack.poll(&mut device)?;

        while let Some((addr, port, data)) = stack.udp_recv(&sock) {
            let text = String::from_utf8_lossy(&data);
            let reply = format!("reply: {}\n", text.trim());
            stack.udp_send(&sock, addr, port, reply.into_bytes());
        }

        stack.wait(&mut device)?;
    }
}
