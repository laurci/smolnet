use std::error::Error;

use smolnet::{
    device::{Device, tap::TapDevice},
    stack::{Stack, StackIdentity},
};

fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().init();

    let identity = StackIdentity {
        mac: [0x02, 0xde, 0xad, 0xbe, 0xef, 0x02],
        ip: [10, 30, 0, 2],
    };

    let mut device = TapDevice::open("tap0")?;

    let mut stack = Stack::new(identity);

    loop {
        stack.poll(&mut device)?;
        device.wait(None, stack.has_pending_egress())?;
    }
}
