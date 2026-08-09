use std::error::Error;
use std::time::Instant;

use smolnet::{
    device::{Device, tap::TapDevice},
    proto::tcp::TcpState,
    stack::{Stack, StackIdentity},
};
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tcp_echo=info,smolnet=info")),
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

    let listener = stack.tcp_listen(7878)?;

    let mut connections = vec![];
    let mut buf = [0u8; 1024];

    loop {
        stack.poll(&mut device, Instant::now())?;

        while let Some(handle) = stack.tcp_accept(&listener) {
            tracing::info!("accepted a connection");
            connections.push(handle);
        }

        connections.retain(|handle| {
            loop {
                let room = stack.tcp_send_capacity(handle).min(buf.len());
                if room == 0 {
                    break;
                }

                let received = stack.tcp_recv(handle, &mut buf[..room]);
                if received == 0 {
                    break;
                }

                let text = String::from_utf8_lossy(&buf[..received]);
                tracing::info!("echoing {} bytes: {}", received, text.trim());

                let reply_text = format!("reply: {}\n", text.trim());
                let reply = &reply_text.into_bytes();

                stack.tcp_send(handle, reply);
            }

            if !stack.tcp_can_recv(handle) && stack.tcp_state(handle) == Some(TcpState::CloseWait) {
                tracing::info!("peer finished; closing");
                stack.tcp_close(handle);
            }

            stack.tcp_state(handle).is_some()
        });

        stack.wait(&mut device, Instant::now())?;
    }
}
