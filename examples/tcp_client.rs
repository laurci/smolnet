use std::error::Error;
use std::time::{Duration, Instant};

use smolnet::{
    addr::Ipv4Addr,
    device::{Device, tap::TapDevice},
    proto::tcp::TcpState,
    stack::{Stack, StackIdentity},
};
use tracing_subscriber::EnvFilter;

const SERVER: Ipv4Addr = [10, 30, 0, 5];
const SERVER_PORT: u16 = 7777;
const MESSAGE: &str = "hello from smolnet";

const TIMEOUT: Duration = Duration::from_secs(5);

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tcp_client=info,smolnet=info")),
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

    let handle = stack.tcp_connect(SERVER, SERVER_PORT, None)?;

    let start = Instant::now();

    let mut request_sent = false;
    let mut closing = false;
    let mut response = vec![];
    let mut buf = [0u8; 1024];

    loop {
        let now = Instant::now();
        stack.poll(&mut device, now)?;

        if closing {
            break;
        }

        if now.duration_since(start) > TIMEOUT {
            tracing::error!("timed out after {:?}", TIMEOUT);
            break;
        }

        let Some(state) = stack.tcp_state(&handle) else {
            tracing::error!("connection went away before a reply arrived");
            break;
        };

        if state == TcpState::Established && !request_sent {
            let line = format!("{MESSAGE}\n");
            let sent = stack.tcp_send(&handle, line.as_bytes());

            tracing::info!("sent {sent} bytes to {SERVER:?}:{SERVER_PORT}");
            request_sent = true;
        }

        loop {
            let received = stack.tcp_recv(&handle, &mut buf);
            if received == 0 {
                break;
            }

            response.extend_from_slice(&buf[..received]);
        }

        let have_reply = response.contains(&b'\n');
        if (request_sent && have_reply) || state == TcpState::CloseWait {
            tracing::info!("closing");
            stack.tcp_close(&handle);
            closing = true;
        }

        stack.wait(&mut device, Instant::now())?;
    }

    if response.is_empty() {
        tracing::warn!("no response received");
    } else {
        println!("{}", String::from_utf8_lossy(&response).trim_end());
    }

    Ok(())
}
