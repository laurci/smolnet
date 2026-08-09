use std::error::Error;
use std::time::Instant;

use smolnet::{
    device::{Device, tap::TapDevice},
    proto::tcp::{TcpSocketHandle, TcpState},
    stack::{Stack, StackIdentity},
};
use tracing_subscriber::EnvFilter;

const HTTP_PORT: u16 = 8080;
const BODY: &str = "Hello, world!\n";
const MAX_REQUEST: usize = 8192;

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("http_hello=info,smolnet=info")),
        )
        .init();
}

struct Connection {
    handle: TcpSocketHandle,
    request: Vec<u8>,
    responded: bool,
}

fn headers_complete(request: &[u8]) -> bool {
    request.windows(4).any(|window| window == b"\r\n\r\n")
}

fn request_line(request: &[u8]) -> String {
    let end = request
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(request.len());

    String::from_utf8_lossy(&request[..end]).into_owned()
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

    let listener = stack.tcp_listen(HTTP_PORT)?;
    tracing::info!("serving http on 10.30.0.2:{HTTP_PORT}");

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        BODY.len(),
        BODY
    );

    let mut connections: Vec<Connection> = vec![];
    let mut buf = [0u8; 1024];

    loop {
        stack.poll(&mut device, Instant::now())?;

        while let Some(handle) = stack.tcp_accept(&listener) {
            connections.push(Connection {
                handle,
                request: vec![],
                responded: false,
            });
        }

        connections.retain_mut(|connection| {
            while connection.request.len() < MAX_REQUEST {
                let received = stack.tcp_recv(&connection.handle, &mut buf);
                if received == 0 {
                    break;
                }

                connection.request.extend_from_slice(&buf[..received]);
            }

            let oversized = connection.request.len() >= MAX_REQUEST;
            if oversized && !connection.responded {
                tracing::warn!("request exceeded {MAX_REQUEST} bytes, dropping the connection");

                connection.responded = true;
                stack.tcp_close(&connection.handle);
            }

            if !connection.responded && headers_complete(&connection.request) {
                tracing::info!("{}", request_line(&connection.request));

                if stack.tcp_send_capacity(&connection.handle) >= response.len() {
                    stack.tcp_send(&connection.handle, response.as_bytes());

                    connection.responded = true;
                    stack.tcp_close(&connection.handle);
                }
            }

            if !connection.responded
                && stack.tcp_state(&connection.handle) == Some(TcpState::CloseWait)
            {
                tracing::info!("client hung up before sending a complete request");
                stack.tcp_close(&connection.handle);
            }

            stack.tcp_state(&connection.handle).is_some()
        });

        stack.wait(&mut device, Instant::now())?;
    }
}
