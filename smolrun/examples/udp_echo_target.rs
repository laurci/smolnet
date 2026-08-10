use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:7000")?;

    eprintln!("udp echo listening on {}", socket.local_addr()?);

    let mut buffer = [0u8; 2048];

    loop {
        let (len, from) = socket.recv_from(&mut buffer)?;

        eprintln!("echoing {len} bytes to {from}");
        socket.send_to(&buffer[..len], from)?;
    }
}
