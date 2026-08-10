use std::io::{Read, Write};
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:7300")?;

    eprintln!("blocking echo listening on {}", listener.local_addr()?);

    for stream in listener.incoming() {
        let mut stream = stream?;
        let peer = stream.peer_addr()?;

        eprintln!("accepted {peer}");

        let mut buffer = [0u8; 2048];

        while let Ok(len) = stream.read(&mut buffer) {
            if len == 0 || stream.write_all(&buffer[..len]).is_err() {
                break;
            }
        }
    }

    Ok(())
}
