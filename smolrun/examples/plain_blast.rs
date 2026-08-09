use std::io::Write;
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:9100")?;

    eprintln!("plain blaster listening on {}", listener.local_addr()?);

    for stream in listener.incoming() {
        let mut stream = stream?;

        std::thread::spawn(move || {
            let block = vec![0x5au8; 64 * 1024];

            while stream.write_all(&block).is_ok() {}
        });
    }

    Ok(())
}
