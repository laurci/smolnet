use std::net::UdpSocket;
use std::os::fd::AsRawFd;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:7100")?;
    let fd = socket.as_raw_fd();

    eprintln!("udp read/write echo on {} (fd {fd})", socket.local_addr()?);

    let mut buffer = [0u8; 2048];

    loop {
        let (len, from) = socket.recv_from(&mut buffer)?;

        socket.connect(from)?;

        let written = unsafe { libc::write(fd, buffer.as_ptr() as *const libc::c_void, len) };

        eprintln!("write() returned {written} for {from}");

        let read_back =
            unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };

        eprintln!("read() returned {read_back}");
    }
}
