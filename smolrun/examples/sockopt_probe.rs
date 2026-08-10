use std::mem::size_of;
use std::net::TcpListener;
use std::os::fd::AsRawFd;

fn get(fd: i32, level: i32, option: i32) -> (i32, i32, u32) {
    let mut value: i32 = -1;
    let mut len = size_of::<i32>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            &mut value as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };

    (result, value, len)
}

fn set(fd: i32, level: i32, option: i32, value: i32) -> i32 {
    unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            &value as *const i32 as *const libc::c_void,
            size_of::<i32>() as libc::socklen_t,
        )
    }
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:7400")?;
    let fd = listener.as_raw_fd();

    println!("SO_TYPE       -> {:?}", get(fd, libc::SOL_SOCKET, libc::SO_TYPE));
    println!("SO_DOMAIN     -> {:?}", get(fd, libc::SOL_SOCKET, libc::SO_DOMAIN));
    println!("SO_ACCEPTCONN -> {:?}", get(fd, libc::SOL_SOCKET, libc::SO_ACCEPTCONN));
    println!("SO_ERROR      -> {:?}", get(fd, libc::SOL_SOCKET, libc::SO_ERROR));

    println!("set SO_RCVBUF=131072 -> {}", set(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 131072));
    println!("SO_RCVBUF     -> {:?}", get(fd, libc::SOL_SOCKET, libc::SO_RCVBUF));

    println!("set TCP_NODELAY=1 -> {}", set(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1));
    println!("TCP_NODELAY   -> {:?}", get(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY));

    let file = std::fs::File::open("/etc/hostname")?;
    let bad = set(file.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1);
    println!(
        "setsockopt on a plain file -> {} (errno {})",
        bad,
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    );

    Ok(())
}
