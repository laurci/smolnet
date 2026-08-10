use std::net::TcpListener;
use std::os::fd::AsRawFd;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:7500")?;
    let fd = listener.as_raw_fd();

    eprintln!("listening on {} (fd {fd})", listener.local_addr()?);

    for round in 0..3 {
        let child = unsafe { libc::fork() };

        if child == 0 {
            unsafe { libc::_exit(0) };
        }

        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };

        eprintln!("round {round}: child {child} inherited fd {fd} and exited without closing it");
    }

    let duplicate = unsafe { libc::dup(fd) };
    eprintln!("dup gave us fd {duplicate}, closing the original {fd}");

    unsafe { libc::close(fd) };

    let mut probe: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            duplicate,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            &mut probe as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };

    eprintln!("the duplicate still reports listening: {result} value {probe}");

    if result != 0 || probe != 1 {
        eprintln!("FAIL: the socket died with its original descriptor");
        std::process::exit(1);
    }

    eprintln!("PASS: the socket outlived the descriptor it was created on");

    Ok(())
}
