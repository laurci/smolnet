use std::net::TcpListener;
use std::os::fd::{AsRawFd, RawFd};

fn send_fd(socket: RawFd, payload: RawFd) -> bool {
    let mut byte = [0u8; 1];
    let mut space = [0u8; 32];

    let mut slice = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut slice;
    message.msg_iovlen = 1;
    message.msg_control = space.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = space.len();

    unsafe {
        let control = libc::CMSG_FIRSTHDR(&message);
        (*control).cmsg_level = libc::SOL_SOCKET;
        (*control).cmsg_type = libc::SCM_RIGHTS;
        (*control).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;

        (libc::CMSG_DATA(control) as *mut RawFd).write_unaligned(payload);
        message.msg_controllen = (*control).cmsg_len;

        libc::sendmsg(socket, &message, 0) >= 0
    }
}

fn recv_fd(socket: RawFd) -> Option<RawFd> {
    let mut byte = [0u8; 1];
    let mut space = [0u8; 32];

    let mut slice = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut slice;
    message.msg_iovlen = 1;
    message.msg_control = space.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = space.len();

    unsafe {
        if libc::recvmsg(socket, &mut message, 0) < 0 {
            return None;
        }

        let control = libc::CMSG_FIRSTHDR(&message);

        if control.is_null() || (*control).cmsg_type != libc::SCM_RIGHTS {
            return None;
        }

        Some((libc::CMSG_DATA(control) as *const RawFd).read_unaligned())
    }
}

fn listening(fd: RawFd) -> bool {
    let mut probe: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            &mut probe as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };

    result == 0 && probe == 1
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:7600")?;
    let fd = listener.as_raw_fd();

    eprintln!("listening on {} (fd {fd})", listener.local_addr()?);

    let mut pair = [0 as RawFd; 2];

    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let child = unsafe { libc::fork() };

    if child == 0 {
        unsafe { libc::close(pair[0]) };

        let received = recv_fd(pair[1]).unwrap_or(-1);
        eprintln!("child received fd {received} over SCM_RIGHTS");

        unsafe { libc::sleep(3) };

        let alive = listening(received);
        eprintln!("child sees the socket listening: {alive}");

        unsafe { libc::_exit(i32::from(!alive)) };
    }

    unsafe { libc::close(pair[1]) };

    if !send_fd(pair[0], fd) {
        eprintln!("FAIL: could not pass the descriptor");
        std::process::exit(1);
    }

    eprintln!("parent passed fd {fd} to the child, now closing its own copy");
    drop(listener);

    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };

    let code = (status >> 8) & 0xff;

    if code != 0 {
        eprintln!("FAIL: the socket died when the parent closed its descriptor");
        std::process::exit(1);
    }

    eprintln!("PASS: the socket survived in the process that received it");

    Ok(())
}
