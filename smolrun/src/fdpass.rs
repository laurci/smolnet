use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use libc::{c_void, cmsghdr, iovec, msghdr};

pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];

    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub fn send(socket: BorrowedFd<'_>, payload: BorrowedFd<'_>, pid: u32) -> io::Result<()> {
    let mut buffer = pid.to_ne_bytes();
    let mut space = [0u8; 32];

    let mut io_slice = iovec {
        iov_base: buffer.as_mut_ptr() as *mut c_void,
        iov_len: buffer.len(),
    };

    let mut message: msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut io_slice;
    message.msg_iovlen = 1;
    message.msg_control = space.as_mut_ptr() as *mut c_void;
    message.msg_controllen = space.len();

    unsafe {
        let control = libc::CMSG_FIRSTHDR(&message) as *mut cmsghdr;
        (*control).cmsg_level = libc::SOL_SOCKET;
        (*control).cmsg_type = libc::SCM_RIGHTS;
        (*control).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;

        let target = libc::CMSG_DATA(control) as *mut RawFd;
        target.write_unaligned(payload.as_raw_fd());

        message.msg_controllen = (*control).cmsg_len;

        if libc::sendmsg(socket.as_raw_fd(), &message, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

pub fn recv(socket: BorrowedFd<'_>) -> io::Result<(OwnedFd, u32)> {
    let mut buffer = [0u8; 4];
    let mut space = [0u8; 32];

    let mut io_slice = iovec {
        iov_base: buffer.as_mut_ptr() as *mut c_void,
        iov_len: buffer.len(),
    };

    let mut message: msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut io_slice;
    message.msg_iovlen = 1;
    message.msg_control = space.as_mut_ptr() as *mut c_void;
    message.msg_controllen = space.len();

    let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };

    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    if received == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the child exited before handing over its notification fd",
        ));
    }

    if received as usize != buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the child sent a truncated handover",
        ));
    }

    unsafe {
        let control = libc::CMSG_FIRSTHDR(&message);

        if control.is_null()
            || (*control).cmsg_level != libc::SOL_SOCKET
            || (*control).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the child did not attach a file descriptor",
            ));
        }

        let source = libc::CMSG_DATA(control) as *const RawFd;

        Ok((
            OwnedFd::from_raw_fd(source.read_unaligned()),
            u32::from_ne_bytes(buffer),
        ))
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, OwnedFd};

    use crate::fdpass::{pair, recv, send};

    #[test]
    fn a_descriptor_survives_the_trip() {
        let (left, right) = pair().unwrap();
        let (payload_a, payload_b) = pair().unwrap();

        send(left.as_fd(), payload_a.as_fd(), 4242).unwrap();
        let (landed, pid): (OwnedFd, u32) = recv(right.as_fd()).unwrap();

        assert_eq!(pid, 4242, "the sender's pid rides along with the descriptor");

        let mut writer = std::fs::File::from(landed);
        writer.write_all(b"through the door").unwrap();

        let mut reader = std::fs::File::from(payload_b);
        let mut buffer = [0u8; 16];
        reader.read_exact(&mut buffer).unwrap();

        assert_eq!(&buffer, b"through the door");
    }

    #[test]
    fn a_closed_sender_is_reported_rather_than_hanging() {
        let (left, right) = pair().unwrap();
        drop(left);

        assert!(recv(right.as_fd()).is_err());
    }
}
