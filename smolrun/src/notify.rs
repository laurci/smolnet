use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use libc::{c_ulong, c_void};

pub const NOTIF_RECV: c_ulong = 0xc050_2100;
pub const NOTIF_SEND: c_ulong = 0xc018_2101;
pub const NOTIF_ID_VALID: c_ulong = 0x4008_2102;
pub const NOTIF_ADDFD: c_ulong = 0x4018_2103;

pub const USER_NOTIF_FLAG_CONTINUE: u32 = 1;
pub const ADDFD_FLAG_SEND: u32 = 1 << 1;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Notif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

fn ioctl(fd: BorrowedFd<'_>, request: c_ulong, argument: *mut c_void) -> io::Result<i64> {
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), request, argument) };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(result as i64)
}

pub fn recv(fd: BorrowedFd<'_>) -> io::Result<Notif> {
    let mut notif = Notif::default();

    ioctl(fd, NOTIF_RECV, &mut notif as *mut Notif as *mut c_void)?;

    Ok(notif)
}

pub fn send(fd: BorrowedFd<'_>, response: NotifResp) -> io::Result<()> {
    let mut response = response;

    ioctl(
        fd,
        NOTIF_SEND,
        &mut response as *mut NotifResp as *mut c_void,
    )?;

    Ok(())
}

pub fn id_valid(fd: BorrowedFd<'_>, id: u64) -> bool {
    let mut id = id;

    ioctl(fd, NOTIF_ID_VALID, &mut id as *mut u64 as *mut c_void).is_ok()
}

pub fn add_fd(fd: BorrowedFd<'_>, request: NotifAddfd) -> io::Result<i32> {
    let mut request = request;

    let installed = ioctl(
        fd,
        NOTIF_ADDFD,
        &mut request as *mut NotifAddfd as *mut c_void,
    )?;

    Ok(installed as i32)
}

pub fn allow(id: u64, value: i64) -> NotifResp {
    NotifResp {
        id,
        val: value,
        error: 0,
        flags: 0,
    }
}

pub fn fail(id: u64, errno: i32) -> NotifResp {
    NotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    }
}

pub fn passthrough(id: u64) -> NotifResp {
    NotifResp {
        id,
        val: 0,
        error: 0,
        flags: USER_NOTIF_FLAG_CONTINUE,
    }
}

#[cfg(test)]
mod test {
    use crate::notify::{Notif, NotifAddfd, NotifResp, SeccompData, fail, passthrough};

    #[test]
    fn the_structures_match_the_kernel_layout() {
        assert_eq!(size_of::<SeccompData>(), 64);
        assert_eq!(size_of::<Notif>(), 80);
        assert_eq!(size_of::<NotifResp>(), 24);
        assert_eq!(size_of::<NotifAddfd>(), 24);
    }

    #[test]
    fn a_failure_carries_a_negative_errno() {
        let response = fail(7, libc::EAFNOSUPPORT);

        assert_eq!(response.id, 7);
        assert_eq!(response.error, -libc::EAFNOSUPPORT);
        assert_eq!(response.flags, 0);
    }

    #[test]
    fn a_passthrough_sets_only_the_continue_flag() {
        let response = passthrough(9);

        assert_eq!(response.error, 0);
        assert_eq!(response.val, 0);
        assert_eq!(response.flags, 1);
    }
}
