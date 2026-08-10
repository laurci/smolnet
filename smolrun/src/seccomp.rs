use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use libc::{c_long, c_uint, c_ulong, c_void, sock_filter, sock_fprog};

pub const INTERCEPTED: &[c_long] = &[
    libc::SYS_socket,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_connect,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_shutdown,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_close,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_fcntl,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_close_range,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

pub const BY_DESCRIPTOR: &[c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_sendmmsg,
    libc::SYS_recvmmsg,
    libc::SYS_readv,
    libc::SYS_writev,
];

pub const DATAGRAM_FD_BASE: u32 = 500;

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = AUDIT_ARCH_X86_64;
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = AUDIT_ARCH_AARCH64;

const SECCOMP_SET_MODE_FILTER: c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: c_ulong = 1 << 3;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const ARCH_OFFSET: u32 = 4;
const NR_OFFSET: u32 = 0;
const FIRST_ARG_OFFSET: u32 = 16;

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;

fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

pub fn program(syscalls: &[c_long], by_descriptor: &[c_long]) -> Vec<sock_filter> {
    let always = syscalls.len();
    let gated = by_descriptor.len();

    let head = 4;
    let examine = head + always + gated + 1;
    let notify = examine + 2;

    let mut filter = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, ARCH_OFFSET),
        jump(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_ARCH, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, NR_OFFSET),
    ];

    for (index, number) in syscalls.iter().enumerate() {
        let at = head + index;

        filter.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            *number as u32,
            (notify - at - 1) as u8,
            0,
        ));
    }

    for (index, number) in by_descriptor.iter().enumerate() {
        let at = head + always + index;

        filter.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            *number as u32,
            (examine - at - 1) as u8,
            0,
        ));
    }

    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, FIRST_ARG_OFFSET));
    filter.push(jump(BPF_JMP | BPF_JGE | BPF_K, DATAGRAM_FD_BASE, 0, 1));
    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    filter
}

pub fn set_no_new_privs() -> io::Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn install(filter: &[sock_filter]) -> io::Result<OwnedFd> {
    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut sock_filter,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const sock_fprog as *const c_void,
        )
    };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

#[cfg(test)]
mod test {
    use crate::seccomp::{BY_DESCRIPTOR, DATAGRAM_FD_BASE, INTERCEPTED, program};

    const ALLOW: u32 = 0x7fff_0000;
    const NOTIFY: u32 = 0x7fc0_0000;
    const KILL: u32 = 0x8000_0000;

    fn built() -> Vec<libc::sock_filter> {
        program(INTERCEPTED, BY_DESCRIPTOR)
    }

    fn notify_slot() -> usize {
        4 + INTERCEPTED.len() + BY_DESCRIPTOR.len() + 3
    }

    #[test]
    fn every_always_intercepted_call_lands_on_notify() {
        let filter = built();

        assert_eq!(filter[notify_slot()].k, NOTIFY);

        for index in 0..INTERCEPTED.len() {
            let at = 4 + index;
            let target = at + 1 + filter[at].jt as usize;

            assert_eq!(
                target,
                notify_slot(),
                "slot {index} jumps to the wrong place"
            );
        }
    }

    #[test]
    fn a_descriptor_gated_call_lands_on_the_range_check() {
        let filter = built();
        let examine = 4 + INTERCEPTED.len() + BY_DESCRIPTOR.len() + 1;

        assert_eq!(filter[examine].k, 16, "loads the first syscall argument");

        for index in 0..BY_DESCRIPTOR.len() {
            let at = 4 + INTERCEPTED.len() + index;
            let target = at + 1 + filter[at].jt as usize;

            assert_eq!(target, examine, "gated slot {index} misses the range check");
        }
    }

    #[test]
    fn a_low_descriptor_is_allowed_and_a_high_one_notifies() {
        let filter = built();
        let compare = 4 + INTERCEPTED.len() + BY_DESCRIPTOR.len() + 2;

        assert_eq!(filter[compare].k, DATAGRAM_FD_BASE);
        assert_eq!(
            filter[compare + 1 + filter[compare].jt as usize].k,
            NOTIFY,
            "a datagram descriptor is handed to us"
        );
        assert_eq!(
            filter[compare + 1 + filter[compare].jf as usize].k,
            ALLOW,
            "an ordinary descriptor goes straight to the kernel"
        );
    }

    #[test]
    fn anything_unlisted_is_allowed() {
        let filter = built();
        let fallthrough = 4 + INTERCEPTED.len() + BY_DESCRIPTOR.len();

        assert_eq!(filter[fallthrough].k, ALLOW);
    }

    #[test]
    fn a_foreign_architecture_is_killed() {
        let filter = built();

        assert_eq!(filter[1].jt, 1);
        assert_eq!(filter[2].k, KILL);
    }

    #[test]
    fn the_syscall_count_fits_the_jump_field() {
        assert!(INTERCEPTED.len() + BY_DESCRIPTOR.len() < 240);
    }
}
