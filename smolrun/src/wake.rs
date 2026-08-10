use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

pub struct Waker {
    fd: OwnedFd,
}

impl Waker {
    pub fn new() -> io::Result<Waker> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Waker {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    pub fn try_clone(&self) -> io::Result<Waker> {
        Ok(Waker {
            fd: self.fd.try_clone()?,
        })
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn wake(&self) {
        let one: u64 = 1;

        unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                &one as *const u64 as *const libc::c_void,
                size_of::<u64>(),
            );
        }
    }

    pub fn drain(&self) {
        let mut count: u64 = 0;

        loop {
            let read = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    &mut count as *mut u64 as *mut libc::c_void,
                    size_of::<u64>(),
                )
            };

            if read <= 0 {
                break;
            }
        }
    }
}

pub fn wait(
    notifications: BorrowedFd<'_>,
    wakeups: BorrowedFd<'_>,
    watched: &[std::os::fd::RawFd],
    timeout: Option<std::time::Duration>,
) -> io::Result<(bool, bool, Vec<std::os::fd::RawFd>)> {
    let mut fds = Vec::with_capacity(2 + watched.len());

    for fd in [notifications.as_raw_fd(), wakeups.as_raw_fd()]
        .into_iter()
        .chain(watched.iter().copied())
    {
        fds.push(libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
    }

    let milliseconds = match timeout {
        Some(timeout) => timeout.as_millis().min(i32::MAX as u128) as i32,
        None => -1,
    };

    loop {
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, milliseconds) };

        if ready < 0 {
            let error = io::Error::last_os_error();

            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }

            return Err(error);
        }

        let finished = fds[2..]
            .iter()
            .filter(|entry| entry.revents != 0)
            .map(|entry| entry.fd)
            .collect();

        return Ok((fds[0].revents != 0, fds[1].revents != 0, finished));
    }
}

#[cfg(test)]
mod test {
    use crate::wake::{Waker, wait};

    #[test]
    fn a_wakeup_is_observed_then_cleared() {
        let waker = Waker::new().unwrap();
        let other = Waker::new().unwrap();

        waker.wake();

        let (_, woken, _) = wait(other.as_fd(), waker.as_fd(), &[], None).unwrap();
        assert!(woken, "the eventfd reports readable");

        waker.drain();

        let mut fds = [libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(&waker.as_fd()),
            events: libc::POLLIN,
            revents: 0,
        }];

        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) };

        assert_eq!(ready, 0, "draining clears the wakeup");
    }

    #[test]
    fn a_clone_wakes_the_original() {
        let waker = Waker::new().unwrap();
        let clone = waker.try_clone().unwrap();
        let idle = Waker::new().unwrap();

        clone.wake();

        let (_, woken, _) = wait(idle.as_fd(), waker.as_fd(), &[], None).unwrap();
        assert!(woken);
    }

    #[test]
    fn a_timeout_returns_with_nothing_ready() {
        let idle = Waker::new().unwrap();
        let other = Waker::new().unwrap();

        let (notified, woken, _) = wait(
            other.as_fd(),
            idle.as_fd(),
            &[],
            Some(std::time::Duration::from_millis(10)),
        )
        .unwrap();

        assert!(!notified && !woken, "a timeout reports nothing ready");
    }
}
