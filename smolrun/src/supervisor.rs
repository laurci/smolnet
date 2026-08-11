use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smolmesh::dns::Zone;
use smolnet::net::{Net, tcp::TcpStream, udp::UdpSocket};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Handle;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::mem::Memory;
use crate::notify::{self, ADDFD_FLAG_SEND, ADDFD_FLAG_SETFD, Notif, NotifAddfd};
use crate::seccomp::DATAGRAM_FD_BASE;
use crate::wake::{self, Waker};

const PAIR_BUFFER: libc::c_int = 64 * 1024;

const MSGHDR_NAME: u64 = 0;
const MSGHDR_NAMELEN: u64 = 8;
const MSGHDR_IOV: u64 = 16;
const MSGHDR_IOVLEN: u64 = 24;
const MSGHDR_FLAGS: u64 = 48;
const MMSGHDR_LEN: u64 = 56;
const MMSGHDR_SIZE: u64 = 64;
const IOVEC_SIZE: u64 = 16;
const IOV_MAX: usize = 1024;
const MSG_TRUNC_FLAG: u32 = 0x20;
const CLOSE_RANGE_CLOEXEC: u64 = 4;
const DNS_PORT: u16 = 53;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

type Arrival = (TcpStream, SocketAddrV4);

type Datagram = (Vec<u8>, SocketAddrV4);

struct Bound {
    socket: Arc<UdpSocket>,
    inbox: UnboundedReceiver<Datagram>,
    /// The other end of the inbox, so the supervisor can put a datagram the
    /// target never sent for onto the socket.
    injector: UnboundedSender<Datagram>,
    bell: OwnedFd,
    peeked: Option<Datagram>,
    drain: OwnedFd,
    receiving: tokio::task::AbortHandle,
}

impl Bound {
    fn take(&mut self) -> Option<Datagram> {
        self.peeked.take().or_else(|| self.inbox.try_recv().ok())
    }
}

impl Drop for Bound {
    fn drop(&mut self) {
        self.receiving.abort();
    }
}

struct Listening {
    arrivals: UnboundedReceiver<Arrival>,
    drain: OwnedFd,
    accepting: tokio::task::AbortHandle,
}

impl Drop for Listening {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

enum Role {
    Fresh,
    Bound,
    Listening(Listening),
    Connected,
    Datagram(Option<Bound>),
}

struct PendingAccept {
    id: u64,
    address: u64,
    address_len: u64,
    flags: i32,
}

struct PendingReceive {
    id: u64,
    buffer: u64,
    capacity: usize,
    flags: i32,
    address: u64,
    address_len: u64,
    scatter: Option<Vec<(u64, usize)>>,
    deadline: Option<Instant>,
}

struct Socket {
    options: HashMap<(i32, i32), i32>,
    waiting_accept: Option<PendingAccept>,
    waiting_receive: Option<PendingReceive>,
    waiting_connect: Option<u64>,
    connecting: Option<tokio::sync::oneshot::Receiver<Result<TcpStream, String>>>,
    error: Option<i32>,
    role: Role,
    local: Option<SocketAddrV4>,
    peer: Option<SocketAddrV4>,
    ours: Option<OwnedFd>,
    theirs: Option<OwnedFd>,
    blocking: bool,
    observed_flags: bool,
    timeouts: (Option<Duration>, Option<Duration>),
    inode: u64,
}

impl Socket {
    fn new(ours: OwnedFd, theirs: OwnedFd) -> Socket {
        let inode = inode_of(theirs.as_fd()).unwrap_or(0);

        Socket {
            options: HashMap::new(),
            waiting_accept: None,
            waiting_receive: None,
            waiting_connect: None,
            connecting: None,
            error: None,
            role: Role::Fresh,
            local: None,
            peer: None,
            ours: Some(ours),
            theirs: Some(theirs),
            blocking: true,
            observed_flags: false,
            timeouts: (None, None),
            inode,
        }
    }
}

fn socket_shaped(nr: i64) -> bool {
    matches!(
        nr,
        libc::SYS_bind
            | libc::SYS_listen
            | libc::SYS_accept
            | libc::SYS_accept4
            | libc::SYS_connect
            | libc::SYS_getsockname
            | libc::SYS_getpeername
            | libc::SYS_setsockopt
            | libc::SYS_getsockopt
            | libc::SYS_shutdown
            | libc::SYS_sendto
            | libc::SYS_recvfrom
    )
}

fn parse_socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

fn group_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = &stat[stat.rfind(')')? + 1..];
    let mut fields = tail.split_whitespace();

    fields.next()?;
    fields.next()?;
    fields.next()?.parse().ok()
}

fn inode_of(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let mut status: libc::stat = unsafe { std::mem::zeroed() };

    if unsafe { libc::fstat(fd.as_raw_fd(), &mut status) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(status.st_ino)
}

pub struct Supervisor {
    listener: OwnedFd,
    overlay: (Ipv4Addr, Ipv4Addr),
    waker: Waker,
    parked: usize,
    connecting: usize,
    memory: Memory,
    memories: HashMap<u32, Memory>,
    current: u32,
    net: Net,
    runtime: Handle,
    sockets: HashMap<i32, Socket>,
    aliases: HashMap<i32, i32>,
    refs: HashMap<i32, usize>,
    pidfds: HashMap<u32, OwnedFd>,
    reconcile_at: Option<Instant>,
    reconciled: Option<Instant>,
    undiscovered: usize,
    group: u32,
    allow_rings: bool,
    warned_rings: bool,
    zone: Option<Zone>,
}

fn socketpair(kind: libc::c_int) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];

    let result = unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, fds.as_mut_ptr()) };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

    for fd in [ours.as_fd(), theirs.as_fd()] {
        set_buffer(fd, libc::SO_SNDBUF)?;
        set_buffer(fd, libc::SO_RCVBUF)?;
    }

    set_nonblocking(ours.as_fd())?;

    Ok((ours, theirs))
}

fn resize(fd: BorrowedFd<'_>, option: libc::c_int, size: libc::c_int) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            &size as *const libc::c_int as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn set_buffer(fd: BorrowedFd<'_>, option: libc::c_int) -> io::Result<()> {
    let size = PAIR_BUFFER;

    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            &size as *const libc::c_int as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };

    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn ring(doorbell: BorrowedFd<'_>) {
    let byte = 1u8;

    unsafe {
        libc::write(
            doorbell.as_raw_fd(),
            &byte as *const u8 as *const libc::c_void,
            1,
        );
    }
}

fn answer(drain: BorrowedFd<'_>) {
    let mut byte = 0u8;

    unsafe {
        libc::recv(
            drain.as_raw_fd(),
            &mut byte as *mut u8 as *mut libc::c_void,
            1,
            libc::MSG_DONTWAIT,
        );
    }
}

fn as_v4(address: SocketAddr) -> SocketAddrV4 {
    match address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    }
}

impl Supervisor {
    pub fn new(
        listener: OwnedFd,
        pid: u32,
        net: Net,
        runtime: Handle,
        overlay: (Ipv4Addr, Ipv4Addr),
        allow_rings: bool,
    ) -> io::Result<Supervisor> {
        let mut supervisor = Supervisor {
            listener,
            overlay,
            waker: Waker::new()?,
            parked: 0,
            connecting: 0,
            memory: Memory::open(pid)?,
            memories: HashMap::new(),
            current: pid,
            net,
            runtime,
            sockets: HashMap::new(),
            aliases: HashMap::new(),
            refs: HashMap::new(),
            pidfds: HashMap::new(),
            reconcile_at: None,
            reconciled: None,
            undiscovered: 0,
            group: pid,
            allow_rings,
            warned_rings: false,
            zone: None,
        };

        supervisor.watch(pid);

        Ok(supervisor)
    }

    /// Give the target a resolver of its own. Without one its dns leaves as any
    /// other off overlay traffic does, which only reaches mesh names when the
    /// machine already runs the daemon.
    pub fn with_resolver(mut self, zone: Zone) -> Supervisor {
        self.zone = Some(zone);
        self
    }

    fn watch(&mut self, pid: u32) {
        if self.pidfds.contains_key(&pid) {
            return;
        }

        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };

        if fd >= 0 {
            self.pidfds
                .insert(pid, unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
    }

    fn members(&self) -> Vec<u32> {
        let mut members: Vec<u32> = std::iter::once(self.current)
            .chain(self.memories.keys().copied())
            .collect();

        let Ok(entries) = std::fs::read_dir("/proc") else {
            return members;
        };

        for entry in entries.filter_map(|entry| entry.ok()) {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };

            if group_of(pid) == Some(self.group) && !members.contains(&pid) {
                members.push(pid);
            }
        }

        members
    }

    fn holds(&self, inode: u64) -> bool {
        for pid in self.members() {
            let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };

            for entry in entries.filter_map(|entry| entry.ok()) {
                if std::fs::read_link(entry.path())
                    .ok()
                    .as_ref()
                    .and_then(|link| link.to_str())
                    .and_then(parse_socket_inode)
                    == Some(inode)
                {
                    return true;
                }
            }
        }

        false
    }

    fn live_inodes(&self) -> Option<std::collections::HashSet<u64>> {
        let mut live = std::collections::HashSet::new();
        let mut reachable = false;

        for pid in self.members() {
            let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };

            reachable = true;

            for entry in entries.filter_map(|entry| entry.ok()) {
                let Ok(target) = std::fs::read_link(entry.path()) else {
                    continue;
                };

                if let Some(inode) = target.to_str().and_then(parse_socket_inode) {
                    live.insert(inode);
                }
            }
        }

        reachable.then_some(live)
    }

    fn reconcile(&mut self) {
        self.reconcile_at = None;
        self.reconciled = Some(Instant::now());

        let Some(live) = self.live_inodes() else {
            return;
        };

        let stale: Vec<i32> = self
            .sockets
            .iter()
            .filter(|(_, socket)| socket.inode != 0 && !live.contains(&socket.inode))
            .map(|(fd, _)| *fd)
            .collect();

        for fd in stale {
            tracing::info!(fd, "reclaiming a socket the target no longer holds");
            self.release(fd);
        }
    }

    fn soon(&mut self, delay: Duration) {
        let floor = self
            .reconciled
            .map(|last| last + RECONCILE_INTERVAL)
            .unwrap_or_else(Instant::now);

        let at = (Instant::now() + delay).max(floor);

        self.reconcile_at = Some(match self.reconcile_at {
            Some(existing) if existing < at => existing,
            _ => at,
        });
    }

    fn receive_deadline(&self, fd: i32) -> Option<Instant> {
        let socket = self.sockets.get(&fd)?;
        let seconds = socket.timeouts.0?;

        Some(Instant::now() + seconds)
    }

    fn next_deadline(&self) -> Option<Duration> {
        if self.parked == 0 && self.reconcile_at.is_none() {
            return None;
        }

        let now = Instant::now();

        self.sockets
            .values()
            .filter_map(|socket| socket.waiting_receive.as_ref()?.deadline)
            .chain(self.reconcile_at)
            .map(|deadline| deadline.saturating_duration_since(now))
            .min()
    }

    fn expire(&mut self) {
        if self.parked == 0 {
            return;
        }

        let now = Instant::now();

        let lapsed: Vec<i32> = self
            .sockets
            .iter()
            .filter(|(_, socket)| {
                socket
                    .waiting_receive
                    .as_ref()
                    .and_then(|waiting| waiting.deadline)
                    .is_some_and(|deadline| deadline <= now)
            })
            .map(|(fd, _)| *fd)
            .collect();

        for fd in lapsed {
            let Some(socket) = self.sockets.get_mut(&fd) else {
                continue;
            };

            let Some(waiting) = socket.waiting_receive.take() else {
                continue;
            };

            self.parked = self.parked.saturating_sub(1);

            tracing::debug!(fd, "a parked receive timed out");
            self.reply(waiting.id, notify::fail(waiting.id, libc::EAGAIN));
        }
    }

    fn resolve(&self, fd: i32) -> i32 {
        self.aliases.get(&fd).copied().unwrap_or(fd)
    }

    fn inode_at(&self, fd: i32) -> Option<u64> {
        parse_socket_inode(std::fs::read_link(format!("/proc/{}/fd/{fd}", self.current)).ok()?.to_str()?)
    }

    fn on_io_uring(&mut self) -> io::Result<Answer> {
        if self.allow_rings {
            return Ok(Answer::Continue);
        }

        if !self.warned_rings {
            self.warned_rings = true;

            tracing::warn!(
                "refusing io_uring, its operations would never reach us; pass --allow-io-uring to permit it"
            );
        }

        Ok(Answer::Error(libc::ENOSYS))
    }

    fn discover(&mut self, fd: i32, probe: bool) -> i32 {
        if (!probe && self.undiscovered == 0)
            || fd < 0
            || self.sockets.contains_key(&fd)
            || self.aliases.contains_key(&fd)
        {
            return fd;
        }

        let Some(inode) = self.inode_at(fd) else {
            return fd;
        };

        let Some(owner) = self
            .sockets
            .iter()
            .find(|(_, socket)| socket.inode == inode)
            .map(|(owner, _)| *owner)
        else {
            return fd;
        };

        self.aliases.insert(fd, owner);

        if self.undiscovered > 0 {
            self.undiscovered -= 1;
        } else {
            self.retain(owner);
        }

        tracing::info!(fd, owner, "matched a stray descriptor back to its socket");

        owner
    }

    fn release(&mut self, fd: i32) -> Option<Socket> {
        let socket = self.sockets.remove(&fd)?;

        self.refs.remove(&fd);
        self.aliases.retain(|_, owner| *owner != fd);

        if socket.connecting.is_some() {
            self.connecting = self.connecting.saturating_sub(1);
        }

        for present in [
            socket.waiting_accept.is_some(),
            socket.waiting_receive.is_some(),
            socket.waiting_connect.is_some(),
        ] {
            if present {
                self.parked = self.parked.saturating_sub(1);
            }
        }

        Some(socket)
    }

    fn retain(&mut self, owner: i32) {
        *self.refs.entry(owner).or_insert(1) += 1;
    }

    fn drop_reference(&mut self, fd: i32) -> bool {
        let owner = self.resolve(fd);

        if fd != owner {
            self.aliases.remove(&fd);
        }

        match self.refs.get_mut(&owner) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            _ => {
                self.refs.remove(&owner);
                true
            }
        }
    }

    fn install(&self, id: u64, fd: BorrowedFd<'_>) -> io::Result<i32> {
        notify::add_fd(
            self.listener.as_fd(),
            NotifAddfd {
                id,
                flags: ADDFD_FLAG_SEND,
                srcfd: fd.as_raw_fd() as u32,
                newfd: 0,
                newfd_flags: libc::O_CLOEXEC as u32,
            },
        )
    }

    fn follow(&mut self, pid: u32) {
        let previous = std::mem::replace(&mut self.current, pid);

        if let Some(memory) = self.memories.remove(&pid) {
            let leaving = std::mem::replace(&mut self.memory, memory);
            self.memories.insert(previous, leaving);

            return;
        }

        match Memory::open(pid) {
            Ok(memory) => {
                tracing::debug!(pid, "following the target into another task");

                let leaving = std::mem::replace(&mut self.memory, memory);
                self.memories.insert(previous, leaving);
            }
            Err(e) => {
                tracing::debug!(pid, "cannot reach that task: {e}");
                self.current = previous;
            }
        }
    }

    fn is_ours(&self, destination: Ipv4Addr) -> bool {
        let (address, netmask) = self.overlay;
        let mask = u32::from(netmask);

        u32::from(destination) & mask == u32::from(address) & mask
    }

    fn hand_back(&mut self, id: u64, fd: i32, kind: libc::c_int) -> io::Result<Answer> {
        let real = unsafe { libc::socket(libc::AF_INET, kind | libc::SOCK_CLOEXEC, 0) };

        if real < 0 {
            return Err(io::Error::last_os_error());
        }

        let real = unsafe { OwnedFd::from_raw_fd(real) };

        // Everything the target set, it set on the socket we were pretending to
        // be. The kernel one it is about to get knows none of it, and a target
        // that asked for a non blocking socket and is handed a blocking one
        // waits forever in a read it expected EAGAIN from.
        self.carry_over(fd, real.as_fd());

        notify::add_fd(
            self.listener.as_fd(),
            NotifAddfd {
                id,
                flags: ADDFD_FLAG_SETFD,
                srcfd: real.as_raw_fd() as u32,
                newfd: fd as u32,
                newfd_flags: 0,
            },
        )?;

        self.sockets.remove(&fd);

        tracing::info!(
            fd,
            "destination is off the overlay, giving the target a kernel socket"
        );

        Ok(Answer::Continue)
    }

    /// The target's resolver traffic never reaches a real name server. Names in
    /// our zone are answered from the peer table; everything else is asked on
    /// the target's behalf and handed back on the same socket.
    ///
    /// Handing over a kernel socket would be simpler, but it gives the target a
    /// new file description behind the same descriptor, and anything that had
    /// already registered the old one with epoll would never hear from it again.
    fn intercept_dns(
        &mut self,
        fd: i32,
        payload: &[u8],
        server: SocketAddrV4,
    ) -> io::Result<Option<Answer>> {
        if server.port() != DNS_PORT {
            return Ok(None);
        }

        let Some(zone) = self.zone.clone() else {
            return Ok(None);
        };

        let sent = Answer::Value(payload.len() as i64);

        if let Some(reply) = zone.answer(payload) {
            tracing::debug!(fd, %server, "answered a query from the peer table");

            self.deliver(fd, reply, server)?;

            return Ok(Some(sent));
        }

        self.forward_query(fd, payload.to_vec(), server)?;

        Ok(Some(sent))
    }

    /// Put a datagram on a socket as though it had arrived from `from`.
    fn deliver(&mut self, fd: i32, payload: Vec<u8>, from: SocketAddrV4) -> io::Result<()> {
        let Some(bound) = self.datagram_socket(fd)? else {
            return Err(io::Error::other("the socket went away"));
        };

        if bound.injector.send((payload, from)).is_err() {
            return Err(io::Error::other("nothing is left to read the socket"));
        }

        ring(bound.bell.as_fd());

        Ok(())
    }

    /// Ask the name server the target chose, from the host's network, and put
    /// the reply on the target's socket when it comes.
    fn forward_query(&mut self, fd: i32, query: Vec<u8>, server: SocketAddrV4) -> io::Result<()> {
        let Some(bound) = self.datagram_socket(fd)? else {
            return Err(io::Error::other("the socket went away"));
        };

        let injector = bound.injector.clone();
        let bell = bound.bell.try_clone()?;
        let nudge = self.waker.try_clone()?;

        self.runtime.spawn(async move {
            let asked = async {
                let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;

                socket.send_to(&query, server).await?;

                let mut buffer = vec![0u8; 65_536];
                let (len, _) = socket.recv_from(&mut buffer).await?;

                buffer.truncate(len);

                Ok::<Vec<u8>, io::Error>(buffer)
            };

            match tokio::time::timeout(DNS_TIMEOUT, asked).await {
                Ok(Ok(reply)) => {
                    if injector.send((reply, server)).is_ok() {
                        ring(bell.as_fd());
                        nudge.wake();
                    }
                }

                // Saying nothing is what a lost datagram looks like, which every
                // resolver already knows how to retry.
                Ok(Err(e)) => tracing::debug!(%server, "could not reach the name server: {e}"),
                Err(_) => tracing::debug!(%server, "the name server did not answer"),
            }
        });

        Ok(())
    }

    /// Move the target's view of a socket onto the real one replacing it.
    fn carry_over(&self, fd: i32, real: BorrowedFd<'_>) {
        let Some(socket) = self.sockets.get(&fd) else {
            return;
        };

        for ((level, option), value) in &socket.options {
            let result = unsafe {
                libc::setsockopt(
                    real.as_raw_fd(),
                    *level,
                    *option,
                    value as *const i32 as *const libc::c_void,
                    size_of::<i32>() as libc::socklen_t,
                )
            };

            if result != 0 {
                tracing::debug!(fd, level, option, "could not carry over a socket option");
            }
        }

        for (option, timeout) in [
            (libc::SO_RCVTIMEO, socket.timeouts.0),
            (libc::SO_SNDTIMEO, socket.timeouts.1),
        ] {
            let Some(timeout) = timeout else {
                continue;
            };

            let value = libc::timeval {
                tv_sec: timeout.as_secs() as libc::time_t,
                tv_usec: timeout.subsec_micros() as libc::suseconds_t,
            };

            unsafe {
                libc::setsockopt(
                    real.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    &value as *const libc::timeval as *const libc::c_void,
                    size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
        }

        if self.is_nonblocking(fd) && let Err(e) = set_nonblocking(real) {
            tracing::debug!(fd, "could not carry over the non blocking flag: {e}");
        }
    }

    /// Whether the target has this descriptor in non blocking mode. A fresh
    /// kernel socket is blocking, so anything we cannot establish stays that way.
    fn is_nonblocking(&self, fd: i32) -> bool {
        if let Some(socket) = self.sockets.get(&fd)
            && socket.observed_flags
        {
            return !socket.blocking;
        }

        std::fs::read_to_string(format!("/proc/{}/fdinfo/{fd}", self.current))
            .ok()
            .and_then(|info| {
                info.lines()
                    .find_map(|line| line.strip_prefix("flags:"))
                    .and_then(|value| i32::from_str_radix(value.trim(), 8).ok())
            })
            .is_some_and(|flags| flags & libc::O_NONBLOCK != 0)
    }

    fn is_blocking(&self, fd: i32) -> bool {
        if let Some(socket) = self.sockets.get(&fd)
            && socket.observed_flags
        {
            return socket.blocking;
        }

        let Ok(info) = std::fs::read_to_string(format!("/proc/{}/fdinfo/{fd}", self.current))
        else {
            return false;
        };

        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| i32::from_str_radix(value.trim(), 8).ok())
            .unwrap_or(libc::O_NONBLOCK);

        flags & libc::O_NONBLOCK == 0
    }

    fn free_datagram_slot(&self) -> u32 {
        let mut candidate = DATAGRAM_FD_BASE;

        while self.sockets.contains_key(&(candidate as i32))
            || std::path::Path::new(&format!("/proc/{}/fd/{candidate}", self.current)).exists()
        {
            candidate += 1;
        }

        candidate
    }

    fn install_datagram(&self, id: u64, fd: BorrowedFd<'_>) -> io::Result<i32> {
        notify::add_fd(
            self.listener.as_fd(),
            NotifAddfd {
                id,
                flags: ADDFD_FLAG_SEND | ADDFD_FLAG_SETFD,
                srcfd: fd.as_raw_fd() as u32,
                newfd: self.free_datagram_slot(),
                newfd_flags: libc::O_CLOEXEC as u32,
            },
        )
    }

    pub fn run(mut self) {
        loop {
            let watched: Vec<std::os::fd::RawFd> =
                self.pidfds.values().map(|fd| fd.as_raw_fd()).collect();

            let ready = wake::wait(
                self.listener.as_fd(),
                self.waker.as_fd(),
                &watched,
                self.next_deadline(),
            );

            let (notified, woken, finished) = match ready {
                Ok(ready) => ready,
                Err(e) => {
                    tracing::debug!("stopped waiting for notifications: {e}");
                    break;
                }
            };

            if woken {
                self.waker.drain();
                self.settle();
            }

            if !finished.is_empty() {
                self.pidfds
                    .retain(|_, fd| !finished.contains(&fd.as_raw_fd()));

                tracing::debug!(tasks = finished.len(), "a task the target owned exited");
                self.reconcile();
            }

            self.expire();

            if self.reconcile_at.is_some_and(|at| at <= Instant::now()) {
                self.reconcile();
            }

            if !notified {
                continue;
            }

            let notification = match notify::recv(self.listener.as_fd()) {
                Ok(notification) => notification,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => {
                    tracing::debug!("notification channel closed: {e}");
                    break;
                }
            };

            self.dispatch(notification);
            self.settle();
        }
    }

    fn settle(&mut self) {
        if self.parked == 0 && self.connecting == 0 {
            return;
        }

        let parked: Vec<i32> = self
            .sockets
            .iter()
            .filter(|(_, socket)| {
                socket.waiting_accept.is_some()
                    || socket.waiting_receive.is_some()
                    || socket.connecting.is_some()
            })
            .map(|(fd, _)| *fd)
            .collect();

        for fd in parked {
            self.settle_accept(fd);
            self.settle_receive(fd);
            self.settle_connect(fd);
        }
    }

    fn reply(&self, id: u64, response: notify::NotifResp) {
        if !notify::id_valid(self.listener.as_fd(), id) {
            tracing::debug!(id, "the target vanished before we answered");
            return;
        }

        if let Err(e) = notify::send(self.listener.as_fd(), response) {
            tracing::debug!(id, "could not answer: {e}");
        }
    }

    fn dispatch(&mut self, notification: Notif) {
        let id = notification.id;
        let mut args = notification.data.args;

        if notification.pid != self.current {
            self.follow(notification.pid);
        }

        if notification.data.nr as i64 != libc::SYS_socket {
            let named = args[0] as i32;
            let owner = self.resolve(named);

            args[0] = if owner == named {
                self.discover(named, socket_shaped(notification.data.nr as i64)) as u32 as u64
            } else {
                owner as u32 as u64
            };
        }

        let outcome = match notification.data.nr as i64 {
            libc::SYS_socket => self.on_socket(id, args),
            libc::SYS_bind => self.on_bind(args),
            libc::SYS_listen => self.on_listen(args),
            libc::SYS_accept => self.on_accept(id, args, 0),
            libc::SYS_accept4 => self.on_accept(id, args, args[3] as i32),
            libc::SYS_getsockname => self.on_getsockname(args),
            libc::SYS_getpeername => self.on_getpeername(args),
            libc::SYS_setsockopt => self.on_setsockopt(args),
            libc::SYS_getsockopt => self.on_getsockopt(args),
            libc::SYS_shutdown => self.on_shutdown(args),
            libc::SYS_sendto => self.on_sendto(id, args),
            libc::SYS_recvfrom => self.on_recvfrom(id, args),
            libc::SYS_sendmsg => self.on_sendmsg(id, args),
            libc::SYS_recvmsg => self.on_recvmsg(id, args),
            libc::SYS_sendmmsg => self.on_sendmmsg(id, args),
            libc::SYS_recvmmsg => self.on_recvmmsg(id, args),
            libc::SYS_writev => self.on_writev(id, args),
            libc::SYS_readv => self.on_readv(id, args),
            libc::SYS_read => self.on_recvfrom(id, [args[0], args[1], args[2], 0, 0, 0]),
            libc::SYS_write => self.on_sendto(id, [args[0], args[1], args[2], 0, 0, 0]),
            libc::SYS_connect => self.on_connect(id, args),
            libc::SYS_close => self.on_close(args),
            libc::SYS_io_uring_setup | libc::SYS_io_uring_enter | libc::SYS_io_uring_register => {
                self.on_io_uring()
            }
            libc::SYS_close_range => self.on_close_range(args),
            libc::SYS_fork | libc::SYS_vfork => self.on_clone(args, 0),
            libc::SYS_clone => self.on_clone(args, args[0]),
            libc::SYS_clone3 => {
                let flags = self.memory.read_u64(args[0]).unwrap_or(0);
                self.on_clone(args, flags)
            }
            libc::SYS_dup => self.on_dup(args),
            libc::SYS_dup2 | libc::SYS_dup3 => self.on_dup2(args),
            libc::SYS_fcntl => self.on_fcntl(args),
            _ => Ok(Answer::Continue),
        };

        match outcome {
            Ok(Answer::Value(value)) => self.reply(id, notify::allow(id, value)),
            Ok(Answer::Error(errno)) => self.reply(id, notify::fail(id, errno)),
            Ok(Answer::Continue) => self.reply(id, notify::passthrough(id)),
            Ok(Answer::Installed) | Ok(Answer::Parked) => {}
            Err(e) => {
                tracing::warn!(syscall = notification.data.nr, "handler failed: {e}");
                self.reply(id, notify::fail(id, libc::EIO));
            }
        }
    }

    fn on_socket(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let domain = args[0] as i32;
        let kind = args[1] as i32;

        if domain == libc::AF_INET6 {
            tracing::debug!("refusing an ipv6 socket so the target falls back to ipv4");
            return Ok(Answer::Error(libc::EAFNOSUPPORT));
        }

        let datagram = match kind & 0xf {
            libc::SOCK_STREAM => false,
            libc::SOCK_DGRAM => true,
            _ => return Ok(Answer::Continue),
        };

        if domain != libc::AF_INET {
            return Ok(Answer::Continue);
        }

        let flavour = if datagram {
            libc::SOCK_DGRAM
        } else {
            libc::SOCK_STREAM
        };

        let (ours, theirs) = socketpair(flavour | libc::SOCK_CLOEXEC)?;

        if kind & libc::SOCK_NONBLOCK != 0 {
            set_nonblocking(theirs.as_fd())?;
        }

        let installed = if datagram {
            self.install_datagram(id, theirs.as_fd())?
        } else {
            self.install(id, theirs.as_fd())?
        };

        tracing::info!(
            fd = installed,
            kind = if datagram { "udp" } else { "tcp" },
            "handed the target a socket"
        );

        let mut socket = Socket::new(ours, theirs);
        socket.blocking = kind & libc::SOCK_NONBLOCK == 0;

        if datagram {
            socket.role = Role::Datagram(None);
        }

        self.sockets.insert(installed, socket);

        Ok(Answer::Installed)
    }

    fn on_bind(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        let Some(socket) = self.sockets.get_mut(&fd) else {
            return Ok(Answer::Continue);
        };

        let endpoint = self.memory.read_sockaddr_in(args[1], args[2] as u32)?;
        let datagram = matches!(socket.role, Role::Datagram(_));

        socket.local = Some(endpoint);

        if datagram {
            tracing::info!(fd, %endpoint, "target bound a udp socket");
            return self.bind_datagram(fd, Some(endpoint.port()));
        }

        socket.role = Role::Bound;

        tracing::info!(fd, %endpoint, "target bound a socket");

        Ok(Answer::Value(0))
    }

    fn bind_datagram(&mut self, fd: i32, port: Option<u16>) -> io::Result<Answer> {
        let socket = match self.net.udp_bind(port) {
            Ok(socket) => Arc::new(socket),
            Err(e) => {
                tracing::warn!(?port, "udp bind failed: {e}");
                return Ok(Answer::Error(libc::EADDRINUSE));
            }
        };

        let entry = self.sockets.get_mut(&fd).expect("caller checked");

        let (arrived, inbox) = unbounded_channel();
        let bell = entry.ours.as_ref().unwrap().try_clone()?;
        let doorbell = entry.ours.as_ref().unwrap().try_clone()?;
        let drain = entry.theirs.as_ref().unwrap().try_clone()?;
        let injector = arrived.clone();
        let receiver = socket.clone();

        let nudge = self.waker.try_clone()?;

        let receiving = self
            .runtime
            .spawn(async move {
                let mut buffer = vec![0u8; 65_536];

                loop {
                    let Ok((len, from)) = receiver.recv_from(&mut buffer).await else {
                        break;
                    };

                    if arrived.send((buffer[..len].to_vec(), as_v4(from))).is_err() {
                        break;
                    }

                    ring(bell.as_fd());
                    nudge.wake();
                }
            })
            .abort_handle();

        entry.role = Role::Datagram(Some(Bound {
            socket,
            inbox,
            injector,
            bell: doorbell,
            peeked: None,
            drain,
            receiving,
        }));

        Ok(Answer::Value(0))
    }

    fn datagram_socket(&mut self, fd: i32) -> io::Result<Option<&mut Bound>> {
        let needs_bind = matches!(
            self.sockets.get(&fd).map(|s| &s.role),
            Some(Role::Datagram(None))
        );

        if needs_bind {
            self.bind_datagram(fd, None)?;
        }

        Ok(match self.sockets.get_mut(&fd).map(|s| &mut s.role) {
            Some(Role::Datagram(bound)) => bound.as_mut(),
            _ => None,
        })
    }

    fn slices(&self, base: u64, count: usize) -> io::Result<Vec<(u64, usize)>> {
        let mut collected = Vec::with_capacity(count.min(IOV_MAX));

        for index in 0..count.min(IOV_MAX) {
            let at = base + index as u64 * IOVEC_SIZE;

            collected.push((
                self.memory.read_u64(at)?,
                self.memory.read_u64(at + 8)? as usize,
            ));
        }

        Ok(collected)
    }

    fn gather(&self, slices: &[(u64, usize)]) -> io::Result<Vec<u8>> {
        let mut payload = Vec::new();

        for (address, len) in slices {
            if *len == 0 {
                continue;
            }

            payload.extend_from_slice(&self.memory.read_bytes(*address, *len)?);
        }

        Ok(payload)
    }

    fn scatter(memory: &Memory, slices: &[(u64, usize)], payload: &[u8]) -> io::Result<usize> {
        let mut written = 0;

        for (address, len) in slices {
            if written >= payload.len() {
                break;
            }

            let take = (*len).min(payload.len() - written);

            if take == 0 {
                continue;
            }

            memory.write(*address, &payload[written..written + take])?;
            written += take;
        }

        Ok(written)
    }

    fn is_datagram(&self, fd: i32) -> bool {
        matches!(
            self.sockets.get(&fd).map(|s| &s.role),
            Some(Role::Datagram(_))
        )
    }

    fn on_sendmsg(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.is_datagram(fd) {
            return Ok(Answer::Continue);
        }

        let header = args[1];
        let name = self.memory.read_u64(header + MSGHDR_NAME)?;
        let namelen = self.memory.read_u32(header + MSGHDR_NAMELEN)?;
        let iov = self.memory.read_u64(header + MSGHDR_IOV)?;
        let iovlen = self.memory.read_u64(header + MSGHDR_IOVLEN)? as usize;

        let slices = self.slices(iov, iovlen)?;
        let payload = self.gather(&slices)?;

        self.send_datagram(id, fd, payload, name, namelen)
    }

    fn on_writev(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.is_datagram(fd) {
            return Ok(Answer::Continue);
        }

        let slices = self.slices(args[1], args[2] as usize)?;
        let payload = self.gather(&slices)?;

        self.send_datagram(id, fd, payload, 0, 0)
    }

    fn on_sendmmsg(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.is_datagram(fd) {
            return Ok(Answer::Continue);
        }

        let base = args[1];
        let count = (args[2] as usize).min(IOV_MAX);
        let mut sent = 0;

        for index in 0..count {
            let header = base + index as u64 * MMSGHDR_SIZE;

            let name = self.memory.read_u64(header + MSGHDR_NAME)?;
            let namelen = self.memory.read_u32(header + MSGHDR_NAMELEN)?;
            let iov = self.memory.read_u64(header + MSGHDR_IOV)?;
            let iovlen = self.memory.read_u64(header + MSGHDR_IOVLEN)? as usize;

            let slices = self.slices(iov, iovlen)?;
            let payload = self.gather(&slices)?;
            let len = payload.len();

            match self.send_datagram(id, fd, payload, name, namelen)? {
                Answer::Value(_) => {
                    self.memory.write_u32(header + MMSGHDR_LEN, len as u32)?;
                    sent += 1;
                }
                other => {
                    if sent == 0 {
                        return Ok(other);
                    }

                    break;
                }
            }
        }

        Ok(Answer::Value(sent as i64))
    }

    fn send_datagram(
        &mut self,
        id: u64,
        fd: i32,
        payload: Vec<u8>,
        name: u64,
        namelen: u32,
    ) -> io::Result<Answer> {
        let destination = if name != 0 {
            self.memory.read_sockaddr_in(name, namelen)?
        } else {
            match self.sockets.get(&fd).and_then(|s| s.peer) {
                Some(peer) => peer,
                None => return Ok(Answer::Error(libc::EDESTADDRREQ)),
            }
        };

        if let Some(answer) = self.intercept_dns(fd, &payload, destination)? {
            return Ok(answer);
        }

        if !self.is_ours(*destination.ip()) {
            return self.hand_back(id, fd, libc::SOCK_DGRAM);
        }

        let Some(bound) = self.datagram_socket(fd)? else {
            return Ok(Answer::Error(libc::EBADF));
        };

        match bound
            .socket
            .send_to(&payload, *destination.ip(), destination.port())
        {
            Ok(sent) => {
                tracing::trace!(fd, %destination, sent, "udp datagram sent");
                Ok(Answer::Value(sent as i64))
            }
            Err(e) => {
                tracing::debug!(fd, %destination, "udp send failed: {e}");
                Ok(Answer::Error(libc::ENOBUFS))
            }
        }
    }

    fn on_recvmsg(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.is_datagram(fd) {
            return Ok(Answer::Continue);
        }

        let header = args[1];
        let flags = args[2] as i32;

        let iov = self.memory.read_u64(header + MSGHDR_IOV)?;
        let iovlen = self.memory.read_u64(header + MSGHDR_IOVLEN)? as usize;
        let slices = self.slices(iov, iovlen)?;
        let capacity: usize = slices.iter().map(|(_, len)| *len).sum();

        let peek = flags & libc::MSG_PEEK != 0;
        let blocking = self.is_blocking(fd) && flags & libc::MSG_DONTWAIT == 0;

        let Some(bound) = self.datagram_socket(fd)? else {
            return Ok(Answer::Error(libc::EBADF));
        };

        let Some((payload, from)) = bound.take() else {
            if blocking {
                let deadline = self.receive_deadline(fd);
                let socket = self.sockets.get_mut(&fd).expect("checked above");

                socket.waiting_receive = Some(PendingReceive {
                    id,
                    buffer: 0,
                    capacity,
                    flags,
                    address: header,
                    address_len: 0,
                    scatter: Some(slices),
                    deadline,
                });

                self.parked += 1;

                return Ok(Answer::Parked);
            }

            return Ok(Answer::Error(libc::EAGAIN));
        };

        if !peek {
            answer(bound.drain.as_fd());
        }

        let whole = payload.len();
        let written = Supervisor::scatter(&self.memory, &slices, &payload)?;

        let name = self.memory.read_u64(header + MSGHDR_NAME)?;

        if name != 0 {
            self.memory
                .write_sockaddr_in(name, header + MSGHDR_NAMELEN, from)?;
        }

        if whole > capacity {
            self.memory.write_u32(header + MSGHDR_FLAGS, MSG_TRUNC_FLAG)?;
        }

        if peek && let Some(bound) = self.datagram_socket(fd)? {
            bound.peeked = Some((payload, from));
        }

        tracing::trace!(fd, %from, written, whole, "udp message delivered");

        Ok(Answer::Value(if flags & libc::MSG_TRUNC != 0 {
            whole as i64
        } else {
            written as i64
        }))
    }

    fn on_readv(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.is_datagram(fd) {
            return Ok(Answer::Continue);
        }

        let slices = self.slices(args[1], args[2] as usize)?;
        let capacity: usize = slices.iter().map(|(_, len)| *len).sum();
        let blocking = self.is_blocking(fd);

        let Some(bound) = self.datagram_socket(fd)? else {
            return Ok(Answer::Error(libc::EBADF));
        };

        let Some((payload, from)) = bound.take() else {
            if blocking {
                let deadline = self.receive_deadline(fd);
                let socket = self.sockets.get_mut(&fd).expect("checked above");

                socket.waiting_receive = Some(PendingReceive {
                    id,
                    buffer: 0,
                    capacity,
                    flags: 0,
                    address: 0,
                    address_len: 0,
                    scatter: Some(slices),
                    deadline,
                });

                self.parked += 1;

                return Ok(Answer::Parked);
            }

            return Ok(Answer::Error(libc::EAGAIN));
        };

        answer(bound.drain.as_fd());

        let written = Supervisor::scatter(&self.memory, &slices, &payload)?;

        tracing::trace!(fd, %from, written, "udp datagram read into iovecs");

        Ok(Answer::Value(written as i64))
    }

    fn on_recvmmsg(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.is_datagram(fd) {
            return Ok(Answer::Continue);
        }

        let base = args[1];
        let count = (args[2] as usize).min(IOV_MAX);
        let flags = args[3] as i32;
        let mut received = 0;

        for index in 0..count {
            let header = base + index as u64 * MMSGHDR_SIZE;
            let single = [args[0], header, flags as u64, 0, 0, 0];

            let waited = received == 0 && flags & libc::MSG_DONTWAIT == 0;
            let attempt = if waited {
                self.on_recvmsg(id, single)?
            } else {
                self.on_recvmsg(id, [args[0], header, libc::MSG_DONTWAIT as u64, 0, 0, 0])?
            };

            match attempt {
                Answer::Value(len) => {
                    self.memory.write_u32(header + MMSGHDR_LEN, len as u32)?;
                    received += 1;
                }
                Answer::Parked => return Ok(Answer::Parked),
                other => {
                    if received == 0 {
                        return Ok(other);
                    }

                    break;
                }
            }
        }

        Ok(Answer::Value(received as i64))
    }

    fn on_sendto(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !matches!(
            self.sockets.get(&fd).map(|s| &s.role),
            Some(Role::Datagram(_))
        ) {
            return Ok(Answer::Continue);
        }

        let len = args[2] as usize;
        let payload = self.memory.read_bytes(args[1], len)?;

        let destination = if args[4] != 0 {
            self.memory.read_sockaddr_in(args[4], args[5] as u32)?
        } else {
            match self.sockets.get(&fd).and_then(|s| s.peer) {
                Some(peer) => peer,
                None => return Ok(Answer::Error(libc::EDESTADDRREQ)),
            }
        };

        if let Some(answer) = self.intercept_dns(fd, &payload, destination)? {
            return Ok(answer);
        }

        if !self.is_ours(*destination.ip()) {
            return self.hand_back(id, fd, libc::SOCK_DGRAM);
        }

        let Some(bound) = self.datagram_socket(fd)? else {
            return Ok(Answer::Error(libc::EBADF));
        };

        match bound
            .socket
            .send_to(&payload, *destination.ip(), destination.port())
        {
            Ok(sent) => {
                tracing::trace!(fd, %destination, sent, "udp datagram sent");
                Ok(Answer::Value(sent as i64))
            }
            Err(e) => {
                tracing::debug!(fd, %destination, "udp send failed: {e}");
                Ok(Answer::Error(libc::ENOBUFS))
            }
        }
    }

    fn on_recvfrom(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !matches!(
            self.sockets.get(&fd).map(|s| &s.role),
            Some(Role::Datagram(_))
        ) {
            return Ok(Answer::Continue);
        }

        let capacity = args[2] as usize;
        let flags = args[3] as i32;
        let peek = flags & libc::MSG_PEEK != 0;
        let blocking = self.is_blocking(fd) && flags & libc::MSG_DONTWAIT == 0;

        let Some(bound) = self.datagram_socket(fd)? else {
            return Ok(Answer::Error(libc::EBADF));
        };

        let Some((payload, from)) = bound.take() else {
            if blocking {
                let deadline = self.receive_deadline(fd);
                let socket = self.sockets.get_mut(&fd).expect("checked above");

                socket.waiting_receive = Some(PendingReceive {
                    id,
                    buffer: args[1],
                    capacity,
                    flags,
                    address: args[4],
                    address_len: args[5],
                    scatter: None,
                    deadline,
                });

                tracing::debug!(fd, "parking a blocking receive until a datagram lands");
                self.parked += 1;

                return Ok(Answer::Parked);
            }

            return Ok(Answer::Error(libc::EAGAIN));
        };

        if !peek {
            answer(bound.drain.as_fd());
        }

        let whole = payload.len();
        let len = whole.min(capacity);

        self.memory.write(args[1], &payload[..len])?;

        if args[4] != 0 && args[5] != 0 {
            self.memory.write_sockaddr_in(args[4], args[5], from)?;
        }

        if peek && let Some(bound) = self.datagram_socket(fd)? {
            bound.peeked = Some((payload, from));
        }

        tracing::trace!(fd, %from, len, whole, peek, "udp datagram delivered");

        Ok(Answer::Value(if flags & libc::MSG_TRUNC != 0 {
            whole as i64
        } else {
            len as i64
        }))
    }

    fn settle_accept(&mut self, fd: i32) {
        let Some(socket) = self.sockets.get_mut(&fd) else {
            return;
        };

        if socket.waiting_accept.is_none() {
            return;
        }

        let Role::Listening(listening) = &mut socket.role else {
            return;
        };

        let Ok(arrival) = listening.arrivals.try_recv() else {
            return;
        };

        let request = socket.waiting_accept.take().expect("checked above");
        self.parked = self.parked.saturating_sub(1);

        match self.complete_accept(
            fd,
            request.id,
            arrival,
            request.address,
            request.address_len,
            request.flags,
        ) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(fd, "could not finish a parked accept: {e}");
                self.reply(request.id, notify::fail(request.id, libc::ECONNABORTED));
            }
        }
    }

    fn settle_receive(&mut self, fd: i32) {
        let Some(socket) = self.sockets.get_mut(&fd) else {
            return;
        };

        if socket.waiting_receive.is_none() {
            return;
        }

        let Role::Datagram(Some(bound)) = &mut socket.role else {
            return;
        };

        let Some((payload, from)) = bound.take() else {
            return;
        };

        let request = socket.waiting_receive.take().expect("checked above");
        let peek = request.flags & libc::MSG_PEEK != 0;

        if peek {
            bound.peeked = Some((payload.clone(), from));
        } else {
            answer(bound.drain.as_fd());
        }

        self.parked = self.parked.saturating_sub(1);

        let whole = payload.len();
        let len = whole.min(request.capacity);

        let delivered = match &request.scatter {
            Some(slices) => {
                Supervisor::scatter(&self.memory, slices, &payload[..len]).and_then(|written| {
                    if request.address != 0 {
                        let name = self.memory.read_u64(request.address + MSGHDR_NAME)?;

                        if name != 0 {
                            self.memory.write_sockaddr_in(
                                name,
                                request.address + MSGHDR_NAMELEN,
                                from,
                            )?;
                        }
                    }

                    Ok(written)
                })
            }
            None => self
                .memory
                .write(request.buffer, &payload[..len])
                .and_then(|()| {
                    if request.address != 0 && request.address_len != 0 {
                        self.memory
                            .write_sockaddr_in(request.address, request.address_len, from)?;
                    }

                    Ok(len)
                }),
        };

        let reported = if request.flags & libc::MSG_TRUNC != 0 {
            whole as i64
        } else {
            delivered.as_ref().copied().unwrap_or(0) as i64
        };

        match delivered {
            Ok(_) => {
                tracing::trace!(fd, %from, len, whole, "parked receive completed");
                self.reply(request.id, notify::allow(request.id, reported));
            }
            Err(e) => {
                tracing::warn!(fd, "could not finish a parked receive: {e}");
                self.reply(request.id, notify::fail(request.id, libc::EIO));
            }
        }
    }

    fn on_listen(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if matches!(
            self.sockets.get(&fd).map(|socket| &socket.role),
            Some(Role::Listening(_))
        ) {
            tracing::debug!(fd, "the target asked to listen on a socket that already is");
            return Ok(Answer::Value(0));
        }

        let Some(local) = self.sockets.get(&fd).and_then(|socket| socket.local) else {
            return Ok(if self.sockets.contains_key(&fd) {
                Answer::Error(libc::EINVAL)
            } else {
                Answer::Continue
            });
        };

        let listener = match self.net.tcp_listen(local.port()) {
            Ok(listener) => listener,
            Err(_) => {
                self.reconcile();

                match self.net.tcp_listen(local.port()) {
                    Ok(listener) => listener,
                    Err(e) => {
                        tracing::warn!(port = local.port(), "listen failed: {e}");
                        return Ok(Answer::Error(libc::EADDRINUSE));
                    }
                }
            }
        };

        let socket = self.sockets.get_mut(&fd).expect("checked above");

        let (arrived, arrivals) = unbounded_channel();
        let bell = socket.ours.as_ref().unwrap().try_clone()?;
        let drain = socket.theirs.as_ref().unwrap().try_clone()?;

        let nudge = self.waker.try_clone()?;

        let accepting = self
            .runtime
            .spawn(async move {
                while let Ok(stream) = listener.accept().await {
                    let peer = as_v4(stream.peer_addr());

                    if arrived.send((stream, peer)).is_err() {
                        break;
                    }

                    ring(bell.as_fd());
                    nudge.wake();
                }
            })
            .abort_handle();

        socket.role = Role::Listening(Listening {
            arrivals,
            drain,
            accepting,
        });

        tracing::info!(fd, port = local.port(), "listening on the smolnet stack");

        Ok(Answer::Value(0))
    }

    fn on_accept(&mut self, id: u64, args: [u64; 6], flags: i32) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.sockets.contains_key(&fd) {
            return Ok(Answer::Continue);
        }

        let blocking = self.is_blocking(fd) && flags & libc::SOCK_NONBLOCK == 0;
        let socket = self.sockets.get_mut(&fd).expect("checked above");

        let Role::Listening(listening) = &mut socket.role else {
            return Ok(Answer::Error(libc::EINVAL));
        };

        let Ok((stream, peer)) = listening.arrivals.try_recv() else {
            if blocking {
                socket.waiting_accept = Some(PendingAccept {
                    id,
                    address: args[1],
                    address_len: args[2],
                    flags,
                });

                tracing::debug!(fd, "parking a blocking accept until a connection lands");
                self.parked += 1;

                return Ok(Answer::Parked);
            }

            return Ok(Answer::Error(libc::EAGAIN));
        };

        answer(listening.drain.as_fd());

        self.complete_accept(fd, id, (stream, peer), args[1], args[2], flags)?;

        Ok(Answer::Installed)
    }

    fn complete_accept(
        &mut self,
        fd: i32,
        id: u64,
        arrival: Arrival,
        address: u64,
        address_len: u64,
        flags: i32,
    ) -> io::Result<()> {
        let (stream, peer) = arrival;

        let local = self
            .sockets
            .get(&fd)
            .and_then(|socket| socket.local)
            .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

        let (ours, theirs) = socketpair(libc::SOCK_STREAM | libc::SOCK_CLOEXEC)?;

        if flags & libc::SOCK_NONBLOCK != 0 {
            set_nonblocking(theirs.as_fd())?;
        }

        if address != 0 && address_len != 0 {
            self.memory.write_sockaddr_in(address, address_len, peer)?;
        }

        let installed = self.install(id, theirs.as_fd())?;

        let mut accepted = Socket::new(ours, theirs);
        accepted.theirs = None;
        accepted.role = Role::Connected;
        accepted.local = Some(local);
        accepted.peer = Some(peer);

        let bridge = accepted.ours.as_ref().unwrap().try_clone()?;
        self.runtime.spawn(pump(bridge, stream));

        tracing::info!(fd = installed, %peer, "accepted a connection onto the stack");

        self.sockets.insert(installed, accepted);

        Ok(())
    }

fn on_connect(&mut self, id: u64, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.sockets.contains_key(&fd) {
            return Ok(Answer::Continue);
        }

        let remote = self.memory.read_sockaddr_in(args[1], args[2] as u32)?;
        let datagram = matches!(
            self.sockets.get(&fd).map(|s| &s.role),
            Some(Role::Datagram(_))
        );

        // A resolver usually connects its socket before it sends, and the name
        // server it connects to is off the overlay. Keep the socket ours so the
        // query still reaches the peer table.
        let resolving = datagram && remote.port() == DNS_PORT && self.zone.is_some();

        if !resolving && !self.is_ours(*remote.ip()) {
            let kind = if datagram {
                libc::SOCK_DGRAM
            } else {
                libc::SOCK_STREAM
            };

            return self.hand_back(id, fd, kind);
        }

        if datagram {
            self.datagram_socket(fd)?;
            self.sockets.get_mut(&fd).expect("checked").peer = Some(remote);

            tracing::info!(fd, %remote, "udp socket connected");

            return Ok(Answer::Value(0));
        }

        if self.sockets.get(&fd).is_some_and(|s| s.connecting.is_some()) {
            return Ok(Answer::Error(libc::EALREADY));
        }

        let net = self.net.clone();
        let nudge = self.waker.try_clone()?;
        let (report, outcome) = tokio::sync::oneshot::channel();

        self.runtime.spawn(async move {
            let reached = net
                .tcp_connect(*remote.ip(), remote.port())
                .await
                .map_err(|e| e.to_string());

            let _ = report.send(reached);
            nudge.wake();
        });

        let blocking = self.is_blocking(fd);
        let socket = self.sockets.get_mut(&fd).expect("checked above");

        socket.peer = Some(remote);
        socket.connecting = Some(outcome);
        self.connecting += 1;

        if blocking {
            self.sockets.get_mut(&fd).expect("checked above").waiting_connect = Some(id);
            self.parked += 1;

            tracing::debug!(fd, %remote, "parking a blocking connect until it completes");

            return Ok(Answer::Parked);
        }

        tracing::debug!(fd, %remote, "connect is in flight, reporting EINPROGRESS");

        Ok(Answer::Error(libc::EINPROGRESS))
    }

    fn settle_connect(&mut self, fd: i32) {
        let Some(socket) = self.sockets.get_mut(&fd) else {
            return;
        };

        let Some(pending) = socket.connecting.as_mut() else {
            return;
        };

        let outcome = match pending.try_recv() {
            Ok(outcome) => outcome,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => return,
            Err(_) => Err("the connect task went away".to_owned()),
        };

        socket.connecting = None;
        self.connecting = self.connecting.saturating_sub(1);

        let socket = self.sockets.get_mut(&fd).expect("checked above");
        let waiting = socket.waiting_connect.take();

        let started = match outcome {
            Ok(stream) => {
                socket.role = Role::Connected;
                socket.theirs = None;
                socket.local = Some(as_v4(stream.local_addr()));

                socket
                    .ours
                    .as_ref()
                    .expect("a connecting socket keeps our end")
                    .try_clone()
                    .map(|bridge| (bridge, stream))
            }
            Err(e) => {
                tracing::info!(fd, "connect refused: {e}");

                socket.error = Some(libc::ECONNREFUSED);
                socket.ours = None;
                socket.theirs = None;

                Err(io::Error::other(e))
            }
        };

        if waiting.is_some() {
            self.parked = self.parked.saturating_sub(1);
        }

        match started {
            Ok((bridge, stream)) => {
                self.runtime.spawn(pump(bridge, stream));

                tracing::info!(fd, "connected through the smolnet stack");

                if let Some(id) = waiting {
                    self.reply(id, notify::allow(id, 0));
                }
            }
            Err(_) => {
                if let Some(id) = waiting {
                    self.reply(id, notify::fail(id, libc::ECONNREFUSED));
                }
            }
        }
    }

    fn on_close(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;
        let owner = self.resolve(fd);

        if !self.sockets.contains_key(&owner) {
            return Ok(Answer::Continue);
        }

        if !self.drop_reference(fd) {
            tracing::debug!(fd, owner, "closed one of several descriptors, keeping the socket");
            self.soon(Duration::from_secs(2));

            return Ok(Answer::Continue);
        }

        let costly = matches!(
            self.sockets.get(&owner).map(|socket| &socket.role),
            Some(Role::Listening(_) | Role::Datagram(_))
        );

        if costly
            && let Some(inode) = self.sockets.get(&owner).map(|socket| socket.inode)
            && inode != 0
            && self.holds(inode)
        {
            tracing::info!(
                fd,
                owner,
                "another task still holds this socket, keeping it past the close"
            );

            self.retain(owner);
            self.soon(Duration::from_secs(2));

            return Ok(Answer::Continue);
        }

        if let Some(socket) = self.release(owner) {
            let role = match socket.role {
                Role::Listening(_) => "listener",
                Role::Connected => "connection",
                Role::Datagram(_) => "datagram",
                _ => "socket",
            };

            tracing::info!(fd, role, "target closed a socket, releasing it");
        }

        Ok(Answer::Continue)
    }

    fn on_close_range(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        if args[2] & CLOSE_RANGE_CLOEXEC != 0 {
            return Ok(Answer::Continue);
        }

        let first = args[0] as i32;
        let last = args[1].min(i32::MAX as u64) as i32;

        let swept: Vec<i32> = self
            .sockets
            .keys()
            .chain(self.aliases.keys())
            .copied()
            .filter(|fd| *fd >= first && *fd <= last)
            .collect();

        for fd in swept {
            let owner = self.resolve(fd);

            if self.drop_reference(fd) {
                tracing::info!(fd, "close_range reclaimed a socket");
                self.release(owner);
            }
        }

        Ok(Answer::Continue)
    }

    fn on_clone(&mut self, args: [u64; 6], flags: u64) -> io::Result<Answer> {
        if flags & libc::CLONE_FILES as u64 != 0 {
            return Ok(Answer::Continue);
        }

        let owned: Vec<i32> = self.sockets.keys().copied().collect();

        for fd in owned {
            self.retain(fd);
        }

        let _ = args;
        self.soon(Duration::from_secs(2));

        tracing::debug!("the target forked, its copy of the descriptor table shares our sockets");

        Ok(Answer::Continue)
    }

    fn on_dup(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let owner = self.resolve(args[0] as i32);

        if self.sockets.contains_key(&owner) {
            self.retain(owner);
            self.undiscovered += 1;

            tracing::debug!(owner, "the target duplicated a socket we own");
        }

        Ok(Answer::Continue)
    }

    fn on_dup2(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let owner = self.resolve(args[0] as i32);
        let new = args[1] as i32;

        if new == args[0] as i32 {
            return Ok(Answer::Continue);
        }

        if self.sockets.contains_key(&self.resolve(new)) && self.drop_reference(new) {
            self.release(self.resolve(new));
        }

        if self.sockets.contains_key(&owner) {
            self.retain(owner);
            self.aliases.insert(new, owner);

            tracing::debug!(owner, new, "the target aliased a socket we own");
        }

        Ok(Answer::Continue)
    }

    fn on_fcntl(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let owner = self.resolve(args[0] as i32);
        let command = args[1] as i32;

        if !self.sockets.contains_key(&owner) {
            return Ok(Answer::Continue);
        }

        match command {
            libc::F_DUPFD | libc::F_DUPFD_CLOEXEC => {
                self.retain(owner);
                self.undiscovered += 1;

                tracing::debug!(owner, "the target duplicated a socket through fcntl");
            }
            libc::F_SETFL => {
                let blocking = args[2] as i32 & libc::O_NONBLOCK == 0;
                let socket = self.sockets.get_mut(&owner).expect("checked above");

                socket.blocking = blocking;
                socket.observed_flags = true;

                tracing::debug!(owner, blocking, "the target changed the socket flags");
            }
            _ => {}
        }

        Ok(Answer::Continue)
    }

    fn on_getsockname(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        let Some(socket) = self.sockets.get(&fd) else {
            return Ok(Answer::Continue);
        };

        let local = socket
            .local
            .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

        self.memory.write_sockaddr_in(args[1], args[2], local)?;

        Ok(Answer::Value(0))
    }

    fn on_getpeername(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        let Some(socket) = self.sockets.get(&fd) else {
            return Ok(Answer::Continue);
        };

        let Some(peer) = socket.peer else {
            return Ok(Answer::Error(libc::ENOTCONN));
        };

        self.memory.write_sockaddr_in(args[1], args[2], peer)?;

        Ok(Answer::Value(0))
    }

    fn on_setsockopt(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.sockets.contains_key(&fd) {
            return Ok(Answer::Continue);
        }

        let level = args[1] as i32;
        let option = args[2] as i32;
        let length = args[4] as usize;

        if matches!(
            (level, option),
            (libc::SOL_SOCKET, libc::SO_RCVTIMEO | libc::SO_SNDTIMEO)
        ) {
            if args[3] == 0 || length < size_of::<libc::timeval>() {
                return Ok(Answer::Error(libc::EINVAL));
            }

            let seconds = self.memory.read_u64(args[3])?;
            let microseconds = self.memory.read_u64(args[3] + 8)?;

            let timeout = if seconds == 0 && microseconds == 0 {
                None
            } else {
                Some(Duration::new(seconds, microseconds as u32 * 1_000))
            };

            let socket = self.sockets.get_mut(&fd).expect("checked above");

            if option == libc::SO_RCVTIMEO {
                socket.timeouts.0 = timeout;
            } else {
                socket.timeouts.1 = timeout;
            }

            tracing::debug!(fd, option, ?timeout, "target set a socket timeout");

            return Ok(Answer::Value(0));
        }

        if args[3] == 0 || length < size_of::<i32>() {
            return Ok(Answer::Value(0));
        }

        let value = self.memory.read_u32(args[3])? as i32;

        if matches!(
            (level, option),
            (libc::SOL_SOCKET, libc::SO_RCVBUF) | (libc::SOL_SOCKET, libc::SO_SNDBUF)
        ) && let Some(ours) = self.sockets[&fd].theirs.as_ref().or(self.sockets[&fd].ours.as_ref())
        {
            let _ = resize(ours.as_fd(), option, value);
        }

        tracing::debug!(fd, level, option, value, "target set a socket option");

        self.sockets
            .get_mut(&fd)
            .expect("checked above")
            .options
            .insert((level, option), value);

        Ok(Answer::Value(0))
    }

    fn on_getsockopt(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.sockets.contains_key(&fd) {
            return Ok(Answer::Continue);
        }

        let level = args[1] as i32;
        let option = args[2] as i32;

        if (level, option) == (libc::SOL_SOCKET, libc::SO_ERROR) {
            let pending = self.sockets[&fd].connecting.is_some();
            let failure = self
                .sockets
                .get_mut(&fd)
                .expect("checked above")
                .error
                .take();

            let value = match failure {
                Some(errno) if !pending => errno,
                _ => 0,
            };

            return self.deliver_option(args, value);
        }

        if let Some(remembered) = self.sockets[&fd].options.get(&(level, option)).copied() {
            return self.deliver_option(args, remembered);
        }

        let value: i32 = match (level, option) {
            (libc::SOL_SOCKET, libc::SO_DOMAIN) => libc::AF_INET,
            (libc::SOL_SOCKET, libc::SO_TYPE) => libc::SOCK_STREAM,
            (libc::SOL_SOCKET, libc::SO_PROTOCOL) => libc::IPPROTO_TCP,
            (libc::SOL_SOCKET, libc::SO_ACCEPTCONN) => {
                i32::from(matches!(self.sockets[&fd].role, Role::Listening(_)))
            }
            (libc::SOL_SOCKET, libc::SO_RCVBUF | libc::SO_SNDBUF) => PAIR_BUFFER,
            (libc::SOL_SOCKET, libc::SO_KEEPALIVE | libc::SO_OOBINLINE) => 0,
            (libc::SOL_SOCKET, libc::SO_REUSEADDR | libc::SO_REUSEPORT) => 1,
            (libc::IPPROTO_TCP, libc::TCP_NODELAY) => 1,
            (libc::IPPROTO_TCP, libc::TCP_MAXSEG) => 1240,
            _ => 0,
        };

        self.deliver_option(args, value)
    }

    fn deliver_option(&mut self, args: [u64; 6], value: i32) -> io::Result<Answer> {
        if args[3] == 0 || args[4] == 0 {
            return Ok(Answer::Value(0));
        }

        let capacity = self.memory.read_u32(args[4])? as usize;
        let bytes = value.to_ne_bytes();
        let len = capacity.min(bytes.len());

        self.memory.write(args[3], &bytes[..len])?;
        self.memory.write_u32(args[4], len as u32)?;

        Ok(Answer::Value(0))
    }

    fn on_shutdown(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if self.sockets.contains_key(&fd) {
            tracing::debug!(fd, how = args[1], "target half closed a socket");
        }

        Ok(Answer::Continue)
    }
}

enum Answer {
    Value(i64),
    Error(i32),
    Continue,
    Installed,
    Parked,
}

async fn pump(ours: OwnedFd, stream: TcpStream) {
    let raw = unsafe { std::os::unix::net::UnixStream::from_raw_fd(ours.into_raw_fd()) };

    if let Err(e) = raw.set_nonblocking(true) {
        tracing::warn!("could not make the bridge non blocking: {e}");
        return;
    }

    let local = match tokio::net::UnixStream::from_std(raw) {
        Ok(local) => local,
        Err(e) => {
            tracing::warn!("could not adopt the bridge: {e}");
            return;
        }
    };

    let (mut from_app, to_app) = tokio::io::split(local);
    let (mut from_net, to_net) = tokio::io::split(stream);

    let outbound = tokio::spawn(async move {
        let mut to_net = to_net;
        let moved = tokio::io::copy(&mut from_app, &mut to_net).await;
        let _ = to_net.shutdown().await;

        moved
    });

    let inbound = tokio::spawn(async move {
        let mut to_app = to_app;
        let moved = tokio::io::copy(&mut from_net, &mut to_app).await;
        let _ = to_app.shutdown().await;

        moved
    });

    let (up, down) = tokio::join!(outbound, inbound);

    tracing::info!(
        up = up.ok().and_then(Result::ok),
        down = down.ok().and_then(Result::ok),
        "connection finished"
    );
}
