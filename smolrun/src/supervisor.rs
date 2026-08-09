use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

use smolnet::net::{Net, tcp::TcpStream};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Handle;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::mem::Memory;
use crate::notify::{self, ADDFD_FLAG_SEND, Notif, NotifAddfd};

const PAIR_BUFFER: libc::c_int = 64 * 1024;

type Arrival = (TcpStream, SocketAddrV4);

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
}

struct Socket {
    role: Role,
    local: Option<SocketAddrV4>,
    peer: Option<SocketAddrV4>,
    ours: Option<OwnedFd>,
    theirs: Option<OwnedFd>,
}

impl Socket {
    fn new(ours: OwnedFd, theirs: OwnedFd) -> Socket {
        Socket {
            role: Role::Fresh,
            local: None,
            peer: None,
            ours: Some(ours),
            theirs: Some(theirs),
        }
    }
}

pub struct Supervisor {
    listener: OwnedFd,
    pid: u32,
    memory: Memory,
    net: Net,
    runtime: Handle,
    sockets: HashMap<i32, Socket>,
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
    pub fn new(listener: OwnedFd, pid: u32, net: Net, runtime: Handle) -> io::Result<Supervisor> {
        Ok(Supervisor {
            listener,
            pid,
            memory: Memory::open(pid)?,
            net,
            runtime,
            sockets: HashMap::new(),
        })
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

    pub fn run(mut self) {
        loop {
            let notification = match notify::recv(self.listener.as_fd()) {
                Ok(notification) => notification,
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => {
                    tracing::debug!("notification channel closed: {e}");
                    break;
                }
            };

            self.dispatch(notification);
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
        let args = notification.data.args;

        let outcome = match notification.data.nr as i64 {
            libc::SYS_socket => self.on_socket(id, args),
            libc::SYS_bind => self.on_bind(args),
            libc::SYS_listen => self.on_listen(args),
            libc::SYS_accept => self.on_accept(id, args, 0),
            libc::SYS_accept4 => self.on_accept(id, args, args[3] as i32),
            libc::SYS_getsockname => self.on_getsockname(args),
            libc::SYS_getpeername => self.on_getpeername(args),
            libc::SYS_setsockopt => Ok(Answer::Value(0)),
            libc::SYS_getsockopt => self.on_getsockopt(args),
            libc::SYS_shutdown => self.on_shutdown(args),
            libc::SYS_connect => self.on_connect(args),
            libc::SYS_close => self.on_close(args),
            _ => Ok(Answer::Continue),
        };

        match outcome {
            Ok(Answer::Value(value)) => self.reply(id, notify::allow(id, value)),
            Ok(Answer::Error(errno)) => self.reply(id, notify::fail(id, errno)),
            Ok(Answer::Continue) => self.reply(id, notify::passthrough(id)),
            Ok(Answer::Installed) => {}
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

        if domain != libc::AF_INET || kind & 0xf != libc::SOCK_STREAM {
            return Ok(Answer::Continue);
        }

        let (ours, theirs) = socketpair(libc::SOCK_STREAM | libc::SOCK_CLOEXEC)?;

        if kind & libc::SOCK_NONBLOCK != 0 {
            set_nonblocking(theirs.as_fd())?;
        }

        let installed = self.install(id, theirs.as_fd())?;

        tracing::info!(fd = installed, "handed the target a tcp socket");

        self.sockets.insert(installed, Socket::new(ours, theirs));

        Ok(Answer::Installed)
    }

    fn on_bind(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        let Some(socket) = self.sockets.get_mut(&fd) else {
            return Ok(Answer::Continue);
        };

        let endpoint = self.memory.read_sockaddr_in(args[1], args[2] as u32)?;

        socket.local = Some(endpoint);
        socket.role = Role::Bound;

        tracing::info!(fd, %endpoint, "target bound a socket");

        Ok(Answer::Value(0))
    }

    fn on_listen(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

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
                self.evict_stale();

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

        let accepting = self
            .runtime
            .spawn(async move {
                while let Ok(stream) = listener.accept().await {
                    let peer = as_v4(stream.peer_addr());

                    if arrived.send((stream, peer)).is_err() {
                        break;
                    }

                    ring(bell.as_fd());
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

        let Some(socket) = self.sockets.get_mut(&fd) else {
            return Ok(Answer::Continue);
        };

        let Role::Listening(listening) = &mut socket.role else {
            return Ok(Answer::Error(libc::EINVAL));
        };

        let Ok((stream, peer)) = listening.arrivals.try_recv() else {
            return Ok(Answer::Error(libc::EAGAIN));
        };

        answer(listening.drain.as_fd());

        let local = socket
            .local
            .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let (ours, theirs) = socketpair(libc::SOCK_STREAM | libc::SOCK_CLOEXEC)?;

        if flags & libc::SOCK_NONBLOCK != 0 {
            set_nonblocking(theirs.as_fd())?;
        }

        if args[1] != 0 && args[2] != 0 {
            self.memory.write_sockaddr_in(args[1], args[2], peer)?;
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

        Ok(Answer::Installed)
    }

    fn evict_stale(&mut self) {
        let live = std::fs::read_dir(format!("/proc/{}/fd", self.pid))
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
                    .collect::<std::collections::HashSet<i32>>()
            })
            .unwrap_or_default();

        if live.is_empty() {
            return;
        }

        let stale: Vec<i32> = self
            .sockets
            .keys()
            .copied()
            .filter(|fd| !live.contains(fd))
            .collect();

        for fd in stale {
            tracing::info!(fd, "reclaiming a socket the target has closed");
            self.sockets.remove(&fd);
        }
    }

    fn on_connect(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.sockets.contains_key(&fd) {
            return Ok(Answer::Continue);
        }

        let remote = self.memory.read_sockaddr_in(args[1], args[2] as u32)?;
        let net = self.net.clone();

        let outcome = self
            .runtime
            .block_on(async move { net.tcp_connect(*remote.ip(), remote.port()).await });

        let stream = match outcome {
            Ok(stream) => stream,
            Err(e) => {
                tracing::info!(%remote, "connect refused: {e}");
                return Ok(Answer::Error(libc::ECONNREFUSED));
            }
        };

        let local = as_v4(stream.local_addr());
        let socket = self.sockets.get_mut(&fd).expect("checked above");

        socket.role = Role::Connected;
        socket.theirs = None;
        socket.local = Some(local);
        socket.peer = Some(remote);

        let bridge = socket.ours.as_ref().unwrap().try_clone()?;
        self.runtime.spawn(pump(bridge, stream));

        tracing::info!(fd, %remote, "connected through the smolnet stack");

        Ok(Answer::Value(0))
    }

    fn on_close(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if let Some(socket) = self.sockets.remove(&fd) {
            let role = match socket.role {
                Role::Listening(_) => "listener",
                Role::Connected => "connection",
                _ => "socket",
            };

            tracing::info!(fd, role, "target closed a socket, releasing it");
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

    fn on_getsockopt(&mut self, args: [u64; 6]) -> io::Result<Answer> {
        let fd = args[0] as i32;

        if !self.sockets.contains_key(&fd) {
            return Ok(Answer::Continue);
        }

        let level = args[1] as i32;
        let option = args[2] as i32;

        let value: i32 = match (level, option) {
            (libc::SOL_SOCKET, libc::SO_ERROR) => 0,
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

        if args[3] != 0 && args[4] != 0 {
            self.memory.write_u32(args[3], value as u32)?;
            self.memory.write_u32(args[4], size_of::<i32>() as u32)?;
        }

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
