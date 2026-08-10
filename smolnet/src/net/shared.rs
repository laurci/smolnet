use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Waker;

use tokio::sync::Notify;

use crate::proto::tcp::TcpListenerHandle;
use crate::{
    proto::{tcp::TcpSocketHandle, udp::engine::UdpSocketHandle},
    stack::Stack,
};

#[derive(Default)]
pub(crate) struct Wakers {
    pub(crate) readable: HashMap<TcpSocketHandle, Waker>,
    pub(crate) writable: HashMap<TcpSocketHandle, Waker>,
    pub(crate) connecting: HashMap<TcpSocketHandle, Waker>,
    pub(crate) accepting: HashMap<TcpListenerHandle, Waker>,
    pub(crate) udp_readable: HashMap<UdpSocketHandle, Waker>,
}

impl Wakers {
    fn wake_all(&mut self) {
        for (_, waker) in self.readable.drain() {
            waker.wake();
        }
        for (_, waker) in self.writable.drain() {
            waker.wake();
        }
        for (_, waker) in self.connecting.drain() {
            waker.wake();
        }
        for (_, waker) in self.accepting.drain() {
            waker.wake();
        }
        for (_, waker) in self.udp_readable.drain() {
            waker.wake();
        }
    }
}

pub(crate) struct Inner {
    pub(crate) stack: Stack,
    pub(crate) wakers: Wakers,
}

impl Inner {
    pub(crate) fn wake_ready(&mut self) {
        let stack = &self.stack;

        self.wakers.readable.retain(|handle, waker| {
            let ready = stack.tcp_can_recv(handle)
                || stack.tcp_peer_finished(handle)
                || stack.tcp_state(handle).is_none();

            if ready {
                waker.wake_by_ref();
            }

            !ready
        });

        self.wakers.writable.retain(|handle, waker| {
            let ready = stack.tcp_send_capacity(handle) > 0 || stack.tcp_state(handle).is_none();

            if ready {
                waker.wake_by_ref();
            }

            !ready
        });

        self.wakers.connecting.retain(|handle, waker| {
            let settled = !matches!(
                stack.tcp_state(handle),
                Some(crate::proto::tcp::TcpState::SynSent)
            );

            if settled {
                waker.wake_by_ref();
            }

            !settled
        });

        self.wakers.accepting.retain(|handle, waker| {
            let ready = stack.tcp_can_accept(handle);

            if ready {
                waker.wake_by_ref();
            }

            !ready
        });

        self.wakers.udp_readable.retain(|handle, waker| {
            let ready = stack.udp_can_recv(handle);

            if ready {
                waker.wake_by_ref();
            }

            !ready
        });
    }
}

pub(crate) struct Shared {
    inner: Mutex<Inner>,

    pub(crate) driver: Notify,
}

impl Shared {
    pub(crate) fn new(stack: Stack) -> Arc<Shared> {
        Arc::new(Shared {
            inner: Mutex::new(Inner {
                stack,
                wakers: Wakers::default(),
            }),
            driver: Notify::new(),
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("stack lock poisoned")
    }

    pub(crate) fn wake_driver(&self) {
        self.driver.notify_one();
    }

    pub(crate) fn shutdown(&self) {
        self.lock().wakers.wake_all();
    }
}
