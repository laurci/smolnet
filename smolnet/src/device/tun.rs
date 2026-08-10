use std::task::{Context, Poll};

use crate::device::{
    Device, DeviceCapabilities, DeviceError, Medium,
    tuntap::{IFF_NO_PI, IFF_TUN, TunTapDevice, TunTapOpenError},
};

pub use crate::device::tuntap::TunTapOpenError as TunDeviceOpenError;

pub struct TunDevice {
    inner: TunTapDevice,
}

impl TunDevice {
    pub fn open(interface_name: &str, mtu: usize) -> Result<TunDevice, TunTapOpenError> {
        let capabilities = DeviceCapabilities {
            medium: Medium::Ip,
            mtu,
        };
        let inner = TunTapDevice::open(interface_name, IFF_TUN | IFF_NO_PI, capabilities)?;

        tracing::info!(
            interface = interface_name,
            mtu = capabilities.mtu,
            "tun device opened"
        );

        Ok(TunDevice { inner })
    }
}

impl Device for TunDevice {
    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }

    fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError> {
        self.inner.read_frame(data)
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), DeviceError> {
        self.inner.write_frame(data)
    }

    fn poll_readable(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_readable(cx)
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_writable(cx)
    }
}
