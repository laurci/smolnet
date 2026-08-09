use std::task::{Context, Poll};

use crate::{
    addr::MacAddr,
    device::{
        Device, DeviceCapabilities, DeviceError, Medium,
        tuntap::{IFF_NO_PI, IFF_TAP, TunTapDevice, TunTapOpenError},
    },
};

pub use crate::device::tuntap::TunTapOpenError as TapDeviceOpenError;

pub struct TapDevice {
    inner: TunTapDevice,
}

impl TapDevice {
    pub fn open(interface_name: &str, mac: MacAddr) -> Result<TapDevice, TunTapOpenError> {
        let capabilities = DeviceCapabilities::new(Medium::Ethernet { mac });
        let inner = TunTapDevice::open(interface_name, IFF_TAP | IFF_NO_PI, capabilities)?;

        tracing::info!(
            interface = interface_name,
            ?mac,
            mtu = capabilities.mtu,
            "tap device opened"
        );

        Ok(TapDevice { inner })
    }
}

impl Device for TapDevice {
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
