use std::time::Duration;

use crate::device::{
    Device, DeviceCapabilities, DeviceError, Medium,
    tuntap::{IFF_NO_PI, IFF_TUN, TunTapDevice, TunTapOpenError},
};

pub use crate::device::tuntap::TunTapOpenError as TunDeviceOpenError;

pub struct TunDevice {
    inner: TunTapDevice,
}

impl TunDevice {
    pub fn open(interface_name: &str) -> Result<TunDevice, TunTapOpenError> {
        let capabilities = DeviceCapabilities::new(Medium::Ip);
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

    fn wait(&mut self, timeout: Option<Duration>, wait_writable: bool) -> Result<(), DeviceError> {
        self.inner.wait(timeout, wait_writable)
    }
}
