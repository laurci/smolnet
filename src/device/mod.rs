pub mod tap;

#[cfg(test)]
pub mod mock;

use std::time::Duration;

use thiserror::Error;

pub const MAX_FRAME_SIZE: usize = 2048;

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("device io:\n{0}")]
    Io(Box<dyn std::error::Error>),

    #[error("device read would block caller")]
    WouldBlock,

    #[error("provided output buffer is not big enough (need = {need}; got = {got})")]
    BufferTooSmall { need: usize, got: usize },
}

pub trait Device {
    fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError>;
    fn write_frame(&mut self, data: &[u8]) -> Result<(), DeviceError>;
    fn wait(&mut self, timeout: Option<Duration>, wait_writable: bool) -> Result<(), DeviceError>;
}
