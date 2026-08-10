use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::FileExt;

pub struct Memory {
    pid: u32,
    file: RefCell<File>,
}

impl Memory {
    pub fn open(pid: u32) -> io::Result<Memory> {
        Ok(Memory {
            pid,
            file: RefCell::new(Memory::handle(pid)?),
        })
    }

    fn handle(pid: u32) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
    }

    fn refresh(&self) -> io::Result<()> {
        *self.file.borrow_mut() = Memory::handle(self.pid)?;

        Ok(())
    }

    pub fn read(&self, address: u64, buffer: &mut [u8]) -> io::Result<()> {
        if self.file.borrow().read_exact_at(buffer, address).is_ok() {
            return Ok(());
        }

        self.refresh()?;
        self.file.borrow().read_exact_at(buffer, address)
    }

    pub fn write(&self, address: u64, buffer: &[u8]) -> io::Result<()> {
        if self.file.borrow().write_all_at(buffer, address).is_ok() {
            return Ok(());
        }

        self.refresh()?;
        self.file.borrow().write_all_at(buffer, address)
    }

    pub fn read_u64(&self, address: u64) -> io::Result<u64> {
        let mut bytes = [0u8; 8];
        self.read(address, &mut bytes)?;

        Ok(u64::from_ne_bytes(bytes))
    }

    pub fn read_u32(&self, address: u64) -> io::Result<u32> {
        let mut bytes = [0u8; 4];
        self.read(address, &mut bytes)?;

        Ok(u32::from_ne_bytes(bytes))
    }

    pub fn write_u32(&self, address: u64, value: u32) -> io::Result<()> {
        self.write(address, &value.to_ne_bytes())
    }

    pub fn read_sockaddr_in(&self, address: u64, length: u32) -> io::Result<SocketAddrV4> {
        if (length as usize) < size_of::<libc::sockaddr_in>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the address is too short to be a sockaddr_in",
            ));
        }

        let mut bytes = [0u8; size_of::<libc::sockaddr_in>()];
        self.read(address, &mut bytes)?;

        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);

        if family != libc::AF_INET as u16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an ipv4 address",
            ));
        }

        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);

        Ok(SocketAddrV4::new(ip, port))
    }

    pub fn write_sockaddr_in(
        &self,
        address: u64,
        length_address: u64,
        endpoint: SocketAddrV4,
    ) -> io::Result<()> {
        if address == 0 || length_address == 0 {
            return Ok(());
        }

        let capacity = self.read_u32(length_address)? as usize;
        let encoded = encode_sockaddr_in(endpoint);

        let written = capacity.min(encoded.len());
        self.write(address, &encoded[..written])?;
        self.write_u32(length_address, encoded.len() as u32)?;

        Ok(())
    }
}

impl Memory {
    pub fn read_bytes(&self, address: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; len];
        self.read(address, &mut buffer)?;

        Ok(buffer)
    }
}

pub fn encode_sockaddr_in(endpoint: SocketAddrV4) -> [u8; size_of::<libc::sockaddr_in>()] {
    let mut bytes = [0u8; size_of::<libc::sockaddr_in>()];

    bytes[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    bytes[2..4].copy_from_slice(&endpoint.port().to_be_bytes());
    bytes[4..8].copy_from_slice(&endpoint.ip().octets());

    bytes
}

#[cfg(test)]
mod test {
    use std::net::SocketAddrV4;

    use crate::mem::{Memory, encode_sockaddr_in};

    #[test]
    fn a_sockaddr_round_trips_through_our_own_memory() {
        let endpoint: SocketAddrV4 = "10.77.0.2:8080".parse().unwrap();
        let encoded = encode_sockaddr_in(endpoint);

        let memory = Memory::open(std::process::id()).unwrap();
        let decoded = memory
            .read_sockaddr_in(encoded.as_ptr() as u64, encoded.len() as u32)
            .unwrap();

        assert_eq!(decoded, endpoint);
    }

    #[test]
    fn a_short_buffer_is_rejected() {
        let encoded = encode_sockaddr_in("127.0.0.1:1".parse().unwrap());
        let memory = Memory::open(std::process::id()).unwrap();

        assert!(memory.read_sockaddr_in(encoded.as_ptr() as u64, 4).is_err());
    }

    #[test]
    fn a_short_buffer_is_never_overrun() {
        let mut guarded = [0xccu8; 32];
        let capacity: u32 = 8;

        let memory = Memory::open(std::process::id()).unwrap();

        memory
            .write_sockaddr_in(
                guarded.as_mut_ptr() as u64,
                &capacity as *const u32 as u64,
                "10.77.0.2:8080".parse().unwrap(),
            )
            .unwrap();

        assert_eq!(
            &guarded[8..],
            &[0xcc; 24],
            "writing past what the caller offered would corrupt its heap"
        );
    }

    #[test]
    fn the_encoding_is_network_order_for_port_and_address() {
        let encoded = encode_sockaddr_in("1.2.3.4:258".parse().unwrap());

        assert_eq!(&encoded[2..4], &[0x01, 0x02]);
        assert_eq!(&encoded[4..8], &[1, 2, 3, 4]);
    }
}
