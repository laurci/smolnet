pub type MacAddr = [u8; 6];

pub type Ipv4Addr = [u8; 4];

pub const BROADCAST_MAC: MacAddr = [0xff; 6];

pub const UNSPECIFIED_MAC: MacAddr = [0x00; 6];

pub fn is_group_mac(mac: &MacAddr) -> bool {
    mac[0] & 0x01 != 0
}
