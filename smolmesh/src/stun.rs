use std::net::{Ipv4Addr, SocketAddrV4};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;

pub const TRANSACTION_SIZE: usize = 12;

pub const HEADER_SIZE: usize = 20;

pub const REQUEST_SIZE: usize = HEADER_SIZE;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const FAMILY_IPV4: u8 = 0x01;

pub type Transaction = [u8; TRANSACTION_SIZE];

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;

    Some(u16::from_be_bytes(pair))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let quad: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;

    Some(u32::from_be_bytes(quad))
}

pub fn is_stun(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_SIZE && bytes[0] & 0xc0 == 0 && u32_at(bytes, 4) == Some(MAGIC_COOKIE)
}

pub fn transaction() -> Transaction {
    rand::random()
}

pub fn request(transaction: &Transaction) -> [u8; REQUEST_SIZE] {
    let mut bytes = [0u8; REQUEST_SIZE];

    bytes[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    bytes[2..4].copy_from_slice(&0u16.to_be_bytes());
    bytes[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    bytes[8..HEADER_SIZE].copy_from_slice(transaction);

    bytes
}

fn mapped_address(value: &[u8], xor: bool) -> Option<SocketAddrV4> {
    if *value.get(1)? != FAMILY_IPV4 {
        return None;
    }

    let mut port = u16_at(value, 2)?;
    let mut address = u32_at(value, 4)?;

    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
        address ^= MAGIC_COOKIE;
    }

    Some(SocketAddrV4::new(Ipv4Addr::from(address), port))
}

pub fn parse_response(bytes: &[u8], transaction: &Transaction) -> Option<SocketAddrV4> {
    if !is_stun(bytes) || u16_at(bytes, 0)? != BINDING_SUCCESS {
        return None;
    }

    if bytes.get(8..HEADER_SIZE)? != transaction {
        return None;
    }

    let declared = u16_at(bytes, 2)? as usize;
    let end = HEADER_SIZE.checked_add(declared)?.min(bytes.len());

    let mut offset = HEADER_SIZE;
    let mut fallback = None;

    while offset + 4 <= end {
        let kind = u16_at(bytes, offset)?;
        let length = u16_at(bytes, offset + 2)? as usize;

        let start = offset + 4;
        let value = bytes.get(start..start.checked_add(length)?)?;

        match kind {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(address) = mapped_address(value, true) {
                    return Some(address);
                }
            }
            ATTR_MAPPED_ADDRESS => fallback = fallback.or(mapped_address(value, false)),
            _ => {}
        }

        offset = start + length.next_multiple_of(4);
    }

    fallback
}

#[cfg(test)]
mod test {
    use std::net::SocketAddrV4;

    use crate::stun::{
        HEADER_SIZE, MAGIC_COOKIE, REQUEST_SIZE, Transaction, is_stun, parse_response, request,
        transaction,
    };

    fn response(transaction: &Transaction, kind: u16, attribute: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_SIZE];

        bytes[..2].copy_from_slice(&kind.to_be_bytes());
        bytes[2..4].copy_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        bytes[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes[8..HEADER_SIZE].copy_from_slice(transaction);

        bytes.extend_from_slice(&attribute.to_be_bytes());
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(value);

        bytes
    }

    fn xor_mapped(endpoint: SocketAddrV4) -> Vec<u8> {
        let port = endpoint.port() ^ (MAGIC_COOKIE >> 16) as u16;
        let address = u32::from(*endpoint.ip()) ^ MAGIC_COOKIE;

        let mut value = vec![0x00, 0x01];
        value.extend_from_slice(&port.to_be_bytes());
        value.extend_from_slice(&address.to_be_bytes());

        value
    }

    #[test]
    fn a_request_is_a_bare_binding_header() {
        let transaction = transaction();
        let bytes = request(&transaction);

        assert_eq!(bytes.len(), REQUEST_SIZE);
        assert_eq!(&bytes[..2], &[0x00, 0x01]);
        assert_eq!(&bytes[2..4], &[0x00, 0x00]);
        assert_eq!(&bytes[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&bytes[8..], &transaction);
        assert!(is_stun(&bytes));
    }

    #[test]
    fn a_xor_mapped_address_is_recovered() {
        let transaction = transaction();
        let endpoint: SocketAddrV4 = "203.0.113.7:51820".parse().unwrap();

        let bytes = response(&transaction, 0x0101, 0x0020, &xor_mapped(endpoint));

        assert_eq!(parse_response(&bytes, &transaction), Some(endpoint));
    }

    #[test]
    fn a_plain_mapped_address_is_accepted_as_a_fallback() {
        let transaction = transaction();
        let endpoint: SocketAddrV4 = "203.0.113.7:51820".parse().unwrap();

        let mut value = vec![0x00, 0x01];
        value.extend_from_slice(&endpoint.port().to_be_bytes());
        value.extend_from_slice(&u32::from(*endpoint.ip()).to_be_bytes());

        let bytes = response(&transaction, 0x0101, 0x0001, &value);

        assert_eq!(parse_response(&bytes, &transaction), Some(endpoint));
    }

    #[test]
    fn a_response_for_another_transaction_is_ignored() {
        let endpoint: SocketAddrV4 = "203.0.113.7:51820".parse().unwrap();
        let bytes = response(&transaction(), 0x0101, 0x0020, &xor_mapped(endpoint));

        assert_eq!(parse_response(&bytes, &transaction()), None);
    }

    #[test]
    fn an_error_response_yields_nothing() {
        let transaction = transaction();
        let endpoint: SocketAddrV4 = "203.0.113.7:51820".parse().unwrap();

        let bytes = response(&transaction, 0x0111, 0x0020, &xor_mapped(endpoint));

        assert_eq!(parse_response(&bytes, &transaction), None);
    }

    #[test]
    fn a_truncated_response_yields_nothing() {
        let transaction = transaction();
        let endpoint: SocketAddrV4 = "203.0.113.7:51820".parse().unwrap();
        let bytes = response(&transaction, 0x0101, 0x0020, &xor_mapped(endpoint));

        for len in 0..bytes.len() {
            assert_eq!(
                parse_response(&bytes[..len], &transaction),
                None,
                "len = {len}"
            );
        }
    }

    #[test]
    fn unknown_attributes_are_skipped() {
        let transaction = transaction();
        let endpoint: SocketAddrV4 = "203.0.113.7:51820".parse().unwrap();

        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[..2].copy_from_slice(&0x0101u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes[8..HEADER_SIZE].copy_from_slice(&transaction);

        let mut attributes = vec![];
        attributes.extend_from_slice(&0x8022u16.to_be_bytes());
        attributes.extend_from_slice(&5u16.to_be_bytes());
        attributes.extend_from_slice(b"smoln");
        attributes.extend_from_slice(&[0, 0, 0]);

        let mapped = xor_mapped(endpoint);
        attributes.extend_from_slice(&0x0020u16.to_be_bytes());
        attributes.extend_from_slice(&(mapped.len() as u16).to_be_bytes());
        attributes.extend_from_slice(&mapped);

        bytes[2..4].copy_from_slice(&(attributes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&attributes);

        assert_eq!(parse_response(&bytes, &transaction), Some(endpoint));
    }

    #[test]
    fn mesh_datagrams_are_never_mistaken_for_stun() {
        let datagram = crate::wire::Datagram::new(
            crate::wire::MessageType::Data,
            crate::NetworkId::random(),
            crate::NodeId::random(),
            b"payload",
        );

        let mut bytes = vec![0u8; datagram.size()];
        datagram.write(&mut bytes);

        assert!(!is_stun(&bytes));
    }
}
