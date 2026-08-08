pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        let word = u16::from_be_bytes([pair[0], pair[1]]);
        sum += u32::from(word);
    }

    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
