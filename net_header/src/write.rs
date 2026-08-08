pub fn write_field_slice<const N: usize>(
    data: [u8; N],
    field_name: &'static str,
    output: &mut [u8],
    offset: usize,
) -> usize {
    let end = offset + N;
    debug_assert!(
        end <= output.len(),
        "insufficient buffer size when writing '{field_name}'; needs = {N}, got = {}",
        output.len() - offset
    );

    output[offset..end].copy_from_slice(&data);

    end
}

macro_rules! impl_write_field_numeric {
        ($($fn_name:ident => $t:ty),* $(,)?) => {
            $(
            pub fn $fn_name(
                data: $t,
                field_name: &'static str,
                output: &mut [u8],
                offset: usize,
            ) -> usize {
                let bytes = data.to_be_bytes();
                write_field_slice(bytes, field_name, output, offset)
            }
        )*
    };
}

impl_write_field_numeric!(
    write_field_u8 => u8,
    write_field_u16 => u16,
    write_field_u64 => u64,
    write_field_u32 => u32,
);

impl_write_field_numeric!(
    write_field_i8 => i8,
    write_field_i16 => i16,
    write_field_i32 => i32,
    write_field_i64 => i64,
);
