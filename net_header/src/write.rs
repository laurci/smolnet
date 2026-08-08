use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum HeaderWriteError {
    #[error(
        "insufficient space in buffer while writing field '{field_name}' (needed = {needed_length}; remaining = {remaining_length})"
    )]
    BufferLenghtForField {
        field_name: &'static str,
        needed_length: usize,
        remaining_length: usize,
    },
}

pub fn write_field_slice<const N: usize>(
    data: [u8; N],
    field_name: &'static str,
    output: &mut [u8],
    offset: usize,
) -> Result<usize, HeaderWriteError> {
    let end = offset + N;
    if end > output.len() {
        return Err(HeaderWriteError::BufferLenghtForField {
            field_name,
            needed_length: N,
            remaining_length: output.len() - offset,
        });
    }

    output[offset..end].copy_from_slice(&data);

    Ok(end)
}

macro_rules! impl_write_field_numeric {
        ($($fn_name:ident => $t:ty),* $(,)?) => {
            $(
            pub fn $fn_name(
                data: $t,
                field_name: &'static str,
                output: &mut [u8],
                offset: usize,
            ) -> Result<usize, HeaderWriteError> {
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
