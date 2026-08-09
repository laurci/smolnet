use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum HeaderParseError {
    #[error(
        "invalid length while parsing field '{field_name}' (expected = {expected_length}; found = {actual_length})"
    )]
    InvalidLengthForField {
        field_name: &'static str,
        expected_length: usize,
        actual_length: usize,
    },
}

pub fn read_field_slice<const N: usize>(
    field_name: &'static str,
    input: &[u8],
    offset: usize,
) -> Result<[u8; N], HeaderParseError> {
    let Some(slice) = input.get(offset..offset.saturating_add(N)) else {
        return Err(HeaderParseError::InvalidLengthForField {
            field_name,
            expected_length: N,
            actual_length: input.len().saturating_sub(offset),
        });
    };

    let slice: [u8; N] = slice
        .try_into()
        .map_err(|_| HeaderParseError::InvalidLengthForField {
            field_name,
            expected_length: N,
            actual_length: slice.len(),
        })?;

    Ok(slice)
}

macro_rules! impl_read_field_numeric {
        ($($fn_name:ident => $t:ty),* $(,)?) => {
            $(
            pub fn $fn_name(
                field_name: &'static str,
                input: &[u8],
                offset: usize,
            ) -> Result<$t, HeaderParseError> {
                let slice = read_field_slice(field_name, input, offset)?;
                Ok(<$t>::from_be_bytes(slice))
            }
        )*
    };
}

impl_read_field_numeric!(
    read_field_u8 => u8,
    read_field_u16 => u16,
    read_field_u32 => u32,
    read_field_u64 => u64,
);

impl_read_field_numeric!(
    read_field_i8 => i8,
    read_field_i16 => i16,
    read_field_i32 => i32,
    read_field_i64 => i64,
);

#[cfg(test)]
mod test {
    use crate::parse::{HeaderParseError, read_field_slice, read_field_u32};

    #[test]
    fn short_input_is_an_error_not_a_panic() {
        let input = [0x01u8, 0x02];

        let result = read_field_slice::<4>("test.field", &input, 0);
        assert_eq!(
            result,
            Err(HeaderParseError::InvalidLengthForField {
                field_name: "test.field",
                expected_length: 4,
                actual_length: 2,
            })
        );
    }

    #[test]
    fn offset_past_end_is_an_error_not_a_panic() {
        let input = [0x01u8, 0x02];

        let result = read_field_u32("test.field", &input, 8);
        assert!(result.is_err());
    }
}
