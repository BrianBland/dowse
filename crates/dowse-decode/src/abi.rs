use alloy_primitives::{Address, B256};

pub fn word(data: &[u8], index: usize) -> Option<&[u8]> {
    let start = index.checked_mul(32)?;
    data.get(start..start.checked_add(32)?)
}

pub fn usize_word(data: &[u8], index: usize) -> Option<usize> {
    let value = word(data, index)?;
    if value[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    usize::try_from(u64::from_be_bytes(value[24..].try_into().ok()?)).ok()
}

pub fn address_word(data: &[u8], index: usize) -> Option<Address> {
    let value = word(data, index)?;
    Some(Address::from_slice(&value[12..]))
}

pub fn bool_word(data: &[u8], index: usize) -> Option<bool> {
    match usize_word(data, index)? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

pub fn b256_word(data: &[u8], index: usize) -> Option<B256> {
    Some(B256::from_slice(word(data, index)?))
}

pub fn bytes(data: &[u8], index: usize) -> Option<&[u8]> {
    let offset = usize_word(data, index)?;
    let length_word = data.get(offset..offset.checked_add(32)?)?;
    let length = usize_word(length_word, 0)?;
    data.get(offset.checked_add(32)?..offset.checked_add(32)?.checked_add(length)?)
}

pub fn array(data: &[u8], index: usize) -> Option<&[u8]> {
    let offset = usize_word(data, index)?;
    data.get(offset..)
}

pub fn address_array(data: &[u8], index: usize, limit: usize) -> Option<Vec<Address>> {
    let values = array(data, index)?;
    let length = usize_word(values, 0)?.min(limit);
    (0..length)
        .map(|item| address_word(values, item + 1))
        .collect()
}

pub fn bytes_array(data: &[u8], index: usize, limit: usize) -> Option<Vec<&[u8]>> {
    let values = array(data, index)?;
    let length = usize_word(values, 0)?.min(limit);
    let heads = values.get(32..)?;
    (0..length)
        .map(|item| {
            let offset = usize_word(heads, item)?;
            let length_data = heads.get(offset..offset.checked_add(32)?)?;
            let byte_length = usize_word(length_data, 0)?;
            heads.get(offset.checked_add(32)?..offset.checked_add(32)?.checked_add(byte_length)?)
        })
        .collect()
}

pub fn tuple_array(data: &[u8], index: usize, limit: usize) -> Option<Vec<&[u8]>> {
    let values = array(data, index)?;
    let length = usize_word(values, 0)?.min(limit);
    let heads = values.get(32..)?;
    let mut tuples = Vec::with_capacity(length);
    for item in 0..length {
        let start = usize_word(heads, item)?;
        let end = if item + 1 < length {
            usize_word(heads, item + 1)?
        } else {
            heads.len()
        };
        if start > end {
            return None;
        }
        tuples.push(heads.get(start..end)?);
    }
    Some(tuples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_dynamic_byte_array() {
        let mut encoded = vec![0u8; 96];
        encoded[31] = 32;
        encoded[63] = 3;
        encoded[64..67].copy_from_slice(&[1, 2, 3]);
        assert_eq!(bytes(&encoded, 0), Some([1, 2, 3].as_slice()));
    }

    #[test]
    fn rejects_words_that_do_not_fit_usize() {
        let mut encoded = [0u8; 32];
        encoded[0] = 1;
        assert_eq!(usize_word(&encoded, 0), None);
    }
}
