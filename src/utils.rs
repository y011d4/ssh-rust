use anyhow::Result;

pub fn add_length(bytes: Vec<u8>) -> Vec<u8> {
    let mut bytes = bytes.clone();
    let mut ret = (bytes.len() as u32).to_be_bytes().to_vec();
    ret.append(&mut bytes);
    ret
}

pub fn remove_length(bytes: &mut Vec<u8>) -> Result<Vec<u8>> {
    let length = u32::from_be_bytes(bytes[..4].try_into()?);
    let ret = bytes[4..4 + length as usize].to_vec();
    *bytes = bytes[4 + length as usize..].to_vec();
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_add_length() -> Result<()> {
        let bytes = vec![1, 2, 3, 4];
        let expected = vec![0, 0, 0, 4, 1, 2, 3, 4];
        let actual = add_length(bytes);
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn test_remove_length() -> Result<()> {
        let mut bytes = vec![0, 0, 0, 4, 1, 2, 3, 4, 0];
        let expected = vec![1, 2, 3, 4];
        let actual = remove_length(&mut bytes)?;
        assert_eq!(actual, expected);
        assert_eq!(bytes, vec![0]);
        Ok(())
    }
}
