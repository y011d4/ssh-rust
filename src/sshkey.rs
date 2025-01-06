use anyhow::{anyhow, Result};
use base64::prelude::*;
use std::path::PathBuf;

use crate::ed25519::ed25519_sign;
use crate::utils::add_length;

#[derive(Clone, Debug, PartialEq)]
pub struct Pubkey {
    key_type: String,
    data: Vec<u8>,
}

impl Pubkey {
    fn new(key_type: String, data: Vec<u8>) -> Self {
        Self { key_type, data }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = vec![0; 32];
        let data = &self.data;
        ret[..data.len()].copy_from_slice(data);
        [
            add_length(self.key_type.clone().into_bytes()),
            add_length(ret),
        ]
        .concat()
        .to_vec()
    }
}

#[derive(Clone, PartialEq)]
pub struct Privkey {
    key_type: String,
    data: Vec<u8>,
    pub pubkey: Pubkey,
}

impl std::fmt::Debug for Privkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("key_type", &self.key_type)
            .field("data", &"[redacted]")
            .field("pubkey", &self.pubkey)
            .finish()
    }
}

impl Privkey {
    fn new(key_type: String, data: Vec<u8>, pubkey: Pubkey) -> Self {
        Self {
            key_type,
            data,
            pubkey,
        }
    }

    pub fn sign(&self, msg: Vec<u8>) -> Vec<u8> {
        ed25519_sign(msg, self.data.clone())
    }
}

fn parse_header(bytes: Vec<u8>) -> Result<(String, Vec<u8>)> {
    let mut ret = vec![];
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0 {
            break;
        }
        ret.push(bytes[i]);
        i += 1;
    }
    Ok((String::from_utf8(ret.clone())?, bytes[i + 1..].to_vec()))
}

fn parse_length_field(bytes: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
    let length_bytes = bytes[..4].try_into()?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    let ret1 = bytes[4..4 + length].to_vec();
    let ret2 = bytes[4 + length..].to_vec();
    Ok((ret1, ret2))
}

fn parse_pubkey(bytes: Vec<u8>) -> Result<Pubkey> {
    let (key_type, bytes) = parse_length_field(bytes)?;
    assert_eq!(
        key_type,
        "ssh-ed25519".as_bytes(),
        "Only ssh-ed25519 can be parsed."
    );
    let (data, bytes) = parse_length_field(bytes)?;
    assert_eq!(bytes, "".as_bytes(), "Something wrong");
    Ok(Pubkey::new(String::from_utf8(key_type)?, data))
}

fn parse_privkey(bytes: Vec<u8>) -> Result<Privkey> {
    let (key_type, privkey_str) = parse_length_field(bytes)?;
    let (pubkey_data, privkey_str) = parse_length_field(privkey_str)?;
    let (privkey_data, privkey_str) = parse_length_field(privkey_str)?;
    let (_comment, privkey_str) = parse_length_field(privkey_str)?;
    let padding = privkey_str;
    assert_eq!(padding, (1..=padding.len() as u8).collect::<Vec<u8>>());
    assert_eq!(privkey_data[32..], pubkey_data);
    // assert_eq!(pubkey.data, pubkey_data);
    let pubkey = Pubkey::new(String::from_utf8(key_type.clone())?, pubkey_data);
    let privkey = Privkey::new(
        String::from_utf8(key_type)?,
        privkey_data[..32].to_vec(),
        pubkey,
    );
    assert_eq!(privkey.key_type, "ssh-ed25519");
    Ok(privkey)
}

fn parse(bytes: Vec<u8>) -> Result<Privkey> {
    let tmp = String::from_utf8(bytes)?;
    let trimmed_str = tmp.trim();
    let base64_string: String;
    match (trimmed_str.find("\n"), trimmed_str.rfind("\n")) {
        (Some(nl), Some(nr)) => {
            match (&trimmed_str[..nl], &trimmed_str[nr + 1..]) {
                ("-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----") => {
                    let mut tmp = trimmed_str[nl + 1..nr].to_string();
                    tmp.retain(|c| c != '\n');
                    base64_string = tmp.clone();
                }
                _ => return Err(anyhow!("Not supported")),
            };
        }
        _ => return Err(anyhow!("Invalid privkey")),
    }
    let decode_str = BASE64_STANDARD.decode(base64_string)?;
    let (header, decode_str) = parse_header(decode_str)?;
    assert_eq!(
        header, "openssh-key-v1",
        "Only openssh-key-v1 can be parsed."
    );
    let (enc_type, decode_str) = parse_length_field(decode_str)?;
    assert_eq!(enc_type, "none".as_bytes(), "Only none can be parsed.");
    let (kdf_type, decode_str) = parse_length_field(decode_str)?;
    assert_eq!(kdf_type, "none".as_bytes(), "Only none can be parsed.");
    let (kdf, decode_str) = parse_length_field(decode_str)?;
    assert_eq!(kdf, "".as_bytes(), "Only no kdf can be parsed.");
    let (tmp, decode_str) = (decode_str[..4].to_vec(), decode_str[4..].to_vec());
    assert_eq!(tmp, vec![0, 0, 0, 1], "fixed data");
    let (pubkey_str, decode_str) = parse_length_field(decode_str)?;
    let pubkey = parse_pubkey(pubkey_str)?;
    let (privkey_str, decode_str) = parse_length_field(decode_str)?;
    assert_eq!(decode_str, []);
    let (rands, privkey_str) = (privkey_str[..8].to_vec(), privkey_str[8..].to_vec());
    assert_eq!(rands[0..4], rands[4..8], "check failed");
    let privkey = parse_privkey(privkey_str)?;
    assert_eq!(pubkey.data, privkey.pubkey.data);
    Ok(privkey)
}

pub fn load(path: &PathBuf) -> Result<Privkey> {
    let bytes = std::fs::read(path)?;
    parse(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_parse_header() -> Result<()> {
        let bytes = "openssh-key-v1\x00hogetaro".as_bytes().to_vec();
        let (header, bytes) = parse_header(bytes)?;
        assert_eq!(header, "openssh-key-v1");
        assert_eq!(bytes, "hogetaro".as_bytes().to_vec());
        Ok(())
    }

    #[test]
    fn test_parse_length_field() -> Result<()> {
        let bytes = vec![0, 0, 0, 4, 1, 2, 3, 4, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let (block, bytes) = parse_length_field(bytes)?;
        assert_eq!(block, vec![1, 2, 3, 4]);
        assert_eq!(bytes, vec![0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let (block, bytes) = parse_length_field(bytes)?;
        assert_eq!(block, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(bytes, vec![]);
        Ok(())
    }

    #[test]
    fn test_parse_pubkey() -> Result<()> {
        let bytes = vec![
            0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 13, 23, 162,
            67, 131, 252, 165, 167, 139, 246, 5, 117, 141, 66, 155, 94, 71, 171, 216, 69, 73, 208,
            47, 49, 155, 188, 105, 6, 135, 20, 158, 124,
        ];
        let pubkey = parse_pubkey(bytes)?;
        assert_eq!(
            pubkey,
            Pubkey {
                key_type: "ssh-ed25519".to_string(),
                data: vec![
                    13, 23, 162, 67, 131, 252, 165, 167, 139, 246, 5, 117, 141, 66, 155, 94, 71,
                    171, 216, 69, 73, 208, 47, 49, 155, 188, 105, 6, 135, 20, 158, 124
                ]
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_privkey() -> Result<()> {
        let bytes = vec![
            0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 13, 23, 162,
            67, 131, 252, 165, 167, 139, 246, 5, 117, 141, 66, 155, 94, 71, 171, 216, 69, 73, 208,
            47, 49, 155, 188, 105, 6, 135, 20, 158, 124, 0, 0, 0, 64, 121, 64, 132, 98, 202, 152,
            187, 129, 4, 251, 205, 198, 248, 238, 236, 112, 108, 132, 174, 125, 72, 32, 2, 239,
            169, 102, 40, 68, 79, 19, 26, 162, 13, 23, 162, 67, 131, 252, 165, 167, 139, 246, 5,
            117, 141, 66, 155, 94, 71, 171, 216, 69, 73, 208, 47, 49, 155, 188, 105, 6, 135, 20,
            158, 124, 0, 0, 0, 18, 121, 48, 49, 49, 100, 52, 64, 121, 48, 49, 49, 100, 52, 45, 103,
            114, 97, 109, 1, 2, 3,
        ];
        let privkey = parse_privkey(bytes)?;
        assert_eq!(
            privkey,
            Privkey {
                key_type: "ssh-ed25519".to_string(),
                data: vec![
                    121, 64, 132, 98, 202, 152, 187, 129, 4, 251, 205, 198, 248, 238, 236, 112,
                    108, 132, 174, 125, 72, 32, 2, 239, 169, 102, 40, 68, 79, 19, 26, 162
                ],
                pubkey: Pubkey {
                    key_type: "ssh-ed25519".to_string(),
                    data: vec![
                        13, 23, 162, 67, 131, 252, 165, 167, 139, 246, 5, 117, 141, 66, 155, 94,
                        71, 171, 216, 69, 73, 208, 47, 49, 155, 188, 105, 6, 135, 20, 158, 124
                    ]
                }
            }
        );
        Ok(())
    }
}
