//! RFC 4253
//! RFC 7539
//! https://github.com/rus-cert/ssh-chacha20-poly1305-drafts/blob/master/ssh-chacha20-poly1305%40openssh.md
use anyhow::{anyhow, Result};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key, Nonce};
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

fn kex_pad(bytes: Vec<u8>) -> Vec<u8> {
    let mut padlen = 8 - (1 + bytes.len()) % 8;
    if padlen < 4 {
        padlen += 8;
    }
    [vec![padlen as u8], bytes, (0u8..padlen as u8).collect()].concat()
}

pub fn kex_encrypt(
    payload: Vec<u8>,
    k_main: Vec<u8>,
    k_header: Vec<u8>,
    sequence_number: u32,
) -> Vec<u8> {
    let mut nonce = vec![0; 12];
    nonce[8..].copy_from_slice(&sequence_number.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce);
    let packet = kex_pad(payload);
    let length_key = Key::from_slice(&k_header);
    let content_key = Key::from_slice(&k_main);
    let mut length_cipher = ChaCha20::new(length_key, nonce);
    let mut content_cipher = ChaCha20::new(content_key, nonce);
    let mut mac_key = poly1305::Key::default();
    content_cipher.apply_keystream(&mut mac_key);
    let mut enc_length = (packet.len() as u32).to_be_bytes();
    length_cipher.apply_keystream(&mut enc_length);
    let mut enc_packet = packet.clone();
    content_cipher.seek(64);
    content_cipher.apply_keystream(&mut enc_packet);
    let poly = Poly1305::new(&mac_key);
    let enc = [enc_length.to_vec(), enc_packet.clone()].concat();
    let auth = poly.compute_unpadded(&enc);
    [enc, auth.to_vec()].concat()
}

pub async fn receive_and_kex_decrypt<T>(
    reader: &Arc<Mutex<tokio::io::BufReader<T>>>,
    content_key: Vec<u8>,
    length_key: Vec<u8>,
    sequence_number: u32,
) -> Result<Vec<u8>>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let mut nonce = vec![0; 12];
    nonce[8..].copy_from_slice(&sequence_number.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce);
    let mut enc_length = [0; 4];
    let n = reader.try_lock()?.read(&mut enc_length).await?;
    if n == 0 {
        return Err(anyhow!("end at length read"));
    }
    let length_key = Key::from_slice(&length_key);
    let content_key = Key::from_slice(&content_key);
    let mut length_cipher = ChaCha20::new(length_key, nonce);
    let mut content_cipher = ChaCha20::new(content_key, nonce);
    let mut mac_key = poly1305::Key::default();
    content_cipher.apply_keystream(&mut mac_key);
    let mut length = enc_length;
    length_cipher.apply_keystream(&mut length);
    let length = u32::from_be_bytes(length);
    if length >= 65536 {
        return Err(anyhow!("too long"));
    }
    let mut enc_packet = vec![0; length as usize];
    let n = reader.try_lock()?.read(&mut enc_packet).await?;
    if n == 0 {
        return Err(anyhow!("end at packet read"));
    }
    content_cipher.seek(64);
    let mut packet = enc_packet.clone();
    content_cipher.apply_keystream(&mut packet);
    let padlen = packet[0];
    let packet = packet[1..(packet.len() as i32 - padlen as i32) as usize].to_vec();
    let mut auth = [0; 16];
    let n = reader.try_lock()?.read(&mut auth).await?;
    if n == 0 {
        return Err(anyhow!("end at auth read"));
    }
    let poly = Poly1305::new(&mac_key);
    let enc = [enc_length.to_vec(), enc_packet.clone()].concat();
    let computed_auth = poly.compute_unpadded(&enc);
    if auth.to_vec() == computed_auth.to_vec() {
        Ok(packet)
    } else {
        Err(anyhow!("auth error"))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tokio_test::io::Builder;

    use super::*;

    #[test]
    fn test_kex_pad() -> Result<()> {
        let bytes = vec![0x15];
        assert_eq!(
            kex_pad(bytes),
            vec![0x06, 0x15, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
        );
        Ok(())
    }

    #[test]
    fn test_kex_encrypt() -> Result<()> {
        let payload = vec![0x15];
        let k_main = vec![0; 32];
        let k_header = [vec![0; 31], vec![1]].concat();
        let sequence_number = 0;
        let expected = hex::decode("4540f0529912e7bf57523c7f66022017cfefd3278ac13f40f8523faf")?;
        let actual = kex_encrypt(payload, k_main, k_header, sequence_number);
        assert_eq!(actual, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_receive_and_kex_decrypt() -> Result<()> {
        let enc = hex::decode("4540f0529912e7bf57523c7f66022017cfefd3278ac13f40f8523faf")?;
        let mock = Builder::new().read(&enc).build();
        let reader = Arc::new(Mutex::new(tokio::io::BufReader::new(mock)));
        let k_main = vec![0; 32];
        let k_header = [vec![0; 31], vec![1]].concat();
        let sequence_number = 0;
        let expected = vec![0x15];
        let actual = receive_and_kex_decrypt(&reader, k_main, k_header, sequence_number).await?;
        assert_eq!(actual, expected);
        Ok(())
    }
}
