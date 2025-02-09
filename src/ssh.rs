//! RFC 4250 - The Secure Shell (SSH) Protocol Assigned Numbers
//! RFC 4251 - The Secure Shell (SSH) Protocol Architecture
//! RFC 4252 - The Secure Shell (SSH) Authentication Protocol
//! RFC 4253 - The Secure Shell (SSH) Transport Layer Protocol
//! RFC 4254 - The Secure Shell (SSH) Connection Protocol
use anyhow::Result;
use rand::prelude::*;
use sha2::Digest;
use std::io::Write;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;

use crate::consts::*;
use crate::ed25519::ed25519_verify;
use crate::kex::{kex_encrypt, receive_and_kex_decrypt};
use crate::sshkey::Privkey;
use crate::utils::{add_length, remove_length};
use crate::x25519::{x25519, GX};

pub struct SshClient<T> {
    reader: Arc<Mutex<tokio::io::BufReader<T>>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    rng: ThreadRng,
    login_name: String,
    privkey: Privkey,
}

fn pad(bytes: Vec<u8>) -> Vec<u8> {
    let mut padlen = 8 - (4 + 1 + bytes.len()) % 8;
    if padlen < 4 {
        padlen += 8;
    }
    [vec![padlen as u8], bytes, vec![0; padlen]].concat()
}

fn packet_to_algorithms(bytes: &mut Vec<u8>) -> Result<Vec<String>> {
    let algorithm_length = u32::from_be_bytes(bytes[..4].try_into()?);
    let algorithm_string =
        String::from_utf8(bytes[4..4usize + algorithm_length as usize].to_vec())?;
    *bytes = bytes[4usize + algorithm_length as usize..].to_vec();
    Ok(algorithm_string.split(",").map(|s| s.to_string()).collect())
}

async fn protocol_version_exchange<T>(
    reader: Arc<Mutex<tokio::io::BufReader<T>>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
) -> Result<(String, String)>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let client_id_string = "SSH-2.0-ssh_rust_0.1".to_string();
    writer
        .try_lock()?
        .write_all((client_id_string.clone() + "\r\n").as_bytes())
        .await?;
    let mut server_id_string_buf = vec![];
    let _ = reader
        .try_lock()?
        .read_until(b'\n', &mut server_id_string_buf)
        .await?;
    let tmp = &server_id_string_buf.clone()
        [(server_id_string_buf.len() as i32 - 2) as usize..server_id_string_buf.len()];
    assert_eq!(tmp, [13, 10], "must end with \r\n");
    let server_id_string = String::from_utf8(
        server_id_string_buf[..(server_id_string_buf.len() as i32 - 2) as usize].to_vec(),
    )?;
    Ok((client_id_string, server_id_string))
}

#[derive(Clone)]
struct AlgorithmNegotiationResult {
    client_key_exchange: Vec<u8>,
    server_key_exchange: Vec<u8>,
}

async fn algorithm_negotiation<T>(
    reader: Arc<Mutex<tokio::io::BufReader<T>>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    rng: &mut ThreadRng,
) -> Result<AlgorithmNegotiationResult>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let mut client_cookie = [0u8; 16];
    rng.fill_bytes(&mut client_cookie);
    let tmp = [
        KEX_ALGORITHMS,
        SERVER_HOST_KEY_ALGORITHMS,
        ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER,
        ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT,
        MAC_ALGORITHMS_CLIENT_TO_SERVER,
        MAC_ALGORITHMS_SERVER_TO_CLIENT,
        COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER,
        COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT,
        LANGUAGES_CLIENT_TO_SERVER,
        LANGUAGES_SERVER_TO_CLIENT,
    ]
    .map(|list| add_length(list.join(",").as_bytes().to_vec()))
    .concat();
    let client_key_exchange = [
        vec![SshMsg::Kexinit.as_u8()],
        client_cookie.to_vec(),
        tmp,
        vec![0, 0, 0, 0, 0],
    ]
    .concat();
    let key_exchange_init = add_length(pad(client_key_exchange.clone()));
    writer.try_lock()?.write_all(&key_exchange_init).await?;
    let packet_length = reader.try_lock()?.read_u32().await?;
    let mut packet = vec![0; packet_length as usize];
    reader.try_lock()?.read_exact(&mut packet).await?;
    let padlen;
    (padlen, packet) = (packet[0], packet[1..].to_vec());
    packet = packet[..(packet.len() as i32 - padlen as i32) as usize].to_vec();
    let server_key_exchange = packet.clone();
    assert_eq!(
        server_key_exchange[0],
        SshMsg::Kexinit.as_u8(),
        "Not Key Exchange Init"
    );
    let _server_cookie;
    (_server_cookie, packet) = (packet[1..17].to_vec(), packet[17..].to_vec());
    let _server_kex_algorithms = packet_to_algorithms(&mut packet)?;
    let _server_server_host_key_algorithms = packet_to_algorithms(&mut packet)?;
    let _server_encryption_algorithms_client_to_server = packet_to_algorithms(&mut packet)?;
    let _server_encryption_algorithms_server_to_client = packet_to_algorithms(&mut packet)?;
    let _server_mac_algorithms_client_to_server = packet_to_algorithms(&mut packet)?;
    let _server_mac_algorithms_server_to_client = packet_to_algorithms(&mut packet)?;
    let _server_compression_algorithms_client_to_server = packet_to_algorithms(&mut packet)?;
    let _server_compression_algorithms_server_to_client = packet_to_algorithms(&mut packet)?;
    let _server_languages_client_to_server = packet_to_algorithms(&mut packet)?;
    let _server_languages_server_to_client = packet_to_algorithms(&mut packet)?;
    assert_eq!(packet[0], 0, "First KEX Packet Follows must be 0");
    assert_eq!(packet[1..], [0, 0, 0, 0], "Reserved must be 0");
    Ok(AlgorithmNegotiationResult {
        client_key_exchange,
        server_key_exchange,
    })
}

#[derive(Clone)]
struct KeyExchangeResult {
    k_s: Vec<u8>,
    host_key_pub: Vec<u8>,
    client_pub: Vec<u8>,
    server_pub: Vec<u8>,
    shared_key: Vec<u8>,
    h_signature: Vec<u8>,
}

async fn key_exchange<T>(
    reader: Arc<Mutex<tokio::io::BufReader<T>>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    rng: &mut ThreadRng,
) -> Result<KeyExchangeResult>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let mut client_priv = [0u8; 32];
    rng.fill_bytes(&mut client_priv);
    let client_priv = client_priv.to_vec();
    let client_pub = x25519(client_priv.clone(), (*GX).clone());
    let key_exchange = add_length(pad([
        vec![SshMsg::KexEcdhInit.as_u8()],
        add_length(client_pub.clone()),
    ]
    .concat()));
    let _ = writer.try_lock()?.write(&key_exchange).await?;
    let packet_length = reader.try_lock()?.read_u32().await?;
    let mut packet = vec![0; packet_length as usize];
    reader.try_lock()?.read_exact(&mut packet).await?;
    let padlen;
    (padlen, packet) = (packet[0], packet[1..].to_vec());
    packet = packet[..(packet.len() as i32 - padlen as i32) as usize].to_vec();
    assert_eq!(packet[0], SshMsg::KexEcdhReply.as_u8());
    packet = packet[1..].to_vec();
    let mut kex_host_key = remove_length(&mut packet)?;
    let k_s = kex_host_key.clone();
    let _key_type = remove_length(&mut kex_host_key)?;
    let host_key_pub = remove_length(&mut kex_host_key)?;
    assert_eq!(kex_host_key.len(), 0);
    let server_pub = remove_length(&mut packet)?;
    let mut h_signature = remove_length(&mut packet)?;
    assert_eq!(packet.len(), 0);
    let _signature_type = remove_length(&mut h_signature)?;
    let _h_signature = remove_length(&mut h_signature)?;
    assert_eq!(h_signature.len(), 0);
    let h_signature = _h_signature;
    let packet_length = reader.try_lock()?.read_u32().await?;
    let mut packet = vec![0; packet_length as usize];
    reader.try_lock()?.read_exact(&mut packet).await?;
    let padlen;
    (padlen, packet) = (packet[0], packet[1..].to_vec());
    packet = packet[..(packet.len() as i32 - padlen as i32) as usize].to_vec();
    assert_eq!(packet, vec![SshMsg::Newkeys.as_u8()]); // New Keys
    let mut shared_key = x25519(client_priv.to_vec(), server_pub.clone());
    if shared_key[0] & 0x80 == 0x80 {
        shared_key = [vec![0], shared_key].concat();
    }

    Ok(KeyExchangeResult {
        k_s,
        host_key_pub,
        client_pub,
        server_pub,
        shared_key,
        h_signature,
    })
}

fn calc_exchange_hash(
    client_id_string: String,
    server_id_string: String,
    algorithm_negotiation_result: AlgorithmNegotiationResult,
    key_exchange_result: KeyExchangeResult,
) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(add_length(client_id_string.into()));
    hasher.update(add_length(server_id_string.into()));
    hasher.update(add_length(algorithm_negotiation_result.client_key_exchange));
    hasher.update(add_length(algorithm_negotiation_result.server_key_exchange));
    hasher.update(add_length(key_exchange_result.k_s));
    hasher.update(add_length(key_exchange_result.client_pub));
    hasher.update(add_length(key_exchange_result.server_pub));
    hasher.update(add_length(key_exchange_result.shared_key.clone()));
    let h = hasher.finalize().to_vec();
    h
}

#[derive(Clone)]
struct EncryptionKeys {
    c_to_s_k_main: Vec<u8>,
    c_to_s_k_header: Vec<u8>,
    s_to_c_k_main: Vec<u8>,
    s_to_c_k_header: Vec<u8>,
}

fn calc_encryption_keys(key_exchange_result: KeyExchangeResult, h: Vec<u8>) -> EncryptionKeys {
    // RFC 4253
    let session_id = h.clone();
    let mut hasher = sha2::Sha256::new();
    hasher.update(add_length(key_exchange_result.shared_key.clone()));
    hasher.update(h.clone());
    hasher.update(b"C");
    hasher.update(session_id.clone());
    let c_to_s_k_main = hasher.finalize().to_vec();

    let mut hasher = sha2::Sha256::new();
    hasher.update(add_length(key_exchange_result.shared_key.clone()));
    hasher.update(h.clone());
    hasher.update(c_to_s_k_main.clone());
    let c_to_s_k_header = hasher.finalize().to_vec();

    let session_id = h.clone();
    let mut hasher = sha2::Sha256::new();
    hasher.update(add_length(key_exchange_result.shared_key.clone()));
    hasher.update(h.clone());
    hasher.update(b"D");
    hasher.update(session_id.clone());
    let s_to_c_k_main = hasher.finalize().to_vec();

    let mut hasher = sha2::Sha256::new();
    hasher.update(add_length(key_exchange_result.shared_key.clone()));
    hasher.update(h.clone());
    hasher.update(s_to_c_k_main.clone());
    let s_to_c_k_header = hasher.finalize().to_vec();

    EncryptionKeys {
        c_to_s_k_main,
        c_to_s_k_header,
        s_to_c_k_main,
        s_to_c_k_header,
    }
}

async fn service_request<T>(
    reader: Arc<Mutex<tokio::io::BufReader<T>>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    encryption_keys: EncryptionKeys,
) -> Result<()>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let packet = [
        vec![SshMsg::ServiceRequest.as_u8()],
        add_length(b"ssh-userauth".to_vec()),
    ]
    .concat();
    let packet = kex_encrypt(
        packet,
        encryption_keys.c_to_s_k_main.clone(),
        encryption_keys.c_to_s_k_header.clone(),
        3,
    );
    writer.try_lock()?.write_all(&packet).await?;

    let mut packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        3,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::ServiceAccept.as_u8()); // Service Accept
    packet = packet[1..].to_vec();
    let service_name = remove_length(&mut packet)?;
    assert_eq!(service_name, b"ssh-userauth");
    Ok(())
}

async fn user_auth<T>(
    reader: Arc<Mutex<tokio::io::BufReader<T>>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    encryption_keys: EncryptionKeys,
    h: Vec<u8>,
    login_name: String,
    privkey: Privkey,
) -> Result<()>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let service_name = b"ssh-connection";
    let method = b"none";
    let packet = [
        vec![SshMsg::UserauthRequest.as_u8()],
        add_length(login_name.clone().into_bytes()),
        add_length(service_name.to_vec()),
        add_length(method.to_vec()),
    ]
    .concat(); // User Authentication Request
    let packet = kex_encrypt(
        packet,
        encryption_keys.c_to_s_k_main.clone(),
        encryption_keys.c_to_s_k_header.clone(),
        4,
    );
    writer.try_lock()?.write_all(&packet).await?;

    let mut packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        4,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::UserauthFailure.as_u8()); // User Authentication Failure
    packet = packet[1..].to_vec();
    let auth_list = remove_length(&mut packet)?;
    let auth_list = String::from_utf8(auth_list)?;
    assert!(auth_list.contains("publickey"));
    assert_eq!(packet, vec![0]); // Partial Success: False

    let service_name = b"ssh-connection";
    let method = b"publickey";
    let have_signature = b"\x00"; // False
    let public_key_algorithm = b"ssh-ed25519";
    let pub_bytes = privkey.pubkey.to_bytes();
    let packet = [
        vec![SshMsg::UserauthRequest.as_u8()],
        add_length(login_name.clone().into_bytes()),
        add_length(service_name.to_vec()),
        add_length(method.to_vec()),
        have_signature.to_vec(),
        add_length(public_key_algorithm.to_vec()),
        add_length(pub_bytes.clone()),
    ]
    .concat(); // User Authentication Request
    let packet = kex_encrypt(
        packet,
        encryption_keys.c_to_s_k_main.clone(),
        encryption_keys.c_to_s_k_header.clone(),
        5,
    );
    writer.try_lock()?.write_all(&packet).await?;

    let mut packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        5,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::UserauthPkOk.as_u8());
    packet = packet[1..].to_vec();
    let public_key_algorithm_name = remove_length(&mut packet)?;
    let public_key_algorithm_name = String::from_utf8(public_key_algorithm_name)?;
    assert_eq!(
        public_key_algorithm_name,
        String::from_utf8(public_key_algorithm.to_vec())?
    );
    let public_key_blob = remove_length(&mut packet)?;
    assert_eq!(public_key_blob, pub_bytes);
    assert_eq!(packet, vec![]);

    let service_name = b"ssh-connection";
    let method = b"publickey";
    let have_signature = b"\x01"; // True
    let public_key_algorithm = b"ssh-ed25519";
    let pub_bytes = privkey.pubkey.to_bytes();
    let packet = [
        vec![SshMsg::UserauthRequest.as_u8()],
        add_length(login_name.clone().into_bytes()),
        add_length(service_name.to_vec()),
        add_length(method.to_vec()),
        have_signature.to_vec(),
        add_length(public_key_algorithm.to_vec()),
        add_length(pub_bytes.clone()),
    ]
    .concat(); // User Authentication Request
    let sig = privkey.sign([add_length(h.clone()), packet.clone()].concat());
    let sig_bytes = [add_length(public_key_algorithm.to_vec()), add_length(sig)].concat();
    let packet = [packet, add_length(sig_bytes)].concat();
    let packet = kex_encrypt(
        packet,
        encryption_keys.c_to_s_k_main.clone(),
        encryption_keys.c_to_s_k_header.clone(),
        6,
    );
    writer.try_lock()?.write_all(&packet).await?;

    let mut packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        6,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::UserauthSuccess.as_u8());
    packet = packet[1..].to_vec();
    assert_eq!(packet, vec![]);
    Ok(())
}

async fn channel_request<T>(
    reader: Arc<Mutex<tokio::io::BufReader<T>>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    encryption_keys: EncryptionKeys,
) -> Result<()>
where
    T: tokio::io::AsyncRead + Unpin,
{
    // Channel Open, Global Request
    let packet = [
        vec![SshMsg::ChannelOpen.as_u8()],
        add_length(b"session".to_vec()), // Channel type
        b"\x00\x00\x00\x00".to_vec(),    // Sender channel
        b"\x00\x10\x00\x00".to_vec(),    // Initial window size
        b"\x00\x00\x40\x00".to_vec(),    // Maximum packet size
    ]
    .concat();
    let packet = kex_encrypt(
        packet,
        encryption_keys.c_to_s_k_main.clone(),
        encryption_keys.c_to_s_k_header.clone(),
        7,
    );
    writer.try_lock()?.write_all(&packet).await?;

    let packet = [
        vec![SshMsg::GlobalRequest.as_u8()],
        add_length(b"no-more-sessions@openssh.com".to_vec()), // Global request name
        b"\x00".to_vec(),                                     // Global request want reply
    ]
    .concat();
    let packet = kex_encrypt(
        packet,
        encryption_keys.c_to_s_k_main.clone(),
        encryption_keys.c_to_s_k_header.clone(),
        8,
    );
    writer.try_lock()?.write_all(&packet).await?;

    let packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        7,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::GlobalRequest.as_u8());

    let packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        8,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::Debug.as_u8());

    let packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        9,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::Debug.as_u8());

    let packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        10,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::ChannelOpenConfirmation.as_u8());

    let packet = [
        vec![SshMsg::ChannelRequest.as_u8()],
        b"\x00\x00\x00\x00".to_vec(), // Recipient channel
        add_length(b"auth-agent-req@openssh.com".to_vec()), // Channel request name
        b"\x00".to_vec(),             // Channel request want reply
    ]
    .concat();
    let packet = kex_encrypt(
        packet,
        encryption_keys.c_to_s_k_main.clone(),
        encryption_keys.c_to_s_k_header.clone(),
        9,
    );
    writer.try_lock()?.write_all(&packet).await?;

    let packet = [
        vec![SshMsg::ChannelRequest.as_u8()],     // Global Request (98)
        b"\x00\x00\x00\x00".to_vec(),             // Recipient channel
        add_length(b"pty-req".to_vec()).to_vec(), // Channel request name
        b"\x01".to_vec(),                         // Channel request want reply
        add_length(b"xterm-256color".to_vec()),   // $TERM
        b"\x00\x00\x01\x1c".to_vec(),             // terminal width, characters
        b"\x00\x00\x00U".to_vec(),                // terminal height, rows
        b"\x00\x00\t\xfc".to_vec(),               // terminal width, pixels
        b"\x00\x00\x05\xfa".to_vec(),             // terminal height, pixels
        add_length(
            [
                b"\x81\x00\x00\x96\x00".to_vec(), // TTY_OP_OSPEED: 38400
                b"\x80\x00\x00\x96\x00".to_vec(), // TTY_OP_ISPEED
                b"\x01\x00\x00\x00\x03".to_vec(), // VINTR
                b"\x02\x00\x00\x00\x1c".to_vec(), // VQUIT
                b"\x03\x00\x00\x00\x7f".to_vec(), // VERASE
                b"\x04\x00\x00\x00\x15".to_vec(), // VKILL
                b"\x05\x00\x00\x00\x04".to_vec(), // VEOF
                b"\x06\x00\x00\x00\xff".to_vec(), // VEOL
                b"\x07\x00\x00\x00\xff".to_vec(), // VEOL2
                b"\x08\x00\x00\x00\x11".to_vec(), // VSTART
                b"\t\x00\x00\x00\x13".to_vec(),   // VSTOP
                b"\n\x00\x00\x00\x1a".to_vec(),   // VSUSP
                b"\x0c\x00\x00\x00\x12".to_vec(), // VREPRINT
                b"\r\x00\x00\x00\x17".to_vec(),   // VWERASE
                b"\x0e\x00\x00\x00\x16".to_vec(), // VLNEXT
                b"\x12\x00\x00\x00\x0f".to_vec(), // VDISCARD
                b"\x1e\x00\x00\x00\x00".to_vec(), // IGNPAR
                b"\x1f\x00\x00\x00\x00".to_vec(), // PARMRK
                b" \x00\x00\x00\x00".to_vec(),    // INPCK
                b"!\x00\x00\x00\x00".to_vec(),    // ISTRIP
                b"\"\x00\x00\x00\x00".to_vec(),   // INLCR
                b"#\x00\x00\x00\x00".to_vec(),    // IGNCR
                b"$\x00\x00\x00\x01".to_vec(),    // ICRNL
                b"%\x00\x00\x00\x00".to_vec(),    // IUCLC
                b"&\x00\x00\x00\x00".to_vec(),    // IXON
                b"'\x00\x00\x00\x00".to_vec(),    // IXANY
                b"(\x00\x00\x00\x00".to_vec(),    // IXOFF
                b")\x00\x00\x00\x00".to_vec(),    // IMAXBEL
                b"*\x00\x00\x00\x01".to_vec(),    // ?
                b"2\x00\x00\x00\x01".to_vec(),    // ISIG
                b"3\x00\x00\x00\x01".to_vec(),    // ICANON
                b"4\x00\x00\x00\x00".to_vec(),    // XCASE
                b"5\x00\x00\x00\x01".to_vec(),    // ECHO
                b"6\x00\x00\x00\x01".to_vec(),    // ECHOE
                b"7\x00\x00\x00\x01".to_vec(),    // ECHOK
                b"8\x00\x00\x00\x00".to_vec(),    // ECHONL
                b"9\x00\x00\x00\x00".to_vec(),    // NOFLSH
                b":\x00\x00\x00\x00".to_vec(),    // TOSTOP
                b";\x00\x00\x00\x01".to_vec(),    // IEXTEN
                b"<\x00\x00\x00\x01".to_vec(),    // ECHOCTL
                b"=\x00\x00\x00\x01".to_vec(),    // ECHOKE
                b">\x00\x00\x00\x00".to_vec(),    // PENDIN
                b"F\x00\x00\x00\x01".to_vec(),    // OPOST
                b"G\x00\x00\x00\x00".to_vec(),    // OLCUC
                b"H\x00\x00\x00\x01".to_vec(),    // ONLCR
                b"I\x00\x00\x00\x00".to_vec(),    // OCRNL
                b"J\x00\x00\x00\x00".to_vec(),    // ONOCR
                b"K\x00\x00\x00\x00".to_vec(),    // ONLRET
                b"Z\x00\x00\x00\x01".to_vec(),    // CS7
                b"[\x00\x00\x00\x01".to_vec(),    // CS8
                b"\\\x00\x00\x00\x00".to_vec(),   // PARENB
                b"]\x00\x00\x00\x00".to_vec(),    // PARODD
                b"\x00".to_vec(),
            ]
            .concat(),
        ),
    ]
    .concat();
    let packet = kex_encrypt(
        packet,
        encryption_keys.c_to_s_k_main.clone(),
        encryption_keys.c_to_s_k_header.clone(),
        10,
    );
    writer.try_lock()?.write_all(&packet).await?;

    let packet = [
        vec![SshMsg::ChannelRequest.as_u8()],
        b"\x00\x00\x00\x00".to_vec(),  // Recipient channel
        add_length(b"shell".to_vec()), // Channel request name
        b"\x01".to_vec(),              // Channel request want reply
    ]
    .concat();
    let packet = kex_encrypt(
        packet,
        encryption_keys.c_to_s_k_main.clone(),
        encryption_keys.c_to_s_k_header.clone(),
        11,
    );
    writer.try_lock()?.write_all(&packet).await?;

    let packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        11,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::ChannelSuccess.as_u8());

    let packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        12,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::ChannelWindowAdjust.as_u8());

    let packet = receive_and_kex_decrypt(
        &reader,
        encryption_keys.s_to_c_k_main.clone(),
        encryption_keys.s_to_c_k_header.clone(),
        13,
    )
    .await?;
    assert_eq!(packet[0], SshMsg::ChannelSuccess.as_u8());
    Ok(())
}

impl<T> SshClient<T>
where
    T: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    pub fn new(
        reader: tokio::io::BufReader<T>,
        writer: OwnedWriteHalf,
        login_name: String,
        privkey: Privkey,
    ) -> Self {
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            rng: thread_rng(),
            login_name,
            privkey,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        let (client_id_string, server_id_string) =
            protocol_version_exchange(Arc::clone(&self.reader), Arc::clone(&self.writer)).await?;
        let algorithm_negotiation_result = algorithm_negotiation(
            Arc::clone(&self.reader),
            Arc::clone(&self.writer),
            &mut self.rng,
        )
        .await?;
        let key_exchange_result = key_exchange(
            Arc::clone(&self.reader),
            Arc::clone(&self.writer),
            &mut self.rng,
        )
        .await?;
        let h = calc_exchange_hash(
            client_id_string.clone(),
            server_id_string.clone(),
            algorithm_negotiation_result.clone(),
            key_exchange_result.clone(),
        );

        let valid = ed25519_verify(
            key_exchange_result.h_signature.clone(),
            h.clone(),
            key_exchange_result.host_key_pub.clone(),
        );
        assert!(valid);

        let encryption_keys = calc_encryption_keys(key_exchange_result.clone(), h.clone());

        let packet = add_length(pad(vec![SshMsg::Newkeys.as_u8()]));
        self.writer.try_lock()?.write_all(&packet).await?;

        service_request(
            Arc::clone(&self.reader),
            Arc::clone(&self.writer),
            encryption_keys.clone(),
        )
        .await?;
        user_auth(
            Arc::clone(&self.reader),
            Arc::clone(&self.writer),
            encryption_keys.clone(),
            h.clone(),
            self.login_name.clone(),
            self.privkey.clone(),
        )
        .await?;
        channel_request(
            Arc::clone(&self.reader),
            Arc::clone(&self.writer),
            encryption_keys.clone(),
        )
        .await?;

        let reader = Arc::clone(&self.reader);
        let server_to_client: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
            let mut server_seq_num = 14;
            let mut stdout = std::io::stdout();
            loop {
                let mut packet = receive_and_kex_decrypt(
                    &reader,
                    encryption_keys.s_to_c_k_main.clone(),
                    encryption_keys.s_to_c_k_header.clone(),
                    server_seq_num,
                )
                .await?;
                assert_eq!(packet[0], SshMsg::ChannelData.as_u8());
                assert_eq!(packet[1..5], [0; 4]);
                packet = packet[5..].to_vec();
                packet = remove_length(&mut packet)?;
                stdout.write_all(&packet)?;
                stdout.flush()?;
                server_seq_num += 1;
            }
        });

        let writer = Arc::clone(&self.writer);
        let client_to_server: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
            let mut client_seq_num = 12;
            let mut cmd = vec![0; 1024];
            let stdin = tokio::io::stdin();
            let mut reader = tokio::io::BufReader::new(stdin);
            loop {
                let n = reader.read(&mut cmd).await?;
                let mut packet = cmd[..n].to_vec();
                packet = add_length(packet);
                packet = [[SshMsg::ChannelData.as_u8(), 0, 0, 0, 0].to_vec(), packet].concat();
                let packet = kex_encrypt(
                    packet,
                    encryption_keys.c_to_s_k_main.clone(),
                    encryption_keys.c_to_s_k_header.clone(),
                    client_seq_num,
                );
                writer.try_lock()?.write_all(&packet).await?;
                client_seq_num += 1;
            }
        });

        tokio::select! {
            res1 = server_to_client => {
                println!("server_to_client finished: {:?}", res1);
            }
            res2 = client_to_server => {
                println!("client_to_server finished: {:?}", res2);
            }
        }

        Ok(())
    }
}
