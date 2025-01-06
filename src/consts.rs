//! RFC 4250 - The Secure Shell (SSH) Protocol Assigned Numbers
//! RFC 5656 - Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer
#![allow(dead_code)]
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum SshMsg {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServiceRequest = 5,
    ServiceAccept = 6,
    Kexinit = 20,
    Newkeys = 21,
    KexEcdhInit = 30,
    KexEcdhReply = 31,
    UserauthRequest = 50,
    UserauthFailure = 51,
    UserauthSuccess = 52,
    UserauthBanner = 53,
    UserauthPkOk = 60,
    GlobalRequest = 80,
    RequestSuccess = 81,
    RequestFailure = 82,
    ChannelOpen = 90,
    ChannelOpenConfirmation = 91,
    ChannelOpenFailure = 92,
    ChannelWindowAdjust = 93,
    ChannelData = 94,
    ChannelExtendedData = 95,
    ChannelEof = 96,
    ChannelClose = 97,
    ChannelRequest = 98,
    ChannelSuccess = 99,
    ChannelFailure = 100,
}

impl SshMsg {
    pub fn as_u8(&self) -> u8 {
        (*self).clone() as u8
    }
}

pub const KEX_ALGORITHMS: [&str; 1] = ["curve25519-sha256"];
pub const SERVER_HOST_KEY_ALGORITHMS: [&str; 1] = ["ssh-ed25519"];
pub const ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER: [&str; 1] = ["chacha20-poly1305@openssh.com"];
pub const ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT: [&str; 1] = ["chacha20-poly1305@openssh.com"];
pub const MAC_ALGORITHMS_CLIENT_TO_SERVER: [&str; 1] = [""];
pub const MAC_ALGORITHMS_SERVER_TO_CLIENT: [&str; 1] = [""];
pub const COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER: [&str; 1] = ["none"];
pub const COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT: [&str; 1] = ["none"];
pub const LANGUAGES_CLIENT_TO_SERVER: [&str; 1] = [""];
pub const LANGUAGES_SERVER_TO_CLIENT: [&str; 1] = [""];
