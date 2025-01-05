//! RFC 4250 - The Secure Shell (SSH) Protocol Assigned Numbers
//! RFC 5656 - Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer
#![allow(dead_code)]
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
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
