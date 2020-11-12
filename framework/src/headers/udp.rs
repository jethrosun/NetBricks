use super::EndOffset;
use crate::headers::IpHeader;
use std::default::Default;
use std::fmt;

/// UDP header using SSE
#[derive(Default)]
#[repr(C, packed)]
pub struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    len: u16,
    csum: u16,
}

impl fmt::Display for UdpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src_port: {} dst_port: {} len: {} checksum: {}",
            self.src_port(),
            self.dst_port(),
            self.length(),
            self.checksum()
        )
    }
}

impl EndOffset for UdpHeader {
    type PreviousHeader = IpHeader;
    #[inline]
    fn offset(&self) -> usize {
        8 // 8 bytes
    }

    #[inline]
    fn size() -> usize {
        8
    }

    #[inline]
    fn payload_size(&self, _: usize) -> usize {
        self.length() as usize - self.offset()
    }

    #[inline]
    fn check_correct(&self, _prev: &IpHeader) -> bool {
        true
    }
}

impl UdpHeader {
    /// Initialize a default UDP header.
    #[inline]
    pub fn new() -> UdpHeader {
        Default::default()
    }

    /// Initialize the src port.
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.src_port)
    }

    /// Initialize the dst port.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dst_port)
    }

    /// Set the src port.
    #[inline]
    pub fn set_src_port(&mut self, port: u16) {
        self.src_port = u16::to_be(port);
    }

    /// Set the dst port.
    #[inline]
    pub fn set_dst_port(&mut self, port: u16) {
        self.dst_port = u16::to_be(port);
    }

    /// Length of the UDP header.
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be(self.len)
    }

    /// Set length of the UDP header.
    #[inline]
    pub fn set_length(&mut self, len: u16) {
        self.len = u16::to_be(len)
    }

    /// Get the checksum of the UDP header.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.csum)
    }

    /// Set the checksum of the UDP header.
    #[inline]
    pub fn set_checksum(&mut self, csum: u16) {
        self.csum = u16::to_be(csum);
    }
}
