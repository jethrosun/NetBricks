//! Interface utils.
pub use self::packet::*;
pub use self::port::*;
pub mod dpdk;
mod packet;
mod port;

use crate::common::*;
use crate::native::zcsi::MBuf;

/// Generic trait for objects that can receive packets.
pub trait PacketRx: Send {
    /// Receive.
    fn recv(&self, pkts: &mut [*mut MBuf]) -> Result<u32>;
}

/// Generic trait for objects that can send packets.
pub trait PacketTx: Send {
    /// Send.
    fn send(&self, pkts: &mut [*mut MBuf]) -> Result<u32>;
}

/// Generic trait for objects that can send and receive packets.
pub trait PacketRxTx: PacketRx + PacketTx {}
