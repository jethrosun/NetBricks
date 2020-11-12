use super::act::Act;
use super::iterator::*;
use super::packet_batch::PacketBatch;
use super::Batch;
use crate::common::*;
use crate::headers::NullHeader;
use crate::interface::PacketTx;

/// Reset parsing batch.
#[derive(Debug)]
pub struct ResetParsingBatch<V>
where
    V: Batch + BatchIterator + Act,
{
    parent: V,
}

impl<V> ResetParsingBatch<V>
where
    V: Batch + BatchIterator + Act,
{
    /// Return a reset parsing batch.
    // TODO:doc
    pub fn new(parent: V) -> ResetParsingBatch<V> {
        ResetParsingBatch { parent }
    }
}

impl<V> BatchIterator for ResetParsingBatch<V>
where
    V: Batch + BatchIterator + Act,
{
    type Header = NullHeader;
    type Metadata = EmptyMetadata;
    #[inline]
    fn start(&mut self) -> usize {
        self.parent.start()
    }

    #[inline]
    unsafe fn next_payload(&mut self, idx: usize) -> Option<PacketDescriptor<NullHeader, EmptyMetadata>> {
        match self.parent.next_payload(idx) {
            Some(PacketDescriptor { packet }) => Some(PacketDescriptor { packet: packet.reset() }),
            None => None,
        }
    }
}

/// Internal interface for packets.
impl<V> Act for ResetParsingBatch<V>
where
    V: Batch + BatchIterator + Act,
{
    act! {}
}

impl<V> Batch for ResetParsingBatch<V> where V: Batch + BatchIterator + Act {}
