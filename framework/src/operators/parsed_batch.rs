use super::act::Act;
use super::iterator::*;
use super::packet_batch::PacketBatch;
use super::Batch;
use crate::common::*;
use crate::headers::EndOffset;
use crate::interface::*;
use std::marker::PhantomData;

/// Parsed Batch.
///
/// ParsedBatch Takes as input a header type and a packet structure (as described above). The
/// abstraction parses the payload using the header type and pushes the resulting header onto the
/// header stack and removes bytes representing the header from the payload.
#[derive(Debug)]
pub struct ParsedBatch<T, V>
where
    T: EndOffset<PreviousHeader = V::Header>,
    V: Batch + BatchIterator + Act,
{
    parent: V,
    phantom: PhantomData<T>,
}

impl<T, V> Act for ParsedBatch<T, V>
where
    T: EndOffset<PreviousHeader = V::Header>,
    V: Batch + BatchIterator + Act,
{
    act! {}
}

impl<T, V> Batch for ParsedBatch<T, V>
where
    V: Batch + BatchIterator + Act,
    T: EndOffset<PreviousHeader = V::Header>,
{
}

impl<T, V> ParsedBatch<T, V>
where
    V: Batch + BatchIterator + Act,
    T: EndOffset<PreviousHeader = V::Header>,
{
    /// Return a parse batch.
    // TODO:doc
    #[inline]
    pub fn new(parent: V) -> ParsedBatch<T, V> {
        ParsedBatch {
            parent,
            phantom: PhantomData,
        }
    }
}

impl<T, V> BatchIterator for ParsedBatch<T, V>
where
    V: Batch + BatchIterator + Act,
    T: EndOffset<PreviousHeader = V::Header>,
{
    type Header = T;
    type Metadata = V::Metadata;
    unsafe fn next_payload(&mut self, idx: usize) -> Option<PacketDescriptor<T, V::Metadata>> {
        self.parent.next_payload(idx).map(|p| PacketDescriptor {
            packet: p.packet.parse_header(),
        })
    }

    #[inline]
    fn start(&mut self) -> usize {
        self.parent.start()
    }
}
