use super::iterator::{BatchIterator, PacketBatchAddressIterator};
use super::act::Act;
use super::Batch;
use super::HeaderOperations;
use super::super::pmd::*;
use super::packet_batch::cast_from_u8;
use super::super::interface::EndOffset;
use std::ptr;
use super::super::interface::Result;

pub struct ReplaceBatch<T, V>
    where T: EndOffset,
          V: Batch + BatchIterator + Act
{
    parent: V,
    template: T,
}

batch!{ReplaceBatch, [parent: V, template: T]}

impl<T, V> Act for ReplaceBatch<T, V>
    where T: EndOffset,
          V: Batch + BatchIterator + Act
{
    fn act(&mut self) -> &mut Self {
        self.parent.act();
        // This inner context is to allow the iter reference to expire before we change self.
        {
            let iter = PacketBatchAddressIterator::new(&mut self.parent);
            for addr in iter {
                unsafe {
                    let address = cast_from_u8::<T>(addr);
                    ptr::copy_nonoverlapping(&self.template, address, 1);
                }
            }
        }
        self
    }

    fn done(&mut self) -> &mut Self {
        self.parent.done();
        self
    }

    fn send_queue(&mut self, port: &mut PmdPort, queue: i32) -> Result<u32> {
        self.parent.send_queue(port, queue)
    }

    fn capacity(&self) -> i32 {
        self.parent.capacity()
    }
}

impl<T, V> BatchIterator for ReplaceBatch<T, V>
    where T: EndOffset,
          V: Batch + BatchIterator + Act
{
    // FIXME: We should just go from packet batch applying, instead of doing this version where act() is triggered as a
    // result of some functions being called.
    #[inline]
    fn start(&mut self) -> usize {
        self.parent.start()
    }

    #[inline]
    unsafe fn payload(&mut self, idx: usize) -> *mut u8 {
        self.parent.payload(idx)
    }

    #[inline]
    unsafe fn address(&mut self, idx: usize) -> *mut u8 {
        self.parent.address(idx)
    }

    #[inline]
    unsafe fn next_address(&mut self, idx: usize) -> Option<(*mut u8, usize)> {
        self.parent.next_address(idx)
    }

    #[inline]
    unsafe fn next_payload(&mut self, idx: usize) -> Option<(*mut u8, usize)> {
        self.parent.next_payload(idx)
    }

    #[inline]
    unsafe fn base_address(&mut self, idx: usize) -> *mut u8 {
        self.parent.base_address(idx)
    }

    #[inline]
    unsafe fn base_payload(&mut self, idx: usize) -> *mut u8 {
        self.parent.base_payload(idx)
    }

    #[inline]
    unsafe fn next_base_address(&mut self, idx: usize) -> Option<(*mut u8, usize)> {
        self.parent.next_base_address(idx)
    }

    #[inline]
    unsafe fn next_base_payload(&mut self, idx: usize) -> Option<(*mut u8, usize)> {
        self.parent.next_base_payload(idx)
    }
}