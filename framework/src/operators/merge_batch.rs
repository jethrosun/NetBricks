use super::act::Act;
use super::iterator::{BatchIterator, PacketDescriptor};
use super::packet_batch::PacketBatch;
use super::Batch;
use crate::common::*;
use crate::interface::PacketTx;
use crate::scheduler::Executable;
use std::cmp;

/// Merge batch.
///
/// MergeBatch provides a node where separate processing branches can be merged together. All
/// packets entering a merge node exit as a single group.
#[derive(Debug)]
pub struct MergeBatch<T: Batch> {
    parents: Vec<T>,
    which: usize,
}

impl<T: Batch> MergeBatch<T> {
    /// Return a merge batch.
    // TODO:doc
    pub fn new(parents: Vec<T>) -> MergeBatch<T> {
        MergeBatch { parents, which: 0 }
    }
}

impl<T: Batch> Batch for MergeBatch<T> {}

impl<T: Batch> BatchIterator for MergeBatch<T> {
    type Header = T::Header;
    type Metadata = T::Metadata;

    #[inline]
    fn start(&mut self) -> usize {
        self.parents[self.which].start()
    }

    #[inline]
    unsafe fn next_payload(&mut self, idx: usize) -> Option<PacketDescriptor<T::Header, T::Metadata>> {
        self.parents[self.which].next_payload(idx)
    }
}

/// Internal interface for packets.
impl<T: Batch> Act for MergeBatch<T> {
    #[inline]
    fn act(&mut self) {
        self.parents[self.which].act()
    }

    #[inline]
    fn done(&mut self) {
        self.parents[self.which].done();
        let next = self.which + 1;
        if next == self.parents.len() {
            self.which = 0
        } else {
            self.which = next
        }
    }

    #[inline]
    fn send_q(&mut self, port: &dyn PacketTx) -> Result<u32> {
        self.parents[self.which].send_q(port)
    }

    #[inline]
    fn capacity(&self) -> i32 {
        self.parents.iter().fold(0, |acc, x| cmp::max(acc, x.capacity()))
    }

    #[inline]
    fn drop_packets(&mut self, idxes: &[usize]) -> Option<usize> {
        self.parents[self.which].drop_packets(idxes)
    }

    #[inline]
    fn clear_packets(&mut self) {
        self.parents[self.which].clear_packets()
    }

    #[inline]
    fn get_packet_batch(&mut self) -> &mut PacketBatch {
        self.parents[self.which].get_packet_batch()
    }

    #[inline]
    fn get_task_dependencies(&self) -> Vec<usize> {
        let mut deps = Vec::with_capacity(self.parents.len()); // Might actually need to be larger, will get resized
        for parent in &self.parents {
            deps.extend(parent.get_task_dependencies().iter())
        }
        // We need to eliminate duplicate tasks. Fortunately this is not called on the critical path so it is fine to do
        // it this way.
        deps.sort();
        deps.dedup();
        deps
    }
}

impl<T: Batch> Executable for MergeBatch<T> {
    #[inline]
    fn execute(&mut self) {
        self.act();
        self.done();
    }

    #[inline]
    fn dependencies(&mut self) -> Vec<usize> {
        self.get_task_dependencies()
    }
}
