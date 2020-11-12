use super::act::Act;
use super::iterator::*;
use super::Batch;
use super::ReceiveBatch;
use super::RestoreHeader;
use crate::headers::EndOffset;
use crate::interface::Packet;
use crate::queues::*;
use crate::scheduler::{Executable, Scheduler};
use std::collections::HashMap;
use std::marker::PhantomData;

/// Group function.
// TODO:doc
pub type GroupFn<T, M> = Box<dyn FnMut(&Packet<T, M>) -> usize + Send>;

/// Group by.
///
/// Group By is used either to explicitly branch control flow within an NF or express branches in
/// how multiple NFs are chained together. The group by abstraction takes as input the number of
/// groups into which packets are split and a packet-based UDF which given a packet returns the ID
/// of the group to which it belongs. NetBricks also provides a set of predefined grouping
/// functions that group traffic using commonly-used criterion (e.g., TCP flow).
#[derive(Debug)]
pub struct GroupBy<T, V>
where
    T: EndOffset + 'static,
    V: Batch + BatchIterator<Header = T> + Act + 'static,
{
    _phantom_v: PhantomData<V>,
    groups: usize,
    _phantom_t: PhantomData<T>,
    consumers: HashMap<usize, ReceiveBatch<MpscConsumer>>,
    task: usize,
}

struct GroupByProducer<T, V>
where
    T: EndOffset + 'static,
    V: Batch + BatchIterator<Header = T> + Act + 'static,
{
    parent: V,
    producers: Vec<MpscProducer>,
    group_fn: GroupFn<T, V::Metadata>,
}

impl<T, V> Executable for GroupByProducer<T, V>
where
    T: EndOffset + 'static,
    V: Batch + BatchIterator<Header = T> + Act + 'static,
{
    #[inline]
    fn execute(&mut self) {
        self.parent.act(); // Let the parent get some packets.
        {
            let iter = PayloadEnumerator::<T, V::Metadata>::new(&mut self.parent);
            while let Some(ParsedDescriptor { mut packet, .. }) = iter.next(&mut self.parent) {
                let group = (self.group_fn)(&packet);
                packet.save_header_and_offset();
                self.producers[group].enqueue_one(packet);
            }
        }
        self.parent.get_packet_batch().clear_packets();
        self.parent.done();
    }

    #[inline]
    fn dependencies(&mut self) -> Vec<usize> {
        self.parent.get_task_dependencies()
    }
}

#[cfg_attr(feature = "dev", allow(len_without_is_empty))]
impl<T, V> GroupBy<T, V>
where
    T: EndOffset + 'static,
    V: Batch + BatchIterator<Header = T> + Act + 'static,
{
    /// Return a group by.
    // TODO:doc
    pub fn new<S: Scheduler + Sized>(
        parent: V,
        groups: usize,
        group_fn: GroupFn<T, V::Metadata>,
        sched: &mut S,
    ) -> GroupBy<T, V> {
        let mut producers = Vec::with_capacity(groups);
        let mut consumers = HashMap::with_capacity(groups);
        for i in 0..groups {
            let (prod, consumer) = new_mpsc_queue_pair();
            producers.push(prod);
            consumers.insert(i, consumer);
        }
        let task = sched
            .add_task(GroupByProducer {
                parent,
                group_fn,
                producers,
            })
            .unwrap();
        GroupBy {
            _phantom_v: PhantomData,
            groups,
            _phantom_t: PhantomData,
            consumers,
            task,
        }
    }

    /// Return the length of the group.
    // TODO:doc
    pub fn len(&self) -> usize {
        self.groups
    }

    /// Return a restore header if we can find it based on the group, o/w return None.
    // TODO:doc
    pub fn get_group(&mut self, group: usize) -> Option<RestoreHeader<T, V::Metadata, ReceiveBatch<MpscConsumer>>> {
        match self.consumers.remove(&group) {
            Some(mut p) => {
                p.get_packet_batch().add_parent_task(self.task);
                Some(RestoreHeader::new(p))
            }
            None => None,
        }
    }
}
