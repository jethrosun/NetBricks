use super::{open_shared, SharedMemory};
use crate::utils::round_to_pages;
use std::borrow::Borrow;
use std::hash::{Hash, Hasher};
use std::ops::{Index, IndexMut, Range, RangeFrom, RangeTo};

/// Shared Vector.
#[allow(dead_code)] // FIXME: While WIP
#[derive(Debug)]
pub struct SharedVec<T: Sized + 'static> {
    vec: Vec<T>,
    shared: SharedMemory<T>,
    modified: bool,
}

impl<T: Sized + 'static> SharedVec<T> {
    /// Initialize the ShareVec with given capacity.
    pub fn new_with_capacity(name: &str, capacity: usize) -> SharedVec<T> {
        let capacity_pages = round_to_pages(capacity);
        unsafe {
            SharedVec {
                vec: Vec::with_capacity(capacity),
                shared: open_shared(name, capacity_pages),
                modified: false,
            }
        }
    }
}

impl<T: Sized + 'static> Borrow<[T]> for SharedVec<T> {
    fn borrow(&self) -> &[T] {
        self.vec.borrow()
    }
}

impl<T: Sized + Hash + 'static> Hash for SharedVec<T> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.vec.hash(state)
    }
}

impl<T: Sized + 'static> Index<usize> for SharedVec<T> {
    type Output = T;
    fn index(&self, index: usize) -> &T {
        self.vec.index(index)
    }
}

impl<T: Sized + 'static> Index<Range<usize>> for SharedVec<T> {
    type Output = [T];
    fn index(&self, index: Range<usize>) -> &[T] {
        self.vec.index(index)
    }
}

impl<T: Sized + 'static> Index<RangeTo<usize>> for SharedVec<T> {
    type Output = [T];
    fn index(&self, index: RangeTo<usize>) -> &[T] {
        self.vec.index(index)
    }
}

impl<T: Sized + 'static> Index<RangeFrom<usize>> for SharedVec<T> {
    type Output = [T];
    fn index(&self, index: RangeFrom<usize>) -> &[T] {
        self.vec.index(index)
    }
}

impl<T: Sized + 'static> IndexMut<usize> for SharedVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        self.modified = true;
        self.vec.index_mut(index)
    }
}
