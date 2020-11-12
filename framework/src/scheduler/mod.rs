//! All projects involve building a thread pool. This is the task equivalent for the threadpool in `NetBricks`.
//! Anything that implements Runnable can be polled by the scheduler. This thing can be a `Batch` (e.g., `SendBatch`) or
//! something else (e.g., the `GroupBy` operator). Eventually this trait will have more stuff.
pub use self::context::*;
pub use self::standalone_scheduler::*;
use crate::common::*;

pub mod embedded_scheduler;
mod standalone_scheduler;

mod context;

/// Executable.
pub trait Executable {
    /// Execute.
    fn execute(&mut self);
    /// Dependencies.
    fn dependencies(&mut self) -> Vec<usize>;
}

impl<F> Executable for F
where
    F: FnMut(),
{
    /// Execute.
    fn execute(&mut self) {
        (*self)()
    }

    /// Dependencies.
    fn dependencies(&mut self) -> Vec<usize> {
        vec![]
    }
}

/// Scheduler.
pub trait Scheduler {
    /// Add task to the scheduler.
    fn add_task<T: Executable + 'static>(&mut self, task: T) -> Result<usize>
    where
        Self: Sized;
}
