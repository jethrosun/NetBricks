//! A New NFV framework that tries to provide optimization to developers and isolation between NFs.

#![recursion_limit = "1024"]
#![feature(asm)]
#![feature(log_syntax)]
#![feature(box_syntax)]
#![feature(specialization)]
#![feature(slice_concat_ext)]
#![feature(alloc)]
#![feature(const_fn)]
// FIXME: Figure out if this is really the right thing here.
#![feature(ptr_internals)]
// Used for cache alignment.
#![feature(allocator_api)]
#![allow(unused_features)]
#![feature(integer_atomics)]
#![allow(unused_doc_comments)]
#![cfg_attr(feature = "dev", allow(unstable_features))]
// Need this since PMD port construction triggers too many arguments.
#![cfg_attr(feature = "dev", allow(too_many_arguments))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
#![cfg_attr(feature = "dev", deny(warnings))]
// Try to deny missing doc?
#![deny(missing_docs)]
extern crate byteorder;
extern crate fnv;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate net2;
extern crate regex;
#[cfg(feature = "sctp")]
extern crate sctp;
extern crate twox_hash;
// TOML for scheduling configuration
extern crate toml;
// UUID for SHM naming
extern crate uuid;

// For cache aware allocation
extern crate alloc;

// Better error handling.
#[macro_use]
extern crate error_chain;

#[cfg(unix)]
extern crate nix;
#[doc(hidden)]
pub mod allocators;
#[doc(hidden)]
pub mod common;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod control;
#[doc(hidden)]
pub mod headers;
#[doc(hidden)]
pub mod interface;
#[allow(dead_code)]
mod native;
mod native_include;
#[doc(hidden)]
pub mod operators;
#[doc(hidden)]
pub mod queues;
#[doc(hidden)]
pub mod scheduler;
#[doc(hidden)]
pub mod shared_state;
#[doc(hidden)]
pub mod state;
#[doc(hidden)]
pub mod utils;
