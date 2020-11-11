//! A New NFV framework that tries to provide optimization to developers and isolation between NFs.
#![deny(missing_docs)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    missing_debug_implementations,
    intra_doc_link_resolution_failure
)]
#![recursion_limit = "1024"]
#![feature(llvm_asm)]
#![feature(log_syntax)]
#![feature(box_syntax)]
#![feature(min_specialization)]
#![feature(slice_concat_ext)]
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
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

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

pub mod allocators;
pub mod common;
pub mod config;
pub mod control;
pub mod headers;
pub mod interface;

#[allow(dead_code)]
mod native;
mod native_include;

pub mod operators;
pub mod pvn;
pub mod queues;
pub mod scheduler;
pub mod shared_state;
pub mod state;
pub mod utils;
