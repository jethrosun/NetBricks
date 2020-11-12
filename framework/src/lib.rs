//! A New NFV framework that tries to provide optimization to developers and isolation between NFs.
#![deny(missing_docs)]
// Consider disable missing debug because dpdk bindgen and several components in framework.
// #![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms, broken_intra_doc_links)]
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

// extern crate getopts;

#[macro_use]
extern crate lazy_static;

// Better error handling.
#[macro_use]
extern crate error_chain;

// #[cfg(feature = "sctp")]
// extern crate sctp;

// extern crate byteorder;
// extern crate fnv;
// extern crate libc;
// extern crate net2;
// extern crate regex;
// extern crate twox_hash;
// TOML for scheduling configuration
// extern crate toml;
// UUID for SHM naming
// extern crate uuid;
// For cache aware allocation
// extern crate alloc;
// #[cfg(unix)]
// extern crate nix;

pub mod allocators;
pub mod common;
pub mod config;
pub mod control;
pub mod headers;
pub mod interface;
pub mod operators;
pub mod pvn;
pub mod queues;
pub mod scheduler;
pub mod shared_state;
pub mod state;
pub mod utils;

#[allow(dead_code)]
mod native;
mod native_include;
