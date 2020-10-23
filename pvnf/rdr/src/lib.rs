//! A Remote Dependency Resolution (RDR) proxy network function will employ a headless browser and
//! fetch the top-level HTML based on the HTTP (or even HTTPS) request. The exact implementation is
//! in `nf.rs`.
#![feature(box_syntax)]
#![feature(asm)]
extern crate e2d2;
extern crate failure;
extern crate fnv;
extern crate getopts;
extern crate headless_chrome;
extern crate rshttp;
extern crate rustc_serialize;
extern crate serde_json;
extern crate time;
extern crate tiny_http;

use self::nf::rdr;
use e2d2::allocators::CacheAligned;
use e2d2::config::*;
use e2d2::interface::*;
use e2d2::operators::*;
use e2d2::scheduler::*;
use std::env;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

mod nf;
mod utils;

const CONVERSION_FACTOR: f64 = 1_000_000_000.;

/// Test for the rdr proxy network function to schedule pipelines.
pub fn rdr_proxy_test<S: Scheduler + Sized>(ports: Vec<CacheAligned<PortQueue>>, sched: &mut S) {
    for port in &ports {
        println!(
            "Receiving port {} rxq {} txq {}",
            port.port.mac_address(),
            port.rxq(),
            port.txq()
        );
    }

    // create a pipeline for each port
    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| rdr(ReceiveBatch::new(port.clone()), sched).send(port.clone()))
        .collect();

    println!("Running {} pipelines", pipelines.len());

    // schedule pipelines
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}
