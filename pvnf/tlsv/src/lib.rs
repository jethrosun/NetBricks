//! A TLS validator network function will identify the TLS handshake messages and extract the
//! certificates. The NF will run a configurable TLS version and enforce the validation of the
//! certs. The exact implementation is in `nf.rs`.
#![feature(box_syntax)]
#![feature(asm)]
extern crate e2d2;
extern crate fnv;
extern crate getopts;
extern crate rustls;
extern crate time;
extern crate webpki;
extern crate webpki_roots;
#[macro_use]
extern crate log;

use self::nf::validator;
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

/// Test for the validator network function to schedule pipelines.
pub fn validator_test<S: Scheduler + Sized>(ports: Vec<CacheAligned<PortQueue>>, sched: &mut S) {
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
        .map(|port| validator(ReceiveBatch::new(port.clone()), sched).send(port.clone()))
        .collect();

    println!("Running {} pipelines", pipelines.len());

    // schedule pipelines
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}
