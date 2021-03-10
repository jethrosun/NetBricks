//! A TLS validator network function will identify the TLS handshake messages and extract the
//! certificates. The NF will run a configurable TLS version and enforce the validation of the
//! certs. The exact implementation is in `nf.rs`.
#![feature(box_syntax)]
#![feature(asm)]
extern crate e2d2;
extern crate fnv;
extern crate rustls;
extern crate time;
extern crate tlsv;
extern crate webpki;
extern crate webpki_roots;

use e2d2::config::*;
use e2d2::interface::*;
use e2d2::operators::*;
use e2d2::scheduler::*;
use std::env;
use std::fmt::Display;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tlsv::validator;

const CONVERSION_FACTOR: f64 = 1_000_000_000.;

/// Test for the validator network function to schedule pipelines.
fn validator_test<T, S>(ports: Vec<T>, sched: &mut S)
where
    T: PacketRx + PacketTx + Display + Clone + 'static,
    S: Scheduler + Sized,
{
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

/// default main
fn main() {
    // setup default parameters
    let opts = basic_opts();
    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let configuration = read_matches(&matches, &opts);

    // configure and start the schedulers
    let mut config = initialize_system(&configuration).unwrap();
    let duration = configuration.duration;

    config.start_schedulers();
    config.add_pipeline_to_run(Arc::new(move |p, s: &mut StandaloneScheduler| validator_test(p, s)));
    config.execute();

    let mut pkts_so_far = (0, 0);
    let mut last_printed = 0.;
    const MAX_PRINT_INTERVAL: f64 = 30.;
    //const PRINT_DELAY: f64 = 15.;
    const PRINT_DELAY: f64 = 30.;
    let sleep_delay = (PRINT_DELAY / 2.) as u64;
    let mut start = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
    let sleep_time = Duration::from_millis(sleep_delay);
    println!("0 OVERALL RX 0.00 TX 0.00 CYCLE_PER_DELAY 0 0 0");
    let begining = Instant::now();

    loop {
        thread::sleep(sleep_time); // Sleep for a bit
        let now = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
        if now - start > PRINT_DELAY {
            let mut rx = 0;
            let mut tx = 0;
            for port in config.ports.values() {
                for q in 0..port.rxqs() {
                    let (rp, tp) = port.stats(q);
                    rx += rp;
                    tx += tp;
                }
            }
            let pkts = (rx, tx);
            let rx_pkts = pkts.0 - pkts_so_far.0;
            if rx_pkts > 0 || now - last_printed > MAX_PRINT_INTERVAL {
                println!(
                    "{:.2} OVERALL RX {:.2} TX {:.2}",
                    now - start,
                    rx_pkts as f64 / (now - start),
                    (pkts.1 - pkts_so_far.1) as f64 / (now - start)
                );
                last_printed = now;
                start = now;
                pkts_so_far = pkts;
            }
        }
        if let Some(d) = duration {
            let new_now = Instant::now();
            if new_now.duration_since(begining) > Duration::new(d as u64, 0) {
                println!("Have run for {:?}, system shutting down", d);
                config.shutdown();
                break;
            }
        }
    }
}
