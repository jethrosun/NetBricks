//! A Remote Dependency Resolution (RDR) proxy network function will employ a headless browser and
//! fetch the top-level HTML based on the HTTP (or even HTTPS) request. The exact implementation is
//! in `nf.rs`.
#![feature(box_syntax)]
#![feature(asm)]
extern crate crossbeam;
extern crate e2d2;
extern crate failure;
extern crate faktory;
extern crate fnv;
extern crate getopts;
extern crate rand;
extern crate resize;
extern crate rustc_serialize;
extern crate serde_json;
extern crate time;
extern crate y4m;

use crate::utils::*;
use e2d2::allocators::CacheAligned;

use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::interface::*;
use e2d2::operators::ReceiveBatch;
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::pvn::xcdr::{xcdr_read_setup, xcdr_retrieve_param};
use e2d2::scheduler::Scheduler;
use faktory::{Producer};
use std::collections::HashMap;


use std::sync::{Arc, Mutex};

use std::time::{Duration, Instant};

pub mod utils;

const CONVERSION_FACTOR: f64 = 1_000_000_000.;

pub fn transcoder<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    let mut metric_exec = true;
    let latencyv = Arc::new(Mutex::new(Vec::<u128>::new()));
    let latv_1 = Arc::clone(&latencyv);
    let latv_2 = Arc::clone(&latencyv);
    println!("Latency vec uses millisecond");

    // Specific setup config for this run

    // setup for this run
    let (setup_val, port, expr_num, inst) = xcdr_read_setup("/home/jethros/setup".to_string()).unwrap();
    let time_span = xcdr_retrieve_param(setup_val).unwrap();
    println!("Setup: {:?} port: {:?},  expr_num: {:?}", setup_val, port, expr_num);

    // faktory job queue
    let fak_conn = Arc::new(Mutex::new(Producer::connect(None).unwrap()));

    // Measurement code
    //
    // NOTE: Store timestamps and calculate the delta to get the processing time for individual
    // packet is disabled here (TOTAL_MEASURED_PKT removed)

    // start timestamps will be a vec protected with arc and mutex.
    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));
    let mut stop_ts_not_matched: HashMap<usize, Instant> = HashMap::with_capacity(EPSILON);
    let stop_ts_matched = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));

    let t1_1 = Arc::clone(&start_ts);
    let t1_2 = Arc::clone(&start_ts);
    let t2_1 = Arc::clone(&stop_ts_matched);
    let t2_2 = Arc::clone(&stop_ts_matched);

    // pkt count
    let mut pkt_count = 0;
    // job id
    let mut job_id = 0;

    let mut pivot = 1 as u128 + time_span;

    let measure_time = if inst { INST_MEASURE_TIME } else { APP_MEASURE_TIME };

    let now = Instant::now();
    let mut cur = Instant::now();
    let mut time_diff = Duration::new(0, 0);

    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .transform(box move |_p| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                let end = Instant::now();
                if inst {
                    w.push(end);
                }
            }
        })
        .parse::<MacHeader>()
        .parse::<IpHeader>()
        .metadata(box move |p| {
            let f = p.get_header().flow();
            match f {
                Some(f) => f,
                None => fake_flow(),
            }
        })
        .parse::<TcpHeader>()
        .group_by(
            2,
            box move |p| {
                pkt_count += 1;
                let f = p.read_metadata();

                let mut matched = false;
                // NOTE: the following ip addr and port are hardcode based on the trace we are
                // replaying
                let match_src_ip = 3_232_235_524 as u32;
                let match_src_port = 58_111;
                let match_dst_ip = 2_457_012_302 as u32;
                let match_dst_port = 443;

                if f.proto == 17 {
                    if f.src_ip == match_src_ip
                        && f.src_port == match_src_port
                        && f.dst_ip == match_dst_ip
                        && f.dst_port == match_dst_port
                    {
                        matched = true
                    } else if f.src_ip == match_dst_ip
                        && f.src_port == match_dst_port
                        && f.dst_ip == match_src_ip
                        && f.dst_port == match_src_port
                    {
                        matched = true
                    }
                }

                if now.elapsed().as_secs() >= measure_time && inst && metric_exec == true {
                    println!("Pivot/span: {:?}", pivot / time_span);
                    let w = latv_1.lock().unwrap();
                    println!("Metric: {:?}", w);

                    println!("pkt count {:?}", pkt_count);
                    let w1 = t1_2.lock().unwrap();
                    let w2 = t2_2.lock().unwrap();
                    println!(
                        "# of start ts\n w1 {:#?}, hashmap {:#?}, # of stop ts: {:#?}",
                        w1.len(),
                        stop_ts_not_matched.len(),
                        w2.len(),
                    );
                    let actual_stop_ts = merge_ts(pkt_count - 1, w2.clone(), stop_ts_not_matched.clone());
                    let num = actual_stop_ts.len();
                    println!(
                        "stop ts matched len: {:?}, actual_stop_ts len: {:?}",
                        w2.len(),
                        actual_stop_ts.len()
                    );
                    println!("Latency results start: {:?}", num);
                    let mut tmp_results = Vec::<u128>::with_capacity(num);
                    for i in 0..num {
                        let stop = actual_stop_ts.get(&i).unwrap();
                        let since_the_epoch = stop.checked_duration_since(w1[i]).unwrap();
                        tmp_results.push(since_the_epoch.as_nanos());
                        // print!("{:?}, ", since_the_epoch1);
                        // total_time1 = total_time1 + since_the_epoch1;
                    }
                    compute_stat(tmp_results);
                    println!("\nLatency results end",);
                    metric_exec = false;
                }

                if pkt_count > NUM_TO_IGNORE && !matched {
                    let end = Instant::now();
                    if inst {
                        stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, end);
                    }
                }
                // println!("{:?}", matched);

                if matched {
                    0
                } else {
                    1
                }
            },
            sched,
        );

    // Create the pipeline--we perform the actual packet processing here.
    let pipe = groups
        .get_group(0)
        .unwrap()
        .transform(box move |_| {
            // time difference
            if time_diff == Duration::new(0, 0) {
                time_diff = now.elapsed();
                println!("update time diff before crash: {:?}", time_diff);
                pivot = pivot + time_diff.as_millis();
                println!("update pivot: {}", pivot);
            }
            let time_elapsed = now.elapsed().as_millis();

            // if we hit a new micro second/millisecond/second
            if time_elapsed >= pivot {
                let t = cur.elapsed().as_millis();
                let mut w = latv_2.lock().unwrap();
                w.push(t);

                let core_id = job_id % setup_val;
                // we append a job to the job queue every *time_span*
                let c = Arc::clone(&fak_conn);
                append_job_faktory(pivot, c, core_id, &expr_num);
                // println!("job: {}, core id: {}", job_id, core_id);

                cur = Instant::now();
                pivot += time_span;
                job_id += 1;
            }

            pkt_count += 1;
            // println!("pkt count {:?}", pkt_count);

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t2_1.lock().unwrap();
                let end = Instant::now();
                if inst {
                    w.push(end);
                }
            }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}

/// Test for the rdr proxy network function to schedule pipelines.
pub fn transcoder_test<S: Scheduler + Sized>(ports: Vec<CacheAligned<PortQueue>>, sched: &mut S) {
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
        .map(|port| transcoder(ReceiveBatch::new(port.clone()), sched).send(port.clone()))
        .collect();

    println!("Running {} pipelines", pipelines.len());

    // schedule pipelines
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}
