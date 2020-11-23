//! A Remote Dependency Resolution (RDR) proxy network function will employ a headless browser and
//! fetch the top-level HTML based on the HTTP (or even HTTPS) request.
#![feature(box_syntax)]
#![feature(asm)]
extern crate e2d2;
extern crate failure;
extern crate getopts;
extern crate headless_chrome;
extern crate rshttp;
extern crate rustc_serialize;
extern crate serde_json;
extern crate time;
extern crate tiny_http;

use crate::utils::*;
use e2d2::allocators::CacheAligned;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::interface::*;
use e2d2::operators::*;
use e2d2::pvn::measure::*;
use e2d2::pvn::rdr::{rdr_load_workload, rdr_read_rand_seed, rdr_retrieve_users};
use e2d2::scheduler::*;
use headless_chrome::Browser;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub mod utils;

// const CONVERSION_FACTOR: f64 = 1_000_000_000.;

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

pub fn rdr<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    _sched: &mut S,
) -> CompositionBatch {
    let param = read_setup_param("/home/jethros/setup".to_string()).unwrap();
    let num_of_users = rdr_retrieve_users(param.setup).unwrap();
    let rdr_users = rdr_read_rand_seed(num_of_users, param.iter).unwrap();

    // Measurement code
    //
    // NOTE: Store timestamps and calculate the delta to get the processing time for individual
    // packet is disabled here (TOTAL_MEASURED_PKT removed)
    let mut metric_exec = true;

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

    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    let workload_path = "/home/jethros/dev/pvn/utils/workloads/rdr_pvn_workloads/rdr_pvn_workload_5.json";
    println!("{:?}", workload_path);
    let num_of_secs = 600;

    let mut rdr_workload = rdr_load_workload(workload_path.to_string(), num_of_secs, rdr_users.clone()).unwrap();
    println!("Workload is generated",);

    // Browser list.
    let mut browser_list: HashMap<i64, Browser> = HashMap::new();

    for user in &rdr_users {
        let browser = browser_create().unwrap();
        browser_list.insert(*user, browser);
    }
    println!("{} browsers are created ", num_of_users);

    let _pivot = 1_usize;

    // Metrics for measurement
    let mut elapsed_time = Vec::new();
    let mut num_of_ok = 0;
    let mut num_of_err = 0;
    let mut num_of_timeout = 0;
    let mut num_of_closed = 0;
    let mut num_of_visit = 0;

    let now = Instant::now();
    println!("Timer started");

    parent
        .transform(box move |_| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                let start = Instant::now();
                if param.inst {
                    w.push(start);
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
        .transform(box move |p| {
            let mut matched = false;
            let f = p.read_metadata();

            // NOTE: the following ip addr and port are hardcode based on the trace we are
            // replaying let match_ip = 3_232_235_524 as u32; // 192.168.0.4 let match_port = 443;
            // let (src_ip, dst_ip, proto): (&u32, &u32, &u8) = match p.read_metadata() {
            // Some((src, dst, p)) => (src, dst, p), None => (&0, &0, &0), };
            //
            //  let src_port = p.get_header().src_port(); let dst_port = p.get_header().dst_port();
            //
            //  if *proto == 6 { if *src_ip == match_ip && dst_port == match_port { matched = true }
            //  else if *dst_ip == match_ip && src_port == match_port { matched = true } }

            let match_ip = 180_907_852_u32; // 10.200.111.76

            if f.proto == 6 && (
                f.src_ip == match_ip || f.dst_ip == match_ip ){
                    matched = true
            }

            // Scheduling browsing jobs.
            if matched {
                // Scheduling browsing jobs. FIXME: This is not ideal as we are not actually
                // schedule browse.
                let cur_time = now.elapsed().as_secs() as usize;
                if rdr_workload.contains_key(&cur_time) {
                    // println!("pivot {:?}", cur_time);
                    let min = cur_time / 60;
                    let rest_sec = cur_time % 60;
                    if let Some(wd) =  rdr_workload.remove(&cur_time) {
                        println!("{:?} min, {:?} second", min, rest_sec);
                        if let Some((oks, errs, timeouts, closeds, visits, elapsed)) = rdr_scheduler_ng(&cur_time, &rdr_users, wd, &browser_list) {
                            num_of_ok += oks;
                            num_of_err += errs;
                            num_of_timeout += timeouts;
                            num_of_closed += closeds;
                            num_of_visit += visits;
                            elapsed_time.push(elapsed);
                        }
                    }
                }

                // Measurement: instrumentation to collect latency metrics
                if pkt_count > NUM_TO_IGNORE {
                    let mut w = t2_1.lock().unwrap();
                    let end = Instant::now();
                    if param.inst {
                        w.push(end);
                    }
                }
            } else if pkt_count > NUM_TO_IGNORE {
                // Insert the timestamp as
                let end = Instant::now();
                if param.inst {
                    stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, end);
                }
            }

            pkt_count += 1;

            if now.elapsed().as_secs() >= param.expr_time && param.inst && metric_exec {
                // Measurement: metric for the performance of the RDR proxy
                println!(
                    "Metric: num_of_oks: {:?}, num_of_errs: {:?}, num_of_timeout: {:?}, num_of_closed: {:?}, num_of_visit: {:?}",
                    num_of_ok, num_of_err, num_of_timeout, num_of_closed, num_of_visit,
                );
                println!(
                    "Metric: Browsing Time: {:?}\n",
                    elapsed_time
                );

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
                    // print!("{:?}, ", since_the_epoch1); total_time1 = total_time1 +
                    // since_the_epoch1;
                }
                compute_stat(tmp_results);
                println!("\nLatency results end",);
                metric_exec = false;
                // println!("avg processing time 1 is {:?}", total_time1 / num as u32);
            }
        })
        .compose()
}
