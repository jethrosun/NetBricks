use crate::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{Batch, CompositionBatch};
use e2d2::pvn::measure::read_setup_iter;
use e2d2::pvn::measure::{compute_stat, merge_ts, APP_MEASURE_TIME, EPSILON, NUM_TO_IGNORE, TOTAL_MEASURED_PKT};
use e2d2::pvn::p2p::{p2p_fetch_workload, p2p_load_json, p2p_read_rand_seed, p2p_read_type, p2p_retrieve_param};
use e2d2::scheduler::Scheduler;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::runtime::Runtime;

pub fn p2p<T: 'static + Batch<Header = NullHeader>>(parent: T, _s: &mut dyn Scheduler) -> CompositionBatch {
    // setup for this run
    let (p2p_setup, p2p_iter) = read_setup_iter("/home/jethros/setup".to_string()).unwrap();
    let num_of_torrents = p2p_retrieve_param("/home/jethros/setup".to_string()).unwrap();
    let p2p_type = p2p_read_type("/home/jethros/setup".to_string()).unwrap();

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

    // Fixed transmission setup
    let torrents_dir = "/home/jethros/dev/pvn/utils/workloads/torrent_files/";

    let mut pivot = 0 as usize;
    let now = Instant::now();
    let mut start = Instant::now();

    let mut workload_exec = true;
    // let mut torrent_list = Vec::new();

    let pipeline = parent
        .transform(box move |_| {
            // first time access start_ts, need to insert timestamp
            pkt_count += 1;
            // println!("pkt_count {:?}", pkt_count);
            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                // let now = Instant::now();
                // w.push(now);
            }
        })
        .parse::<MacHeader>()
        .parse::<IpHeader>()
        .metadata(box move |p| {
            let src_ip = p.get_header().src();
            let dst_ip = p.get_header().dst();
            let proto = p.get_header().protocol();

            Some((src_ip, dst_ip, proto))
        })
        .parse::<TcpHeader>()
        .transform(box move |p| {
            let mut matched = false;
            const APP_MEASURE_TIME: u64 = 600;

            // NOTE: the following ip addr and port are hardcode based on the trace we are
            // replaying
            let match_ip = 180907852 as u32;
            // https://wiki.wireshark.org/BitTorrent
            let match_port = vec![6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969];

            let (src_ip, dst_ip, proto): (&u32, &u32, &u8) = match p.read_metadata() {
                Some((src, dst, p)) => {
                    // println!("src: {:?} dst: {:}", src, dst); //
                    (src, dst, p)
                }
                None => (&0, &0, &0),
            };

            let src_port = p.get_header().src_port();
            let dst_port = p.get_header().dst_port();
            // println!("src: {:?} dst: {:}", src_port, dst_port); //

            if *proto == 6 {
                if *src_ip == match_ip && match_port.contains(&dst_port) {
                    // println!("pkt count: {:?}", pkt_count);
                    // println!("We got a hit\n src ip: {:?}, dst port: {:?}", src_ip, dst_port);
                    matched = true;
                } else if *dst_ip == match_ip && match_port.contains(&src_port) {
                    // println!("pkt count: {:?}", pkt_count);
                    // println!("We got a hit\n dst ip: {:?}, src port: {:?}", dst_ip, src_port);
                    matched = true;
                }
            }

            if matched {
                if workload_exec {
                    // Workload
                    let fp_workload = p2p_fetch_workload("/home/jethros/setup".to_string()).unwrap();

                    println!("p2p type: {}", p2p_type);
                    match &*p2p_type {
                        // use our shell wrapper to interact with qBitTorrent
                        // FIXME: it would be nicer if we can employ a Rust crate for this
                        "app_p2p-controlled" => {
                            println!("match p2p controlled before btrun");
                            // let _ = bt_run_torrents(fp_workload, num_of_torrents);
                            let _ = bt_run_torrents(fp_workload, p2p_setup.clone());

                            println!("bt run is not blocking");
                            workload_exec = false;
                        }
                        // use the transmission rpc for general and ext workload
                        "app_p2p" | "app_p2p-ext" => {
                            println!("match p2p general or ext ");
                            let p2p_torrents = p2p_read_rand_seed(num_of_torrents, p2p_iter.to_string()).unwrap();
                            let mut workload = p2p_load_json(fp_workload.to_string(), p2p_torrents);

                            let mut rt = Runtime::new().unwrap();
                            match rt.block_on(add_all_torrents(
                                num_of_torrents,
                                workload.clone(),
                                torrents_dir.to_string(),
                            )) {
                                Ok(_) => println!("Add torrents success"),
                                Err(e) => println!("Add torrents failed with {:?}", e),
                            }
                            match rt.block_on(run_all_torrents()) {
                                Ok(_) => println!("Run torrents success"),
                                Err(e) => println!("Run torrents failed with {:?}", e),
                            }
                        }
                        _ => println!("Current P2P type: {:?} doesn't match to any workload we know", p2p_type),
                    }

                    workload_exec = false;
                }

                if pkt_count > NUM_TO_IGNORE {
                    let mut w = t2_1.lock().unwrap();
                    let end = Instant::now();
                    // w.push(end);
                }
            } else {
                if pkt_count > NUM_TO_IGNORE {
                    // Insert the timestamp as
                    let end = Instant::now();
                    // stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, end;
                }
            }

            pkt_count += 1;

            if now.elapsed().as_secs() >= APP_MEASURE_TIME && metric_exec == true {
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
        });
    pipeline.compose()
}