use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::pvn::p2p::*;
use e2d2::pvn::rdr::*;
use e2d2::scheduler::Scheduler;
use headless_chrome::Browser;
use p2p::utils::*;
use rdr::utils::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::runtime::Runtime;

pub fn rdr_p2p_test<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // FIXME: read inst mode
    let inst = false;

    // RDR setup
    let (rdr_setup, rdr_iter, inst) = read_setup_param("/home/jethros/setup".to_string()).unwrap();
    let num_of_users = rdr_retrieve_users(rdr_setup).unwrap();
    let rdr_users = rdr_read_rand_seed(num_of_users, rdr_iter).unwrap();

    // P2P setup
    let (p2p_setup, p2p_iter, inst) = read_setup_param("/home/jethros/setup".to_string()).unwrap();
    let num_of_torrents = p2p_retrieve_param("/home/jethros/setup".to_string()).unwrap();
    let p2p_type = p2p_read_type("/home/jethros/setup".to_string()).unwrap();
    let torrents_dir = "/home/jethros/dev/pvn/utils/workloads/torrent_files/";
    let mut workload_exec = true;

    // Measurement code
    //
    // NOTE: Store timestamps and calculate the delta to get the processing time for individual
    // packet is disabled here (TOTAL_MEASURED_PKT removed)
    let mut metric_exec = true;
    let mut latency_exec = true;

    // start timestamps will be a vec protected with arc and mutex.
    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));
    let mut stop_ts_not_matched: HashMap<usize, Instant> = HashMap::with_capacity(EPSILON);
    let stop_ts_matched = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));

    let t1_1 = Arc::clone(&start_ts);
    let t1_2 = Arc::clone(&start_ts);
    let t2_1 = Arc::clone(&stop_ts_matched);
    let t2_2 = Arc::clone(&stop_ts_matched);
    let t2_3 = Arc::clone(&stop_ts_matched);

    // Pkt counter. We keep track of every packet.
    let mut pkt_count = 0;

    // Workloads:
    let workload_path = "/home/jethros/dev/pvn/utils/workloads/rdr_pvn_workloads/rdr_pvn_workload_5.json";
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

    // Metrics for measurement
    let mut elapsed_time = Vec::new();
    let mut num_of_ok = 0;
    let mut num_of_err = 0;
    let mut num_of_timeout = 0;
    let mut num_of_closed = 0;
    let mut num_of_visit = 0;

    // let mut pivot = 1;
    let now = Instant::now();
    let mut start = Instant::now();

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .transform(box move |_| {
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
            let src_ip = p.get_header().src();
            let dst_ip = p.get_header().dst();
            let proto = p.get_header().protocol();

            Some((src_ip, dst_ip, proto))
        })
        .parse::<TcpHeader>()
        .group_by(
            3,
            box move |p| {
                pkt_count += 1;
                let (src_ip, dst_ip, proto): (&u32, &u32, &u8) = match p.read_metadata() {
                    Some((src, dst, p)) => (src, dst, p),
                    None => (&0, &0, &0),
                };
                let src_port = p.get_header().src_port();
                let dst_port = p.get_header().dst_port();

                // 0 means the packet doesn't match RDR or P2P
                let mut matched = 0;
                // NOTE: the following ip addr and port are hardcode based on the trace we are
                // replaying
                let match_ip = 180_907_852 as u32; // 10.200.111.76
                let rdr_match_port = 443 as u16;
                // https://wiki.wireshark.org/BitTorrent
                let p2p_match_port = vec![6346, 6882, 6881, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969];

                // Match RDR packets to group 1 and P2P packets to group 2, the rest to group 0
                if *proto == 6 {
                    if *src_ip == match_ip || *dst_ip == match_ip {
                        if src_port == rdr_match_port || dst_port == rdr_match_port {
                            matched = 1
                        } else if p2p_match_port.contains(&src_port) || p2p_match_port.contains(&dst_port) {
                            matched = 2
                        }
                    }
                }

                if now.elapsed().as_secs() >= APP_MEASURE_TIME && latency_exec == true {
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
                    }
                    compute_stat(tmp_results);
                    println!("\nLatency results end",);
                    latency_exec = false;
                }

                if pkt_count > NUM_TO_IGNORE && matched == 0 {
                    let end = Instant::now();
                    if inst {
                        stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, end);
                    }
                }

                matched
            },
            sched,
        );

    let rdr_pipe = groups
        .get_group(1)
        .unwrap()
        .transform(box move |pkt| {
            // Scheduling browsing jobs.
            // FIXME: This is not ideal as we are not actually schedule browse.
            let cur_time = now.elapsed().as_secs() as usize;
            if rdr_workload.contains_key(&cur_time) {
                println!("pivot {:?}", cur_time);
                let min = cur_time / 60;
                let rest_sec = cur_time % 60;
                println!("{:?} min, {:?} second", min, rest_sec);
                match rdr_workload.remove(&cur_time) {
                    Some(wd) => match rdr_scheduler_ng(&cur_time, &rdr_users, wd, &browser_list) {
                        Some((oks, errs, timeouts, closeds, visits, elapsed)) => {
                            num_of_ok += oks;
                            num_of_err += errs;
                            num_of_timeout += timeouts;
                            num_of_closed += closeds;
                            num_of_visit += visits;
                            elapsed_time.push(elapsed);
                        }
                        None => println!("No workload for second {:?}", cur_time),
                    },
                    None => println!("No workload for second {:?}", cur_time),
                }
            }

            pkt_count += 1;

            if now.elapsed().as_secs() >= APP_MEASURE_TIME && metric_exec == true {
                // Measurement: metric for the performance of the RDR proxy
                println!(
                    "Metric: num_of_oks: {:?}, num_of_errs: {:?}, num_of_timeout: {:?}, num_of_closed: {:?}, num_of_visit: {:?}",
                    num_of_ok, num_of_err, num_of_timeout, num_of_closed, num_of_visit,
                );
                println!("Metric: Browsing Time: {:?}\n", elapsed_time);
                metric_exec = false;
            }

            // Measurement: instrumentation to collect latency metrics
            if pkt_count > NUM_TO_IGNORE {
                let mut w = t2_3.lock().unwrap();
                let end = Instant::now();
                if inst {
                    w.push(end);
                }
            }
        })
        .reset()
        .compose();

    let p2p_pipe = groups
        .get_group(2)
        .unwrap()
        .transform(box move |_| {
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
                        let workload = p2p_load_json(fp_workload.to_string(), p2p_torrents);

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

            if start.elapsed().as_secs() >= 1 as u64 {
                start = Instant::now();
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

    merge(vec![groups.get_group(0).unwrap().compose(), rdr_pipe, p2p_pipe]).compose()
}