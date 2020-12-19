use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::pvn::p2p::*;
use e2d2::pvn::xcdr::*;
use e2d2::scheduler::Scheduler;
use faktory::{Job, Producer};
use p2p::utils::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use xcdr::utils::*;

pub fn xcdr_p2p_test<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // XCDR setup
    let xcdr_param = xcdr_read_setup("/home/jethros/setup".to_string()).unwrap();
    let time_span = xcdr_retrieve_param(xcdr_param.setup).unwrap();
    println!(
        "Setup: {:?} port: {:?},  expr_num: {:?}",
        xcdr_param.setup, xcdr_param.port, xcdr_param.expr_num
    );

    let latencyv = Arc::new(Mutex::new(Vec::<u128>::new()));
    let latv_1 = Arc::clone(&latencyv);
    let latv_2 = Arc::clone(&latencyv);
    println!("Latency vec uses millisecond");

    // faktory job queue
    let fak_conn = Arc::new(Mutex::new(Producer::connect(None).unwrap()));
    // job id
    let mut job_id = 0;

    let mut pivot = 1_u128 + time_span;

    let now = Instant::now();
    let mut cur = Instant::now();
    let mut time_diff = Duration::new(0, 0);

    // P2P setup
    let p2p_param = read_setup_param("/home/jethros/setup".to_string()).unwrap();
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
                if xcdr_param.inst {
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
        .group_by(
            3,
            box move |p| {
                pkt_count += 1;
                let f = p.read_metadata();

                // 0 means the packet doesn't match RDR or P2P
                let mut matched = 0;

                // NOTE: the following ip addr and port are hardcode based on the trace we are
                // replaying
                let match_src_ip = 3_232_235_524_u32;
                let match_src_port = 443;
                let match_dst_ip = 2_457_012_302_u32;
                let match_dst_port = 58_111;

                let match_ip = 180_907_852_u32; // 10.200.111.76

                // https://wiki.wireshark.org/BitTorrent
                let p2p_match_port = vec![6346, 6882, 6881, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969];

                // Match XCDR packets to group 1 and P2P packets to group 2, the rest to group 0
                if f.proto == 17
                    && ((f.src_ip == match_src_ip
                        && f.src_port == match_src_port
                        && f.dst_ip == match_dst_ip
                        && f.dst_port == match_dst_port)
                        || (f.src_ip == match_dst_ip
                            && f.src_port == match_dst_port
                            && f.dst_ip == match_src_ip
                            && f.dst_port == match_src_port))
                {
                    matched = 1
                } else if (f.proto == 6)
                    && (f.src_ip == match_ip || f.dst_ip == match_ip)
                    && (p2p_match_port.contains(&f.src_port) || p2p_match_port.contains(&f.dst_port))
                {
                    matched = 2
                }

                if now.elapsed().as_secs() >= xcdr_param.expr_time && latency_exec {
                    // perf XCDR
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
                    }
                    compute_stat(tmp_results);
                    println!("\nLatency results end",);
                    latency_exec = false;
                }

                if pkt_count > NUM_TO_IGNORE && matched == 0 {
                    let end = Instant::now();
                    if xcdr_param.inst {
                        stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, end);
                    }
                }

                matched
            },
            sched,
        );

    let xcdr_pipe = groups
        .get_group(1)
        .unwrap()
        .transform(box move |pkt| {
            // time difference
            if time_diff == Duration::new(0, 0) {
                time_diff = now.elapsed();
                println!("update time diff before crash: {:?}", time_diff);
                pivot += time_diff.as_millis();
                println!("update pivot: {}", pivot);
            }
            let time_elapsed = now.elapsed().as_millis();

            // if we hit a new micro second/millisecond/second
            if time_elapsed >= pivot {
                let t = cur.elapsed().as_millis();
                let mut w = latv_2.lock().unwrap();
                w.push(t);

                let core_id = job_id % xcdr_param.setup;
                // we append a job to the job queue every *time_span*
                let c = Arc::clone(&fak_conn);
                append_job_faktory(pivot, c, core_id, xcdr_param.expr_num);
                // println!("job: {}, core id: {}", job_id, core_id);

                cur = Instant::now();
                pivot += time_span;
                job_id += 1;
            }

            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t2_1.lock().unwrap();
                let end = Instant::now();
                if xcdr_param.inst {
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
                    "app_p2p-controlled" | "chain_tlsv_p2p" | "chain_rdr_p2p" | "chain_xcdr_p2p" => {
                        println!("match p2p controlled before btrun");
                        let p2p_torrents = p2p_read_rand_seed(
                            num_of_torrents,
                            p2p_param.iter.to_string(),
                            "p2p_controlled".to_string(),
                        )
                        .unwrap();

                        let _ = bt_run_torrents(p2p_torrents);

                        println!("bt run is not blocking");
                        // workload_exec = false;
                    }
                    // use the transmission rpc for general and ext workload
                    "app_p2p" | "app_p2p-ext" => {
                        println!("match p2p general or ext ");
                        let p2p_torrents =
                            p2p_read_rand_seed(num_of_torrents, p2p_param.iter.to_string(), "p2p".to_string()).unwrap();
                        let workload = p2p_load_json(fp_workload.to_string(), p2p_torrents);

                        let mut rt = Runtime::new().unwrap();
                        match rt.block_on(add_all_torrents(num_of_torrents, workload, torrents_dir.to_string())) {
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

            if start.elapsed().as_secs() >= 1_u64 {
                start = Instant::now();
            }

            pkt_count += 1;
            // println!("pkt count {:?}", pkt_count);

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t2_3.lock().unwrap();
                let end = Instant::now();
                if xcdr_param.inst {
                    w.push(end);
                }
            }
        })
        .reset()
        .compose();

    merge(vec![groups.get_group(0).unwrap().compose(), xcdr_pipe, p2p_pipe]).compose()
}
