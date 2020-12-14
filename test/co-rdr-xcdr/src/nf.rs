use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::pvn::rdr::*;
use e2d2::pvn::xcdr::*;
use e2d2::scheduler::Scheduler;
use faktory::{Job, Producer};
use headless_chrome::Browser;
use rdr::utils::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use xcdr::utils::*;

pub fn rdr_xcdr_test<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // RDR setup
    let rdr_param = read_setup_param("/home/jethros/setup".to_string()).unwrap();
    let num_of_users = rdr_retrieve_users(rdr_param.setup).unwrap();
    let rdr_users = rdr_read_rand_seed(num_of_users, rdr_param.iter).unwrap();

    // XCDR setup
    let latencyv = Arc::new(Mutex::new(Vec::<u128>::new()));
    let latv_1 = Arc::clone(&latencyv);
    let latv_2 = Arc::clone(&latencyv);
    println!("Latency vec uses millisecond");
    let xcdr_param = xcdr_read_setup("/home/jethros/setup".to_string()).unwrap();
    let time_span = xcdr_retrieve_param(xcdr_param.setup).unwrap();
    println!(
        "Setup: {:?} port: {:?},  expr_num: {:?}",
        rdr_param.setup, xcdr_param.port, xcdr_param.expr_num
    );

    // faktory job queue
    let fak_conn = Arc::new(Mutex::new(Producer::connect(None).unwrap()));

    // job id
    let mut job_id = 0;

    let mut pivot = 1 as u128 + time_span;

    let now = Instant::now();
    let mut cur = Instant::now();
    let mut time_diff = Duration::new(0, 0);

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
                if rdr_param.inst {
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
            3,
            box move |p| {
                pkt_count += 1;
                let f = p.read_metadata();

                // 0 means the packet doesn't match RDR or XCDR
                let mut matched = 0;
                // NOTE: the following ip addr and port are hardcode based on the trace we are
                // replaying
                let match_ip = 180_907_852_u32; // 10.200.111.76
                let rdr_match_port = 443_u16;

                let xcdr_match_src_ip = 3_232_235_524_u32;
                let xcdr_match_src_port = 443;
                let xcdr_match_dst_ip = 2_457_012_302_u32;
                let xcdr_match_dst_port = 58_111;

                // Match RDR packets to group 1 and XCDR packets to group 2, the rest to group 0
                if f.proto == 6
                    && (f.src_ip == match_ip || f.dst_ip == match_ip)
                    && (f.src_port == rdr_match_port || f.dst_port == rdr_match_port)
                {
                    matched = 1
                } else if f.proto == 17
                    && ((f.src_ip == xcdr_match_src_ip
                        && f.src_port == xcdr_match_src_port
                        && f.dst_ip == xcdr_match_dst_ip
                        && f.dst_port == xcdr_match_dst_port)
                        || (f.src_ip == xcdr_match_dst_ip
                            && f.src_port == xcdr_match_dst_port
                            && f.dst_ip == xcdr_match_src_ip
                            && f.dst_port == xcdr_match_src_port))
                {
                    matched = 2
                }

                if now.elapsed().as_secs() >= rdr_param.expr_time && latency_exec {
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
                    if rdr_param.inst {
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
                // println!("pivot {:?}", cur_time);
                let min = cur_time / 60;
                let rest_sec = cur_time % 60;
                if let  Some(wd) = rdr_workload.remove(&cur_time) {
                        println!("{:?} min, {:?} second", min, rest_sec);
                        if let Some((oks, errs, timeouts, closeds, visits, elapsed)) =  rdr_scheduler_ng(&cur_time, &rdr_users, wd, &browser_list) {
                                num_of_ok += oks;
                                num_of_err += errs;
                                num_of_timeout += timeouts;
                                num_of_closed += closeds;
                                num_of_visit += visits;
                                elapsed_time.push(elapsed);
                            }
                        }
                    }

            pkt_count += 1;

            if now.elapsed().as_secs() >= rdr_param.expr_time && metric_exec {
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
                if rdr_param.inst {
                    w.push(end);
                }
            }
        })
        .reset()
        .compose();

    let xcdr_pipe = groups
        .get_group(2)
        .unwrap()
        .transform(box move |_| {
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
                if rdr_param.inst {
                    w.push(end);
                }
            }
        })
        .reset()
        .compose();

    merge(vec![groups.get_group(0).unwrap().compose(), rdr_pipe, xcdr_pipe]).compose()
}
