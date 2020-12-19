use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::pvn::xcdr::*;
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use faktory::{Job, Producer};
use rustls::internal::msgs::handshake::HandshakePayload::{ClientHello, ClientKeyExchange, ServerHello};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tlsv::utils::*;
use xcdr::utils::*;

pub fn tlsv_xcdr_test<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // TLSV setup
    //
    let mut payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());
    // Temporary payload cache.
    let mut tmp_payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());
    // New map to keep track of the expected seq #
    let mut seqnum_map = HashMap::<Flow, u32>::with_hasher(Default::default());
    // Temporary map to keep track of the expected seq #
    let mut tmp_seqnum_map = HashMap::<Flow, (u32, u32)>::with_hasher(Default::default());
    // TLS connection with invalid certs.
    let mut unsafe_connection: HashSet<Flow> = HashSet::new();
    // DNS name cache.
    let mut name_cache = HashMap::<Flow, webpki::DNSName>::with_hasher(Default::default());
    // Cert count
    let mut cert_count = 0;

    // XCDR setup
    let latencyv = Arc::new(Mutex::new(Vec::<u128>::new()));
    let latv_1 = Arc::clone(&latencyv);
    let latv_2 = Arc::clone(&latencyv);
    println!("Latency vec uses millisecond");
    let xcdr_param = xcdr_read_setup("/home/jethros/setup".to_string()).unwrap();
    let time_span = xcdr_retrieve_param(xcdr_param.setup).unwrap();
    println!(
        "Setup: {:?} port: {:?}, expr_num: {:?}",
        xcdr_param.setup, xcdr_param.port, xcdr_param.expr_num
    );
    // faktory job queue
    let fak_conn = Arc::new(Mutex::new(Producer::connect(None).unwrap()));
    // job id
    let mut job_id = 0;

    let mut pivot = 1 as u128 + time_span;

    let now = Instant::now();
    let mut cur = Instant::now();
    let mut time_diff = Duration::new(0, 0);
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
                let match_ip = 180_907_852_u32; // 10.200.111.76
                let xcdr_match_src_ip = 3_232_235_524_u32;
                let xcdr_match_src_port = 443;
                let xcdr_match_dst_ip = 2_457_012_302_u32;
                let xcdr_match_dst_port = 58_111;

                // Match TLS packets to group 1 and XCDR packets to group 2, the rest to group 0
                if f.proto == 6 {
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

                if now.elapsed().as_secs() >= xcdr_param.expr_time && latency_exec {
                    // perf of XCDR
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

    let tlsv_pipe = groups
        .get_group(1)
        .unwrap()
        .metadata(box move |p| {
            let flow = p.get_header().flow().unwrap();
            flow
        })
        .parse::<TcpHeader>()
        .transform(box move |p| {
            let flow = p.read_metadata();
            let rev_flow = flow.reverse_flow();
            let _seq = p.get_header().seq_num();
            let _tcph = p.get_header();
            let _payload_size = p.payload_size();

            // FIXME: The else part should be written as a filter and it should exec before all these..
            if !unsafe_connection.contains(flow) {
                // check if the flow is recognized
                if payload_cache.contains_key(flow) {
                    // The rest of the TLS server hello handshake should be captured here.
                    // Check if this packet is not expected, ie, is a out of order segment.
                    match _seq.cmp(seqnum_map.get(&flow).unwrap()) {
                        Ordering::Equal => {
                            // We received an expected packet
                            //debug!("{:?}", p.get_payload());
                            tlsf_update(payload_cache.entry(*flow), &p.get_payload());
                            seqnum_map.entry(*flow).and_modify(|e| {
                                *e += _payload_size as u32;
                            });
                        }
                        Ordering::Greater => {
                            // We received a out-of-order TLS segment
                            // We need to check if we should update the entry in the tmp payload cache
                            if tmp_payload_cache.contains_key(flow) {
                                // Check if we should update the entry in the tmp payload cache
                                let (_, entry_expected_seqno) = *tmp_seqnum_map.get(flow).unwrap();
                                if _seq == entry_expected_seqno {
                                    tlsf_update(tmp_payload_cache.entry(*flow), &p.get_payload());
                                    tmp_seqnum_map.entry(*flow).and_modify(|(_, entry_expected_seqno)| {
                                        *entry_expected_seqno += _payload_size as u32;
                                    });
                                } else {
                                }
                            } else {
                                tmp_seqnum_map.insert(*flow, (_seq, _seq + _payload_size as u32));
                                tmp_payload_cache.insert(*flow, p.get_payload().to_vec());
                            }
                        }
                        Ordering::Less => {}
                    }
                } else {
                    match on_frame(&p.get_payload()) {
                        Some((handshake, _)) => {
                            match handshake.payload {
                                ClientHello(_) => {
                                    let server_name = match get_server_name(&p.get_payload()) {
                                        Some(n) => n,
                                        None => {
                                            // FIXME: tmp hack
                                            let name_ref =
                                                webpki::DNSNameRef::try_from_ascii_str("github.com").unwrap();
                                            webpki::DNSName::from(name_ref)
                                        }
                                    };
                                    name_cache
                                        .entry(rev_flow)
                                        .and_modify(|e| *e = server_name.clone())
                                        .or_insert(server_name);
                                }
                                ServerHello(_) => {
                                    // capture the sequence number
                                    seqnum_map.insert(*flow, _seq + _payload_size as u32);
                                    payload_cache.insert(*flow, p.get_payload().to_vec());
                                }
                                ClientKeyExchange(_) => {
                                    let dns_name = name_cache.remove(&rev_flow);
                                    match dns_name {
                                        Some(name) => {
                                            if tmp_payload_cache.contains_key(&rev_flow) {
                                                unordered_validate(
                                                    name,
                                                    &flow,
                                                    &mut cert_count,
                                                    &mut unsafe_connection,
                                                    &mut tmp_payload_cache,
                                                    &mut tmp_seqnum_map,
                                                    &mut payload_cache,
                                                    &mut seqnum_map,
                                                )
                                            } else {
                                                ordered_validate(
                                                    name,
                                                    &flow,
                                                    &mut cert_count,
                                                    &mut unsafe_connection,
                                                    &mut payload_cache,
                                                    &mut seqnum_map,
                                                )
                                            }
                                        }
                                        None => eprintln!("We are missing the dns name from the client hello",),
                                    }
                                }
                                _ => eprintln!("Other kinds of payload",),
                            }
                        }
                        None => eprintln!("Get none for matching payload",),
                    }
                }
            } else {
                // Disabled for now, we can enable it when we are finished.

                // info!("Pkt #{} belong to a unsafe flow!\n", _seq);
                // info!("{:?} is marked as unsafe connection so we have to reset\n", flow);
                // let _ = unsafe_connection.take(flow);
                // let tcph = p.get_mut_header();
                // tcph.set_rst_flag();
            }

            pkt_count += 1;

            if pkt_count == NUM_TO_IGNORE {
                println!("\nMeasurement started ",);
                println!(
                    "NUM_TO_IGNORE: {:#?}, TOTAL_MEASURED_PKT: {:#?}, pkt_count: {:#?}",
                    NUM_TO_IGNORE, TOTAL_MEASURED_PKT, pkt_count
                );
            }

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
                if xcdr_param.inst {
                    w.push(end);
                }
            }
        })
        .reset()
        .compose();

    merge(vec![groups.get_group(0).unwrap().compose(), tlsv_pipe, xcdr_pipe]).compose()
}
