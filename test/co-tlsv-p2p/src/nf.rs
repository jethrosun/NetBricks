use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::pvn::p2p::*;
use e2d2::pvn::rdr::*;
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use p2p::utils::*;
use rustls::internal::msgs::handshake::HandshakePayload::{ClientHello, ClientKeyExchange, ServerHello};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tlsv::utils::*;
use tokio::runtime::Runtime;

pub fn tlsv_p2p_test<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
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
                if p2p_param.inst {
                    w.push(end);
                }
            }
        })
        .parse::<MacHeader>()
        .parse::<IpHeader>()
        .metadata(box move |p| {
            let flow = p.get_header().flow().unwrap();
            flow
        })
        .parse::<TcpHeader>()
        .group_by(
            3,
            box move |p| {
                pkt_count += 1;
                let f = *p.read_metadata();

                // 0 means the packet doesn't match RDR or P2P
                let mut matched = 0;
                // NOTE: the following ip addr and port are hardcode based on the trace we are
                // replaying
                let match_ip = 180_907_852_u32; // 10.200.111.76
                let rdr_match_port = 443_u16;
                // https://wiki.wireshark.org/BitTorrent
                let p2p_match_port = vec![6346, 6882, 6881, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969];

                // warning: borrow of packed field is unsafe and requires unsafe function or block (error E0133)
                let src_port = f.src_port;
                let dst_port = f.dst_port;
                // Match RDR packets to group 1 and P2P packets to group 2, the rest to group 0
                if f.proto == 6 {
                    if (f.src_ip == match_ip || f.dst_ip == match_ip)
                        && (p2p_match_port.contains(&src_port) || p2p_match_port.contains(&dst_port))
                    {
                        matched = 2
                    } else {
                        matched = 1
                    }
                }

                if now.elapsed().as_secs() >= p2p_param.expr_time && latency_exec {
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
                    if p2p_param.inst {
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
                    // Check if this packet is not expected, ie, is a out of order segment.
                    match _seq.cmp(seqnum_map.get(&flow).unwrap()) {
                        Ordering::Equal => {
                            // We received an expected packet
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
                if p2p_param.inst {
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
                        let _ = bt_run_torrents(fp_workload, p2p_param.setup);

                        println!("bt run is not blocking");
                        workload_exec = false;
                    }
                    // use the transmission rpc for general and ext workload
                    "app_p2p" | "app_p2p-ext" => {
                        println!("match p2p general or ext ");
                        let p2p_torrents = p2p_read_rand_seed(num_of_torrents, p2p_param.iter.to_string()).unwrap();
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
                let mut w = t2_1.lock().unwrap();
                let end = Instant::now();
                if p2p_param.inst {
                    w.push(end);
                }
            }
        })
        .reset()
        .compose();

    merge(vec![groups.get_group(0).unwrap().compose(), tlsv_pipe, p2p_pipe]).compose()
}
