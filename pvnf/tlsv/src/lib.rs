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

use self::utils::{do_client_key_exchange, get_server_name, on_frame, tlsf_update};
use e2d2::allocators::CacheAligned;

use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::interface::*;
use e2d2::operators::{Batch, CompositionBatch, ReceiveBatch};
use e2d2::pvn::measure::*;
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use rustls::internal::msgs::handshake::HandshakePayload::{ClientHello, ClientKeyExchange, ServerHello};
use std::collections::{HashMap, HashSet};

use std::sync::{Arc, Mutex};

use std::time::{Duration, Instant};

pub mod utils;

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
        .map(|port| validator(ReceiveBatch::new(port.clone())).send(port.clone()))
        .collect();

    println!("Running {} pipelines", pipelines.len());

    // schedule pipelines
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}

// pub fn validator<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
//     parent: T,
//     sched: &mut S,
// ) -> CompositionBatch
pub fn validator<T: 'static + Batch<Header = NullHeader>>(parent: T) -> CompositionBatch {
    let (_, _, inst) = read_setup_param("/home/jethros/setup".to_string()).unwrap();
    let mut metric_exec = true;

    // New payload cache.
    //
    // Here impl the new data structure for handling reassembling packets in TCP. Note that it is a
    // naive implementation of TCP out-of-order segments, for a more comprehensive version you
    // should visit something like [assembler in
    // smoltcp](https://github.com/m-labs/smoltcp/blob/master/src/storage/assembler.rs) and [ring
    // buffer](https://github.com/m-labs/smoltcp/blob/master/src/storage/ring_buffer.rs#L238-L333)
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
    // pkt count
    let mut pkt_count = 0;

    // Measurement code
    //
    // start timestamps will be a vec protected with arc and mutex.
    let start_ts_1 = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON)));
    let stop_ts_non_tcp = Arc::new(Mutex::new(HashMap::<usize, Instant>::with_capacity(
        TOTAL_MEASURED_PKT + EPSILON,
    )));
    let mut stop_ts_tcp: Vec<Instant> = Vec::with_capacity(TOTAL_MEASURED_PKT + EPSILON);

    let t1_1 = Arc::clone(&start_ts_1);
    let t1_2 = Arc::clone(&start_ts_1);
    let t2_1 = Arc::clone(&stop_ts_non_tcp);
    let t2_2 = Arc::clone(&stop_ts_non_tcp);

    let measure_time = if inst { INST_MEASURE_TIME } else { APP_MEASURE_TIME };

    let now = Instant::now();

    // group packets into MAC, TCP and UDP packet.
    parent
        .transform(box move |p| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                let end = Instant::now();
                if inst {
                    w.push(end);
                }
            }

            // p.get_mut_header().swap_addresses();
            p.get_mut_header();
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

            let flow = p.read_metadata();

            if flow.proto == 6 {
                matched = true;
            }

            if matched {
                let rev_flow = flow.reverse_flow();
                let _seq = p.get_header().seq_num();
                let _tcph = p.get_header();
                let _payload_size = p.payload_size();

                // FIXME: The else part should be written as a filter and it should exec before all these..
                if !unsafe_connection.contains(&flow) {
                    // eprintln!("DEBUE: matchit",);
                    // check if the flow is recognized
                    if payload_cache.contains_key(&flow) {
                        info!("Pkt #{} is Occupied!", _seq);
                        info!("And the flow is: {:?}", flow);

                        // The rest of the TLS server hello handshake should be captured here.
                        info!("There is nothing, that is why we should insert the packet!!!");
                        debug!(
                            "Pkt seq # is {}, the expected seq # is {} ",
                            _seq,
                            seqnum_map.get(&flow).unwrap()
                        );
                        // Check if this packet is not expected, ie, is a out of order segment.
                        if _seq == *seqnum_map.get(&flow).unwrap() {
                            // We received an expected packet
                            debug!("Pkt match expected seq #, update the flow entry...");
                            //debug!("{:?}", p.get_payload());
                            tlsf_update(*flow, payload_cache.entry(*flow), &p.get_payload());
                            seqnum_map.entry(*flow).and_modify(|e| {
                                *e = *e + _payload_size as u32;
                                ()
                            });
                        } else if _seq > *seqnum_map.get(&flow).unwrap() {
                            // We received a out-of-order TLS segment
                            debug!("OOO: pkt seq # is larger then expected seq #\n");
                            // We need to check if we should update the entry in the tmp payload cache
                            if tmp_payload_cache.contains_key(&flow) {
                                debug!("OOO: we already have entry in the tmp payload cache");
                                // Check if we should update the entry in the tmp payload cache
                                let (_, entry_expected_seqno) = *tmp_seqnum_map.get(&flow).unwrap();
                                if _seq == entry_expected_seqno {
                                    debug!("OOO: seq # of current pkt matches the expected seq # of the entry in tpc");
                                    tlsf_update(*flow, tmp_payload_cache.entry(*flow), &p.get_payload());
                                    tmp_seqnum_map.entry(*flow).and_modify(|(_, entry_expected_seqno)| {
                                        *entry_expected_seqno = *entry_expected_seqno + _payload_size as u32;
                                    });
                                } else {
                                    info!("Oops: passing because it should be a unrelated packet");
                                }
                            } else {
                                debug!("OOO: We are adding an entry in the tpc!");
                                tmp_seqnum_map.insert(*flow, (_seq, _seq + _payload_size as u32));
                                tmp_payload_cache.insert(*flow, p.get_payload().to_vec());
                            }
                        } else {
                            debug!("Oops: pkt seq # is even smaller then the expected #");
                        }
                    } else {
                        // eprintln!("DEBUE: not matchit",);
                        info!("Pkt #{} is Vacant", _seq);
                        info!("And the flow is: {:?}", flow);

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
                                        debug!("Got ServerHello, insert the flow entry");
                                        seqnum_map.insert(*flow, _seq + _payload_size as u32);
                                        payload_cache.insert(*flow, p.get_payload().to_vec());
                                    }
                                    ClientKeyExchange(_) => {
                                        let dns_name = name_cache.remove(&rev_flow);
                                        match dns_name {
                                            Some(name) => do_client_key_exchange(
                                                name,
                                                &flow,
                                                &rev_flow,
                                                &mut cert_count,
                                                &mut unsafe_connection,
                                                &mut tmp_payload_cache,
                                                &mut tmp_seqnum_map,
                                                &mut payload_cache,
                                                &mut seqnum_map,
                                            ),
                                            None => info!("We are missing the dns name from the client hello",),
                                        }
                                    }
                                    _ => info!("Other kinds of payload",),
                                }
                            }
                            None => info!("Get none for matching payload",),
                        }
                        // eprintln!("DEBUG: Match on_frame done");
                    }
                } else {
                    // Disabled for now, we can enable it when we are finished.

                    // info!("Pkt #{} belong to a unsafe flow!\n", _seq);
                    // info!("{:?} is marked as unsafe connection so we have to reset\n", flow);
                    // let _ = unsafe_connection.take(flow);
                    // let tcph = p.get_mut_header();
                    // tcph.set_rst_flag();
                }

                if pkt_count > NUM_TO_IGNORE {
                    let end = Instant::now();
                    if inst {
                        stop_ts_tcp.push(end);
                    }
                }
            } else {
                if pkt_count > NUM_TO_IGNORE {
                    let mut w = t2_1.lock().unwrap();
                    if inst {
                        w.insert(pkt_count - NUM_TO_IGNORE, Instant::now());
                    }
                }
            }

            pkt_count += 1;

            if pkt_count == NUM_TO_IGNORE {
                println!("\nMeasurement started ",);
                println!(
                    "NUM_TO_IGNORE: {:#?}, TOTAL_MEASURED_PKT: {:#?}, pkt_count: {:#?}",
                    NUM_TO_IGNORE, TOTAL_MEASURED_PKT, pkt_count
                );
            }

            if now.elapsed().as_secs() >= measure_time && metric_exec == true {
                println!("pkt count {:?}", pkt_count);
                // let mut total_duration = Duration::new(0, 0);
                let _total_time1 = Duration::new(0, 0);
                let w1 = t1_2.lock().unwrap();
                let w2 = t2_2.lock().unwrap();
                println!(
                    "# of start ts\n w1 {:#?}, hashmap {:#?}, # of stop ts: {:#?}",
                    w1.len(),
                    w2.len(),
                    stop_ts_tcp.len(),
                );
                let actual_stop_ts = merge_ts(pkt_count - 1, stop_ts_tcp.clone(), w2.clone());
                let num = actual_stop_ts.len();
                println!(
                    "stop ts tcp len: {:?}, actual_stop_ts len: {:?}",
                    stop_ts_tcp.len(),
                    actual_stop_ts.len()
                );

                println!("Latency results start: {:?}", num);
                let mut tmp_results = Vec::<u128>::with_capacity(num);
                for i in 0..num {
                    let stop = actual_stop_ts.get(&i).unwrap();
                    let since_the_epoch = stop.checked_duration_since(w1[i]).unwrap();
                    // print!("{:?}, ", since_the_epoch1);
                    // total_time1 = total_time1 + since_the_epoch1;
                    tmp_results.push(since_the_epoch.as_nanos());
                }
                compute_stat(tmp_results);
                println!("\nLatency results end",);
                metric_exec = false;
            }
        })
        .compose()
}
