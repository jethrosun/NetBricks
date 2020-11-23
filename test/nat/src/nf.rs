use e2d2::headers::{IpHeader, MacHeader, NullHeader};
use e2d2::operators::{Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::scheduler::Scheduler;
use e2d2::utils::{ipv4_extract_flow, Flow};
use fnv::FnvHasher;
use std::collections::HashMap;
use std::convert::From;
use std::hash::BuildHasherDefault;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct Unit;

#[derive(Clone, Copy, Default)]
struct FlowUsed {
    pub flow: Flow,
    pub time: u64,
    pub used: bool,
}

type FnvHash = BuildHasherDefault<FnvHasher>;

pub fn nat<T: 'static + Batch<Header = NullHeader>>(
    parent: T,
    _s: &mut dyn Scheduler,
    nat_ip: &Ipv4Addr,
) -> CompositionBatch {
    // Measurement code

    // pkt count
    let mut pkt_count = 0;

    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON)));
    let start1 = Arc::clone(&start_ts);
    let start2 = Arc::clone(&start_ts);
    let mut stop_ts = Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON);

    let ip = u32::from(*nat_ip);
    let mut port_hash = HashMap::<Flow, Flow, FnvHash>::with_capacity_and_hasher(65536, Default::default());
    let mut flow_vec: Vec<FlowUsed> = (MIN_PORT..65535).map(|_| Default::default()).collect();
    let mut next_port = 1024;
    const MIN_PORT: u16 = 1024;
    const MAX_PORT: u16 = 65535;
    let now = Instant::now();

    let pipeline = parent
        .transform(box move |_| {
            // first time access start_ts, need to insert timestamp
            pkt_count += 1;
            if pkt_count > NUM_TO_IGNORE {
                let now = Instant::now();
                let mut w = start1.lock().unwrap();
                // println!("START insert for pkt count {:?}: {:?}", pkt_count, now);
                w.push(now);
            }
        })
        .parse::<MacHeader>()
        .transform(box move |pkt| {
            // FIXME: this part might crash if the replayed trace satisfies some condition, need to
            // fix
            //
            // let f = pkt.get_header().flow().clone().unwrap();
            let payload = pkt.get_mut_payload();

            // wrap the nat part around since we only have ipv4_extract_flow
            // if f.proto == 4 {
            if let Some(flow) = ipv4_extract_flow(payload) {
                let found = match port_hash.get(&flow) {
                    Some(s) => {
                        s.ipv4_stamp_flow(payload);
                        true
                    }
                    None => false,
                };
                if !found && next_port < MAX_PORT {
                    let assigned_port = next_port; //FIXME.
                    next_port += 1;
                    flow_vec[assigned_port as usize].flow = flow;
                    flow_vec[assigned_port as usize].used = true;
                    let mut outgoing_flow = flow;
                    outgoing_flow.src_ip = ip;
                    outgoing_flow.src_port = assigned_port;
                    let rev_flow = outgoing_flow.reverse_flow();

                    port_hash.insert(flow, outgoing_flow);
                    port_hash.insert(rev_flow, flow.reverse_flow());

                    outgoing_flow.ipv4_stamp_flow(payload);
                }
            }
            // }

            pkt_count += 1;

            if now.elapsed().as_secs() == SHORT_MEASURE_TIME {
                // if pkt_count == TOTAL_MEASURED_PKT + NUM_TO_IGNORE {
                let now = Instant::now();
                // println!("STOP pkt # {:?}, stop time {:?}", pkt_count, now);
                stop_ts.push(now);

                println!("\npkt count {:?}", pkt_count);
                let mut total_time = Duration::new(0, 0);
                let start = start2.lock().unwrap();
                println!("# of start ts: {:?}, # of stop ts: {:?}", start.len(), stop_ts.len());
                // assert_ge!(w.len(), stop_ts.len());
                let num = stop_ts.len();

                println!("Latency results start: {:?}", num);
                let mut tmp_results = Vec::<u128>::with_capacity(num);
                for i in 0..num {
                    let since_the_epoch = stop_ts[i].duration_since(start[i]);
                    // total_time = total_time + since_the_epoch;
                    // print!("{:?}", since_the_epoch);
                    tmp_results.push(since_the_epoch.as_nanos());
                }
                compute_stat(tmp_results);
                println!("Latency results end",);
                // println!("start to reset: avg processing time is {:?}", total_time / num as u32);
            }

            if pkt_count > NUM_TO_IGNORE {
                if pkt_count == TOTAL_MEASURED_PKT + NUM_TO_IGNORE {
                } else {
                    let now = Instant::now();
                    // println!("STOP pkt # {:?}, stop time {:?}", pkt_count, now);
                    stop_ts.push(now);
                }
            }
        });
    pipeline.compose()
}
