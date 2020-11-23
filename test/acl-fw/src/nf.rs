use e2d2::headers::{IpHeader, MacHeader, NullHeader};
use e2d2::operators::{Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::utils::{Flow, Ipv4Prefix};
use fnv::FnvHasher;
use std::collections::HashSet;
use std::hash::BuildHasherDefault;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

type FnvHash = BuildHasherDefault<FnvHasher>;

#[derive(Clone)]
pub struct Acl {
    pub src_ip: Option<Ipv4Prefix>,
    pub dst_ip: Option<Ipv4Prefix>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub established: Option<bool>,
    // Related not done
    pub drop: bool,
}

impl Acl {
    pub fn matches(&self, flow: &Flow, connections: &HashSet<Flow, FnvHash>) -> bool {
        if (self.src_ip.is_none() || self.src_ip.unwrap().in_range(flow.src_ip))
            && (self.dst_ip.is_none() || self.dst_ip.unwrap().in_range(flow.dst_ip))
            && (self.src_port.is_none() || flow.src_port == self.src_port.unwrap())
            && (self.dst_port.is_none() || flow.dst_port == self.dst_port.unwrap())
        {
            if let Some(established) = self.established {
                let rev_flow = flow.reverse_flow();
                (connections.contains(flow) || connections.contains(&rev_flow)) == established
            } else {
                true
            }
        } else {
            false
        }
    }
}

pub fn acl_match<T: 'static + Batch<Header = NullHeader>>(parent: T, acls: Vec<Acl>) -> CompositionBatch {
    // Measurement code

    // pkt count
    let mut pkt_count = 0;

    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON)));
    let start1 = Arc::clone(&start_ts);
    let start2 = Arc::clone(&start_ts);
    let mut stop_ts = Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON);

    let now = Instant::now();

    let mut flow_cache = HashSet::<Flow, FnvHash>::with_hasher(Default::default());
    parent
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
        .transform(box move |p| {
            p.get_mut_header().swap_addresses();
        })
        .parse::<IpHeader>()
        .filter(box move |p| {
            let mut result = false;
            if let Some(flow) = p.get_header().flow() {
                for acl in &acls {
                    if acl.matches(&flow, &flow_cache) {
                        if !acl.drop {
                            flow_cache.insert(flow);
                        }
                        result = !acl.drop;
                    }
                }
            }

            pkt_count += 1;

            if now.elapsed().as_secs() == SHORT_MEASURE_TIME {
                // if pkt_count == TOTAL_MEASURED_PKT + NUM_TO_IGNORE {
                let now = Instant::now();
                // println!("STOP pkt # {:?}, stop time {:?}", pkt_count, now);
                stop_ts.push(now);

                println!("\npkt count {:?}", pkt_count);
                let start = start2.lock().unwrap();
                println!("# of start ts: {:?}, # of stop ts: {:?}", start.len(), stop_ts.len());
                // assert_ge!(w.len(), stop_ts.len());
                let num = stop_ts.len();
                println!("Latency results start: {:?}", num);

                let mut tmp_results = Vec::<u128>::with_capacity(num);
                for i in 0..num {
                    let since_the_epoch = stop_ts[i].duration_since(start[i]);
                    tmp_results.push(since_the_epoch.as_nanos());
                    // print!("{:?}", since_the_epoch);
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

            result
        })
        .compose()
}
