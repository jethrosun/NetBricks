use e2d2::headers::{MacHeader, NullHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::scheduler::Scheduler;
use e2d2::utils::ipv4_flow_hash;
use fnv::FnvHasher;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use twox_hash::XxHash;

type FnvHash = BuildHasherDefault<FnvHasher>;
type XxHashFactory = BuildHasherDefault<XxHash>;

struct Maglev {
    // permutation: Box<Vec<Vec<usize>>>,
    lut: Vec<usize>,
    lut_size: usize,
}

impl Maglev {
    pub fn offset_skip_for_name(name: &str, h1: &FnvHash, h2: &XxHashFactory, lsize: usize) -> (usize, usize) {
        let mut fnv_state = h1.build_hasher();
        name.hash(&mut fnv_state);
        let hash1 = fnv_state.finish() as usize;
        let mut xx_state = h2.build_hasher();
        name.hash(&mut xx_state);
        let hash2 = xx_state.finish() as usize;
        let offset = hash2 % lsize;
        let skip = hash1 % (lsize - 1) + 1;
        (offset, skip)
    }

    pub fn generate_permutations(backends: &[&str], lsize: usize) -> Vec<Vec<usize>> {
        println!("Generating permutations");
        let fnv_hasher: FnvHash = Default::default();
        let xx_hasher: XxHashFactory = Default::default();
        backends
            .iter()
            .map(|n| Maglev::offset_skip_for_name(n, &fnv_hasher, &xx_hasher, lsize))
            .map(|(offset, skip)| (0..lsize).map(|j| (offset + j * skip) % lsize).collect())
            .collect()
    }

    fn generate_lut(permutations: &[Vec<usize>], size: usize) -> Vec<usize> {
        let mut next: Vec<_> = permutations.iter().map(|_| 0).collect();
        let mut entry: Box<Vec<usize>> = box ((0..size).map(|_| 0x8000).collect());
        let mut n = 0;
        println!("Generating LUT");
        while n < size {
            for i in 0..next.len() {
                let mut c = permutations[i][next[i]];
                while entry[c] != 0x8000 {
                    next[i] += 1;
                    c = permutations[i][next[i]];
                }
                if entry[c] == 0x8000 {
                    entry[c] = i;
                    next[i] += 1;
                    n += 1;
                }
                if n >= size {
                    break;
                }
            }
        }
        println!("Done Generating LUT");
        entry.to_vec()
    }

    pub fn new(name: &[&str], lsize: usize) -> Maglev {
        let permutations = box Maglev::generate_permutations(name, lsize);
        Maglev {
            lut: Maglev::generate_lut(&*permutations, lsize),
            lut_size: lsize,
        }
    }

    pub fn lookup(&self, hash: usize) -> usize {
        let idx = hash % self.lut_size;
        self.lut[idx]
    }
}

pub fn maglev<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    s: &mut S,
    backends: &[&str],
) -> CompositionBatch {
    // Measurement code

    // pkt count
    let mut pkt_count = 0;

    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON)));
    let start1 = Arc::clone(&start_ts);
    let start2 = Arc::clone(&start_ts);
    let mut stop_ts = Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON);

    let now = Instant::now();

    let ct = backends.len();
    let lut = Maglev::new(backends, 65537);
    let mut cache = HashMap::<usize, usize, FnvHash>::with_hasher(Default::default());
    let mut groups = parent
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
            assert!(pkt.refcnt() == 1);
            let hdr = pkt.get_mut_header();
            hdr.swap_addresses();
        })
        .group_by(
            ct,
            box move |pkt| {
                let payload = pkt.get_payload();
                let hash = ipv4_flow_hash(payload, 0);
                let out = cache.entry(hash).or_insert_with(|| lut.lookup(hash));
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
                        tmp_results.push(since_the_epoch.as_nanos());
                        // total_time = total_time + since_the_epoch;
                        // print!("{:?}, ", since_the_epoch);
                    }
                    println!("Latency results end",);
                    compute_stat(tmp_results);
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
                *out
            },
            s,
        );
    let pipeline = merge((0..ct).map(|i| groups.get_group(i).unwrap()).collect());
    pipeline.compose()
}
