//! Utils functions for measuring the PVN NFs.
use crate::utils::Flow;
use serde_json::{from_reader, Value};
use statrs::statistics::OrderStatistics;
use statrs::statistics::Variance;
use statrs::statistics::{Max, Mean, Median, Min};
use std::collections::HashMap;
use std::fs::File;
use std::time::Instant;

/// Epsilon.
pub const EPSILON: usize = 1000;
/// Number of packets to ignore before starting measurement. Currently deprecated.
pub const NUM_TO_IGNORE: usize = 0;
/// Estimated number of packets for allocating large size array.
pub const TOTAL_MEASURED_PKT: usize = 100_000_000;
// pub const TOTAL_MEASURED_PKT: usize = 300_000_000;

/// Time for the Inst experiment.
pub const INST_MEASURE_TIME: u64 = 601;
// pub const INST_MEASURE_TIME: u64 = 60;
/// Time for the App experiment.
pub const APP_MEASURE_TIME: u64 = 610;

/// Fake flow when retrieving flow failed.
pub fn fake_flow() -> Flow {
    Flow {
        src_ip: 0 as u32,
        dst_ip: 0 as u32,
        src_port: 0 as u16,
        dst_port: 0 as u16,
        proto: 0 as u8,
    }
}

/// Read various params from setup.
///
/// Currently returns: *setup* (which setup it is), *iter* (which iteration it
/// is), and *inst* (instrumentation for retrieving latencies for every packet).
pub fn read_setup_param(file_path: String) -> Option<(String, String, bool)> {
    let file = File::open(file_path.clone()).expect("file should open read only");
    let read_json = file_path + "should be proper JSON";
    let json: Value = from_reader(file).expect(&read_json);

    let setup: Option<String> = match serde_json::from_value(json.get("setup").expect("file should have setup").clone())
    {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    let iter: Option<String> = match serde_json::from_value(json.get("iter").expect("file should have setup").clone()) {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    let inst: Option<String> = match serde_json::from_value(json.get("inst").expect("file should have setup").clone()) {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };
    let inst_val = match &*inst.unwrap() {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    };

    if setup.is_some() && iter.is_some() && inst_val.is_some() {
        println!("Setup: {:?}, Iter: {:?}, Inst mode: {:?}", setup, iter, inst_val);
        Some((setup.unwrap(), iter.unwrap(), inst_val.unwrap()))
    } else {
        None
    }
}

/// Merge all the timestamps we have and generate meaningful latencies for each
/// packet.
///
/// The current implementation just works so please don't touch the code unless
/// you have time to verify the correctness.
pub fn merge_ts(
    total_measured_pkt: usize,
    stop_ts_matched: Vec<Instant>,
    stop_ts_not_matched: HashMap<usize, Instant>,
) -> HashMap<usize, Instant> {
    let mut actual_ts = HashMap::<usize, Instant>::with_capacity(total_measured_pkt);
    let mut not_matched_c = 0;

    for pivot in 1..total_measured_pkt + 1 {
        if stop_ts_not_matched.contains_key(&pivot) {
            // non tcp ts
            let item = stop_ts_not_matched.get(&pivot).unwrap();
            actual_ts.insert(pivot - 1, *item);
            // println!("INSERT: pivot: {:?} is {:?}", pivot - 1, *item);
            not_matched_c += 1;
        } else {
            // NOTE: we need this early stop because of the drifting behavior in groupby operations
            if pivot - not_matched_c - 1 == stop_ts_matched.len() {
                println!("merging finished!",);
                return actual_ts;
            }
            actual_ts.insert(pivot - 1, stop_ts_matched[pivot - not_matched_c - 1]);
        }
    }

    println!("This should never be reached!",);
    actual_ts
}

/// Compute statistics for the latency results collected.
pub fn compute_stat(mut tmp_results: Vec<u128>) {
    tmp_results.sort();
    let mut results: Vec<f64> = tmp_results.into_iter().map(|item| item as f64).collect();
    let bar = results.percentile(99);
    let (rest, mut results): (_, Vec<_>) = results.into_iter().partition(|x| x >= &bar);
    println!("sorting and then type casting done",);

    println!("Details of the results in rest",);
    let mut count1 = 0;
    let chunk_size1 = rest.len() / 100 + 1;
    //generate 100 groups
    for chunk in rest.chunks(chunk_size1) {
        println!(
            "Rest_group {:?}, median: {:02?}, mean: {:02?}, std dev: {:02?}",
            count1,
            chunk.median(),
            chunk.mean(),
            chunk.std_dev()
        );
        count1 += 1;
    }

    println!("Details of the results in main",);
    let mut count = 0;
    let chunk_size = results.len() / 100 + 1;
    //generate 100 groups
    for chunk in results.chunks(chunk_size) {
        println!(
            "Group {:?}, median: {:02?}, mean: {:02?}, std dev: {:02?}",
            count,
            chunk.median(),
            chunk.mean(),
            chunk.std_dev()
        );
        count += 1;
    }

    let min = results.min();
    let max = results.max();
    println!(
        "Stat_extra, mean: {:?}, median: {:?}, std: {:?}, 90%iles: {:?}, 95%iles: {:?}, ",
        results.mean(),
        results.median(),
        results.std_dev(),
        results.percentile(90),
        results.percentile(95),
    );
    println!(
        "Stat, min: {:?}, 25%iles: {:?}, 50%iles: {:?}, 75%iles: {:?}, max: {:?}",
        min,
        results.percentile(25),
        results.percentile(50),
        results.percentile(75),
        max,
    );
}
