//! Utils functions for the PVN Transcoder NF.
use serde_json::{from_reader, Value};
use std::collections::HashMap;
use std::fs::File;
use std::time::Instant;

/// Read setup for transcoder NF. This function returns <setup, port, expr number>.
///
/// We need to get the port number for faktory queue besides the setup value.
pub fn xcdr_read_setup(file_path: String) -> Option<(usize, String, String, bool)> {
    let file = File::open(file_path).expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let setup: Option<String> = match serde_json::from_value(json.get("setup").expect("file should have setup").clone())
    {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    let port: Option<String> = match serde_json::from_value(json.get("port").expect("file should have port").clone()) {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    let expr_num: Option<String> =
        match serde_json::from_value(json.get("expr_num").expect("file should have expr_num").clone()) {
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

    if port.is_some() && setup.is_some() && expr_num.is_some() && inst_val.is_some() {
        return Some((
            setup.unwrap().parse::<usize>().unwrap(),
            port.unwrap().to_string(),
            expr_num.unwrap().to_string(),
            inst_val.unwrap(),
        ));
    } else {
        println!("Setup: {:?} and Port: {:?} have None values", setup, port);
        return None;
    }
}

/// Return the time span between submitting jobs to the faktory job queue
/// based on the setup value for running transcoder experiments.
///
/// 50 videos per second -- 1% pktgen sending rate
/// 100 videos per second -- 2% pktgen sending rate
/// 500 videos per second -- 10% pktgen sending rate
/// 1000 videos per second -- 20% pktgen sending rate
/// 2500 videos per second -- 50% pktgen sending rate
/// 5000 videos per second -- 100% pktgen sending rate
pub fn xcdr_inst_retrieve_param(setup_val: usize) -> Option<u128> {
    let mut time_span = 0;
    let mut map = HashMap::new();
    map.insert(1, 50);
    map.insert(2, 100);
    map.insert(3, 500);
    map.insert(4, 1000);
    map.insert(5, 2500);
    map.insert(6, 5000);

    if setup_val <= 3 {
        // maps to milli second
        time_span = 1_000 / map.remove(&setup_val).unwrap();
        println!("setup: {:?} maps to time span: {:?} millisecond", setup_val, time_span);
    } else if 3 < setup_val && setup_val <= 6 {
        // maps to micro second
        time_span = 1_000_000 / map.remove(&setup_val).unwrap();
        println!("setup: {:?} maps to time span: {:?} microsecond", setup_val, time_span);
    } else {
        println!("setup value doesn't match to a valid param");
    }

    Some(time_span as u128)
}

/// Return the time span between submitting jobs to the faktory job queue
/// based on the setup value for running transcoder experiments.
///
/// We configure the number of users per setup: 10, 20, 50, 100, 150, 200. We
/// calculate the time duration between submitted jobs as follows:
///     jobs_submitted_per_second = (number_of_users * 12MB/second) / video_unit [10MB]
///     duration = 1 second [1000 milliseconds] / jobs_submitted_per_second
pub fn xcdr_retrieve_param(setup_val: usize) -> Option<u128> {
    let mut map = HashMap::new();
    map.insert(1, 10);
    map.insert(2, 20);
    map.insert(3, 40);
    map.insert(4, 80);
    map.insert(5, 100);
    map.insert(6, 150);

    let jobs_submitted_per_second = map.remove(&setup_val).unwrap() * 12 / 10;
    let time_span = 1_000 / jobs_submitted_per_second;
    println!(
        "setup: {:?} maps to time span: {:?} millisecond",
        setup_val, time_span as u128
    );

    Some(time_span as u128)
}

/// Wrapper for counting time elapsed.
pub fn pvn_elapsed_deprecated(setup_val: usize, now: Instant) -> Option<u128> {
    if setup_val <= 3 {
        // maps to milli second
        let t = now.elapsed().as_millis();
        // println!("time elapsed: {:?} millisecond", t);
        Some(t)
    } else if 3 < setup_val && setup_val <= 6 {
        // maps to micro second
        let t = now.elapsed().as_micros();
        // println!("time elapsed: {:?} mi", t);
        Some(t)
    } else {
        println!("setup value doesn't match to a valid param");
        None
    }
}
