//! Utils functions for the PVN P2P NF.
use crate::pvn::measure::read_setup_param;
use serde_json::{from_reader, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::Result;

fn construct_p2p_workload() -> Option<(
    HashMap<&'static str, String>,
    HashMap<&'static str, String>,
    HashMap<&'static str, String>,
)> {
    let mut p2p_ext_map: HashMap<&str, String> = HashMap::new();
    let single_wl = "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-";
    p2p_ext_map.insert("11", single_wl.clone().to_owned() + "1.json");
    p2p_ext_map.insert("12", single_wl.clone().to_owned() + "2.json");
    p2p_ext_map.insert("13", single_wl.clone().to_owned() + "3.json");
    p2p_ext_map.insert("14", single_wl.clone().to_owned() + "4.json");
    p2p_ext_map.insert("15", single_wl.clone().to_owned() + "5.json");
    p2p_ext_map.insert("16", single_wl.clone().to_owned() + "6.json");
    p2p_ext_map.insert("17", single_wl.clone().to_owned() + "7.json");
    p2p_ext_map.insert("18", single_wl.clone().to_owned() + "8.json");
    p2p_ext_map.insert("19", single_wl.clone().to_owned() + "9.json");
    p2p_ext_map.insert("20", single_wl.to_owned() + "10.json");

    let mut p2p_controlled_map: HashMap<&str, String> = HashMap::new();
    let control_wl = "/home/jethros/dev/pvn/utils/workloads/p2p_controlled_workload.json";
    p2p_controlled_map.insert("1", control_wl.to_owned());
    p2p_controlled_map.insert("2", control_wl.to_owned());
    p2p_controlled_map.insert("3", control_wl.to_owned());
    p2p_controlled_map.insert("4", control_wl.to_owned());
    p2p_controlled_map.insert("5", control_wl.to_owned());
    p2p_controlled_map.insert("6", control_wl.to_owned());

    let mut p2p_general_map: HashMap<&str, String> = HashMap::new();
    let p2p_wl = "/home/jethros/dev/pvn/utils/workloads/p2p-workload.json";
    p2p_general_map.insert("1", p2p_wl.to_owned());
    p2p_general_map.insert("2", p2p_wl.to_owned());
    p2p_general_map.insert("3", p2p_wl.to_owned());
    p2p_general_map.insert("4", p2p_wl.to_owned());
    p2p_general_map.insert("5", p2p_wl.to_owned());
    p2p_general_map.insert("6", p2p_wl.to_owned());

    Some((p2p_ext_map, p2p_controlled_map, p2p_general_map))
}

fn construct_p2p_job() -> Option<(HashMap<usize, usize>, HashMap<usize, usize>, HashMap<usize, usize>)> {
    let mut p2p_ext_map: HashMap<usize, usize> = HashMap::new();
    let mut p2p_controlled_map: HashMap<usize, usize> = HashMap::new();
    let mut p2p_general_map: HashMap<usize, usize> = HashMap::new();

    p2p_ext_map.insert(11, 1);
    p2p_ext_map.insert(12, 1);
    p2p_ext_map.insert(13, 1);
    p2p_ext_map.insert(14, 1);
    p2p_ext_map.insert(15, 1);
    p2p_ext_map.insert(16, 1);
    p2p_ext_map.insert(17, 1);
    p2p_ext_map.insert(18, 1);
    p2p_ext_map.insert(19, 1);
    p2p_ext_map.insert(20, 1);

    p2p_controlled_map.insert(1, 1);
    p2p_controlled_map.insert(2, 2);
    p2p_controlled_map.insert(3, 4);
    p2p_controlled_map.insert(4, 6);
    p2p_controlled_map.insert(5, 8);
    p2p_controlled_map.insert(6, 10);

    p2p_general_map.insert(1, 1);
    p2p_general_map.insert(2, 10);
    p2p_general_map.insert(3, 50);
    p2p_general_map.insert(4, 100);
    p2p_general_map.insert(5, 150);
    p2p_general_map.insert(6, 200);

    Some((p2p_ext_map, p2p_controlled_map, p2p_general_map))
}

/// Get the number of torrents for the current p2p experiments.
///
/// 1 torrent job in total -- 3% pktgen sending rate
/// 5 torrent job in total -- 13% pktgen sending rate
/// 10 torrent job in total -- 25% pktgen sending rate
/// 20 torrent job in total -- 50% pktgen sending rate
/// 30 torrent job in total -- 75% pktgen sending rate
/// 40 torrent job in total -- 100% pktgen sending rate
pub fn p2p_retrieve_param(fp_setup: String) -> Option<usize> {
    println!("fetch param");
    let p2p_type = p2p_read_type(fp_setup.clone()).unwrap();
    let param = read_setup_param(fp_setup).unwrap();

    let (mut p2p_ext_map, mut p2p_controlled_map, mut p2p_general_map) = construct_p2p_job().unwrap();

    println!("type: {}, setup: {}, iter: {}", p2p_type, param.setup, param.iter);
    match &*p2p_type {
        "app_p2p-controlled" => return p2p_controlled_map.remove(&param.setup),
        "app_p2p" => return p2p_general_map.remove(&param.setup),
        "app_p2p-ext" => return p2p_general_map.remove(&param.setup),
        // chain
        "chain_rdr_p2p" => {
            return p2p_controlled_map.remove(&param.setup);
        }
        "chain_tlsv_p2p" => {
            return p2p_controlled_map.remove(&param.setup);
        }
        "chain_xcdr_p2p" => {
            return p2p_controlled_map.remove(&param.setup);
        }
        // coresident
        "co_tlsv_rdr_p2p" => {
            return p2p_controlled_map.remove(&param.setup);
        }
        "co_tlsv_p2p_xcdr" => {
            return p2p_controlled_map.remove(&param.setup);
        }
        "co_rdr_xcdr_p2p" => {
            return p2p_controlled_map.remove(&param.setup);
        }
        "co_tlsv_rdr_p2p_xcdr" => {
            return p2p_controlled_map.remove(&param.setup);
        }
        _ => {
            println!("\tP2P type: {:?} doesn't match to any param.", p2p_type);
            return None;
        }
    }
}

/// Retrieve the p2p type param in the pvn setup config file.
pub fn p2p_read_type(fp_setup: String) -> Option<String> {
    println!("p2p read type: {}", fp_setup);
    let file = File::open(fp_setup.clone()).expect("file should open read only");
    let read_json = fp_setup + "should be proper JSON";
    let json_data: Value = from_reader(file).expect(&read_json);

    let p2p_type: Option<String> =
        match serde_json::from_value(json_data.get("p2p_type").expect("file should have setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response for p2p_type: {}", e);
                None
            }
        };
    p2p_type
}

/// Retrieve the corresponding workload based on pvn setup config file.
pub fn p2p_fetch_workload(fp_setup: String) -> Option<String> {
    println!("fetch worklaod");
    let (mut p2p_ext_map, mut p2p_controlled_map, mut p2p_general_map) = construct_p2p_workload().unwrap();

    // load setup param
    let file = File::open(fp_setup.clone()).expect("file should open read only");
    let read_json = fp_setup + "should be proper JSON";
    let json_data: Value = from_reader(file).expect(&read_json);

    let setup: Option<String> =
        match serde_json::from_value(json_data.get("setup").expect("file should have setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response for setup: {}", e);
                None
            }
        };

    let p2p_type: Option<String> =
        match serde_json::from_value(json_data.get("p2p_type").expect("file should have setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response for p2p_type: {}", e);
                None
            }
        };

    match p2p_type.clone().unwrap().as_ref() {
        "app_p2p-ext" => {
            println!("Got p2p_ext");
            return p2p_ext_map.remove(&*setup.unwrap());
        }
        "app_p2p-controlled" => {
            println!("\tworkload: Got p2p_controlled");
            return p2p_controlled_map.remove(&*setup.unwrap());
        }
        "app_p2p" => {
            println!("Got p2p_general");
            return p2p_general_map.remove(&*setup.unwrap());
        }
        // chain
        "chain_rdr_p2p" => {
            return p2p_controlled_map.remove(&*setup.unwrap());
        }
        "chain_tlsv_p2p" => {
            return p2p_controlled_map.remove(&*setup.unwrap());
        }
        "chain_xcdr_p2p" => {
            return p2p_controlled_map.remove(&*setup.unwrap());
        }
        // coresident
        "co_tlsv_rdr_p2p" => {
            return p2p_controlled_map.remove(&*setup.unwrap());
        }
        "co_tlsv_p2p_xcdr" => {
            return p2p_controlled_map.remove(&*setup.unwrap());
        }
        "co_rdr_xcdr_p2p" => {
            return p2p_controlled_map.remove(&*setup.unwrap());
        }
        "co_tlsv_rdr_p2p_xcdr" => {
            return p2p_controlled_map.remove(&*setup.unwrap());
        }
        &_ => {
            println!("\tP2P type: {:?}, unable to fetch workload", p2p_type.unwrap());
            return None;
        }
    }
}

/// Parse the given p2p json workload.
pub fn p2p_load_json(fp_workload: String, _p2p_torrents: Vec<i64>) -> Vec<String> {
    let file = File::open(fp_workload).expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let torrent_files = json.get("torrents_files").expect("file should have time key").clone();

    let torrents: Vec<String> = serde_json::from_value(torrent_files).unwrap();
    torrents
}

/// Retrieve the p2p random seed from rand_seed file.
pub fn p2p_read_rand_seed(num_of_torrents: usize, iter: String, p2p_type: String) -> Result<Vec<i64>> {
    println!("num_of_torrents: {:?}, iter: {:?}", num_of_torrents, iter);
    let rand_seed_file = "/home/jethros/dev/pvn/utils/rand_number/rand.json";
    let mut rand_vec = Vec::new();
    let file = File::open(rand_seed_file).expect("rand seed file should open read only");
    let json_data: Value = from_reader(file).expect("file should be proper JSON");

    match json_data.get(p2p_type) {
        Some(p2p_data) => match p2p_data.get(&num_of_torrents.clone().to_string()) {
            Some(setup_data) => match setup_data.get(iter.clone()) {
                Some(data) => {
                    for x in data.as_array().unwrap() {
                        rand_vec.push(x.as_i64().unwrap() + 1);
                        println!("P2P torrent: {:?}", x.as_i64().unwrap() + 1);
                    }
                }
                None => println!("No rand data for iter {:?} for torrent {:?}", iter, num_of_torrents),
            },
            None => println!("No rand data for torrents {:?}", num_of_torrents),
        },
        None => println!("No p2p data in the rand seed file"),
    }
    Ok(rand_vec)
}
