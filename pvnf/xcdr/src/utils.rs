use faktory::{Job};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};



/// Append job to a faktory queue.
pub fn append_job_faktory(
    pivot: u128,
    faktory_conn: Arc<Mutex<faktory::Producer<TcpStream>>>,
    core_id: usize,
    expr_num: &str,
) {
    let infile = "/home/jethros/dev/pvn/utils/data/tiny.y4m";
    let width_height = "360x24";
    let outfile = "/home/jethros/dev/pvn/utils/data/output_videos/".to_owned() + &pivot.to_string() + ".y4m";
    // println!(
    //     "faktory: {:?}",
    //     "app-xcdr_".to_owned() + &core_id.to_string() + "-" + expr_num,
    // );

    faktory_conn
        .lock()
        .unwrap()
        .enqueue(Job::new(
            "app-xcdr_".to_owned() + &core_id.to_string() + "-" + expr_num,
            // "app-xcdr_".to_owned() + expr_num,
            vec![infile.to_string(), outfile.to_string(), width_height.to_string()],
        ))
        .unwrap();
}
