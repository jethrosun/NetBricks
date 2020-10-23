use dotenv::dotenv;
use fork::{daemon, Fork};
use futures::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
};
use std::env;
use std::env::var;
use std::error::Error;
use std::io::{self, Write};
use std::process::Command;
use transmission_rpc::types::{BasicAuth, Result, RpcResponse};
use transmission_rpc::types::{Id, Nothing, TorrentAction};
use transmission_rpc::types::{Torrent, TorrentGetField, Torrents};
use transmission_rpc::types::{TorrentAddArgs, TorrentAdded};
use transmission_rpc::TransClient;

///
pub fn create_transmission_client() -> Result<TransClient> {
    println!("debug: create transmission client");
    dotenv().ok();
    // env_logger::init();

    // setup session
    let url: String = env::var("TURL")?;
    let basic_auth = BasicAuth {
        user: env::var("TUSER")?,
        password: env::var("TPWD")?,
    };
    let client = TransClient::with_auth(&url, basic_auth);
    Ok(client)
}

///
pub async fn add_all_torrents(p2p_param: usize, mut workload: Vec<String>, torrents_dir: String) -> Result<()> {
    println!("debug: add all torrent to transmission client");
    let client = create_transmission_client().unwrap();
    let mut futures: FuturesUnordered<BoxFuture<Result<RpcResponse<TorrentAdded>>>> = FuturesUnordered::new();

    for (pos, t) in workload.iter().enumerate() {
        println!("Torrent at position {}: {:?}", pos, t);
        if pos >= p2p_param {
            println!("exiting with {}", pos);
            break;
        }
        // add torrent
        let add: TorrentAddArgs = TorrentAddArgs {
            filename: Some(torrents_dir.clone() + &t.to_string()),
            ..TorrentAddArgs::default()
        };

        futures.push(Box::pin(client.torrent_add(add)));
    }

    while let Some(result) = futures.next().await {
        match result {
            Ok(_) => println!("ok"),
            Err(e) => eprintln!("err {}", e),
        }
    }

    Ok(())
}

///
pub async fn run_all_torrents() -> Result<()> {
    println!("debug: run all torrent to transmission client");
    let client = create_transmission_client().unwrap();
    let res: RpcResponse<Torrents<Torrent>> = client
        .torrent_get(Some(vec![TorrentGetField::Id, TorrentGetField::Name]), None)
        .await?;
    let ids: Vec<Id> = res
        .arguments
        .torrents
        .iter()
        .map(|it| Id::Id(*it.id.as_ref().unwrap()))
        .collect();

    let res1: RpcResponse<Nothing> = client.torrent_action(TorrentAction::Start, ids).await?;
    println!("Start result: {:?}", &res1.is_ok());

    Ok(())
}

/// Run BitTorrent jobs via deluge console
pub fn bt_run_torrents_prev(workload: &str, num_of_torrents: usize) -> Result<Vec<std::process::Child>> {
    let mut bt_process = Vec::new();
    for i in 1..(num_of_torrents + 1) {
        let mut argv = Vec::new();
        argv.push("deluge-console".to_string());
        argv.push("-c".to_string());
        argv.push("/home/jethros/bt_data/config".to_string());

        let s = "add /home/jethros/dev/pvn/utils/workloads/torrent_files/p2p_image_".to_owned()
            + &i.to_string()
            + ".img.torrent";
        argv.push(s);

        let child = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .spawn()
            .expect("failed to start subprocess");
        bt_process.push(child);
    }

    Ok(bt_process)
}

/// Run BitTorrent jobs via deluge console
pub fn bt_run_torrents(workload: &str, setup: String) -> Result<()> {
    let mut argv = Vec::new();
    argv.push("/home/jethros/dev/pvn/utils/p2p_expr/p2p_run_nb.sh".to_string());
    argv.push(setup);
    // argv.push("&".to_string());

    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .spawn()
        .expect("failed to execute process");

    Ok(())
}

/// Run BitTorrent jobs via deluge console
pub fn bt_run_torrents_ng(workload: &str, setup: String) -> Result<()> {
    let mut argv = Vec::new();
    argv.push("/home/jethros/dev/pvn/utils/p2p_expr/p2p_run_nb.sh".to_string());
    argv.push(setup.to_string());

    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .expect("failed to execute process");

    println!("status: {}", output.status);
    io::stdout().write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stderr).unwrap();
    Ok(())
}
