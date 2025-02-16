use std::sync::Arc;

use clap::Parser;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use timeboost_utils::types::logging::init_logging;
use warp::Filter;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(long, short)]
    committee_size: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Node {
    id: u32,
    ip: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct Response {
    ready: bool,
    nodes: Vec<Node>,
}

#[tokio::main]
async fn main() {
    init_logging();

    let cli = Cli::parse();

    let committee = Arc::new(Mutex::new(Vec::new()));

    let committee_clone = Arc::clone(&committee);
    let start = warp::get().and(warp::path("start")).map(move || {
        let cc = committee_clone.lock();
        if cc.len() == cli.committee_size {
            warp::reply::json(&Response {
                ready: true,
                nodes: cc.to_vec(),
            })
        } else {
            warp::reply::json(&Response {
                ready: false,
                nodes: [].to_vec(),
            })
        }
    });

    // POST /ready  {"id":0,"ip":"192.168.1.1"}
    let committee_clone = Arc::clone(&committee);
    let ready = warp::post()
        .and(warp::path("ready"))
        .and(warp::body::json())
        .map(move |node: Node| {
            tracing::info!("received node {node:?}");
            committee_clone.lock().push(node);
            "ok"
        });

    let routes = start.or(ready);

    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await
}
