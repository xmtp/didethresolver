mod rpc;
mod types;
mod util;

use anyhow::Error;
use jsonrpsee::{rpc_params, server::Server, RpcModule};

fn main() {
    util::init_logging();
    println!("Hello, world!");
}
/*
pub async fn run_server() -> Result<(), Error> {
    let server = Server::builder().build("127.0.0.1:0").await?;
    let addr = server.local_addr()?;
    let handle = server.start(DidRegistryMethods);
}
*/