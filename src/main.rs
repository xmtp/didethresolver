mod resolver;
pub mod rpc;
pub mod types;
mod util;

use argh::FromArgs;
use jsonrpsee::server::Server;

use crate::rpc::DidRegistryServer;

#[derive(FromArgs)]
/// DID Ethereum Resolver XMTP Gateway
struct DidEthGatewayApp {
    /// the address to start the server
    #[argh(option, short = 'a', default = "String::from(\"127.0.0.1:9944\")")]
    address: String,

    /// ethereum RPC Provider
    #[argh(
        option,
        short = 'p',
        default = "String::from(\"https://eth.llamarpc.com\")"
    )]
    provider: String,
}

#[tokio::main]
async fn main() {
    crate::util::init_logging();
    let opts: DidEthGatewayApp = argh::from_env();

    let server = Server::builder().build(opts.address).await.unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.start(rpc::DidRegistryMethods.into_rpc());

    log::info!("Server Started at {addr}");
    handle.stopped().await;
}
