mod resolver;
pub mod rpc;
pub mod types;
mod util;

use std::str::FromStr;

use anyhow::Result;
use argh::FromArgs;
use ethers::types::Address;
use jsonrpsee::server::Server;

pub use crate::{
    resolver::{did_registry, Resolver},
    rpc::DidRegistryMethods,
    rpc::DidRegistryServer,
};

pub const DID_ETH_REGISTRY: &str = "0xd1D374DDE031075157fDb64536eF5cC13Ae75000";

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
        default = "String::from(\"wss://eth.llamarpc.com\")"
    )]
    provider: String,
}
// TODO:
// Handle different contract addresses
// through an environment variable
// or CLI Flag

/// Entrypoint for the DID:Ethr Gateway
pub async fn run() -> Result<()> {
    crate::util::init_logging();
    let opts: DidEthGatewayApp = argh::from_env();

    let server = Server::builder().build(opts.address).await.unwrap();
    let addr = server.local_addr().unwrap();
    let registry_address = Address::from_str(DID_ETH_REGISTRY)?;
    let resolver = Resolver::new(opts.provider, registry_address).await?;
    let handle = server.start(rpc::DidRegistryMethods::new(resolver).into_rpc());

    log::info!("Server Started at {addr}");
    handle.stopped().await;
    Ok(())
}
