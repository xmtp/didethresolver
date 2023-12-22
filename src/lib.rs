mod resolver;
pub mod rpc;
pub mod types;
mod util;

use std::str::FromStr;
use serde::Deserialize;

use anyhow::Result;
use ethers::types::Address;
use jsonrpsee::server::Server;

pub use crate::{
    resolver::{did_registry, Resolver},
    rpc::DidRegistryMethods,
    rpc::DidRegistryServer,
};

const DEFAULT_ADDRESS: &str = "127.0.0.1:9944";
const DEFAULT_PROVIDER: &str = "http://127.0.0.1:8545";

// TODO: Get registry address from environment variable, or configuration file
// in order to support multiple chains, we may need to support multiple providers via RPC
// so it could be worth defining a config file that maps chainId to RPC provider (like
// did-eth-resolver)
/// The address of the DID Registry contract on the Ethereum Sepolia Testnet
pub const DID_ETH_REGISTRY: &str = "0xd1D374DDE031075157fDb64536eF5cC13Ae75000";

#[derive(Deserialize)]
/// DID Ethereum Resolver XMTP Gateway
struct DidEthGatewayApp {
    /// the address to start the server
    #[serde(default= "default_address")]
    address: String,

    /// ethereum RPC Provider
    #[serde(default= "default_provider")]
    provider: String,
}

fn default_address() -> String {
    DEFAULT_ADDRESS.to_string()
}

fn default_provider() -> String {
    DEFAULT_PROVIDER.to_string()
}

/// Entrypoint for the did:ethr Gateway
pub async fn run() -> Result<()> {
    crate::util::init_logging();
    dotenvy::dotenv()?;
    let opts: DidEthGatewayApp = envy::from_env()?;
    
    let server = Server::builder().build(opts.address).await?;
    let addr = server.local_addr()?;
    let registry_address = Address::from_str(DID_ETH_REGISTRY)?;
    let resolver = Resolver::new(opts.provider, registry_address).await?;
    let handle = server.start(rpc::DidRegistryMethods::new(resolver).into_rpc());

    log::info!("Server Started at {addr}");
    handle.stopped().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal() {
        assert_eq!(DEFAULT_ADDRESS, default_address());
        assert_eq!(DEFAULT_PROVIDER, default_provider());
    }
}