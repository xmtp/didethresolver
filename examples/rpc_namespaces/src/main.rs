//! Example of composing a did:ethr resolution server with multiple other namespaces/rpcs.
//! This example creates a did:ethr resolver connected to the Sepolia Ethereum testnet and composes
//! the rpc with the [`turtle`] rpc
//!
//! All did methods will be available under the `did_` namespace, all turtle methods under the `turtle_` namespace.
//!
//! Try running this example and executing the command `curl -H "Content-Type: application/json" -d '{"id":1, "jsonrpc":"2.0", "method": "rpc_methods"}' http://localhost:PORT/` | jq .result
//! (requires `curl` and `jq` packages to be installed)

use std::str::FromStr;

use anyhow::{Context, Result};
use ethers::{
    providers::{Provider, Ws},
    types::Address,
};
use jsonrpsee::{server::Server, RpcModule};
use lib_didethresolver::{rpc::DidRegistryMethods, DidRegistryServer, Resolver};
use turtle_rpc::{TurtleMethods, TurtleRpcServer};

mod turtle_rpc;

/// The address of the DID Registry contract on the Ethereum Sepolia Testnet
pub const DID_ETH_REGISTRY: &str = "0xd1D374DDE031075157fDb64536eF5cC13Ae75000";

#[tokio::main]
async fn main() -> Result<()> {
    let server = Server::builder().build("127.0.0.1:0").await?;

    let addr = server.local_addr()?;

    let mut methods = RpcModule::new(());
    // add the turtle RPC namespace
    methods.merge(TurtleMethods.into_rpc())?;

    // add the did:ethr RPC namespace
    let registry_address = Address::from_str(DID_ETH_REGISTRY)?;
    let endpoint = "wss://ethereum-sepolia.publicnode.com";
    let provider = Provider::<Ws>::connect(endpoint).await?;
    let resolver = Resolver::new(provider, registry_address)
        .await
        .context(format!(
            "Unable to create a resolver for provider {} and registry address {}",
            endpoint, registry_address,
        ))?;

    methods.merge(DidRegistryMethods::new(resolver).into_rpc())?;

    let methods = build_rpc_api(methods);
    let handle = server.start(methods);

    println!("Listening on: {}", addr);

    handle.stopped().await;

    Ok(())
}

// this is here to create an endpoint that lists all the methods available on the server, at the
// endpoint `/rpc_methods`
fn build_rpc_api<M: Send + Sync + 'static>(mut rpc_api: RpcModule<M>) -> RpcModule<M> {
    let mut available_methods = rpc_api.method_names().collect::<Vec<_>>();
    // The "rpc_methods" is defined below and we want it to be part of the reported methods.
    available_methods.push("rpc_methods");
    available_methods.sort();

    rpc_api
        .register_method("rpc_methods", move |_, _| {
            serde_json::json!({
                "methods": available_methods,
            })
        })
        .expect("infallible all other methods have their own address space; qed");

    rpc_api
}
