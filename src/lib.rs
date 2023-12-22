//! ## Endpoint Documentation: `resolveDid`
//!
//! ### Overview
//!
//! The `resolveDid` endpoint is designed to receive an Ethereum public key and return did document in a JSON format. This endpoint is part of our decentralized data service, which provides access to decentralized identity.
//!
//! ### Endpoint
//!
//! ```text
//! POST /api/v1/resolveDid
//! ```
//!
//! ### Request Format
//!
//! The request should be a JSON object containing one field: `publicKey`.
//!
//! - `publicKey` (string, required): The Ethereum public key (starting with '0x').
//!
//! Example Request:
//! ```json
//! {
//!   "publicKey": "0x123abc..."
//! }
//! ```
//!
//! ### Response Format
//!
//! The response will be a JSON object containing a did document for related to the provided Ethereum public key.
//!
//! Example Response:
//! ```json
//! {
//!   "@context": [
//!     "https://www.w3.org/ns/did/v1",
//!     "https://w3id.org/security/suites/ed25519-2020/v1"
//!   ],
//!   "controller": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!   "id": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!   "service": [
//!     {
//!       "id": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "recipientKeys": "0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "serviceEndpoint": "https://xmtp.com/resolver",
//!       "type": "MessagingService"
//!     }
//!   ],
//!   "verificationMethod": [
//!     {
//!       "controller": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "id": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "publicKeyMultibase": "0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "type": "Ed25519VerificationKey2020"
//!     }
//!   ]
//! ```
//!
//! ### Error Handling
//!
//! In case of an error (e.g., invalid public key, server error), the endpoint will return a JSON object with an `error` field describing the issue.
//!
//! Example Error Response:
//! ```json
//! {
//!   "error": "Invalid public key format"
//! }
//! ```
//!
//! ### Security and Authentication
//!
//! - The endpoint is open access.
//!
//! ### Future requirements
//! - Access control
//! - All requests must be made over HTTPS.
//! - Rate limiting is applied to prevent abuse.
//!
//!
//! ### Support
//!
//! Please refer to the DID specification: [DID](https://www.w3.org/TR/did-core/)

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

// TODO: Get registry address from environment variable, or configuration file
// in order to support multiple chains, we may need to support multiple providers via RPC
// so it could be worth defining a config file that maps chainId to RPC provider (like
// did-eth-resolver)
/// The address of the DID Registry contract on the Ethereum Sepolia Testnet
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

/// Entrypoint for the did:ethr Gateway
pub async fn run() -> Result<()> {
    crate::util::init_logging();
    let opts: DidEthGatewayApp = argh::from_env();

    let server = Server::builder().build(opts.address).await?;
    let addr = server.local_addr()?;
    let registry_address = Address::from_str(DID_ETH_REGISTRY)?;
    let resolver = Resolver::new(opts.provider, registry_address).await?;
    let handle = server.start(rpc::DidRegistryMethods::new(resolver).into_rpc());

    log::info!("Server Started at {addr}");
    handle.stopped().await;
    Ok(())
}
