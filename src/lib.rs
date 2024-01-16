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

pub use crate::{
    resolver::{did_registry, Resolver},
    rpc::DidRegistryMethods,
};

#[cfg(feature = "server")]
pub use rpc::DidRegistryServer;

// TODO: Get registry address from environment variable, or configuration file
// in order to support multiple chains, we may need to support multiple providers via RPC
// so it could be worth defining a config file that maps chainId to RPC provider (like
// did-eth-resolver)
/// The address of the DID Registry contract on the Ethereum Sepolia Testnet
pub const DID_ETH_REGISTRY: &str = "0xd1D374DDE031075157fDb64536eF5cC13Ae75000";

#[cfg(feature = "gateway")]
pub use gateway::*;

#[cfg(feature = "gateway")]
mod gateway {
    use anyhow::{Context, Result};
    use serde::Deserialize;
    use std::str::FromStr;

    use ethers::{
        providers::{Provider, Ws},
        types::Address,
    };
    use jsonrpsee::server::Server;

    use super::*;

    pub(crate) const DEFAULT_ADDRESS: &str = "127.0.0.1:9944";
    pub(crate) const DEFAULT_PROVIDER: &str = "http://127.0.0.1:8545";
    #[derive(Deserialize)]
    /// DID Ethereum Resolver XMTP Gateway
    struct DidEthGatewayApp {
        /// the address to start the server
        #[serde(default = "default_address")]
        address: String,

        /// ethereum RPC Provider
        #[serde(default = "default_provider")]
        provider: String,
    }

    pub(crate) fn default_address() -> String {
        DEFAULT_ADDRESS.to_string()
    }

    pub(crate) fn default_provider() -> String {
        DEFAULT_PROVIDER.to_string()
    }

    /// Entrypoint for the did:ethr Gateway
    pub async fn run() -> Result<()> {
        crate::util::init_logging();
        match dotenvy::dotenv() {
            Ok(path) => {
                // .env file successfully loaded.
                log::debug!("Env file {} was loaded successfully", path.display());
            }
            Err(err) => {
                // Error handling for the case where dotenv() fails
                log::info!("Unable to load env file(s) : {err}");
            }
        }
        let opts = envy::from_env::<DidEthGatewayApp>()?;

        let server = Server::builder().build(opts.address).await?;
        let addr = server.local_addr()?;
        let registry_address = Address::from_str(DID_ETH_REGISTRY)?;
        let provider_endpoint = opts.provider.clone();
        let provider = Provider::<Ws>::connect(provider_endpoint.clone()).await?;
        let resolver = Resolver::new(provider, registry_address)
            .await
            .context(format!(
                "Unable to create a resolver for provider {} and registry address {}",
                provider_endpoint, registry_address,
            ))?;

        let handle = server.start(rpc::DidRegistryMethods::new(resolver).into_rpc());

        log::info!("Server Started at {addr}");
        handle.stopped().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "gateway")]
    #[test]
    fn internal() {
        assert_eq!(DEFAULT_ADDRESS, default_address());
        assert_eq!(DEFAULT_PROVIDER, default_provider());
    }
}
