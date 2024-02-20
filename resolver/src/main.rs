//! ## Endpoint Documentation: `resolveDid`
//!
//! ### Overview
//!
//! The `resolveDid` endpoint is designed to receive an Ethereum public key and return did document in a JSON format. This endpoint is part of our decentralized data service, which provides access to decentralized identity.
//!
//! ### Endpoint
//!
//! ```text
//! POST
//! ```
//!
//! ### Request Format
//!
//! The request should be a JSON object containing one field: `address`.
//!
//! - `address` (string, required): The Ethereum address (starting with '0x').
//!
//! Example Request:
//! ```json
//! {
//!   "address": "0x123abc..."
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
//!   "error": "Invalid address format"
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
//! ### Example
//!
//! ```bash
//! curl -H "Content-Type: application/json" -d '{"id":1, "jsonrpc":"2.0", "method":"did_resolveDid", "params": { "publicKey":"x"} }' http://localhost:8080
//! ```
//!
//! ### Support
//!
//! Please refer to the DID specification: [DID](https://www.w3.org/TR/did-core/)

use anyhow::{Context, Result};
use std::str::FromStr;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

use lib_didethresolver::{rpc::DidRegistryMethods, DidRegistryServer, Resolver};

use ethers::{
    providers::{Provider, Ws},
    types::Address,
};
use jsonrpsee::server::Server;

mod argenv;

/// Entrypoint for the did:ethr Gateway
pub async fn run() -> Result<()> {
    init_logging();
    load_env()?;
    let opts = argenv::parse_args();

    let server_host = host_from(opts.host, opts.port);
    let server = Server::builder().build(server_host).await?;
    let addr = server.local_addr()?;
    let registry_address = Address::from_str(&opts.did_registry)?;
    let provider_endpoint = opts.rpc_url.clone();
    log::info!(
        "Connecting to provider {provider_endpoint} with registry address {registry_address}"
    );
    let provider = Provider::<Ws>::connect(provider_endpoint.clone()).await?;
    let resolver = Resolver::new(provider, registry_address)
        .await
        .context(format!(
            "Unable to create a resolver for provider {} and registry address {}",
            provider_endpoint, registry_address,
        ))?;

    let handle = server.start(DidRegistryMethods::new(resolver).into_rpc());

    log::info!("Server Started at {addr}");
    handle.stopped().await;
    Ok(())
}

fn load_env() -> Result<()> {
    match dotenvy::dotenv_override() {
        Ok(path) => {
            // .env file successfully loaded.
            log::debug!("Env file {} was loaded successfully", path.display());
        }
        Err(err) => {
            // Error handling for the case where dotenv() fails
            log::info!("env file(s) not loaded : {err}");
        }
    };
    Ok(())
}

fn host_from(host: String, port: u16) -> String {
    format!("{}:{}", host, port)
}

fn init_logging() {
    let fmt = fmt::layer().compact();
    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt)
        .init()
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_from() {
        assert_eq!(host_from(String::from("abc"), 123), "abc:123");
        assert_eq!(host_from(String::from("abc"), 0), "abc:0");
    }
}
