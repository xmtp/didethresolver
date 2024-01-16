//! Interface Implementations for DID Registry JSON-RPC

use std::str::FromStr;

use async_trait::async_trait;
use ethers::{
    providers::Middleware,
    types::{H160, U64},
};
use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

use super::api::*;
use crate::{resolver::Resolver, types::DidResolutionResult};

/// Read-only methods for the DID Registry JSON-RPC
pub struct DidRegistryMethods<M> {
    resolver: Resolver<M>,
}

/// The implementation of the JSON-RPC trait, [`DidRegistryServer`].
impl<M: Middleware> DidRegistryMethods<M> {
    pub fn new(resolver: Resolver<M>) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl<M: Middleware + 'static> DidRegistryServer for DidRegistryMethods<M> {
    async fn resolve_did(
        &self,
        public_key: String,
        version_id: Option<String>,
    ) -> Result<DidResolutionResult, ErrorObjectOwned> {
        log::debug!("did_resolveDid called");

        // parse the version_id
        let parsed_version_id = version_id.map(|str| U64::from(u64::from_str(&str).unwrap()));

        let resolution_result = self
            .resolver
            .resolve_did(
                H160::from_str(&public_key).map_err(RpcError::from)?,
                parsed_version_id,
            )
            .await?;

        Ok(resolution_result)
    }
}

/// Error types for DID Registry JSON-RPC
#[derive(Debug, Error)]
enum RpcError {
    /// A public key parameter was invalid
    #[error("Invalid public key format")]
    InvalidPublicKey(#[from] rustc_hex::FromHexError),
}

impl From<RpcError> for ErrorObjectOwned {
    fn from(error: RpcError) -> Self {
        match error {
            RpcError::InvalidPublicKey(_) => {
                ErrorObjectOwned::owned(-31999, error.to_string(), None::<()>)
            }
        }
    }
}
