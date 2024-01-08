//! Interface Implementations for DID Registry JSON-RPC

use std::str::FromStr;

use async_trait::async_trait;
use ethers::types::{H160, U64};
use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

use super::api::*;
use crate::{resolver::Resolver, types::DidResolutionResult};

/// Read-only methods for the DID Registry JSON-RPC
pub struct DidRegistryMethods {
    resolver: Resolver,
}

/// The implementation of the JSON-RPC trait, [`DidRegistryServer`].
impl DidRegistryMethods {
    pub fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl DidRegistryServer for DidRegistryMethods {
    async fn resolve_did(&self, public_key: String, version_id: Option<String>) -> Result<DidResolutionResult, ErrorObjectOwned> {
        log::debug!("did_resolveDid called");

        // parse the version_id
        let parsed_version_id = match version_id {
            Some(str) => Some(U64::from(u64::from_str(&str).unwrap())),
            None => None,
        };

        let resolution_result = self
            .resolver
            .resolve_did(
                H160::from_str(&public_key).map_err(RpcError::from)?, 
                parsed_version_id)
            .await
            .map_err(into_error_object)?;

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

/// Convenience function to convert an anyhow::Error into an ErrorObjectOwned.
fn into_error_object(error: anyhow::Error) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-31000, error.to_string(), None::<()>)
}
