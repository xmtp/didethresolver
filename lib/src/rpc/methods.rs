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
        address: String,
        version_id: Option<String>,
    ) -> Result<DidResolutionResult, ErrorObjectOwned> {
        log::debug!("did_resolveDid called");

        log::trace!("Resolving for key {}", &address);

        // parse the version_id
        let parsed_version_id = version_id.map(|str| U64::from(u64::from_str(&str).unwrap()));

        let resolution_result = self
            .resolver
            .resolve_did(
                H160::from_str(&address).map_err(RpcError::from)?,
                parsed_version_id,
            )
            .await;
        log::debug!("Resolution Result {:?}", resolution_result);

        Ok(resolution_result?)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_error_conversion() {
        let gen_error = H160::from_str("0xerror").unwrap_err();
        let rpc_error = RpcError::from(gen_error);

        let error_object = ErrorObjectOwned::from(rpc_error);

        assert_eq!(error_object.code(), -31999);
        assert_eq!(error_object.message(), "Invalid public key format");
    }
}
