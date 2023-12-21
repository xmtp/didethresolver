//! Interface Implementations for DID Registry JSON-RPC

use std::str::FromStr;

use async_trait::async_trait;
use ethers::types::H160;
use jsonrpsee::types::ErrorObjectOwned;

use super::api::*;
use crate::{resolver::Resolver, types::DidDocument};

pub struct DidRegistryMethods {
    resolver: Resolver,
}

impl DidRegistryMethods {
    pub fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl DidRegistryServer for DidRegistryMethods {
    async fn resolve_did(&self, public_key: String) -> Result<DidDocument, ErrorObjectOwned> {
        log::debug!("did_resolveDid called");

        let result = self
            .resolver
            .resolve_did(H160::from_str(&public_key).unwrap())
            .await;

        // TODO: Enumerate and map errors to meaningful JSON-RPC errors
        match result {
            Ok(doc) => Ok(doc),
            Err(e) => {
                log::error!("Error resolving DID: {}", e);
                Err(ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))
            }
        }
    }
}
