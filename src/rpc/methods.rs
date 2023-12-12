//! Interface Implementations for DID Registry JSON-RPC

use std::str::FromStr;

use async_trait::async_trait;
use ethers::types::H160;
use jsonrpsee::types::ErrorObjectOwned;

use super::api::*;
use crate::{resolver::Resolver, types::DidDocument, types::DidUrl};

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
        log::debug!("resolve_did called");
        // placeholder
        Ok(self
            .resolver
            .resolve_did(H160::from_str(&public_key).unwrap())
            .await
            .unwrap())
    }
}
