//! Trait Implementations for DID JSON-RPC
use super::api::*;
use crate::types::DidDocument;

use jsonrpsee::types::ErrorObjectOwned;

use async_trait::async_trait;

const LOG_TARGET: &str = "rpc";

pub struct DidRegistryMethods;

#[async_trait]
impl DidRegistryServer for DidRegistryMethods {
    async fn resolve_did(&self, _public_key: String) -> Result<DidDocument, ErrorObjectOwned> {
        //TODO: Stub for resolveDid, ref: [#4](https://github.com/xmtp/didethresolver/issues/4)
        log::debug!(target: LOG_TARGET, "resolve_did called");
        todo!();
    }
}
