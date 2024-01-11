//! Trait Interface Definitions for DID Registry JSON-RPC

use crate::types::DidResolutionResult;

use jsonrpsee::{proc_macros::rpc, types::ErrorObjectOwned};

/// Decentralized Identifier JSON-RPC Interface Methods
#[rpc(server, client, namespace = "did")]
pub trait DidRegistry {
    #[method(name = "resolveDid")]
    async fn resolve_did(
        &self,
        public_key: String,
        version_id: Option<String>,
    ) -> Result<DidResolutionResult, ErrorObjectOwned>;
}
