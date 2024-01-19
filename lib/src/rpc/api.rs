//! Trait Interface Definitions for DID Registry JSON-RPC

use crate::types::DidResolutionResult;

use jsonrpsee::{proc_macros::rpc, types::ErrorObjectOwned};

/// Decentralized Identifier JSON-RPC Interface Methods
#[cfg(feature = "server")]
#[rpc(server, namespace = "did")]
pub trait DidRegistry {
    #[method(name = "resolveDid")]
    async fn resolve_did(
        &self,
        public_key: String,
        version_id: Option<String>,
    ) -> Result<DidResolutionResult, ErrorObjectOwned>;
}

/// Decentralized Identifier JSON-RPC Interface Methods
#[cfg(feature = "client")]
#[rpc(client, namespace = "did")]
pub trait DidRegistry {
    #[method(name = "resolveDid")]
    async fn resolve_did(
        &self,
        public_key: String,
        version_id: Option<String>,
    ) -> Result<DidResolutionResult, ErrorObjectOwned>;
}
