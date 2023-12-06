//! Trait Interface Definitions for DID Registry JSON-RPC

use crate::types::DidDocument;

use jsonrpsee::{proc_macros::rpc, types::ErrorObjectOwned};

/// Decentralized Identifier JSON-RPC Interface Methods
#[rpc(server, client, namespace = "did")]
pub trait DidRegistry {
    #[method(name = "resolveDid")]
    async fn resolve_did(&self, public_key: String) -> Result<DidDocument, ErrorObjectOwned>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use mockall::{mock, predicate::*};

    use crate::rpc::tests::with_client;

    mock! {
        pub DidRegistryMethods {}

        #[async_trait]
        impl DidRegistryServer for DidRegistryMethods {
            async fn resolve_did(&self, _public_key: String) -> Result<DidDocument, ErrorObjectOwned>;
        }
    }

    #[tokio::test]
    pub async fn test_resolve_did() {
        crate::util::init_logging();

        let mut mock = MockDidRegistryMethods::new();
        mock.expect_resolve_did().returning(|_| Ok(DidDocument));
        // test stub
    }

    #[tokio::test]
    #[should_panic]
    pub async fn test_resolve_did_server() {
        let _ = super::tests::with_client(None, |client| async move {
            client.resolve_did("Hello".to_string()).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await;
    }
}
