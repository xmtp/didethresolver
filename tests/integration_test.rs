mod integration_util;

use anyhow::Result;
use didethresolver::{
    rpc::DidRegistryClient,
};
use ethers::{
    types::U256,
    signers::{LocalWallet, Signer as _}
};
use integration_util::{with_client, validate_document};

#[tokio::test]
pub async fn test_attributes() -> Result<()> {
    with_client(
        None,
        |client, registry, signer, _| async move {
            let me = signer.address();
            let did = registry.set_attribute(
                me,
                *b"did/pub/Secp256k1/veriKey/hex   ",
                b"02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71".into(),
                U256::from(604_800),
            );
            did.send().await?.await?;

            let did = registry.set_attribute(
                me,
                *b"did/pub/Ed25519/veriKey/base64  ",
                b"f3beac30c498d9e26865f34fcaa57dbb935b0d74".into(),
                U256::from(604_800),
            );
            did.send().await?.await?;

            let document = client.resolve_did(hex::encode(me)).await?;
            validate_document(document).await;
    
            Ok(())
        },
    )
    .await
}

#[tokio::test]
pub async fn test_delegate() -> Result<()> {
    with_client(None, |client, registry, signer, anvil| async move {
        let me = signer.address();
        let delegate: LocalWallet = anvil.keys()[4].clone().into();
        let did = registry.add_delegate(
            me,
            *b"sigAuth                         ",
            delegate.address(),
            U256::from(604_800),
        );
        did.send().await?.await?;
        
        let did = registry.add_delegate(
            me,
            *b"veriKey                         ",
            delegate.address(),
            U256::from(604_800),
        );
        did.send().await?.await?;

        let document = client.resolve_did(hex::encode(me)).await?;
        validate_document(document).await;

        Ok(())
    }).await
}
