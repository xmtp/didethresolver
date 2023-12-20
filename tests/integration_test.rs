mod integration_util;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use didethresolver::{
    rpc::DidRegistryClient,
    types::{DidUrl, VerificationMethodProperties},
};
use ethers::{
    signers::{LocalWallet, Signer as _},
    types::U256,
};
use integration_util::{validate_document, with_client};

#[tokio::test]
pub async fn test_attributes() -> Result<()> {
    with_client(None, |client, registry, signer, _| async move {
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
        validate_document(&document).await;

        assert_eq!(
            document.verification_method[0].id,
            DidUrl::parse(format!("did:ethr:0x{}#delegate-0", hex::encode(me))).unwrap()
        );
        assert_eq!(
            document.verification_method[0].controller,
            DidUrl::parse(format!("did:ethr:0x{}", hex::encode(me))).unwrap()
        );
        assert_eq!(
            document.verification_method[0].verification_properties,
            Some(VerificationMethodProperties::PublicKeyBase64 {
                public_key_base64: "MCowBQYDK2VuAyEAEYVXd3/7B4d0NxpSsA/tdVYdz5deYcR1U+ZkphdmEFI="
                    .to_string()
            })
        );

        Ok(())
    })
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
        validate_document(&document).await;

        assert_eq!(
            document.verification_method[0].id,
            DidUrl::parse(format!("did:ethr:0x{}#delegate-0", hex::encode(me))).unwrap()
        );
        assert_eq!(
            document.verification_method[0].controller,
            DidUrl::parse(format!("did:ethr:0x{}", hex::encode(me))).unwrap()
        );
        assert_eq!(
            document.verification_method[0].verification_properties,
            Some(VerificationMethodProperties::BlockchainAccountId {
                blockchain_account_id: format!("0x{}", hex::encode(delegate.address()))
            })
        );

        Ok(())
    })
    .await
}

#[tokio::test]
pub async fn test_owner_changed() -> Result<()> {
    with_client(None, |client, registry, signer, anvil| async move {
        let me = signer.address();
        let new_owner: LocalWallet = anvil.keys()[4].clone().into();
        let did = registry.change_owner(me, new_owner.address());
        did.send().await?.await?;

        let document = client.resolve_did(hex::encode(me)).await?;
        validate_document(&document).await;

        assert_eq!(
            document.controller,
            Some(
                DidUrl::parse(format!("did:ethr:0x{}", hex::encode(new_owner.address()))).unwrap()
            )
        );
        Ok(())
    })
    .await
}
