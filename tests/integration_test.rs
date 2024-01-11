mod integration_util;

use anyhow::Result;
use didethresolver::{
    rpc::DidRegistryClient,
    types::{DidUrl, KeyType, VerificationMethodProperties},
};
use ethers::{
    signers::{LocalWallet, Signer as _},
    types::U256,
};
use integration_util::{validate_document, with_client};

//TODO: Add tests for: Errors, formats, entire document asserts, different padding methods(0s and spaces)

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
            b"302a300506032b656e032100118557777ffb078774371a52b00fed75561dcf975e61c47553e664a617661052".into(),
            U256::from(604_800),
        );
        did.send().await?.await?;

        let resolution_response = client.resolve_did(hex::encode(me), None).await?;
        validate_document(&resolution_response.document).await;
        assert_eq!(
            resolution_response.document.verification_method[0].id,
            DidUrl::parse(format!("did:ethr:0x{}#delegate-0", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[0].controller,
            DidUrl::parse(format!("did:ethr:0x{}", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[0].verification_type,
            KeyType::EcdsaSecp256k1VerificationKey2019
        );
        assert_eq!(
            resolution_response.document.verification_method[0].verification_properties,
            Some(VerificationMethodProperties::PublicKeyHex {
                public_key_hex:
                    "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71".to_string()
            })
        );

        assert_eq!(
            resolution_response.document.verification_method[1].id,
            DidUrl::parse(format!("did:ethr:0x{}#delegate-1", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[1].controller,
            DidUrl::parse(format!("did:ethr:0x{}", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[1].verification_type,
            KeyType::Ed25519VerificationKey2020
        );
        assert_eq!(
            resolution_response.document.verification_method[1].verification_properties,
            Some(VerificationMethodProperties::PublicKeyBase64 {
                public_key_base64: "MCowBQYDK2VuAyEAEYVXd3/7B4d0NxpSsA/tdVYdz5deYcR1U+ZkphdmEFI="
                    .to_string()
            })
        );
        assert_eq!(
            resolution_response.metadata.clone().unwrap().deactivated,
            false
        );
        assert_eq!(
            resolution_response.metadata.clone().unwrap().version_id,
            3
        );
        assert_eq!(
            resolution_response.metadata.unwrap().next_version_id,
            None
        );

        Ok(())
    })
    .await
}

#[tokio::test]
pub async fn test_attributes_versions() -> Result<()> {
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
            b"302a300506032b656e032100118557777ffb078774371a52b00fed75561dcf975e61c47553e664a617661052".into(),
            U256::from(604_800),
        );
        did.send().await?.await?;

        let resolution_response = client.resolve_did(hex::encode(me), Some::<String>("2".to_string())).await?;
        validate_document(&resolution_response.document).await;

        assert_eq!(
            resolution_response.metadata.clone().unwrap().deactivated,
            false
        );
        assert_eq!(
            resolution_response.metadata.clone().unwrap().version_id,
            2
        );
        assert_eq!(
            resolution_response.metadata.unwrap().next_version_id,
            Some::<u64>(3)
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

        let resolution_response = client.resolve_did(hex::encode(me), None).await?;
        validate_document(&resolution_response.document).await;

        assert_eq!(
            resolution_response.document.verification_method[0].id,
            DidUrl::parse(format!("did:ethr:0x{}#delegate-0", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[0].controller,
            DidUrl::parse(format!("did:ethr:0x{}", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[0].verification_properties,
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

        let resolution_response = client.resolve_did(hex::encode(me), None).await?;
        validate_document(&resolution_response.document).await;

        assert_eq!(
            resolution_response.document.controller,
            Some(
                DidUrl::parse(format!("did:ethr:0x{}", hex::encode(new_owner.address()))).unwrap()
            )
        );
        Ok(())
    })
    .await
}
