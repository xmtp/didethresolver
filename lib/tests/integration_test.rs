mod integration_util;

use std::str::FromStr;

use anyhow::Result;
use ethers::{
    signers::{LocalWallet, Signer as _},
    types::{Address, U256},
};
use integration_util::{revoke_attribute, set_attribute, validate_document, with_client};
use regex::Regex;

#[cfg(test)]
mod it {

    use lib_didethresolver::{
        did_registry::RegistrySignerExt,
        rpc::DidRegistryClient,
        types::{DidUrl, KeyType, VerificationMethodProperties, NULL_ADDRESS},
    };

    use super::*;

    #[tokio::test]
    pub async fn test_attributes() -> Result<()> {
        with_client(None, |client, registry, signer, _| async move {
        let me = signer.address();
        set_attribute(&registry, me, "did/pub/Secp256k1/veriKey/hex", "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71", 604_800).await?;
        set_attribute(&registry, me, "did/pub/Ed25519/veriKey/base64", "302a300506032b656e032100118557777ffb078774371a52b00fed75561dcf975e61c47553e664a617661052", 604_800).await?;

        let resolution_response = client.resolve_did(hex::encode(me), None).await?;
        validate_document(&resolution_response.document).await;
        assert_eq!(
            resolution_response.document.verification_method[1].id,
            DidUrl::parse(format!("did:ethr:0x{}#delegate-0", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[1].controller,
            DidUrl::parse(format!("did:ethr:0x{}", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[1].verification_type,
            KeyType::EcdsaSecp256k1VerificationKey2019
        );
        assert_eq!(
            resolution_response.document.verification_method[1].verification_properties,
            Some(VerificationMethodProperties::PublicKeyHex {
                public_key_hex: "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71".to_string()
            })
        );

        assert_eq!(
            resolution_response.document.verification_method[2].id,
            DidUrl::parse(format!("did:ethr:0x{}#delegate-1", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[2].controller,
            DidUrl::parse(format!("did:ethr:0x{}", hex::encode(me))).unwrap()
        );
        assert_eq!(
            resolution_response.document.verification_method[2].verification_type,
            KeyType::Ed25519VerificationKey2020
        );
        assert_eq!(
            resolution_response.document.verification_method[2].verification_properties,
            Some(VerificationMethodProperties::PublicKeyBase64 {
                public_key_base64: "MCowBQYDK2VuAyEAEYVXd3/7B4d0NxpSsA/tdVYdz5deYcR1U+ZkphdmEFI="
                    .to_string()
            })
        );
        assert!(
            !resolution_response.metadata.clone().deactivated
        );
        assert_eq!(
            resolution_response.metadata.clone().version_id,
            3
        );
        assert_eq!(
            resolution_response.metadata.next_version_id,
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
        set_attribute(&registry, me,"did/pub/Secp256k1/veriKey/hex", "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71", 604_800).await?;
        set_attribute(&registry, me, "did/pub/Ed25519/veriKey/base64", "302a300506032b656e032100118557777ffb078774371a52b00fed75561dcf975e61c47553e664a617661052", 604_800).await?;

        let resolution_response = client.resolve_did(hex::encode(me), Some::<String>("2".to_string())).await?;
        validate_document(&resolution_response.document).await;

        assert!(
            !resolution_response.metadata.clone().deactivated
        );
        assert_eq!(
            resolution_response.metadata.clone().version_id,
            2
        );
        assert_eq!(
            resolution_response.metadata.next_version_id,
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
                resolution_response.document.verification_method[1].id,
                DidUrl::parse(format!("did:ethr:0x{}#delegate-0", hex::encode(me))).unwrap()
            );
            assert_eq!(
                resolution_response.document.verification_method[1].controller,
                DidUrl::parse(format!("did:ethr:0x{}", hex::encode(me))).unwrap()
            );
            assert_eq!(
                resolution_response.document.verification_method[1].verification_properties,
                Some(VerificationMethodProperties::BlockchainAccountId {
                    blockchain_account_id: format!("0x{}", hex::encode(delegate.address()))
                })
            );

            assert_eq!(
                resolution_response.document.verification_method[2].id,
                DidUrl::parse(format!("did:ethr:0x{}#delegate-1", hex::encode(me))).unwrap()
            );
            assert_eq!(
                resolution_response.document.verification_method[2].controller,
                DidUrl::parse(format!("did:ethr:0x{}", hex::encode(me))).unwrap()
            );
            assert_eq!(
                resolution_response.document.verification_method[2].verification_properties,
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
                    DidUrl::parse(format!("did:ethr:0x{}", hex::encode(new_owner.address())))
                        .unwrap()
                )
            );
            Ok(())
        })
        .await
    }

    #[tokio::test]
    pub async fn test_attribute_revocation() -> Result<()> {
        with_client(None, |client, registry, signer, _| async move {
            let me = signer.address();

            set_attribute(
                &registry,
                me,
                "did/pub/Secp256k1/veriKey/hex",
                "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
                604_800,
            )
            .await?;
            revoke_attribute(
                &registry,
                me,
                "did/pub/Secp256k1/veriKey/hex",
                "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
            )
            .await?;

            let document = client.resolve_did(hex::encode(me), None).await?.document;
            validate_document(&document).await;

            assert_eq!(
                document.verification_method[0].id,
                DidUrl::parse(format!("did:ethr:0x{}#controller", hex::encode(me))).unwrap()
            );
            assert_eq!(document.verification_method.len(), 1);

            Ok(())
        })
        .await
    }

    #[tokio::test]
    pub async fn test_delegate_revocation() -> Result<()> {
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

            let did = registry.revoke_delegate(
                me,
                *b"sigAuth0000000000000000000000000",
                delegate.address(),
            );
            did.send().await?.await?;

            let document = client.resolve_did(hex::encode(me), None).await?.document;
            validate_document(&document).await;

            assert_eq!(
                document.verification_method[0].id,
                DidUrl::parse(format!("did:ethr:0x{}#controller", hex::encode(me))).unwrap()
            );
            // delegate 1, veriKey should still be valid after revoking delegate 0
            assert_eq!(
                document.verification_method[1].id,
                DidUrl::parse(format!("did:ethr:0x{}#delegate-1", hex::encode(me))).unwrap()
            );
            assert_eq!(document.verification_method.len(), 2);

            Ok(())
        })
        .await
    }

    #[tokio::test]
    pub async fn test_owner_revocation() -> Result<()> {
        with_client(None, |client, registry, signer, _| async move {
            let me = signer.address();
            let null = Address::from_str(NULL_ADDRESS.strip_prefix("0x").unwrap()).unwrap();
            let did = registry.change_owner(me, null);
            did.send().await?.await?;

            let resolved = client.resolve_did(hex::encode(me), None).await?;
            validate_document(&resolved.document).await;

            assert!(resolved.metadata.deactivated);

            Ok(())
        })
        .await
    }

    #[tokio::test]
    pub async fn test_xmtp_revocation() -> Result<()> {
        with_client(None, |client, registry, signer, _| async move {
            let me = signer.address();
            let attribute_name = "xmtp/installation/hex           ";
            set_attribute(
                &registry,
                me,
                attribute_name,
                "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
                604_800,
            )
            .await?;

            let document = client.resolve_did(hex::encode(me), None).await?.document;
            let regexr = format!(
                r"did:ethr:mainnet:0x{}\?meta=installation&timestamp=\d+#xmtp-0",
                hex::encode(me)
            );
            let test = Regex::new(&regexr).unwrap();
            assert!(test.is_match(&document.verification_method[1].id.to_string()));

            revoke_attribute(
                &registry,
                me,
                attribute_name,
                "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
            )
            .await?;

            let document = client.resolve_did(hex::encode(me), None).await?.document;
            validate_document(&document).await;
            assert_eq!(
                document.verification_method[0].id,
                DidUrl::parse(format!("did:ethr:0x{}#controller", hex::encode(me))).unwrap()
            );
            assert_eq!(document.verification_method.len(), 1);

            Ok(())
        })
        .await
    }

    #[tokio::test]
    pub async fn test_signed_fns() -> Result<()> {
        with_client(None, |_, registry, _, anvil| async move {
            let me: LocalWallet = anvil.keys()[3].clone().into();
            let name = *b"xmtp/installation/hex           ";
            let value = b"02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71";
            let validity = U256::from(604_800);
            let signature = me
                .sign_attribute(&registry, name, value.to_vec(), validity)
                .await?;

            let attr = registry.set_attribute_signed(
                me.address(),
                signature.v.try_into().unwrap(),
                signature.r.into(),
                signature.s.into(),
                name,
                value.into(),
                validity,
            );
            attr.send().await?.await?;

            let signature = me
                .sign_revoke_attribute(&registry, name, value.to_vec())
                .await?;
            registry
                .revoke_attribute_signed(
                    me.address(),
                    signature.v.try_into().unwrap(),
                    signature.r.into(),
                    signature.s.into(),
                    name,
                    value.into(),
                )
                .send()
                .await?
                .await?;

            let delegate_type = *b"sigAuth                         ";

            let signature = me
                .sign_delegate(&registry, delegate_type, me.address(), validity)
                .await?;
            registry
                .add_delegate_signed(
                    me.address(),
                    signature.v.try_into().unwrap(),
                    signature.r.into(),
                    signature.s.into(),
                    delegate_type,
                    me.address(),
                    validity,
                )
                .send()
                .await?
                .await?;

            let signature = me
                .sign_revoke_delegate(&registry, delegate_type, me.address())
                .await?;

            registry
                .revoke_delegate_signed(
                    me.address(),
                    signature.v.try_into().unwrap(),
                    signature.r.into(),
                    signature.s.into(),
                    delegate_type,
                    me.address(),
                )
                .send()
                .await?
                .await?;

            let new_owner = Address::from_str(NULL_ADDRESS.strip_prefix("0x").unwrap()).unwrap();
            let signature = me.sign_owner(&registry, new_owner).await?;
            registry
                .change_owner_signed(
                    me.address(),
                    signature.v.try_into().unwrap(),
                    signature.r.into(),
                    signature.s.into(),
                    new_owner,
                )
                .send()
                .await?
                .await?;

            Ok(())
        })
        .await
    }
}
