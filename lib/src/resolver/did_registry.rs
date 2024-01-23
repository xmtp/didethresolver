//! Generated ABI Functions, along with some extra to make it easier to interact with the registry.

use crate::error::RegistrySignerError;
use ethers::{
    abi::{Address, Token},
    contract::abigen,
    core::abi::encode_packed,
    providers::Middleware,
    signers::{LocalWallet, Signer},
    types::{Signature, H256, U256, U64},
};
use tiny_keccak::{Hasher, Keccak};

pub use self::did_registry::*;

abigen!(
    DIDRegistry,
    "./src/abi/DIDRegistry.json",
    derives(serde::Serialize, serde::Deserialize)
);

impl DIDRegistryEvents {
    pub fn previous_change(&self) -> U64 {
        match self {
            DIDRegistryEvents::DidattributeChangedFilter(attribute_changed) => {
                U64::from(attribute_changed.previous_change.as_u64())
            }
            DIDRegistryEvents::DiddelegateChangedFilter(delegate_changed) => {
                U64::from(delegate_changed.previous_change.as_u64())
            }
            DIDRegistryEvents::DidownerChangedFilter(owner_changed) => {
                U64::from(owner_changed.previous_change.as_u64())
            }
        }
    }
}

impl DidattributeChangedFilter {
    pub fn value_string_lossy(&self) -> String {
        String::from_utf8_lossy(self.value.as_ref()).to_string()
    }

    pub fn name_string_lossy(&self) -> String {
        String::from_utf8_lossy(self.name.as_ref()).to_string()
    }
}

/// Signer for data that is externally signed to be processed by the DIDRegistry Contract.
/// Useful if the transaction is being submitted by someone other than the owner of the identity.
#[async_trait::async_trait]
pub trait RegistrySignerExt {
    /// Sign hash of the data for [`DIDRegistry::set_attribute_signed`]
    async fn sign_attribute<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        key: [u8; 32],
        value: Vec<u8>,
        validity: U256,
    ) -> Result<Signature, RegistrySignerError<M>>;

    /// Sign hash of the data for [`DIDRegistry::revoke_attribute_signed`]
    async fn sign_revoke_attribute<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        key: [u8; 32],
        value: Vec<u8>,
    ) -> Result<Signature, RegistrySignerError<M>>;

    /// Sign hash of the data for [`DIDRegistry::add_delegate_signed`]
    async fn sign_delegate<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        delegate_type: [u8; 32],
        delegate: Address,
        validity: U256,
    ) -> Result<Signature, RegistrySignerError<M>>;

    /// Sign hash of the data for [`DIDRegistry::revoke_delegate_signed`]
    async fn sign_revoke_delegate<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        key: [u8; 32],
        delegate: Address,
    ) -> Result<Signature, RegistrySignerError<M>>;

    /// Sign hash of the data for [`DIDRegistry::change_owner_signed`]
    async fn sign_owner<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        new_owner: Address,
    ) -> Result<Signature, RegistrySignerError<M>>;
}

#[async_trait::async_trait]
impl RegistrySignerExt for LocalWallet {
    async fn sign_attribute<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        key: [u8; 32],
        value: Vec<u8>,
        validity: U256,
    ) -> Result<Signature, RegistrySignerError<M>> {
        // ethers does not return correct encoded values for U256: https://github.com/gakonst/ethers-rs/issues/2225
        let mut validity_bytes = [0; 32];
        validity.to_big_endian(&mut validity_bytes);

        let message = vec![
            Token::Bytes(b"setAttribute".to_vec()),
            Token::FixedBytes(key.to_vec()),
            Token::Bytes(value),
            Token::Bytes(validity_bytes[0..32].to_vec()),
        ];

        sign_data(self, registry, message).await
    }

    async fn sign_revoke_attribute<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        key: [u8; 32],
        value: Vec<u8>,
    ) -> Result<Signature, RegistrySignerError<M>> {
        let message = vec![
            Token::Bytes(b"revokeAttribute".to_vec()),
            Token::FixedBytes(key.to_vec()),
            Token::Bytes(value.to_vec()),
        ];
        sign_data(self, registry, message).await
    }

    async fn sign_delegate<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        delegate_type: [u8; 32],
        delegate: Address,
        validity: U256,
    ) -> Result<Signature, RegistrySignerError<M>> {
        let mut validity_bytes = [0; 32];
        validity.to_big_endian(&mut validity_bytes);

        let message = vec![
            Token::Bytes(b"addDelegate".to_vec()),
            Token::FixedBytes(delegate_type.to_vec()),
            Token::Address(delegate),
            Token::Bytes(validity_bytes[0..32].to_vec()),
        ];

        sign_data(self, registry, message).await
    }

    async fn sign_revoke_delegate<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        key: [u8; 32],
        delegate: Address,
    ) -> Result<Signature, RegistrySignerError<M>> {
        let message = vec![
            Token::Bytes(b"revokeDelegate".to_vec()),
            Token::FixedBytes(key.to_vec()),
            Token::Address(delegate),
        ];
        sign_data(self, registry, message).await
    }

    async fn sign_owner<M: Middleware>(
        &self,
        registry: &DIDRegistry<M>,
        new_owner: Address,
    ) -> Result<Signature, RegistrySignerError<M>> {
        let message = vec![
            Token::Bytes(b"changeOwner".to_vec()),
            Token::Address(new_owner),
        ];
        sign_data(self, registry, message).await
    }
}

async fn sign_data<M: Middleware>(
    wallet: &LocalWallet,
    registry: &DIDRegistry<M>,
    tokens: Vec<Token>,
) -> Result<Signature, RegistrySignerError<M>> {
    let message = encode_packed(tokens.as_slice())?;
    let owner_nonce = registry.nonce(wallet.address()).call().await?;
    let mut owner_bytes = [0; 32];
    owner_nonce.to_big_endian(&mut owner_bytes);

    let tokens = vec![
        Token::FixedBytes(vec![0x19]),
        Token::FixedBytes(vec![0x0]),
        Token::Address(registry.address()),
        Token::Bytes(owner_bytes[0..32].to_vec()),
        Token::Address(wallet.address()),
        Token::Bytes(message),
    ];
    let encoded = encode_packed(tokens.as_slice())?;
    let hash = H256(keccak256(encoded));

    let signature = wallet.sign_hash(hash)?;
    Ok(signature)
}

/// Compute the Keccak-256 hash of input bytes.
///
/// Note that strings are interpreted as UTF-8 bytes,
// TODO: Add Solidity Keccak256 packing support
pub fn keccak256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut output = [0u8; 32];

    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);

    output
}
