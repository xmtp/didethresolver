//! Generated ABI Functions, along with some extra to make it easier to interact with the registry.

use crate::error::RegistryError;
use ethers::{
    abi::Token,
    contract::abigen,
    core::abi::encode,
    signers::Signer,
    types::{Signature, U256, U64},
};

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

impl<M> DIDRegistry<M> {
    /// Sign an Attribute
    pub async fn sign_attribute(
        signer: impl Signer,
        key: [u8; 32],
        value: Vec<u8>,
        validity: U256,
    ) -> Result<Signature, RegistryError> {
        let tokens = vec![
            Token::Bytes(b"SetAttribute".to_vec()),
            Token::FixedBytes(key.to_vec()),
            Token::Bytes(value),
            Token::Uint(validity),
        ];
        let encoded = encode(tokens.as_slice());
        let signature = signer
            .sign_message(encoded)
            .await
            .map_err(|e| RegistryError::SignError(e.to_string()))?;
        Ok(signature)
    }
}
