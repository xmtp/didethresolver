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
    "./abi/DIDRegistry.json",
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

    /// Check if a [`DIDRegistryEvents`] is valid at a given time.
    pub fn is_valid(&self, now: &U256) -> bool {
        match self {
            DIDRegistryEvents::DidattributeChangedFilter(attribute_changed) => {
                attribute_changed.is_valid(now)
            }
            DIDRegistryEvents::DiddelegateChangedFilter(delegate_changed) => {
                delegate_changed.is_valid(now)
            }
            DIDRegistryEvents::DidownerChangedFilter(_) => true,
        }
    }
}

impl DidattributeChangedFilter {
    /// Get the value of the attribute as a string. non-UTF8 bytes will be replaced with the unicode replacement character, �.
    pub fn value_string_lossy(&self) -> String {
        String::from_utf8_lossy(self.value.as_ref()).to_string()
    }

    /// Get the name of the attribute as a string. non-UTF8 bytes will be replaced with the unicode replacement character, �.
    pub fn name_string_lossy(&self) -> String {
        String::from_utf8_lossy(self.name.as_ref()).to_string()
    }

    /// Check if a [`DidattributeChangedFilter`] is valid at a given time.
    pub fn is_valid(&self, now: &U256) -> bool {
        self.valid_to > *now
    }
}

impl DiddelegateChangedFilter {
    /// Check if a [`DiddelegateChangedFilter`] is valid at a given time.
    pub fn is_valid(&self, now: &U256) -> bool {
        self.valid_to > *now
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

        sign_typed_data(self, registry, message).await
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
        sign_typed_data(self, registry, message).await
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

        sign_typed_data(self, registry, message).await
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
        sign_typed_data(self, registry, message).await
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
        sign_typed_data(self, registry, message).await
    }
}

/// Sign data in an [EIP-712](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md) compliant format
async fn sign_typed_data<M: Middleware>(
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
pub fn keccak256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut output = [0u8; 32];

    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);

    output
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_delegate_is_valid() {
        let event = DiddelegateChangedFilter {
            identity: Address::zero(),
            delegate_type: [0; 32],
            delegate: Address::zero(),
            valid_to: U256::from(100),
            previous_change: U256::from(0),
        };
        assert!(event.is_valid(&U256::from(0)));
        assert!(!event.is_valid(&U256::from(100)));
    }

    #[test]
    fn test_attribute_is_valid() {
        let event = DidattributeChangedFilter {
            identity: Address::zero(),
            name: [0; 32],
            value: vec![0].into(),
            valid_to: U256::from(100),
            previous_change: U256::from(0),
        };
        assert!(event.is_valid(&U256::from(0)));
        assert!(!event.is_valid(&U256::from(100)));
    }

    #[test]
    fn test_event_is_valid() {
        let events = vec![
            DIDRegistryEvents::DidattributeChangedFilter(DidattributeChangedFilter {
                identity: Address::zero(),
                name: [0; 32],
                value: vec![0].into(),
                valid_to: U256::from(100),
                previous_change: U256::from(0),
            }),
            DIDRegistryEvents::DiddelegateChangedFilter(DiddelegateChangedFilter {
                identity: Address::zero(),
                delegate_type: [0; 32],
                delegate: Address::zero(),
                valid_to: U256::from(100),
                previous_change: U256::from(0),
            }),
        ];

        let now = U256::from(50);
        for event in &events {
            assert!(event.is_valid(&now));
        }

        let now = U256::from(100);
        for event in &events {
            assert!(!event.is_valid(&now));
        }
    }

    #[test]
    fn test_owner_is_valid() {
        let event = DIDRegistryEvents::DidownerChangedFilter(DidownerChangedFilter {
            identity: Address::zero(),
            owner: Address::zero(),
            previous_change: U256::from(0),
        });
        assert!(event.is_valid(&U256::from(0)));
        assert!(event.is_valid(&U256::MAX));
    }
}
