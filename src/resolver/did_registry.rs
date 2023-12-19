//! Generated ABI Functions, along with some extra to make it easier to interact with the registry.

use ethers::{
    contract::abigen,
    types::{U256, U64},
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

    pub fn valid_to(&self) -> Option<U256> {
        match self {
            DIDRegistryEvents::DiddelegateChangedFilter(delegate_changed) => {
                Some(delegate_changed.valid_to)
            }
            DIDRegistryEvents::DidattributeChangedFilter(attribute_changed) => {
                Some(attribute_changed.valid_to)
            }
            DIDRegistryEvents::DidownerChangedFilter(_) => None,
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
