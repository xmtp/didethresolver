//! Ethereum DID Method implementation according to https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md
//! This implementation offers [`EthrBuilder`] which allows dynamically building a DID document
//! from the events emitted by the [`DIDRegistry`](crate::resolver::DIDRegistry).
//!
//! # Examples
//!
//! let mut builder = EthrBuilder::default();
//! builder.public_key(&Address::from_str("0x872A62ABAfa278F0E0f02c1C5042D0614c3f38eb")).unwrap();
//! let document = builder.build();

use super::{
    Attribute, DidDocument, DidUrl, KeyEncoding, KeyPurpose, KeyType, PublicKey, Service,
    ServiceType, VerificationMethod, VerificationMethodProperties,
};
use crate::{
    resolver::did_registry::{DidattributeChangedFilter, DiddelegateChangedFilter},
    types,
};

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine};
use ethers::types::{Address, U256};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EthrBuilder {
    context: Vec<Url>,
    id: DidUrl,
    also_known_as: Vec<DidUrl>,
    controller: Option<DidUrl>,
    verification_method: Vec<VerificationMethod>,
    authentication: Vec<DidUrl>,
    assertion_method: Vec<DidUrl>,
    key_agreement: Vec<DidUrl>,
    capability_invocation: Vec<DidUrl>,
    capability_delegation: Vec<DidUrl>,
    service: Vec<Service>,
    delegate_count: usize,
    service_count: usize,
    now: U256,
}

impl Default for EthrBuilder {
    fn default() -> Self {
        Self {
            context: vec![
                Url::parse("https://www.w3.org/ns/did/v1").unwrap(),
                Url::parse("https://w3id.org/security/suites/ed25519-2020/v2").unwrap(),
            ],
            id: DidUrl::parse("did:ethr:0x0000000000000000000000000000000000000000").unwrap(),
            also_known_as: Default::default(),
            controller: None,
            verification_method: Default::default(),
            authentication: Default::default(),
            assertion_method: Default::default(),
            key_agreement: Default::default(),
            capability_invocation: Default::default(),
            capability_delegation: Default::default(),
            service: Default::default(),
            delegate_count: 0,
            service_count: 0,
            now: U256::zero(),
        }
    }
}

/// Builder to dynamically build a DID document from the events emitted by the [`DIDRegistry`](crate::resolver::DIDRegistry).
impl EthrBuilder {
    /// Set the current time this document is valid for.
    pub fn now(&mut self, now: U256) {
        self.now = now;
    }

    /// set the identity of the document
    pub fn public_key(&mut self, key: &Address) {
        self.id.set_path(&format!("ethr:0x{}", hex::encode(key)));
    }

    /// set any aliases this identity may also go by
    pub fn also_known_as(&mut self, did: &DidUrl) {
        self.also_known_as.push(did.clone());
    }

    /// Set the controller of the document
    pub fn controller(&mut self, controller: &Address) {
        let mut did = self.id.clone();
        did.set_path(&hex::encode(&controller));
        self.controller = Some(did);
    }

    /// Add an `did:ethr` attribute to the DID Document.
    /// Delegate keys are Ethereum addresses that can either be general signing keys or optionally also perform authentication.
    /// They are also verifiable from Solidity (on-chain).
    /// When a delegate is added or revoked, a DIDDelegateChanged event is published that MUST be used to update the DID document.
    ///
    /// reference: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
    pub fn delegate_event(&mut self, event: DiddelegateChangedFilter) {
        if event.valid_to < self.now {
            self.delegate_count += 1;
            return;
        }

        let delegate_type = String::from_utf8_lossy(&event.delegate_type);
        match &*delegate_type {
            "sigAuth" => {
                self.delegate(&event.delegate, KeyPurpose::SignatureAuthentication);
            }
            "veriKey" => {
                self.delegate(&event.delegate, KeyPurpose::VerificationKey);
            }
            d => {
                log::warn!("Unsupported or Unknown delegate type {d}");
            }
        };
    }

    /// A general attribute which indicates external services or keys are associated with the DID.
    /// The name of the attribute added to ERC1056 should follow this format: `did/pub/(Secp256k1|RSA|Ed25519|X25519)/(veriKey|sigAuth|enc)/(hex|base64|base58)`
    ///
    /// reference: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
    pub fn attribute_event(&mut self, event: DidattributeChangedFilter) -> Result<()> {
        let name = event.name_string_lossy();
        let attribute = types::parse_attribute(&name).unwrap_or(Attribute::Other(name.to_string()));

        // invalid events still increment the counter
        if event.valid_to < self.now {
            match attribute {
                Attribute::PublicKey(_) => {
                    self.delegate_count += 1;
                }
                Attribute::Service(_) => {
                    self.service_count += 1;
                }
                _ => {}
            };
            return Ok(());
        }

        match attribute {
            Attribute::PublicKey(key) => {
                self.delegate_count += 1;
                self.external_public_key(&event.value, key);
            }
            Attribute::Service(service) => {
                self.service_count += 1;
                self.service(&event.value, service)?;
            }
            Attribute::Other(_) => {
                log::trace!("Unhandled Attribute {name}:{}", event.value_string_lossy())
            }
        };
        Ok(())
    }

    /// Add an external service to the document.
    /// The endpoint is the value of the attribute committed to the chain.
    ///
    /// reference: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
    pub fn service<V: AsRef<[u8]>>(&mut self, value: V, service: ServiceType) -> Result<()> {
        let mut did = self.id.clone();
        did.set_fragment(Some(&format!("service-{}", self.service_count)));

        let endpoint = Url::parse(&String::from_utf8_lossy(value.as_ref()))?;
        self.service.push(Service {
            id: did,
            service_type: service,
            service_endpoint: endpoint,
            recipient_keys: "".into(),
        });
        Ok(())
    }

    /// Set a published public key external to the consensus system (cannot be queried from within
    /// smart contracts).
    ///   
    /// * `veriKey` adds a verification key to the verificationMethod section of document and adds a reference to it in the assertionMethod section of document.
    /// * `sigAuth` adds a verification key to the verificationMethod section of document and adds a reference to it in the authentication section of document.
    /// * `enc` adds a key agreement key to the verificationMethod section and a corresponding entry to the keyAgreement section. This is used to perform a Diffie-Hellman key exchange and derive a secret key for encrypting messages to the DID that lists such a key.
    ///
    /// reference: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
    pub fn external_public_key<V: AsRef<[u8]>>(&mut self, value: V, key: PublicKey) {
        let mut did = self.id.clone();
        did.set_fragment(Some(&format!("delegate-{}", self.delegate_count)));

        let mut method = VerificationMethod {
            id: did,
            controller: self.id.clone(),
            verification_type: key.key_type,
            verification_properties: None,
        };

        method.verification_properties = match key.encoding {
            KeyEncoding::Hex => Some(VerificationMethodProperties::PublicKeyHex {
                public_key_hex: hex::encode(value.as_ref()),
            }),
            KeyEncoding::Base64 => Some(VerificationMethodProperties::PublicKeyBase64 {
                public_key_base64: BASE64.encode(value.as_ref()),
            }),
            KeyEncoding::Base58 => Some(VerificationMethodProperties::PublicKeyBase58 {
                public_key_base58: bs58::encode(value.as_ref()).into_string(),
            }),
        };

        self.verification_method.push(method.clone());

        match key.purpose {
            KeyPurpose::SignatureAuthentication => {
                self.authentication.push(method.id.clone());
            }
            KeyPurpose::VerificationKey => {
                self.assertion_method.push(method.id.clone());
            }
            KeyPurpose::Encryption => {
                self.key_agreement.push(method.id.clone());
            }
        }
    }

    /// Adds a delegate to the document
    /// The only 2 delegateTypes that are currently published in the DID document are:
    /// * `veriKey` which adds a EcdsaSecp256k1RecoveryMethod2020 to the verificationMethod section of the DID document with the blockchainAccountId(ethereumAddress) of the delegate, and adds a reference to it in the assertionMethod section.
    /// * `sigAuth` which adds a EcdsaSecp256k1RecoveryMethod2020 to the verificationMethod section of document and a reference to it in the authentication section.
    ///
    /// reference: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
    pub fn delegate(&mut self, delegate: &Address, purpose: KeyPurpose) {
        let mut did = self.id.clone();
        did.set_fragment(Some(&format!("delegate-{}", self.delegate_count)));

        // TODO: Handle ChainID
        let method = VerificationMethod {
            id: did,
            controller: self.id.clone(),
            verification_type: KeyType::EcdsaSecp256kRecoveryMethod2020,
            verification_properties: Some(VerificationMethodProperties::BlockchainAccountId {
                blockchain_account_id: delegate.to_string(),
            }),
        };

        self.verification_method.push(method.clone());
        match purpose {
            KeyPurpose::VerificationKey => {
                self.assertion_method.push(method.id.clone());
            }
            KeyPurpose::SignatureAuthentication => {
                self.authentication.push(method.id.clone());
            }
            _ => {}
        }
    }

    /// Build the DID Document
    pub fn build(mut self) -> DidDocument {
        log::debug!("Building Document");
        let mut controller = self.id.clone();
        controller.set_fragment(Some("controller"));

        self.verification_method.push(VerificationMethod {
            id: controller,
            controller: self.id.clone(),
            verification_type: KeyType::EcdsaSecp256kRecoveryMethod2020,
            verification_properties: Some(VerificationMethodProperties::BlockchainAccountId {
                blockchain_account_id: self.id.id().to_string(),
            }),
        });

        if self.controller.as_ref() == Some(&self.id) {
            let mut controller_key = self.id.clone();
            controller_key.set_fragment(Some("controllerKey"));
            self.verification_method.push(VerificationMethod {
                id: controller_key.clone(),
                controller: self.id.clone(),
                verification_type: KeyType::EcdsaSecp256kRecoveryMethod2020,
                verification_properties: Some(VerificationMethodProperties::BlockchainAccountId {
                    blockchain_account_id: self.id.id().to_string(),
                }),
            });
            self.authentication.push(controller_key);
        }

        DidDocument {
            context: self.context,
            id: self.id,
            also_known_as: self.also_known_as,
            controller: self.controller,
            verification_method: self.verification_method,
            authentication: self.authentication,
            assertion_method: self.assertion_method,
            key_agreement: self.key_agreement,
            capability_invocation: self.capability_invocation,
            capability_delegation: self.capability_delegation,
            service: self.service,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_changed() {
        let events = vec![];
    }
}
