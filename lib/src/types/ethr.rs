//! Ethereum DID Method implementation according to [specification](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
//! This implementation offers [`EthrBuilder`] which allows dynamically building a DID document
//! from the events emitted by the [`DIDRegistry`](crate::resolver::DIDRegistry).
//!
//! # Examples
//!
//! let mut builder = EthrBuilder::default();
//! builder.account_address(&Address::from_str("0x872A62ABAfa278F0E0f02c1C5042D0614c3f38eb")).unwrap();
//! let document = builder.build();

use std::{collections::HashMap, str::FromStr};

use super::{
    Account, Attribute, DidDocument, DidUrl, KeyEncoding, KeyPurpose, KeyType, PublicKey, Service,
    ServiceType, VerificationMethod, VerificationMethodProperties,
};
use crate::{
    error::EthrBuilderError,
    resolver::{
        did_registry::{
            DidattributeChangedFilter, DiddelegateChangedFilter, DidownerChangedFilter,
        },
        EventContext,
    },
    types::{self, NULL_ADDRESS},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ethers::types::{Address, Bytes, U256};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Key {
    Attribute {
        name: [u8; 32],
        value: Bytes,
        attribute: Attribute,
    },
    Delegate {
        delegate: Address,
        purpose: KeyPurpose,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// DID Ethr Builder
pub struct EthrBuilder {
    /// Context of the DID
    pub(super) context: Vec<Url>,
    /// The DID
    pub(super) id: DidUrl,
    /// Aliases for the DID
    pub(super) also_known_as: Vec<DidUrl>,
    /// Controller of the DID
    pub(super) controller: Option<DidUrl>,
    /// Verification methods associated with the DID
    pub(super) verification_method: Vec<VerificationMethod>,
    /// Authentication methods associated with the DID
    pub(super) authentication: Vec<DidUrl>,
    /// Assertion methods associated with the DID
    pub(super) assertion_method: Vec<DidUrl>,
    /// Key agreement keys associated with the DID
    pub(super) key_agreement: Vec<DidUrl>,
    /// Invokers associated with the DID    
    pub(super) capability_invocation: Vec<DidUrl>,
    /// Delegates associated with the DID
    pub(super) capability_delegation: Vec<DidUrl>,
    /// External services associated with the DID
    pub(super) service: Vec<Service>,
    /// the index a new delegate should be assigned
    pub(super) delegate_count: usize,
    /// the index a new service should be assigned
    pub(super) service_count: usize,
    /// the index a new xmtp key should be assigned
    pub(super) xmtp_count: usize,
    /// whether the document has been deactivated
    pub(super) is_deactivated: bool,
    /// Current time for the document
    pub(super) now: U256,
    /// Map of keys to their index in the document
    /// _*NOTE*_: this is used to ensure the order of keys is maintained, but indexes of the same
    /// number are expected. (EX: a delegate and service both with index 0)
    pub(super) keys: HashMap<Key, (usize, EventContext)>,
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
            verification_method: Default::default(),
            controller: None,
            authentication: Default::default(),
            assertion_method: Default::default(),
            key_agreement: Default::default(),
            capability_invocation: Default::default(),
            capability_delegation: Default::default(),
            service: Default::default(),
            delegate_count: 0,
            service_count: 0,
            xmtp_count: 0,
            now: U256::zero(),
            keys: Default::default(),
            is_deactivated: false,
        }
    }
}

/// Builder to dynamically build a DID document from the events emitted by the [`DIDRegistry`](crate::resolver::did_registry::DIDRegistry).
impl EthrBuilder {
    /// Set the current time this document is valid for.
    pub fn now(&mut self, now: U256) {
        self.now = now;
    }

    /// set the identity of the document
    pub fn account_address(&mut self, key: &Address) -> Result<(), EthrBuilderError> {
        self.id = self.id.with_account(types::Account::Address(*key));
        Ok(())
    }

    /// set the identity of the document
    pub fn public_key(&mut self, key: &[u8]) -> Result<(), EthrBuilderError> {
        self.id = self.id.with_account(types::Account::HexKey(key.to_vec()));
        Ok(())
    }

    /// set any aliases this identity may also go by
    pub fn also_known_as(&mut self, did: &DidUrl) {
        self.also_known_as.push(did.clone());
    }

    /// Set the controller of the document
    pub fn controller(&mut self, controller: &Address) -> Result<(), EthrBuilderError> {
        let did = self.id.with_account(types::Account::Address(*controller));
        self.controller = Some(did);
        Ok(())
    }

    /// check whether the document has been deactivated
    pub fn is_deactivated(&mut self) -> bool {
        self.is_deactivated
    }

    /// Add a delegate to the DID Document.
    /// Delegate keys are Ethereum addresses that can either be general signing keys or optionally also perform authentication.
    /// They are also verifiable from Solidity (on-chain).
    /// When a delegate is added or revoked, a DIDDelegateChanged event is published that MUST be used to update the DID document.
    ///
    /// reference: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
    pub fn delegate_event(
        &mut self,
        event: DiddelegateChangedFilter,
        context: &EventContext,
    ) -> Result<(), EthrBuilderError> {
        let delegate_type = String::from_utf8_lossy(&event.delegate_type);
        let key_purpose = types::parse_delegate(&delegate_type)?;

        let key = Key::Delegate {
            delegate: event.delegate,
            purpose: key_purpose,
        };

        if !event.is_valid(&self.now) {
            log::debug!("No Longer Valid {:?}", key);
            self.keys.remove(&key);
            return Ok(());
        }

        self.keys
            .insert(key, (self.delegate_count, context.clone()));
        self.delegate_count += 1;

        Ok(())
    }

    /// Add a general attribute which indicates external services or keys associated with the DID.
    /// The name of the attribute added to ERC1056 should follow this format: `did/pub/(Secp256k1|RSA|Ed25519|X25519)/(veriKey|sigAuth|enc)/(hex|base64|base58)`
    ///
    /// reference: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
    pub fn attribute_event(
        &mut self,
        event: DidattributeChangedFilter,
        context: &EventContext,
    ) -> Result<(), EthrBuilderError> {
        let name = event.name_string_lossy();

        if log::log_enabled!(log::Level::Trace) {
            log::trace!(
                "Attribute Event name={}, value={}, now={}, valid_to={}",
                name.clone(),
                event.value_string_lossy(),
                self.now,
                event.valid_to
            );
        }

        let attribute =
            types::parse_attribute(&name).unwrap_or_else(|_err| Attribute::Other(name.to_owned()));

        let key = Key::Attribute {
            name: event.name,
            value: event.value.clone(),
            attribute: attribute.clone(),
        };

        // if the event is invalid, and the key exists, it means this attribute changed event
        // is revoking the key
        if !event.is_valid(&self.now) && self.keys.remove(&key).is_some() {
            return Ok(());
        }

        match attribute {
            Attribute::PublicKey(_) => {
                if event.is_valid(&self.now) {
                    self.keys
                        .insert(key, (self.delegate_count, context.clone()));
                }
                self.delegate_count += 1;
            }
            Attribute::Service(_) => {
                if event.is_valid(&self.now) {
                    self.keys.insert(key, (self.service_count, context.clone()));
                }
                self.service_count += 1;
            }
            Attribute::Xmtp(_) => {
                if event.is_valid(&self.now) {
                    self.keys.insert(key, (self.xmtp_count, context.clone()));
                }
                self.xmtp_count += 1;
            }
            Attribute::Other(_) => {
                log::warn!(
                    "unhandled or malformed attribute name=`{name}`,value=`{}`",
                    event.value_string_lossy()
                )
            }
        };

        Ok(())
    }

    ///  Add an owner to the document
    ///  The event data is used to update the #controller entry in the verificationMethod array.
    ///  When resolving DIDs with publicKey identifiers, if the controller (owner) address is different from the corresponding address of the publicKey, then the #controllerKey entry in the verificationMethod array MUST be omitted.
    ///
    ///  referecne: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#controller-changes-didownerchanged)
    pub fn owner_event(&mut self, event: DidownerChangedFilter) -> Result<(), EthrBuilderError> {
        self.controller(&event.owner)?;
        if event.owner == Address::from_str(NULL_ADDRESS).expect("const address is correct") {
            // set the deactivated flag in case the address was deactivated.
            self.is_deactivated = true;
        }
        Ok(())
    }

    /// Add an external service to the document.
    /// The endpoint is the value of the attribute committed to the chain.
    ///
    /// reference: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
    pub fn service<V: AsRef<[u8]>>(
        &mut self,
        index: usize,
        value: V,
        service: ServiceType,
    ) -> Result<(), EthrBuilderError> {
        let did = self.id.with_fragment(Some(&format!("service-{}", index)));
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
    pub fn external_public_key<V: AsRef<[u8]>>(
        &mut self,
        index: usize,
        value: V,
        key: PublicKey,
    ) -> Result<(), EthrBuilderError> {
        let did = self.id.with_fragment(Some(&format!("delegate-{}", index)));
        let method = VerificationMethod {
            id: did,
            controller: self.id.clone(),
            verification_type: key.key_type,
            verification_properties: Self::encode_attribute_value(value, key.encoding)?,
        };

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
        };

        self.verification_method.push(method.clone());
        Ok(())
    }

    /// Internal helper fn to encode a value into the correct format required by the DID Document.
    pub(super) fn encode_attribute_value<V: AsRef<[u8]>>(
        value: V,
        encoding: KeyEncoding,
    ) -> Result<Option<VerificationMethodProperties>, EthrBuilderError> {
        log::debug!(
            "decoding attribute value {:?} with encoding: {}",
            value.as_ref(),
            encoding
        );

        Ok(match encoding {
            KeyEncoding::Hex => Some(VerificationMethodProperties::PublicKeyHex {
                public_key_hex: hex::encode(value),
            }),
            KeyEncoding::Base64 => Some(VerificationMethodProperties::PublicKeyBase64 {
                public_key_base64: BASE64.encode(value),
            }),
            KeyEncoding::Base58 => Some(VerificationMethodProperties::PublicKeyBase58 {
                public_key_base58: bs58::encode(value).into_string(),
            }),
        })
    }

    /// Adds a delegate to the document
    /// The only 2 delegateTypes that are currently published in the DID document are:
    /// * `veriKey` which adds a EcdsaSecp256k1RecoveryMethod2020 to the verificationMethod section of the DID document with the blockchainAccountId(ethereumAddress) of the delegate, and adds a reference to it in the assertionMethod section.
    /// * `sigAuth` which adds a EcdsaSecp256k1RecoveryMethod2020 to the verificationMethod section of document and a reference to it in the authentication section.
    ///
    /// reference: [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
    pub fn delegate(&mut self, index: usize, delegate: &Address, purpose: KeyPurpose) {
        let did = self.id.with_fragment(Some(&format!("delegate-{}", index)));

        // TODO: Handle ChainID
        let method = VerificationMethod {
            id: did,
            controller: self.id.clone(),
            verification_type: KeyType::EcdsaSecp256k1RecoveryMethod2020,
            verification_properties: Some(VerificationMethodProperties::BlockchainAccountId {
                blockchain_account_id: format!("0x{}", hex::encode(delegate)),
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

    /// Handle controller changes according to [owner changed](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#controller-changes-didownerchanged) and [registration](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#create-register)
    fn build_controller(&mut self) {
        let mut controller = self.controller.clone().unwrap_or(self.id.clone());
        controller = controller.with_fragment(Some("controller"));

        self.verification_method.push(VerificationMethod {
            id: controller.clone(),
            controller: self.id.clone(),
            verification_type: KeyType::EcdsaSecp256k1VerificationKey2019,
            verification_properties: Some(VerificationMethodProperties::BlockchainAccountId {
                blockchain_account_id: self.id.did.account.to_string(),
            }),
        });

        // if we are resolving for a key that is a public key which matches the id, we need to add
        // another `controllerKey` verification method
        if let Account::HexKey(_) = self.id.account() {
            let controller_key = self.id.with_fragment(Some("controllerKey"));
            self.verification_method.push(VerificationMethod {
                id: controller_key.clone(),
                controller: self.id.clone(),
                verification_type: KeyType::EcdsaSecp256k1VerificationKey2019,
                verification_properties: Some(VerificationMethodProperties::BlockchainAccountId {
                    blockchain_account_id: self.id.did.account.to_string(),
                }),
            });
            self.authentication.push(controller_key.clone());
            self.assertion_method.push(controller_key);
        }
    }

    /// Build the DID Document
    pub fn build(mut self) -> Result<DidDocument, EthrBuilderError> {
        self.build_controller();

        if !self.is_deactivated {
            self.build_keys()?;
        }

        Ok(DidDocument {
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
        })
    }

    fn build_keys(&mut self) -> Result<(), EthrBuilderError> {
        let mut keys = self
            .keys
            .drain()
            .collect::<Vec<(Key, (usize, EventContext))>>();
        keys.sort_by_key(|(_, (index, _))| *index);

        for (key, (index, context)) in keys {
            match key {
                Key::Attribute {
                    value, attribute, ..
                } => match attribute {
                    Attribute::PublicKey(key) => {
                        self.external_public_key(index, value, key)?;
                    }
                    Attribute::Service(service) => {
                        self.service(index, value, service)?;
                    }
                    Attribute::Xmtp(xmtp) => self.xmtp_key(index, value, xmtp, &context)?,
                    Attribute::Other(_) => (),
                },
                Key::Delegate { delegate, purpose } => {
                    self.delegate(index, &delegate, purpose);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::types::test::address;

    impl EventContext {
        pub fn mock(block_timestamp: u64) -> Self {
            Self { block_timestamp }
        }
    }

    //TODO: dids are case-sensitive w.r.t their addresses. One did should equal the other, no
    //matter the case of the address (other than blockchain_account_id b/c of EIP55)
    pub fn base_attr_changed(
        identity: Address,
        valid_to: Option<u32>,
    ) -> DidattributeChangedFilter {
        DidattributeChangedFilter {
            identity,
            previous_change: U256::zero(),
            valid_to: valid_to.map(Into::into).unwrap_or(U256::MAX),
            name: [0u8; 32],
            value: b"".into(),
        }
    }

    #[test]
    fn test_attribute_changed_secp256k() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");

        let event = DidattributeChangedFilter {
            name: *b"did/pub/Secp256k1/veriKey/hex   ",
            value: hex::decode(
                "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
            )
            .unwrap()
            .into(),
            ..base_attr_changed(identity, None)
        };

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        let context = EventContext::mock(0);
        builder.attribute_event(event, &context).unwrap();
        let doc = builder.build().unwrap();
        assert_eq!(
            doc.verification_method[1],
            VerificationMethod {
                id: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f#delegate-0")
                    .unwrap(),
                verification_type: KeyType::EcdsaSecp256k1VerificationKey2019,
                controller: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f")
                    .unwrap(),
                verification_properties: Some(VerificationMethodProperties::PublicKeyHex {
                    public_key_hex:
                        "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71".into()
                }),
            }
        )
    }

    #[test]
    fn test_attribute_changed_ed25519() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let event = DidattributeChangedFilter {
            name: *b"did/pub/Ed25519/veriKey/base58  ",
            value: hex::decode("b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71")
                .unwrap()
                .into(),
            ..base_attr_changed(identity, None)
        };

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        builder
            .attribute_event(event, &EventContext::mock(0))
            .unwrap();
        let doc = builder.build().unwrap();
        assert_eq!(
            doc.verification_method[1],
            VerificationMethod {
                id: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f#delegate-0")
                    .unwrap(),
                verification_type: KeyType::Ed25519VerificationKey2020,
                controller: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f")
                    .unwrap(),
                verification_properties: Some(VerificationMethodProperties::PublicKeyBase58 {
                    public_key_base58: "DV4G2kpBKjE6zxKor7Cj21iL9x9qyXb6emqjszBXcuhz".into()
                }),
            }
        );
    }

    #[test]
    fn test_attribute_changed_ed25519_from_hex_bytes() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let name_from_hex_str =
            hex::decode("6469642f7075622f456432353531392f766572694b65792f6261736535380000")
                .unwrap();
        let name_bytes: [u8; 32] = name_from_hex_str.try_into().unwrap();

        let event = DidattributeChangedFilter {
            name: name_bytes,
            value: hex::decode("302a300506032b656e032100118557777ffb078774371a52b00fed75561dcf975e61c47553e664a617661052")
                .unwrap()
                .into(),
            ..base_attr_changed(identity, None)
        };

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        builder
            .attribute_event(event, &EventContext::mock(0))
            .unwrap();

        let doc = builder.build().unwrap();
        assert_eq!(
            doc.verification_method[1],
            VerificationMethod {
                id: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f#delegate-0")
                    .unwrap(),
                verification_type: KeyType::Ed25519VerificationKey2020,
                controller: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f")
                    .unwrap(),
                verification_properties: Some(VerificationMethodProperties::PublicKeyBase58 {
                    public_key_base58:
                        "GfHq2tTVk9z3mSdEuYacxyV1C1p5arm7aGSJBzhWFKwi5imJXQmyWNbNEjEZ".into()
                }),
            }
        );
    }

    #[test]
    fn test_attribute_changed_x25519() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let event = DidattributeChangedFilter {
            name: *b"did/pub/X25519/enc/base64       ",
            value: hex::decode("302a300506032b656e032100118557777ffb078774371a52b00fed75561dcf975e61c47553e664a617661052").unwrap().into(),
            ..base_attr_changed(identity, None)
        };

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        builder
            .attribute_event(event, &EventContext::mock(0))
            .unwrap();
        let doc = builder.build().unwrap();
        assert_eq!(
            doc.verification_method[1],
            VerificationMethod {
                id: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f#delegate-0")
                    .unwrap(),
                verification_type: KeyType::X25519KeyAgreementKey2019,
                controller: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f")
                    .unwrap(),
                verification_properties: Some(VerificationMethodProperties::PublicKeyBase64 {
                    public_key_base64:
                        "MCowBQYDK2VuAyEAEYVXd3/7B4d0NxpSsA/tdVYdz5deYcR1U+ZkphdmEFI=".into()
                }),
            }
        );
    }

    #[test]
    fn test_attribute_changed_service() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let event = DidattributeChangedFilter {
            name: *b"did/svc/MessagingService        ",
            value: b"https://xmtp.com/resolver".into(),
            ..base_attr_changed(identity, None)
        };

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        builder
            .attribute_event(event, &EventContext::mock(0))
            .unwrap();
        let doc = builder.build().unwrap();
        assert_eq!(
            doc.service,
            vec![Service {
                id: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f#service-0")
                    .unwrap(),
                service_type: ServiceType::Messaging,
                service_endpoint: Url::parse("https://xmtp.com/resolver").unwrap(),
                recipient_keys: "".into(),
            }]
        );
    }

    #[test]
    fn test_attribute_changed_service_from_hex_bytes() {
        let name_data =
            hex::decode("6469642f7376632f4d6573736167696e67536572766963650000000000000000")
                .unwrap();
        let name_bytes: [u8; 32] = name_data.try_into().unwrap();
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let event = DidattributeChangedFilter {
            name: name_bytes,
            value: b"https://xmtp.com/resolver".into(),
            ..base_attr_changed(identity, None)
        };

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        builder
            .attribute_event(event, &EventContext::mock(0))
            .unwrap();
        let doc = builder.build().unwrap();
        assert_eq!(
            doc.service,
            vec![Service {
                id: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f#service-0")
                    .unwrap(),
                service_type: ServiceType::Messaging,
                service_endpoint: Url::parse("https://xmtp.com/resolver").unwrap(),
                recipient_keys: "".into(),
            }]
        );
    }

    #[test]
    fn test_attribute_increments_correctly() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let events = vec![
            DidattributeChangedFilter {
                name: *b"did/pub/Secp256k1/veriKey/hex   ",
                value: hex::decode("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71").unwrap().into(),
                ..base_attr_changed(identity, None)
            },
            DidattributeChangedFilter {
                name: *b"did/pub/Secp256k1/sigAuth/base58",
                value: hex::decode("b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71").unwrap().into(),
                ..base_attr_changed(identity, None)
            },
            DidattributeChangedFilter {
                name: *b"did/pub/X25519/enc/base64       ",
                value: hex::decode("302a300506032b656e032100118557777ffb078774371a52b00fed75561dcf975e61c47553e664a617661052").unwrap().into(),
                ..base_attr_changed(identity, None)
            },
            DidattributeChangedFilter {
                name: *b"did/svc/HubService              ",
                value: b"https://hubs.uport.me".into(),
                ..base_attr_changed(identity, None)
            },
            DidattributeChangedFilter {
                name: *b"did/svc/MessagingService        ",
                value: b"https://xmtp.com/resolver".into(),
                ..base_attr_changed(identity, None)
            }
        ];

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());

        for event in events {
            builder
                .attribute_event(event, &EventContext::mock(0))
                .unwrap();
        }

        let doc = builder.build().unwrap();
        assert_eq!(
            doc.verification_method[1].id.fragment().unwrap(),
            "delegate-0"
        );
        assert_eq!(
            doc.verification_method[2].id.fragment().unwrap(),
            "delegate-1"
        );
        assert_eq!(
            doc.verification_method[3].id.fragment().unwrap(),
            "delegate-2"
        );
        assert_eq!(doc.service[0].id.fragment().unwrap(), "service-0");
        assert_eq!(doc.service[1].id.fragment().unwrap(), "service-1");
    }

    #[test]
    fn test_attribute_increments_if_invalid() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let events = vec![
            DidattributeChangedFilter {
                name: *b"did/pub/Secp256k1/veriKey/hex   ",
                value: hex::decode("02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71").unwrap().into(),
                ..base_attr_changed(identity, None)
            },
            DidattributeChangedFilter {
                name: *b"did/pub/Secp256k1/sigAuth/base58",
                value: hex::decode("b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71").unwrap().into(),
                ..base_attr_changed(identity, Some(10))
            },
            DidattributeChangedFilter {
                name: *b"did/pub/X25519/enc/base64       ",
                value: hex::decode("302a300506032b656e032100118557777ffb078774371a52b00fed75561dcf975e61c47553e664a617661052").unwrap().into(),
                ..base_attr_changed(identity, None)
            },
            DidattributeChangedFilter {
                name: *b"did/svc/HubService              ",
                value: b"https://hubs.uport.me".into(),
                ..base_attr_changed(identity, Some(0))
            },
            DidattributeChangedFilter {
                name: *b"did/svc/MessagingService        ",
                value: b"https://xmtp.com/resolver".into(),
                ..base_attr_changed(identity, None)
            }
        ];

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::from(100));
        for event in events {
            builder
                .attribute_event(event, &EventContext::mock(0))
                .unwrap();
        }
        let doc = builder.build().unwrap();

        assert_eq!(
            doc.verification_method[1].id.fragment().unwrap(),
            "delegate-0"
        );
        assert_eq!(
            doc.verification_method[2].id.fragment().unwrap(),
            "delegate-2"
        );
        assert_eq!(doc.service[0].id.fragment().unwrap(), "service-1");
    }

    #[test]
    fn test_owner_changes() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let event = DidownerChangedFilter {
            identity,
            owner: address("0xfc88f377218e665d8ede610034c4ab2b81e5f9ff"),
            previous_change: U256::zero(),
        };

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        builder.owner_event(event).unwrap();

        assert_eq!(
            builder.controller,
            Some(DidUrl::parse("did:ethr:0xfc88f377218e665d8ede610034c4ab2b81e5f9ff").unwrap())
        );
    }

    #[test]
    fn test_delegate_changes() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let events = vec![
            DiddelegateChangedFilter {
                identity,
                delegate_type: *b"veriKey                         ",
                delegate: address("0xfc88f377218e665d8ede610034c4ab2b81e5f9ff"),
                valid_to: U256::MAX,
                previous_change: U256::zero(),
            },
            DiddelegateChangedFilter {
                identity,
                delegate_type: *b"sigAuth                         ",
                delegate: address("0xfc88f377218e665d8ede610034c4ab2b81e5f9ff"),
                valid_to: U256::MAX,
                previous_change: U256::zero(),
            },
        ];

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        for event in events {
            builder
                .delegate_event(event, &EventContext::mock(0))
                .unwrap();
        }
        let doc = builder.build().unwrap();

        assert_eq!(
            doc.verification_method[1],
            VerificationMethod {
                id: DidUrl::parse(
                    "did:ethr:mainnet:0x7e575682a8e450e33eb0493f9972821ae333cd7f#delegate-0"
                )
                .unwrap(),
                verification_type: KeyType::EcdsaSecp256k1RecoveryMethod2020,
                controller: DidUrl::parse(
                    "did:ethr:mainnet:0x7e575682a8e450e33eb0493f9972821ae333cd7f"
                )
                .unwrap(),
                verification_properties: Some(VerificationMethodProperties::BlockchainAccountId {
                    // TODO: Handle chain_id
                    blockchain_account_id: "0xfc88f377218e665d8ede610034c4ab2b81e5f9ff".into()
                })
            }
        );

        assert_eq!(
            doc.verification_method[2],
            VerificationMethod {
                id: DidUrl::parse(
                    "did:ethr:mainnet:0x7e575682a8e450e33eb0493f9972821ae333cd7f#delegate-1"
                )
                .unwrap(),
                verification_type: KeyType::EcdsaSecp256k1RecoveryMethod2020,
                controller: DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f")
                    .unwrap(),
                verification_properties: Some(VerificationMethodProperties::BlockchainAccountId {
                    // TODO: Handle chain_id
                    blockchain_account_id: "0xfc88f377218e665d8ede610034c4ab2b81e5f9ff".into()
                })
            }
        );

        assert_eq!(
            DidUrl::parse("did:ethr:mainnet:0x7e575682a8e450e33eb0493f9972821ae333cd7f#delegate-0")
                .unwrap(),
            doc.assertion_method[0]
        );
        assert_eq!(
            DidUrl::parse("did:ethr:mainnet:0x7e575682a8e450e33eb0493f9972821ae333cd7f#delegate-1")
                .unwrap(),
            doc.authentication[0]
        );
    }

    #[test]
    fn test_revoke_delegates() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let events = vec![
            DiddelegateChangedFilter {
                identity,
                delegate_type: *b"veriKey                         ",
                delegate: address("0xfc88f377218e665d8ede610034c4ab2b81e5f9ff"),
                valid_to: U256::from(100),
                previous_change: U256::zero(),
            },
            DiddelegateChangedFilter {
                identity,
                delegate_type: *b"sigAuth                         ",
                delegate: address("0xfc88f377218e665d8ede610034c4ab2b81e5f9ff"),
                valid_to: U256::from(50),
                previous_change: U256::zero(),
            },
        ];

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        for event in &events {
            builder
                .delegate_event(event.clone(), &EventContext::mock(0))
                .unwrap();
        }

        // both events are valid
        assert_eq!(builder.keys.len(), 2);

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::from(75));
        for event in &events {
            builder
                .delegate_event(event.clone(), &EventContext::mock(0))
                .unwrap();
        }
        // only one event is valid
        assert_eq!(builder.keys.len(), 1);

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::from(125));
        for event in &events {
            builder
                .delegate_event(event.clone(), &EventContext::mock(0))
                .unwrap();
        }

        // no events valid
        assert_eq!(builder.keys.len(), 0);
    }

    #[test]
    fn test_delegates_sort() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let attributes = vec![
            DidattributeChangedFilter {
                name: *b"did/pub/Secp256k1/veriKey/hex   ",
                value: hex::decode(
                    "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
                )
                .unwrap()
                .into(),
                ..base_attr_changed(identity, None)
            },
            DidattributeChangedFilter {
                name: *b"did/pub/Secp256k1/sigAuth/base58",
                value: hex::decode(
                    "b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
                )
                .unwrap()
                .into(),
                ..base_attr_changed(identity, None)
            },
        ];
        let delegates = vec![
            DiddelegateChangedFilter {
                identity,
                delegate_type: *b"veriKey                         ",
                delegate: address("0xfc88f377218e665d8ede610034c4ab2b81e5f9ff"),
                valid_to: U256::from(100),
                previous_change: U256::zero(),
            },
            DiddelegateChangedFilter {
                identity,
                delegate_type: *b"sigAuth                         ",
                delegate: address("0xfc88f377218e665d8ede610034c4ab2b81e5f9ff"),
                valid_to: U256::from(50),
                previous_change: U256::zero(),
            },
        ];

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());

        let context = EventContext::mock(0);
        builder
            .attribute_event(attributes[0].clone(), &context)
            .unwrap();
        builder
            .delegate_event(delegates[0].clone(), &context)
            .unwrap();
        builder
            .attribute_event(attributes[1].clone(), &context)
            .unwrap();
        builder
            .delegate_event(delegates[1].clone(), &context)
            .unwrap();

        let doc = builder.build().unwrap();

        assert_eq!(
            doc.verification_method[1].id.fragment().unwrap(),
            "delegate-0"
        );
        assert_eq!(
            doc.verification_method[2].id.fragment().unwrap(),
            "delegate-1"
        );
        assert_eq!(
            doc.verification_method[3].id.fragment().unwrap(),
            "delegate-2"
        );
        assert_eq!(
            doc.verification_method[4].id.fragment().unwrap(),
            "delegate-3"
        );
    }

    #[test]
    fn test_owner_revoked() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let events = vec![
            DidownerChangedFilter {
                identity,
                owner: address("0xfc88f377218e665d8ede610034c4ab2b81e5f9ff"),
                previous_change: U256::zero(),
            },
            DidownerChangedFilter {
                identity,
                owner: address("0x0000000000000000000000000000000000000000"),
                previous_change: U256::one(),
            },
        ];

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());
        for event in events {
            builder.owner_event(event).unwrap();
        }

        assert_eq!(
            builder.controller,
            Some(DidUrl::parse("did:ethr:0x0000000000000000000000000000000000000000").unwrap())
        );
    }

    #[test]
    fn test_also_known_as() {
        let other = DidUrl::parse("did:ethr:0x7e575682a8e450e33eb0493f9972821ae333cd7f").unwrap();
        let mut builder = EthrBuilder::default();
        builder.also_known_as(&other);
        builder.now(U256::zero());
        assert_eq!(builder.also_known_as[0], other);
    }

    #[test]
    fn test_other_attribute() {
        let identity = address("0x7e575682a8e450e33eb0493f9972821ae333cd7f");
        let event = DidattributeChangedFilter {
            name: *b"test/random/attribute99999999   ",
            value: hex::decode(
                "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
            )
            .unwrap()
            .into(),
            ..base_attr_changed(identity, None)
        };

        let mut builder = EthrBuilder::default();
        builder.account_address(&identity).unwrap();
        builder.now(U256::zero());

        builder
            .attribute_event(event, &EventContext::mock(0))
            .unwrap();

        let doc = builder.build().unwrap();

        // no events should have been registered
        assert_eq!(doc.verification_method.len(), 1);
    }
}
