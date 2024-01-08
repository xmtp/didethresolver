//! Type Definitions adhering to the [DID Specification](https://www.w3.org/TR/did-core/#abstract)
//! and [did:ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#method-specific-identifier)

mod did_parser;
mod did_url;
mod ethr;

use serde::{Deserialize, Serialize};
use url::Url;

pub use did_parser::*;
pub use did_url::*;
pub use ethr::*;

/// The ethereum null addresss
pub const NULL_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// A DID Document, based on the did specification, [DID Document Properties](https://www.w3.org/TR/did-core/#did-document-properties)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<Url>,
    pub id: DidUrl,
    #[serde(default, rename = "alsoKnownAs", skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<DidUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<DidUrl>,
    #[serde(
        default,
        rename = "verificationMethod",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<DidUrl>,
    #[serde(
        default,
        rename = "assertionMethod",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub assertion_method: Vec<DidUrl>,
    #[serde(
        default,
        rename = "keyAgreement",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub key_agreement: Vec<DidUrl>,
    #[serde(
        default,
        rename = "capabilityInvocation",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_invocation: Vec<DidUrl>,
    #[serde(
        default,
        rename = "capabilityDelegation",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_delegation: Vec<DidUrl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,
}

impl DidDocument {
    pub fn ethr_builder() -> EthrBuilder {
        EthrBuilder::default()
    }
}

/// Represents a service associated with a DID.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The unique identifier of the service.
    pub id: DidUrl,
    /// The type of the service (e.g., messaging, hub, etc.).
    #[serde(rename = "type")]
    pub service_type: ServiceType,
    /// The URL representing the service endpoint.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: Url,
    /// A string listing recipient keys associated with the service.
    #[serde(rename = "recipientKeys")]
    pub recipient_keys: String,
}

/// Describes a method for verifying a DID.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethod {
    /// The unique identifier of the verification method, typically a DID URL.
    pub id: DidUrl,
    /// The DID URL of the controller for this verification method.
    pub controller: DidUrl,
    /// The type of the verification method (e.g., cryptographic key type).
    #[serde(rename = "type")]
    pub verification_type: KeyType,
    /// the public key and its encoding
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub verification_properties: Option<VerificationMethodProperties>,
}

/// TODO
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum VerificationMethodProperties {
    /// Public key encoded as hex
    PublicKeyHex {
        #[serde(rename = "publicKeyHex")]
        public_key_hex: String,
    },
    /// Public key encoded as base64, using the default alphabet
    PublicKeyBase64 {
        #[serde(rename = "publicKeyBase64")]
        public_key_base64: String,
    },
    /// Public key encoded as base58
    PublicKeyBase58 {
        #[serde(rename = "publicKeyBase58")]
        public_key_base58: String,
    },
    /// Public key as a Json-Web-Key
    PublicKeyJwk {
        #[serde(rename = "publicKeyJwk")]
        public_key_jwk: String,
    },
    /// Public key in Multibase format
    PublicKeyMultibase {
        #[serde(rename = "publicKeyMultibase")]
        public_key_multibase: String,
    },
    /// Blockcahin account identitfier, case insensitive (does not support EIP-55)
    BlockchainAccountId {
        #[serde(rename = "blockchainAccountId")]
        blockchain_account_id: String,
    },
}

/// Represents different types of services associated with a DID.
/// Currently, only [`ServiceType::Messaging`] is directly supported
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ServiceType {
    /// Specific serice type for messaging
    #[serde(rename = "MessagingService")]
    Messaging,
    /// Other Service type, not directly supported
    Other(String),
}

/// Various cryptographic key types defined in the [DID Specification](https://www.w3.org/TR/did-spec-registries/#verification-method-types)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    JsonWebKey2020,
    Ed25519VerificationKey2020,
    EcdsaSecp256k1RecoveryMethod2020,
    EcdsaSecp256k1VerificationKey2019,
    RsaVerificationKey2018,
    X25519KeyAgreementKey2019,
}

impl From<KeyType> for String {
    fn from(kt: KeyType) -> String {
        match kt {
            KeyType::JsonWebKey2020 => "jwk".into(),
            KeyType::Ed25519VerificationKey2020 => "Ed25519".into(),
            KeyType::EcdsaSecp256k1RecoveryMethod2020 => "Secp256k1".into(),
            KeyType::EcdsaSecp256k1VerificationKey2019 => "Secp256k1".into(),
            KeyType::RsaVerificationKey2018 => "RSA".into(),
            KeyType::X25519KeyAgreementKey2019 => "X25519".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    VerificationKey,
    SignatureAuthentication,
    Encryption,
}

impl From<KeyPurpose> for String {
    fn from(purpose: KeyPurpose) -> String {
        match purpose {
            KeyPurpose::VerificationKey => "veriKey".into(),
            KeyPurpose::SignatureAuthentication => "sigAuth".into(),
            KeyPurpose::Encryption => "enc".into(),
        }
    }
}

impl From<KeyEncoding> for String {
    fn from(enc: KeyEncoding) -> String {
        match enc {
            KeyEncoding::Hex => "hex".into(),
            KeyEncoding::Base64 => "base64".into(),
            KeyEncoding::Base58 => "base58".into(),
        }
    }
}

/// A parsed did:ethr did:ethr attribute name value, returned from [`parse_attribute`]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Attribute {
    PublicKey(PublicKey),
    Service(ServiceType),
    Other(String),
}

/// Indicates the encoding of a key in a did:ethr attribute
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyEncoding {
    Hex,
    Base64,
    Base58,
}

/// Indicates the Public Key Type, Purpose, and Encoding from a did:ethr attribute name
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub key_type: KeyType,
    pub purpose: KeyPurpose,
    pub encoding: KeyEncoding,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DidDocumentMetadata {
    #[serde(default, rename="deactivated")]
    pub deactivated: bool,
    #[serde(default, rename="versionId")]
    pub version_id: u64,
    #[serde(default, rename="updated", skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(default, rename="nextVersionId", skip_serializing_if = "Option::is_none")]
    pub next_version_id: Option<u64>,
    #[serde(default, rename="nextUpdate", skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DidResolutionMetadata {
    #[serde(default, rename="contentType")]
    pub content_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DidResolutionResult {
    #[serde(default, rename="didDocumentMetadata", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<DidDocumentMetadata>,
    #[serde(rename="didResolutionMetadata", skip_serializing_if = "Option::is_none")]
    pub resolution_metadata: Option<DidResolutionMetadata>,
    #[serde(rename="didDocument")]
    pub document: DidDocument,
}

#[cfg(test)]
mod test {
    use super::*;
    use ethers::types::Address;
    use serde_json::json;

    /// Get an address from a hex string
    pub fn address(s: &str) -> Address {
        let s = s.strip_prefix("0x").unwrap_or(s);
        Address::from_slice(&hex::decode(s).unwrap())
    }

    #[test]
    fn test_serialization_of_document() {
        let sample_did = json!({
            "@context": [
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "controller": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
            "id": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
            "service": [
              {
                "id": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
                "recipientKeys": "0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
                "serviceEndpoint": "https://xmtp.com/resolver",
                "type": "MessagingService"
              }
            ],
            "verificationMethod": [
              {
                "controller": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
                "id": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
                "publicKeyMultibase": "0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
                "type": "Ed25519VerificationKey2020"
              }
            ]
        });
        let doc: DidDocument = serde_json::from_value(sample_did.clone()).unwrap();

        assert_eq!(
            doc,
            DidDocument {
                context: vec![
                    "https://www.w3.org/ns/did/v1".try_into().unwrap(),
                    "https://w3id.org/security/suites/ed25519-2020/v1"
                        .try_into()
                        .unwrap()
                ],
                id: DidUrl::parse("did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad").unwrap(),
                controller: Some(
                    DidUrl::parse("did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad").unwrap()
                ),
                service: vec![Service {
                    id: DidUrl::parse("did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad")
                        .unwrap(),
                    recipient_keys: "0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad".to_string(),
                    service_endpoint: Url::parse("https://xmtp.com/resolver").unwrap(),
                    service_type: ServiceType::Messaging,
                }],
                verification_method: vec![VerificationMethod {
                    id: DidUrl::parse("did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad")
                        .unwrap(),
                    controller: DidUrl::parse(
                        "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad"
                    )
                    .unwrap(),
                    verification_type: KeyType::Ed25519VerificationKey2020,
                    verification_properties: Some(
                        VerificationMethodProperties::PublicKeyMultibase {
                            public_key_multibase: "0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad"
                                .to_string(),
                        }
                    ),
                }],
                ..DidDocument::ethr_builder().build()
            }
        );
        assert_eq!(serde_json::to_value(doc).unwrap(), sample_did);
    }

    #[test]
    fn test_keytype_to_str() {
        assert_eq!(String::from(KeyType::JsonWebKey2020), "jwk");
        assert_eq!(String::from(KeyType::Ed25519VerificationKey2020), "Ed25519");
        assert_eq!(
            String::from(KeyType::EcdsaSecp256k1RecoveryMethod2020),
            "Secp256k1"
        );
        assert_eq!(
            String::from(KeyType::EcdsaSecp256k1VerificationKey2019),
            "Secp256k1"
        );
        assert_eq!(String::from(KeyType::RsaVerificationKey2018), "RSA");
        assert_eq!(String::from(KeyType::X25519KeyAgreementKey2019), "X25519");
    }
}
