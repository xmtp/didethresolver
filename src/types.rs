//! Type Definitions for the DID Registry compatible with JSON

mod did_url;

use serde::{Deserialize, Serialize};
use smart_default::SmartDefault;
use url::Url;

pub use did_url::*;

/// DID Document, Based on did-eth reference
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<Url>,
    pub id: DidUrl,
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Option<Vec<DidUrl>>,
    pub controller: Option<DidUrl>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Option<Vec<VerificationMethod>>,
    pub service: Option<Vec<Service>>,
}

/// TODO
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Service {
    id: DidUrl,
    r#type: ServiceType,
    #[serde(rename = "serviceEndpoint")]
    service_endpoint: Url,
    #[serde(rename = "recipientKeys")]
    recipient_keys: String,
}

/// TODO
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethod {
    pub id: DidUrl,
    pub controller: DidUrl,
    #[serde(rename = "type")]
    pub verification_type: VerificationType,
    #[serde(rename = "publicKeyBase58")]
    pub public_key_base58: Option<String>,
    #[serde(rename = "publicKeyBase64")]
    pub public_key_base64: Option<String>,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Option<String>,
    #[serde(rename = "publicKeyHex")]
    pub public_key_hex: Option<String>,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "blockchain_account_id")]
    pub blockchain_account_id: Option<String>,
    #[serde(rename = "ethereumAddress")]
    pub ethereum_address: Option<String>,
    // does not cover conditional proof2022 subtypes
}

impl VerificationMethod {
    pub fn new(id: DidUrl, controller: DidUrl, verification_type: VerificationType) -> Self {
        Self {
            id,
            controller,
            verification_type,
            public_key_base58: None,
            public_key_base64: None,
            public_key_jwk: None,
            public_key_hex: None,
            public_key_multibase: None,
            blockchain_account_id: None,
            ethereum_address: None,
        }
    }

    pub fn set_blockchain_id(&mut self, id: String) {
        self.blockchain_account_id = Some(id);
    }
}

/// TODO
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ServiceType {
    #[default]
    MessagingService,
}

/// TODO
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum VerificationType {
    #[default]
    Ed25519VerificationKey2020,
}
