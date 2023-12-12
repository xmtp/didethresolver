//! Type Definitions for the DID Registry compatible with JSON

mod did_url;

use serde::{Deserialize, Serialize};
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
    id: DidUrl,
    controller: DidUrl,
    r#type: VerificationType,
    #[serde(rename = "publicKeyBase58")]
    public_key_base58: Option<String>,
    #[serde(rename = "publicKeyBase64")]
    public_key_base64: Option<String>,
    #[serde(rename = "publicKeyJwk")]
    public_key_jwk: Option<String>,
    #[serde(rename = "publicKeyHex")]
    public_key_hex: Option<String>,
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: Option<String>,
    #[serde(rename = "blockchain_account_id")]
    blockchain_account_id: Option<String>,
    #[serde(rename = "ethereumAddress")]
    ethereum_address: Option<String>,
    // does not cover conditional proof2022 subtypes
}

/// TODO
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ServiceType {
    MessagingService,
}

/// TODO
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum VerificationType {
    Ed25519VerificationKey2020,
}
