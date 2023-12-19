//! Parsing Expression Grammer (PEG) parsing rules for parts of a Decentralized Identifier

use crate::types::*;

pub use did_ethr_attribute_parser::attribute as parse_attribute;

peg::parser! {
    grammar did_ethr_attribute_parser() for str {

        rule secp256k1() -> KeyType
            = "Secp256k1" { KeyType::EcdsaSecp256kRecoveryMethod2020 }

        rule ed25519() -> KeyType
            = "Ed25519" { KeyType::Ed25519VerificationKey2020 }

        rule rsa() -> KeyType
            = "RSA" { KeyType::RsaVerificationKey2018 }

        rule x25519() -> KeyType
            = "X25519" { KeyType::X25519KeyAgreementKey2019 }

        rule key_type() -> KeyType
            = kt:(secp256k1() / ed25519() / rsa() / x25519() ) { kt }

        rule key_purpose() -> KeyPurpose
            = "veriKey" { KeyPurpose::VerificationKey } / "sigAuth" { KeyPurpose::SignatureAuthentication } / "enc" { KeyPurpose::Encryption }

        rule encoding() -> KeyEncoding
            = "hex" { KeyEncoding::Hex } / "base64" { KeyEncoding::Base64 } / "base58" { KeyEncoding::Base58 }

        rule public_key() -> (KeyType, KeyPurpose, KeyEncoding)
            = "did/pub/" kt:key_type() "/" kp:key_purpose() "/" enc:encoding() {
                (kt, kp, enc)
            }

        rule messaging_service() -> ServiceType
            = "MessagingService"  { ServiceType::Messaging }

        rule other_service() -> ServiceType
            = svc:$([ 'a'..='z' | 'A'..='Z' | '0'..='9']+) { ServiceType::Other(svc.to_string()) }

        rule service() -> ServiceType
            = "did/svc/" svc:(messaging_service() / other_service()) { svc }

        /// Parses the `did/pub/(Secp256k1|RSA|Ed25519|X25519)/(veriKey|sigAuth|enc)/(hex|base64|base58)` part of a DID attribute name for adding a public key,
        /// or the `did/svc/[ServiceName]` part for adding a service
        pub rule attribute() -> Attribute
            = pk:public_key() {
                let key = PublicKey { key_type: pk.0, purpose: pk.1, encoding: pk.2 };
                Attribute::PublicKey(key)
            }
            / svc:service() { Attribute::Service(svc) }
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_attribute_parser() {
        let keys = [
            "did/pub/Secp256k1/veriKey/hex",
            "did/pub/Secp256k1/veriKey/base64",
            "did/pub/Secp256k1/veriKey/base58",
            "did/pub/Secp256k1/sigAuth/hex",
            "did/pub/Secp256k1/sigAuth/base64",
            "did/pub/Secp256k1/sigAuth/base58",
            "did/pub/Secp256k1/enc/hex",
            "did/pub/Secp256k1/enc/base64",
            "did/pub/Secp256k1/enc/base58",
            "did/pub/RSA/veriKey/hex",
            "did/pub/RSA/veriKey/base64",
            "did/pub/RSA/veriKey/base58",
            "did/pub/RSA/sigAuth/hex",
            "did/pub/RSA/sigAuth/base64",
            "did/pub/RSA/sigAuth/base58",
            "did/pub/RSA/enc/hex",
            "did/pub/RSA/enc/base64",
            "did/pub/RSA/enc/base58",
            "did/pub/Ed25519/veriKey/hex",
            "did/pub/Ed25519/veriKey/base64",
            "did/pub/Ed25519/veriKey/base58",
            "did/pub/Ed25519/sigAuth/hex",
            "did/pub/Ed25519/sigAuth/base64",
            "did/pub/Ed25519/sigAuth/base58",
            "did/pub/Ed25519/enc/hex",
            "did/pub/Ed25519/enc/base64",
            "did/pub/Ed25519/enc/base58",
            "did/pub/X25519/veriKey/hex",
            "did/pub/X25519/veriKey/base64",
            "did/pub/X25519/veriKey/base58",
            "did/pub/X25519/sigAuth/hex",
            "did/pub/X25519/sigAuth/base64",
            "did/pub/X25519/sigAuth/base58",
            "did/pub/X25519/enc/hex",
            "did/pub/X25519/enc/base64",
            "did/pub/X25519/enc/base58",
            "did/svc/MessagingService",
        ];

        for key in keys {
            let parsed = parse_attribute(key);
            assert!(parsed.is_ok(), "Failed to parse key: {}", key);
        }
    }
}
