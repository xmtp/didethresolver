//! Parsing Expression Grammer (PEG) parsing rules for parts of a Decentralized Identifier

use crate::types::*;

pub use did_attribute_parser::attribute as parse_attribute;

peg::parser! {
    grammar did_path_parser() for str {

        // Define a rule to parse a method name (lowercase letters and digits)
        rule method_name() -> String
            = m:$(['a'..='z' | '0'..='9']+) { m.to_string() }

        // Define a rule to parse a method-specific identifier (alphanumeric and special characters)
        rule method_specific_id() -> String
            = id:$(['a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_']+) { id.to_string() }

        // Define the main rule to parse the entire DID URL path
        pub rule did_url() -> (String, String)
            = "did:" method:method_name() ":" id:method_specific_id() {
                (method, id)
            }
    }
}

// TODO: Handle X25519
peg::parser! {
    grammar did_attribute_parser() for str {

        rule secp256k1() -> KeyType
            = "secp256k1" { KeyType::EcdsaSecp256kRecoveryMethod2020 }

        rule ed25519() -> KeyType
            = "ed25519" { KeyType::Ed25519VerificationKey2020 }

        rule jwk() -> KeyType
            = "jwk" { KeyType::JsonWebKey2020 }

        rule rsa() -> KeyType
            = "rsa" { KeyType::RsaVerificationKey2018 }

        rule key_type() -> KeyType
            = kt:(secp256k1() / ed25519() / rsa()) { kt }

        rule key_purpose() -> KeyPurpose
            = "veriKey" { KeyPurpose::VerificationKey } / "sigAuth" { KeyPurpose::SignatureAuthentication } / "enc" { KeyPurpose::Encryption }

        rule encoding() -> KeyEncoding
            = "hex" { KeyEncoding::Hex } / "base64" { KeyEncoding::Base64 }

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

        /// Parses the `did/pub/(Secp256k1|Rsa|Ed25519)/(veriKey|sigAuth)/(hex|base64)` part of a DID attribute name for adding a public key,
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

    fn test_did_attribute_parser() {
        // let name = ""
    }
}
