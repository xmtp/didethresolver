//! Parsing Expression Grammer (PEG) parsing rules for parts of a Decentralized Identifier

use ethers::types::Address;

use crate::types::*;

pub use did_ethr_attribute_parser::attribute as parse_attribute;
pub use did_ethr_delegate_parser::delegate as parse_delegate;
pub use did_ethr_parser::ethr_did as parse_ethr_did;

peg::parser! {
    grammar did_ethr_parser() for str {
        /// parses the `path` part of a [DID-URL](https://www.w3.org/TR/did-core/#did-syntax)
        ///
        /// # Example
        /// ```rust
        /// use didethresolver::types::{Method, Id, ChainId, AddressOrHexKey, MethodAndId, parse_ethr_did};
        /// use ethers::types::Address;
        /// let parsed = parse_ethr_did("ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        /// assert_eq!(
        ///    parsed,
        ///    MethodAndId {
        ///        method: Method::Ethr,
        ///        id: Id {
        ///            chain: ChainId::Mainnet,
        ///            public_key: AddressOrHexKey::Address(Address::from_slice(
        ///                &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
        ///            ))
        ///        }
        ///   });
        /// ```
        pub rule ethr_did() -> MethodAndId
            = method:method() id:id() { MethodAndId { method, id } }

        rule method() -> Method
            = "ethr:" { Method::Ethr } / expected!("the only supported method is `ethr`")

        rule id() -> Id
            = id: id_no_network() { id } / id:id_and_network() { id }

        rule id_and_network() -> Id
            = network:ethr_network() ":" key:address_or_hex() { Id { chain: network, public_key: key } }

        // the default chain is Mainnet, if it's ommitted we default to Mainnet
        rule id_no_network() -> Id
            = key:address_or_hex() { Id { chain: Default::default(), public_key: key } }

        rule ethr_network() -> ChainId
            = network_chain_id:network_chain_id() { network_chain_id }
            / network_name:(mainnet() / goerli()) { network_name }

        rule address_or_hex() -> AddressOrHexKey
            = address:ethereum_address() { address }
            / key:public_key_hex() { key }

        rule mainnet() -> ChainId
            = i("mainnet") { ChainId::Mainnet }

        rule goerli() -> ChainId
            = i("goerli") {
                #[allow(deprecated)]
                ChainId::Goerli
            }

        rule network_chain_id() -> ChainId
            = "0" i("x") digits:$(hex_digit()+) {
                ChainId::from(digits)
            }

        rule ethereum_address() -> AddressOrHexKey
            = "0" i("x") digits:$(hex_digit()*<40>) {
                AddressOrHexKey::Address(Address::from_slice(&hex::decode(&digits).unwrap()))
            }

        rule public_key_hex() -> AddressOrHexKey
            = "0" i("x") digits:$(hex_digit()*<66>) {
                AddressOrHexKey::HexKey(hex::decode(digits).unwrap())
            }

        rule hex_digit() -> String
           = digits:$(['0'..='9' | 'a'..='f' | 'A'..='F']) { digits.to_string() }

        // case insensitive rule (see https://github.com/kevinmehall/rust-peg/issues/216)
        rule i(literal: &'static str)
            = input:$([_]*<{literal.len()}>)
            {? if input.eq_ignore_ascii_case(literal) { Ok(()) } else { Err(literal) } }
    }
}

peg::parser! {
    grammar did_ethr_attribute_parser() for str {

        // case insensitive rule (see https://github.com/kevinmehall/rust-peg/issues/216)
        rule i(literal: &'static str)
            = input:$([_]*<{literal.len()}>)
            {? if input.eq_ignore_ascii_case(literal) { Ok(()) } else { Err(literal) } }

        rule padding() = [ ' '  | '0' ]*

        rule secp256k1() -> KeyType
            = i("Secp256k1") { KeyType::EcdsaSecp256k1VerificationKey2019 }

        rule ed25519() -> KeyType
            = i("Ed25519") { KeyType::Ed25519VerificationKey2020 }

        rule rsa() -> KeyType
            = i("RSA") { KeyType::RsaVerificationKey2018 }

        rule x25519() -> KeyType
            = i("X25519") { KeyType::X25519KeyAgreementKey2019 }

        rule key_type() -> KeyType
            = kt:(secp256k1() / ed25519() / rsa() / x25519() ) { kt }

        rule key_purpose() -> KeyPurpose
            = i("veriKey") { KeyPurpose::VerificationKey } / "sigAuth" { KeyPurpose::SignatureAuthentication } / "enc" { KeyPurpose::Encryption }

        rule encoding() -> KeyEncoding
            = i("hex") { KeyEncoding::Hex } / "base64" { KeyEncoding::Base64 } / "base58" { KeyEncoding::Base58 }


        rule messaging_service() -> ServiceType
            = i("MessagingService")  { ServiceType::Messaging }

        rule other_service() -> ServiceType
            = svc:$([ 'a'..='z' | 'A'..='Z' | '0'..='9']+) { ServiceType::Other(svc.to_string()) }

        rule service() -> ServiceType
            = padding() "did/svc/" svc:(messaging_service() / other_service()) padding()  { svc }

        rule public_key() -> (KeyType, KeyPurpose, KeyEncoding)
            = padding() "did/pub/" kt:key_type() "/" kp:key_purpose() "/" enc:encoding() padding() {
                (kt, kp, enc)
            }

        /// Parses the DID attribute name value
        ///
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

peg::parser! {
    grammar did_ethr_delegate_parser() for str {
        // case insensitive rule (see https://github.com/kevinmehall/rust-peg/issues/216)
        rule i(literal: &'static str)
            = input:$([_]*<{literal.len()}>)
            {? if input.eq_ignore_ascii_case(literal) { Ok(()) } else { Err(literal) } }

        rule padding() = [ ' ' | '0' ]*

        rule veri_key() -> KeyPurpose
            = quiet!{ i("veriKey") } { KeyPurpose::VerificationKey }

        rule sig_auth() -> KeyPurpose
            = quiet!{ i("sigAuth") } { KeyPurpose::SignatureAuthentication }

        rule key_purpose() -> KeyPurpose
            = kp:(veri_key() / sig_auth() / expected!("the only supported delegate types are `sigAuth` and `veriKey`")) { kp }

        /// Parses the delegate type from a did:ethr attribute name (either `sigAuth` or `veriKey`)
        pub rule delegate() -> KeyPurpose
            = quiet! { padding() } kp:key_purpose() quiet! { padding() } { kp }
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

    #[test]
    fn test_ethr_method_parser() {
        let parsed =
            parse_ethr_did("ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(
            parsed,
            MethodAndId {
                method: Method::Ethr,
                id: Id {
                    chain: ChainId::Mainnet,
                    public_key: AddressOrHexKey::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                }
            }
        );

        // Mainnet is default
        let parsed = parse_ethr_did("ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(
            parsed,
            MethodAndId {
                method: Method::Ethr,
                id: Id {
                    chain: ChainId::Mainnet,
                    public_key: AddressOrHexKey::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                }
            }
        );

        let parsed =
            parse_ethr_did("ethr:0x01:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(
            parsed,
            MethodAndId {
                method: Method::Ethr,
                id: Id {
                    chain: ChainId::Mainnet,
                    public_key: AddressOrHexKey::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                }
            }
        );
    }

    #[test]
    fn test_ethr_delegate_parser() {
        let parsed = parse_delegate("sigAuth").unwrap();
        assert_eq!(parsed, KeyPurpose::SignatureAuthentication);

        let parsed = parse_delegate("veriKey").unwrap();
        assert_eq!(parsed, KeyPurpose::VerificationKey);

        let parsed = parse_delegate("verikey").unwrap();
        assert_eq!(parsed, KeyPurpose::VerificationKey);

        let parsed = parse_delegate("sigauth").unwrap();
        assert_eq!(parsed, KeyPurpose::SignatureAuthentication);

        let parsed = parse_delegate("enc").unwrap_err();
        assert_eq!(
            parsed.to_string(),
            "error at 1:1: expected the only supported delegate types are `sigAuth` and `veriKey`"
        );
    }
}
