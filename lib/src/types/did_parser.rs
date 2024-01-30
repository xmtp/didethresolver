//! Parsing Expression Grammer (PEG) parsing rules for parts of a Decentralized Identifier

use ethers::types::Address;

use crate::types::*;

pub use did_ethr_attribute_parser::attribute as parse_attribute;
pub use did_ethr_delegate_parser::delegate as parse_delegate;
pub use did_ethr_parser::ethr_did as parse_ethr_did;
pub use did_ethr_parser::ethr_did_url as parse_ethr_did_url;

peg::parser! {
    grammar did_ethr_parser() for str {
        /// parses the `did` with a url path part of a [DID-URL](https://www.w3.org/TR/did-core/#did-syntax)
        /// # Example
        /// ```rust
        /// use lib_didethresolver::types::{DidUrl, Did, Method, Network, Account, parse_ethr_did_url};
        /// use ethers::types::Address;
        /// let parsed = parse_ethr_did_url("did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a/abc").unwrap();
        /// assert_eq!(
        ///   parsed,
        ///  DidUrl {
        ///     did: Did {
        ///        method: Method::Ethr,
        ///        network: Network::Mainnet,
        ///       account: Account::Address(Address::from_slice(
        ///       &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap())),
        ///     },
        ///     path: Some("/abc".to_string()),
        ///     query: None,
        ///     fragment: None
        ///  });
        /// ```
        ///
        pub rule ethr_did_url() -> DidUrl
            = did:ethr_did() path:did_path() query:did_query() fragment:did_fragment() { DidUrl { did, path, query, fragment } }

        /// parses the `did` part of a [DID-URL](https://www.w3.org/TR/did-core/#did-syntax)
        ///
        /// # Example
        /// ```rust
        /// use lib_didethresolver::types::{Did, Method, Network, Account, parse_ethr_did};
        /// use ethers::types::Address;
        /// let parsed = parse_ethr_did("did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        /// assert_eq!(
        ///    parsed,
        ///    Did {
        ///        method: Method::Ethr,
        ///        network: Network::Mainnet,
        ///        account: Account::Address(Address::from_slice(
        ///            &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
        ///        ))
        ///   });
        /// ```
        pub rule ethr_did() -> Did
            = did() ":" method:method() ":" network:(chain_id() / network())? account:account() { Did { method, network: network.unwrap_or_default(), account } }

        rule did() = "did" / expected!("only `did` is supported")

        rule method() -> Method
            = "ethr" { Method::Ethr } / expected!("the only supported method is `ethr`")

        rule chain_id() -> Network
            = "0" i("x") digits:$(HEXDIG()+) ":" { Network::from(digits) }

        rule network() -> Network
            // chain id networks
            = // named networks
            "mainnet:" { Network::Mainnet }
            / "sepolia:" { Network::Sepolia }
            / expected!("the only supported networks are `mainnet`, `sepolia`")

        rule account() -> Account
            = "0" i("x") digits:$(HEXDIG()*<40>) { Account::Address(Address::from_slice(&hex::decode(digits).unwrap())) }
            / "0" i("x") digits:$(HEXDIG()*<66>) { Account::HexKey(hex::decode(digits).unwrap()) }

        // case insensitive rule (see https://github.com/kevinmehall/rust-peg/issues/216)
        rule i(literal: &'static str)
            = input:$([_]*<{literal.len()}>)
            {? if input.eq_ignore_ascii_case(literal) { Ok(()) } else { Err(literal) } }

        // parses a url path according to the RFC 3986 definition
        // https://www.rfc-editor.org/rfc/rfc3986#section-3.3

        rule did_path() -> Option<String> = path:$(path_rootless() / path_abempty() / path_absolute() / path_noscheme() / path_empty()) (&"?" / ![_])?
            { if path.is_empty() { None } else { Some(path.to_string()) } }

        rule path_abempty() = ( "/" segment() )*

        rule path_absolute() = "/" ( segment_nz() ( "/" segment() )* )+

        rule path_rootless() = segment_nz() ( "/" segment() )*

        rule path_noscheme() = segment_nz_nc() ( "/" segment() )*

        rule segment() = pchar()*

        rule segment_nz() = pchar()+

        rule segment_nz_nc() = ( unreserved() / pct_encoded() / sub_delims() / "@" )+

        rule pchar() = unreserved() / pct_encoded() / sub_delims() / ":" / "@"

        rule unreserved() = ALPHA() / DIGIT() / "-" / "." / "_" / "~"

        rule pct_encoded() = "%" HEXDIG() HEXDIG()

        rule sub_delims() = "!" / "$" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=" / "&"

        rule path_empty() = ""

        rule qchar() = unreserved() / pct_encoded() / ":" / "@" / "/" / "?"

        rule ALPHA() -> char
            = ['a'..='z' | 'A'..='Z']

        rule DIGIT() -> char
            = ['0'..='9']

        rule HEXDIG() -> char
            = ['0'..='9' | 'a'..='f' | 'A'..='F']

        // parses a query according to the RFC 3986 definition
        // https://www.rfc-editor.org/rfc/rfc3986#section-3.4
        rule did_query() -> Option<Vec<(String, String)>> = query()?

        rule query() -> Vec<(String, String)> = "?" q:query_assignment() ** "&" (&"#" / ![_]) { q }

        rule query_assignment() -> (String, String) = n:$(query_name()) "=" v:$(query_value()) { (n.to_string(), v.to_string()) }

        rule query_name() = qchar()+

        rule query_value() = qchar()*

        // parses a fragment according to the RFC 3986 definition
        // https://www.rfc-editor.org/rfc/rfc3986#section-3.5
        rule did_fragment() -> Option<String> = fragment:$(fragment()?)
            {
                let fragment = fragment.strip_prefix('#').unwrap_or("");
                if fragment.is_empty() { None } else { Some(fragment.to_string()) }
            }

        rule fragment() = "#" ( pchar() / "/" / "?" )* ![_]
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

        rule xmtp_purpose() -> XmtpKeyPurpose
            = "installation" { XmtpKeyPurpose::Installation }

        rule xmtp() -> Attribute
            = padding() "xmtp/" xmtp:xmtp_purpose() "/" enc:encoding() padding() { Attribute::Xmtp(XmtpAttribute { purpose: xmtp, encoding: enc })}

        rule ethr() -> Attribute
            = pk:public_key() {
                let key = PublicKey { key_type: pk.0, purpose: pk.1, encoding: pk.2 };
                Attribute::PublicKey(key)
            }
            / svc:service() { Attribute::Service(svc) }

        /// Parses the DID attribute name value
        ///
        /// Parses
        /// *`did/pub/(Secp256k1|RSA|Ed25519|X25519)/(veriKey|sigAuth|enc|xmtp)/(hex|base64|base58)` part of a DID attribute name for adding a public key,
        /// * `did/svc/[ServiceName]` part for adding a service
        /// * `xmtp/installation/(hex|base64|base58)` attribute for adding an xmtp installation key
        pub rule attribute() -> Attribute
            = x:xmtp() { x } / e:ethr() { e }
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
    fn test_did_xmtp_attribute_parser() {
        let keys = [
            "xmtp/installation/hex",
            "xmtp/installation/base58",
            "xmtp/installation/base64",
        ];

        for key in keys {
            let parsed = parse_attribute(key);
            assert!(parsed.is_ok(), "Failed to parse key: {}", key);
        }
    }

    #[test]
    fn test_xmtp_attribute_parses() {
        assert_eq!(
            parse_attribute("xmtp/installation/hex"),
            Ok(Attribute::Xmtp(XmtpAttribute {
                purpose: XmtpKeyPurpose::Installation,
                encoding: KeyEncoding::Hex
            }))
        );

        assert_eq!(
            parse_attribute("xmtp/installation/base64"),
            Ok(Attribute::Xmtp(XmtpAttribute {
                purpose: XmtpKeyPurpose::Installation,
                encoding: KeyEncoding::Base64,
            }))
        );

        assert_eq!(
            parse_attribute("xmtp/installation/base58"),
            Ok(Attribute::Xmtp(XmtpAttribute {
                purpose: XmtpKeyPurpose::Installation,
                encoding: KeyEncoding::Base58
            }))
        );
    }

    #[test]
    fn test_did_ethr_is_required() {
        let parsed = parse_ethr_did("did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a");
        assert!(parsed.is_ok());
        let parsed = parse_ethr_did("ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a");
        assert!(parsed.is_err());
    }

    #[test]
    fn test_ethr_method_parser() {
        let parsed =
            parse_ethr_did("did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(
            parsed,
            Did {
                method: Method::Ethr,
                network: Network::Mainnet,
                account: Account::Address(Address::from_slice(
                    &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                ))
            }
        );

        // Mainnet is default
        let parsed = parse_ethr_did("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(
            parsed,
            Did {
                method: Method::Ethr,
                network: Network::Mainnet,
                account: Account::Address(Address::from_slice(
                    &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                ))
            }
        );

        let parsed =
            parse_ethr_did("did:ethr:0x01:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(
            parsed,
            Did {
                method: Method::Ethr,
                network: Network::Mainnet,
                account: Account::Address(Address::from_slice(
                    &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                ))
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

    #[test]
    fn test_ethr_did_parse_url() {
        let parsed = parse_ethr_did_url(
            "did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a/location/1/2:/3",
        )
        .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                },
                path: Some("/location/1/2:/3".to_string()),
                query: None,
                fragment: None
            }
        );
    }

    #[test]
    fn test_ethr_did_parse_url_1() {
        let parsed =
            parse_ethr_did_url("did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a/")
                .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                },
                path: Some("/".to_string()),
                query: None,
                fragment: None
            }
        );
    }

    #[test]
    fn test_ethr_did_parse_url_empty_path() {
        let parsed =
            parse_ethr_did_url("did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a")
                .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                },
                path: None,
                query: None,
                fragment: None
            }
        );
    }

    #[test]
    fn test_ethr_did_parse_url_query() {
        let parsed = parse_ethr_did_url(
            "did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a?a=????&c=d",
        )
        .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                },
                path: None,
                query: Some(vec![
                    ("a".to_string(), "????".to_string()),
                    ("c".to_string(), "d".to_string())
                ]),
                fragment: None
            }
        );
    }

    #[test]
    fn test_ethr_did_parse_url_fragment() {
        let parsed = parse_ethr_did_url(
            "did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a#section3_5",
        )
        .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                },
                path: None,
                query: None,
                fragment: Some("section3_5".to_string())
            }
        );
    }

    #[test]
    fn test_ethr_did_parse_url_path_query() {
        let parsed = parse_ethr_did_url(
            "did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a/:1/:2/:3/?a=b&c=d",
        )
        .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                },
                path: Some("/:1/:2/:3/".to_string()),
                query: Some(vec![
                    ("a".to_string(), "b".to_string()),
                    ("c".to_string(), "d".to_string())
                ]),
                fragment: None,
            }
        );
    }

    #[test]
    fn test_ethr_did_parse_url_path_fragment() {
        let parsed = parse_ethr_did_url(
            "did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a/a/b/c#section3_5",
        )
        .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                },
                path: Some("/a/b/c".to_string()),
                query: None,
                fragment: Some("section3_5".to_string())
            }
        );
    }

    #[test]
    fn test_ethr_did_parse_url_query_fragment() {
        let parsed = parse_ethr_did_url(
            "did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a?a=b&c=d#section3_5",
        )
        .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                },
                path: None,
                query: Some(vec![
                    ("a".to_string(), "b".to_string()),
                    ("c".to_string(), "d".to_string())
                ]),
                fragment: Some("section3_5".to_string())
            }
        );
    }

    #[test]
    fn test_ethr_did_parse_url_path_query_fragment() {
        let parsed = parse_ethr_did_url(
            "did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a/a/b/c?x=y&z1=#section3_5",
        )
        .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap()
                    ))
                },
                path: Some("/a/b/c".to_string()),
                query: Some(vec![
                    ("x".to_string(), "y".to_string()),
                    ("z1".to_string(), "".to_string())
                ]),
                fragment: Some("section3_5".to_string())
            }
        );
    }

    #[test]
    fn test_ethr_did_parse_url_query_chars() {
        let parsed = parse_ethr_did_url(
            "did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a?a=b&c=d:/?@",
        )
        .unwrap();
        assert_eq!(
            parsed,
            DidUrl {
                did: Did {
                    method: Method::Ethr,
                    network: Network::Mainnet,
                    account: Account::Address(Address::from_slice(
                        &hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap(),
                    ))
                },
                path: None,
                query: Some(vec![
                    ("a".to_string(), "b".to_string()),
                    ("c".to_string(), "d:/?@".to_string())
                ]),
                fragment: None
            }
        );
    }
}
