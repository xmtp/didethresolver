//! Convenience Wrapper around [`Url`] for DID URIs according to the [DID Spec](https://www.w3.org/TR/did-core/#did-syntax)

use anyhow::{Context, Error, Result};
use ethers::types::Address;
use serde::{Deserialize, Serialize, Serializer};
use smart_default::SmartDefault;
use url::Url;

use super::parse_ethr_did;

/// A DID URL, based on the did specification, [DID URL Syntax](https://www.w3.org/TR/did-core/#did-url-syntax)
/// Currently only supports did:ethr: [did-ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidUrl {
    url: Url,
    method_and_id: MethodAndId,
}

/// The `method` and `id` parts of a [did:ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md) URL, returned by [`parse_ethr_did`]
#[derive(Debug, Clone, PartialEq, Eq, SmartDefault)]
pub struct MethodAndId {
    pub method: Method,
    pub id: Id,
}
// TODO: Could read a map of ChainId -> Provider from a configuration file or environment variable
// (not in didurl parser though)

/// The `id` part of a [did:ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md) URL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Id {
    pub chain: ChainId,
    pub public_key: AddressOrHexKey,
}

/// The `public_key` part of a [did:ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md) Url.
/// A did:ethr URL may contain either a [`AddressOrHexKey::Address`] or [`AddressOrHexKey::HexKey`].
#[derive(Debug, Clone, PartialEq, Eq, SmartDefault)]
pub enum AddressOrHexKey {
    Address(Address),
    // the default is an empty hex key
    #[default]
    HexKey(Vec<u8>),
}

impl ToString for AddressOrHexKey {
    fn to_string(&self) -> String {
        match self {
            AddressOrHexKey::Address(addr) => format!("0x{}", hex::encode(addr.as_bytes())),
            AddressOrHexKey::HexKey(key) => format!("0x{}", hex::encode(key)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, SmartDefault)]
pub enum Method {
    #[default]
    Ethr,
}

#[derive(Debug, Clone, PartialEq, Eq, SmartDefault)]
pub enum ChainId {
    #[default]
    Mainnet,
    // here for possible backwards compatibility, but should error on creation of any new DID's
    #[deprecated]
    Goerli,
    Sepolia,
    Other(usize),
}

impl<'a> From<&'a str> for ChainId {
    fn from(digits: &'a str) -> ChainId {
        let num = usize::from_str_radix(digits, 16).expect("String must be valid Hex");

        match num {
            1 => ChainId::Mainnet,
            #[allow(deprecated)]
            5 => ChainId::Goerli,
            11155111 => ChainId::Sepolia,
            _ => ChainId::Other(num),
        }
    }
}

impl DidUrl {
    /// Parses a Decentralized Identifier (DID) URI string.
    ///
    /// Takes a string slice (`input`) representing a DID URI and attempts to parse it
    /// into a `DidUrl` object. At a minimum, the DID URL needs to define a method.
    ///
    /// # Arguments
    /// * `input` - A string slice that holds the DID URI to be parsed.
    ///
    /// # Returns
    /// A `Result` which, on success, contains the `DidUrl` object representing the parsed DID URI.
    /// On failure, it returns a [`Error`] indicating the reason for the parsing failure.
    ///
    /// # Examples
    /// ```
    /// use didethresolver::types::DidUrl;
    ///
    /// let did_url = "did:not:123";
    /// let did_url = DidUrl::parse(did_url).unwrap_err();
    /// assert_eq!(did_url.source().unwrap().to_string(), "error at 1:1: expected one of \"ethr:\", the only supported method is `ethr`");
    /// ```
    /// ```
    /// use didethresolver::types::DidUrl;
    ///
    /// let did_url = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
    /// let did_url = DidUrl::parse(did_url).unwrap();
    /// ```
    ///
    /// # Errors
    /// returns a `Error` if the parsing of the URI fails or if the extracted
    /// components (method name, method-specific ID) do not conform to the expected DID structure.
    ///
    pub fn parse<S: AsRef<str>>(input: S) -> Result<Self, Error> {
        let url = Url::parse(input.as_ref())?;

        let mut path = url.path().split('/');

        let method_and_id = if let Some(path) = path.next() {
            log::debug!("Parsing method and id from path: {}", path);
            Some(parse_ethr_did(path).context("Method and Id could not be parsed from URL")?)
        } else {
            None
        };

        path.next().and_then(|p| parse_ethr_did(p).ok());

        Ok(Self {
            url,
            method_and_id: method_and_id.unwrap_or(Default::default()),
        })
    }

    /// Retrieves the method from the DID URL, as defined in the [did-ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)).
    ///
    /// Extracts the method name part of the DID URI, which indicates the specific DID method used.
    /// The method name indicates the underlying consensus system (e.g. ethereum) the DID is associated with.
    ///
    /// # Returns
    /// A string slice (`&str`) with the DID method name.
    ///
    /// # Examples
    /// ```
    /// use didethresolver::types::{DidUrl, Method};
    ///
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// assert_eq!(did_url.method(), &Method::Ethr);
    /// ```
    ///
    pub fn method(&self) -> &Method {
        &self.method_and_id.method
    }

    /// Retrieves the chainId for an DID:ETHR URL, as defined in the [did-ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md).
    ///
    /// # Returns
    /// A enum [`ChainId`] indicating the chain this DID belongs to.
    ///
    /// # Examples
    /// ```
    /// use didethresolver::types::{ChainId, DidUrl};
    /// let did_url = DidUrl::parse("did:ethr:0x01:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// assert_eq!(did_url.chain_id(), &ChainId::Mainnet);
    /// ```
    ///
    pub fn chain_id(&self) -> &ChainId {
        &self.method_and_id.id.chain
    }

    /// Retrieves the identity part from the DID URL, as defined in the [did-ethr spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)).
    ///
    /// # Returns
    /// A Enum [`AddressOrHexKey`] which identifies the DID. This can be either an 20-byte [`Address`] or a 33-byte [`Vec<u8>`].
    ///
    /// # Examples
    /// ```
    /// use didethresolver::types::{AddressOrHexKey, DidUrl};
    /// use ethers::types::Address;
    ///
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// let address = hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// assert_eq!(did_url.id(), &AddressOrHexKey::Address(Address::from_slice(address.as_slice())));
    /// ```
    ///
    pub fn id(&self) -> &AddressOrHexKey {
        &self.method_and_id.id.public_key
    }

    /// Returns this DID's fragment identifier, if any.
    ///  A fragment is the part of the URL after the # symbol. The fragment is optional and, if present, contains a fragment identifier that identifies a secondary resource, such as a section heading of a document.
    ///
    /// In a DID, a fragment may be used to reference a specific section or component within a DID document, such as
    /// a particular verification method or service endpoint.
    ///
    ///  # Examples
    /// ```
    /// use didethresolver::types::DidUrl;
    ///
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#delegate-0").unwrap();
    /// assert_eq!(did_url.fragment(), Some("delegate-0"));
    /// ```
    ///
    /// **Note**: the parser did not percent-encode this component, but the input may have been percent-encoded already.

    pub fn fragment(&self) -> Option<&str> {
        self.url.fragment()
    }

    /// Change this DID's fragment identifier
    /// # Examples
    ///
    ///
    /// ```
    /// use didethresolver::types::DidUrl;
    ///
    /// let mut did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// did_url.set_fragment(Some("controller"));
    /// assert_eq!(did_url.as_str(), "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller");
    /// ```
    pub fn set_fragment(&mut self, fragment: Option<&str>) {
        self.url.set_fragment(fragment)
    }

    /// Return the serialization of this URL.
    ///
    /// This is fast since the serialization is already stored in the [`DidUrl`] struct.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Change this DID's path
    ///
    /// # Returns
    /// A Result indicating if the path was successfully set.
    ///
    /// # Examples
    /// ```
    /// use didethresolver::types::DidUrl;
    ///
    /// let mut did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// did_url.set_path("ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a");
    /// assert_eq!(did_url.as_str(), "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a");
    /// ```
    ///
    /// # Errors
    /// returns a `Error` if the parsing of the URI fails because it is not the expected format or if the method is unsupported.
    ///
    pub fn set_path(&mut self, path: &str) -> Result<()> {
        self.url.set_path(path);
        let mut path = self.url.path().split('/');
        if let Some(path) = path.next() {
            log::debug!("Parsing method and id from path: {}", path);
            self.method_and_id =
                parse_ethr_did(path).context("Method and Id could not be parsed from URL")?;
        };
        Ok(())
    }
}

impl Serialize for DidUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let decoded = percent_encoding::percent_decode_str(self.url.as_str());
        serializer.serialize_str(&decoded.decode_utf8_lossy())
    }
}

impl<'de> Deserialize<'de> for DidUrl {
    fn deserialize<D>(deserializer: D) -> Result<DidUrl, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DidUrl::parse(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test::address;

    #[test]
    fn test_method() {
        assert_eq!(
            DidUrl::parse("did:ethr:0x7e575682A8E450E33eB0493f9972821aE333cd7F/path")
                .unwrap()
                .method(),
            &Method::Ethr
        );

        let err = DidUrl::parse("did:pkh:0x7e575682A8E450E33eB0493f9972821aE333cd7F").unwrap_err();
        assert_eq!(
            "error at 1:1: expected one of \"ethr:\", the only supported method is `ethr`"
                .to_string(),
            err.source().unwrap().to_string()
        );
    }

    #[test]
    fn test_id() {
        let addr = AddressOrHexKey::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"));

        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a/path")
                .unwrap()
                .id(),
            &addr,
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a?versionId=1")
                .unwrap()
                .id(),
            &addr
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#public-key-0")
                .unwrap()
                .id(),
            &addr,
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#agent")
                .unwrap()
                .id(),
            &addr
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a?service=agent&relativeRef=/credentials#degree")
                .unwrap()
                .id(),
            &addr
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a?versionTime=2021-05-10T17:00:00Z")
                .unwrap()
                .id(),
            &addr
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a?service=files&relativeRef=/resume.pdf")
                .unwrap()
                .id(),
            &addr
        );
    }
}
