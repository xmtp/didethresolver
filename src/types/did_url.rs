//! Convenience Wrapper around [`Url`] for DID URIs according to the [DID Spec](https://www.w3.org/TR/did-core/#did-syntax)

use serde::{Deserialize, Serialize};
use smart_default::SmartDefault;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidUrl {
    url: Url,
    #[serde(skip)]
    method_end: usize,
    #[serde(skip)]
    id: Id,
}

impl DidUrl {
    /// Parses a Decentralized Identifier (DID) URI string.
    ///
    /// This method takes a string slice (`input`) representing a DID URI and attempts to parse it
    /// into a `DidUrl` object.
    ///
    /// # Arguments
    /// * `input` - A string slice that holds the DID URI to be parsed.
    ///
    /// # Returns
    /// A `Result` which, on success, contains the `DidUrl` object representing the parsed DID URI.
    /// On failure, it returns a `ParseError` indicating the reason for the parsing failure.
    ///
    /// # Examples
    /// ```
    /// let did_uri = "did:example:123";
    /// let did_url = DidUrl::parse(did_uri).expect("Failed to parse DID URI");
    /// ```
    ///
    /// # Errors
    /// This method returns a `ParseError` if the parsing of the URI fails or if the extracted
    /// components (method name, method-specific ID) do not conform to the expected DID structure.
    ///
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let url = Url::parse(input)?;

        let (method_end, id_end) = Self::extract_method_and_id(&url);
        let id: Id = url.path()[method_end + 1..id_end].try_into()?;
        Ok(Self {
            url,
            method_end,
            id,
        })
    }

    /// Internal method for extracting method and ID from the path of the parsed [`Url`]
    fn extract_method_and_id(url: &Url) -> (usize, usize) {
        let path = url.path();
        let method_end = path.find(':').expect("Method required");
        let id_end = path.find('/').unwrap_or(path.len());
        (method_end, id_end)
    }

    /// Retrieves the method name from the DID URL, as defined in the [W3C DID specification](https://www.w3.org/TR/did-core/#did-url-syntax).
    ///
    /// Extracts the method name part of the DID URI, which indicates the specific DID method used.
    /// The method name indicates the underlying consensus system (e.g. ethereum) the DID is associated with.
    ///
    /// # Returns
    /// A string slice (`&str`) with the DID method name.
    ///
    /// # Examples
    /// ```
    /// let did_url = DidUrl::parse("did:example:123").unwrap();
    /// assert_eq!(did_url.method(), "example");
    /// ```
    ///
    pub fn method(&self) -> &str {
        let path: &str = self.url.path();
        &path[0..self.method_end]
    }

    /// Retrieves the method-specific ID from the DID URL, as defined in the [W3C DID specification](https://www.w3.org/TR/did-core/#did-url-syntax).
    ///
    /// This method extracts the method-specific ID from the DID URI. This ID is unique within the scope
    /// of the DID method, ensuring the global uniqueness of the DID.
    ///
    /// # Returns
    /// A string slice (`&str`) containing the method-specific ID of the DID URI.
    ///
    /// # Examples
    /// ```
    /// let did_url = DidUrl::parse("did:example:123").unwrap();
    /// assert_eq!(did_url.id(), "123");
    /// ```
    ///
    pub fn id(&self) -> &Id {
        &self.id
    }
}

/// The supported networks for this DID
#[derive(Copy, Clone, Debug, PartialEq, Eq, SmartDefault)]
pub enum NetworkId {
    /// The Ethereum Main Net
    #[default]
    Ethereum,
    /// The Sepolia Ethereum Test Network
    Sepolia,
}

impl<'a> TryFrom<&'a str> for NetworkId {
    type Error = ParseError;
    fn try_from(network_id: &'a str) -> Result<NetworkId, ParseError> {
        match network_id {
            "0x1" => Ok(NetworkId::Ethereum),
            "0xaa36a7" => Ok(NetworkId::Sepolia),
            _ => Err(ParseError::UnknownNetwork(network_id.into())),
        }
    }
}

impl From<NetworkId> for String {
    fn from(id: NetworkId) -> String {
        match id {
            NetworkId::Ethereum => "0x1".into(),
            NetworkId::Sepolia => "0xaa36a7".into(),
        }
    }
}

impl<'a> TryFrom<&'a str> for AddressOrTransactionHash {
    type Error = ParseError;

    fn try_from(address_or_hash: &'a str) -> Result<AddressOrTransactionHash, Self::Error> {
        if is_valid_evm_address(address_or_hash) {
            return Ok(AddressOrTransactionHash::Address(address_or_hash.into()));
        } else if is_valid_tx_hash(address_or_hash) {
            return Ok(AddressOrTransactionHash::TransactionHash(
                address_or_hash.into(),
            ));
        }

        Err(ParseError::UnknownConsensusId(address_or_hash.into()))
    }
}

/// The ID part of the DID. The ID contains an optional [`NetworkId`] and one of
/// [`AddressOrTransactionHash`]. If the network is missing from the DID URL, we default to
/// Mainnet, or [`NetworkId::Ethereum`]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Id {
    pub network_id: NetworkId,
    pub address_or_hash: AddressOrTransactionHash,
}

impl Id {
    pub fn new(network_id: Option<NetworkId>, address_or_hash: AddressOrTransactionHash) -> Self {
        Self {
            network_id: network_id.unwrap_or(Default::default()),
            address_or_hash,
        }
    }
}

/// Represents Either an Address or TransactionHash
#[derive(Clone, Debug, PartialEq, Eq, SmartDefault)]
pub enum AddressOrTransactionHash {
    #[default]
    Address(String),
    TransactionHash(String),
}

impl<'a> TryFrom<&'a str> for Id {
    type Error = ParseError;

    fn try_from(id: &'a str) -> Result<Id, Self::Error> {
        let separator_indices: Vec<usize> = id
            .char_indices()
            .filter(|(_, c)| *c == ':')
            .map(|(idx, _)| idx)
            .collect();
        if separator_indices.len() > 2 {
            return Err(ParseError::UnsupportedMethodId(id.to_string()));
        }

        // the network ID is included in the DID
        if separator_indices.len() == 1 {
            let network_id: NetworkId = id[0..separator_indices[0]].try_into()?;
            let address_or_hash = id[(separator_indices[0] + 1)..].try_into()?;

            Ok(Id {
                network_id,
                address_or_hash,
            })
        } else {
            let address_or_hash = id.try_into()?;
            Ok(Id {
                network_id: NetworkId::Ethereum,
                address_or_hash,
            })
        }
    }
}

/// Check if an string is a valid ethereum address (valid hex and length 40 (20 bytes)).
pub fn is_valid_evm_address<S: AsRef<str>>(address: S) -> bool {
    let address = address.as_ref();
    let address = address.strip_prefix("0x").unwrap_or(address);

    if address.len() != 40 {
        return false;
    }

    address.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check if an string is a valid transaction hash (valid hex and length 66 (33 bytes)).
pub fn is_valid_tx_hash<S: AsRef<str>>(address: S) -> bool {
    let address = address.as_ref();
    let address = address.strip_prefix("0x").unwrap_or(address);

    if address.len() != 64 {
        return false;
    }

    address.chars().all(|c| c.is_ascii_hexdigit())
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error("The DID contains unsupported ID Elements {0}")]
    UnsupportedMethodId(String),
    #[error("The network {0} is not supported")]
    UnknownNetwork(String),
    #[error("The Id {0} is not an address or transaction hash")]
    UnknownConsensusId(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_did() {
        let examples = vec![
            "did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74/path",
            "did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74?versionId=1",
            "did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#public-key-0",
            "did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#agent",
            "did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74?service=agent&relativeRef=/credentials#degree",
            "did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74?versionTime=2021-05-10T17:00:00Z",
            "did:example:0x9744fb1c8b01358ddb9310e7f0accac0843ac8800a1490cf446f56ef34dc0909?service=files&relativeRef=/resume.pdf",
            "did:example:0x9744fb1c8b01358ddb9310e7f0accac0843ac8800a1490cf446f56ef34dc0909/file-test_23.png?service=files&relativeRef=/resume.pdf",
            "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad?service=agent&relativeRef=/credentials#degree",
        ];

        for did_url in examples {
            DidUrl::parse(did_url).unwrap();
        }
    }

    #[test]
    fn test_invalid_did_throws_error() {
        let did = "did:ethr:123";
        assert_eq!(
            DidUrl::parse(did),
            Err(ParseError::UnknownConsensusId("123".into()))
        );
        let did = "did:ethr:0x123456:2342345";
        assert_eq!(
            DidUrl::parse(did),
            Err(ParseError::UnknownNetwork("0x123456".into()))
        );
        let did = "did:ethr:123:123:123:123";
        assert_eq!(
            DidUrl::parse(did),
            Err(ParseError::UnsupportedMethodId("123:123:123:123".into()))
        );
    }

    #[test]
    fn test_networks() {
        let sepolia = "did:ethr:0xaa36a7:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74";
        assert_eq!(
            DidUrl::parse(sepolia).unwrap().id(),
            &Id::new(
                Some(NetworkId::Sepolia),
                "0xf3beac30c498d9e26865f34fcaa57dbb935b0d74"
                    .try_into()
                    .unwrap()
            )
        );

        let ethereum = "did:ethr:0x1:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74";
        assert_eq!(
            DidUrl::parse(ethereum).unwrap().id(),
            &Id::new(
                Some(NetworkId::Ethereum),
                "0xf3beac30c498d9e26865f34fcaa57dbb935b0d74"
                    .try_into()
                    .unwrap()
            )
        );

        let ethereum = "did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74";
        assert_eq!(
            DidUrl::parse(ethereum).unwrap().id(),
            &Id::new(
                Some(NetworkId::Ethereum),
                "0xf3beac30c498d9e26865f34fcaa57dbb935b0d74"
                    .try_into()
                    .unwrap()
            )
        );
    }

    #[test]
    fn test_method() {
        assert_eq!(
            DidUrl::parse("did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74/path")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74?versionId=1")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#public-key-0")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#agent")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74?service=agent&relativeRef=/credentials#degree")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74?versionTime=2021-05-10T17:00:00Z")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74?service=files&relativeRef=/resume.pdf")
                .unwrap()
                .method(),
            "example"
        );
    }

    #[test]
    fn test_id() {
        assert_eq!(
            DidUrl::parse("did:example:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74?service=files&relativeRef=/resume.pdf")
                .unwrap()
                .id(),
            &Id::new(None, "0xf3beac30c498d9e26865f34fcaa57dbb935b0d74".try_into().unwrap())
        );

        assert_eq!(
            DidUrl::parse("did:ethr:0x1:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74")
                .unwrap()
                .id(),
            &Id {
                network_id: NetworkId::Ethereum,
                address_or_hash: AddressOrTransactionHash::Address(
                    "0xf3beac30c498d9e26865f34fcaa57dbb935b0d74".into()
                )
            },
        );
    }
}
