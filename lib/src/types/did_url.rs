//! Convenience Wrapper around [`Url`] for DID URIs according to the [DID Spec](https://www.w3.org/TR/did-core/#did-syntax)

use serde::{Deserialize, Serialize, Serializer};
use smart_default::SmartDefault;

use ethers::{types::Address, utils::keccak256};

use super::parse_ethr_did_url;
use crate::error::DidError;

/**
 * Converts a public key to an ethereum address.  The last 20 bytes
 * of the keccak256 hash of the public key is returned
 */
fn public_key_to_address(key: &[u8]) -> String {
    let keydigest = keccak256(key);
    let address = &keydigest[12..];
    format!("0x{}", hex::encode(address)).to_string()
}

/**
 * Convert an Ethereum address string into a hex string
 *
 * Returns the hex string without the 0x prefix if it exists
 */
fn as_hex_digits(s: &str) -> &str {
    if s.starts_with("0x") {
        return s.strip_prefix("0x").unwrap();
    }
    s
}

/// A DID URL, based on the did specification, [DID URL Syntax](https://www.w3.org/TR/did-core/#did-url-syntax)
/// Currently only supports did:ethr: [did-ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidUrl {
    pub did: Did,
    pub path: Option<String>,
    pub query: Option<Vec<(String, String)>>,
    pub fragment: Option<String>,
}

/// The `did` part of a [did:ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md) URL. returned by [`parse_ethr_did`]
#[derive(Debug, Clone, PartialEq, Eq, SmartDefault)]
pub struct Did {
    pub method: Method,
    pub network: Network,
    pub account: Account,
}

impl ToString for Did {
    fn to_string(&self) -> String {
        format!(
            "did:{}:{}:{}",
            self.method.as_str(),
            self.network.to_string().as_str(),
            self.account.to_string().as_str()
        )
    }
}

// TODO: Could read a map of ChainId -> Provider from a configuration file or environment variable
// (not in didurl parser though)

/// The `ethereum-address / public-key-hex` part of a [did:ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#method-specific-identifier) Url.
/// A did:ethr URL may contain either a [`Account::Address`] or [`Account::HexKey`].
#[derive(Debug, Clone, PartialEq, Eq, SmartDefault)]
pub enum Account {
    Address(Address),
    // the default is an empty hex key
    #[default]
    HexKey(Vec<u8>),
}

impl From<Address> for Account {
    fn from(addr: Address) -> Self {
        Account::Address(addr)
    }
}

impl From<Vec<u8>> for Account {
    fn from(key: Vec<u8>) -> Self {
        Account::HexKey(key)
    }
}

impl From<&str> for Account {
    fn from(s: &str) -> Self {
        if s.starts_with("0x") {
            Account::Address(Address::from_slice(&hex::decode(as_hex_digits(s)).unwrap()))
        } else {
            Account::HexKey(hex::decode(s).unwrap())
        }
    }
}

impl From<Account> for Address {
    fn from(account: Account) -> Self {
        match account {
            Account::Address(addr) => addr,
            Account::HexKey(key) => {
                let addr = public_key_to_address(&key);
                Address::from_slice(&hex::decode(as_hex_digits(&addr)).unwrap())
            }
        }
    }
}

impl ToString for Account {
    fn to_string(&self) -> String {
        match self {
            Account::Address(addr) => format!("0x{}", hex::encode(addr.as_bytes())),
            Account::HexKey(key) => hex::encode(key).to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, SmartDefault)]
pub enum Method {
    #[default]
    Ethr,
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Method::Ethr => "ethr",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, SmartDefault)]
pub enum Network {
    #[default]
    Mainnet,
    // here for possible backwards compatibility, but should error on creation of any new DID's
    #[deprecated]
    Goerli,
    Sepolia,
    Other(usize),
}

impl ToString for Network {
    fn to_string(&self) -> String {
        match self {
            Network::Mainnet => "mainnet".to_string(),
            #[allow(deprecated)]
            Network::Goerli => "goerli".to_string(),
            Network::Sepolia => "sepolia".to_string(),
            Network::Other(num) => num.to_string(),
        }
    }
}

impl From<usize> for Network {
    fn from(chain_id: usize) -> Network {
        match chain_id {
            1 => Network::Mainnet,
            #[allow(deprecated)]
            5 => Network::Goerli,
            11155111 => Network::Sepolia,
            _ => Network::Other(chain_id),
        }
    }
}

impl<'a> From<&'a str> for Network {
    fn from(network: &'a str) -> Network {
        match network.to_lowercase().as_str() {
            "mainnet" => Network::Mainnet,
            #[allow(deprecated)]
            "goerli" => Network::Goerli,
            "sepolia" => Network::Sepolia,
            _ => {
                let chain_id = usize::from_str_radix(as_hex_digits(network), 16)
                    .expect("String must be valid Hex");
                Network::from(chain_id)
            }
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
    /// On failure, it returns a [`DidError`] indicating the reason for the parsing failure.
    ///
    /// # Examples
    /// ```
    /// use lib_didethresolver::types::DidUrl;
    ///
    /// let did_url = "did:not:123";
    /// let did_url = DidUrl::parse(did_url).unwrap_err();
    /// assert_eq!(did_url.to_string(), "Parsing of ethr:did failed, error at 1:5: expected one of \"ethr\", the only supported method is `ethr`");
    /// ```
    /// ```
    /// use lib_didethresolver::types::DidUrl;
    ///
    /// let did_url = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
    /// let did_url = DidUrl::parse(did_url).unwrap();
    /// ```
    ///
    /// # Errors
    /// returns a [`DidError`] if the parsing of the URI fails or if the extracted
    /// components (method name, method-specific ID) do not conform to the expected DID structure.
    ///
    pub fn parse<S: AsRef<str>>(input: S) -> Result<Self, DidError> {
        let did_url = parse_ethr_did_url(input.as_ref());
        if let Err(e) = did_url {
            return Err(DidError::Parse(e));
        }

        let did_url = did_url.unwrap();
        Ok(Self { ..did_url })
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
    /// use lib_didethresolver::types::{DidUrl, Method};
    ///
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// assert_eq!(did_url.method(), &Method::Ethr);
    /// ```
    ///
    pub fn method(&self) -> &Method {
        &self.did.method
    }

    /// Retrieves the chainId for an DID:ETHR URL, as defined in the [did-ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md).
    ///
    /// # Returns
    /// A enum [`ChainId`] indicating the chain this DID belongs to.
    ///
    /// # Examples
    /// ```
    /// use lib_didethresolver::types::{Network, DidUrl};
    /// let did_url = DidUrl::parse("did:ethr:0x01:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// assert_eq!(did_url.network(), &Network::Mainnet);
    /// ```
    ///
    pub fn network(&self) -> &Network {
        &self.did.network
    }

    /// Retrieves the identity part from the DID URL, as defined in the [did-ethr spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)).
    ///
    /// # Returns
    /// A Enum [`AddressOrHexKey`] which identifies the DID. This can be either an 20-byte [`Address`] or a 33-byte [`Vec<u8>`].
    ///
    /// # Examples
    /// ```
    /// use lib_didethresolver::types::{Account, DidUrl};
    /// use ethers::types::Address;
    ///
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// let address = hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// assert_eq!(did_url.account(), &Account::Address(Address::from_slice(address.as_slice())));
    /// ```
    ///
    pub fn account(&self) -> &Account {
        &self.did.account
    }

    /// Retrieves the path part from the DID URL, as defined in the [did-ethr spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)).
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn contains_query(&self, key: String, value: String) -> bool {
        self.query
            .as_ref()
            .map(|q| q.contains(&(key, value)))
            .unwrap_or(false)
    }

    pub fn query(&self) -> Option<&[(String, String)]> {
        self.query.as_deref()
    }

    /// Immutable copy constructor that returns the same DID URL without its query
    pub fn without_query(&self) -> Self {
        let mut minion = self.clone();
        minion.query = None;
        minion
    }

    /// Immutable copy constructor to add a query parameter to the DID URL.
    /// # Examples
    /// ```rust
    /// use lib_didethresolver::types::DidUrl;
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// let did_url = did_url.with_query("versionId", Some("1"));
    /// assert_eq!(did_url.query(), Some(&[("versionId".to_string(), "1".to_string())][..]));
    /// ```
    /// **Note**: the parser did not percent-encode this component, but the input may have been percent-encoded already.
    pub fn with_query(&self, key: &str, value: Option<&str>) -> Self {
        let mut minion = self.clone();
        if minion.query.is_none() {
            minion.query = Some(Vec::new());
        }
        let query = minion.query.as_mut().unwrap();
        query.push((key.to_string(), value.unwrap_or("").to_string()));
        minion
    }

    /// Returns this DID's fragment identifier, if any.
    ///  A fragment is the part of the URL after the # symbol. The fragment is optional and, if present, contains a fragment identifier that identifies a secondary resource, such as a section heading of a document.
    ///
    /// In a DID URL, a fragment may be used to reference a specific section or component within a DID document, such as
    /// a particular verification method or service endpoint.
    ///
    ///  # Examples
    /// ```
    /// use lib_didethresolver::types::DidUrl;
    ///
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#delegate-0").unwrap();
    /// assert_eq!(did_url.fragment(), Some("delegate-0"));
    /// ```
    ///
    /// **Note**: the parser did not percent-encode this component, but the input may have been percent-encoded already.
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    /// Immutable copy builder to add a fragment to this did url
    /// # Examples
    /// ```rust
    /// use lib_didethresolver::types::DidUrl;
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// let did_url = did_url.with_fragment(Some(&"controller"));
    /// assert_eq!(did_url.fragment(), Some("controller"));
    /// ```
    /// **Note**: the parser did not percent-encode this component, but the input may have been percent-encoded already.
    ///
    pub fn with_fragment(&self, fragment: Option<&str>) -> Self {
        let mut minion = self.clone();
        if let Some(fragment) = fragment {
            minion.fragment = Some(fragment.to_string());
        } else {
            minion.fragment = None;
        }
        minion
    }

    /// Immutable copy constructor returns an identical DID with the specified path
    ///
    /// # Examples
    /// ```
    /// use lib_didethresolver::types::DidUrl;
    ///
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// let did_url = did_url.with_path(Some(&"/path/to/resource"));
    /// assert_eq!(did_url.path, Some("/path/to/resource".to_string()));
    /// ```
    ///
    pub fn with_path(&self, path: Option<&str>) -> Self {
        let mut minion = self.clone();
        if let Some(path) = path {
            minion.path = Some(path.to_string());
        } else {
            minion.path = None;
        }
        minion
    }

    /// Immutable copy constructor returns an identical DID with the specified account
    ///
    /// # Examples
    /// ```rust
    /// use lib_didethresolver::types::{Account, DidUrl};
    /// use ethers::types::Address;
    /// let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// let address = hex::decode("b9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// let account = Account::Address(Address::from_slice(address.as_slice()));
    /// let did_url = did_url.with_account(account.clone());
    /// assert_eq!(did_url.account(), &account);
    /// ```
    pub fn with_account(&self, account: Account) -> Self {
        let mut minion = self.clone();
        minion.did.account = account.clone();
        minion
    }
}

impl ToString for DidUrl {
    fn to_string(&self) -> String {
        let mut string = format!("{}{}", self.did.to_string(), self.path().unwrap_or(""));
        if let Some(query) = self.query() {
            let format_str = query
                .iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect::<Vec<String>>()
                .join("&");
            string = format!("{}?{}", string, format_str);
        }
        if let Some(fragment) = self.fragment() {
            string = format!("{}#{}", string, fragment);
        }
        string
    }
}

impl Serialize for DidUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let binding = self.to_string();
        let decoded = percent_encoding::percent_decode_str(binding.as_str());
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
            "Parsing of ethr:did failed, error at 1:5: expected one of \"ethr\", the only supported method is `ethr`"
                .to_string(),
            err.to_string()
        );
    }

    #[test]
    fn test_account() {
        let account = Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"));

        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a/path")
                .unwrap()
                .account(),
            &account,
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a?versionId=1")
                .unwrap()
                .account(),
            &account
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#public-key-0")
                .unwrap()
                .account(),
            &account,
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#agent")
                .unwrap()
                .account(),
            &account
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a?service=agent&relativeRef=/credentials#degree")
                .unwrap()
                .account(),
            &account
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a?versionTime=2021-05-10T17:00:00Z")
                .unwrap()
                .account(),
            &account
        );
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a?service=files&relativeRef=/resume.pdf")
                .unwrap()
                .account(),
            &account
        );
    }

    #[test]
    fn test_network() {
        assert_eq!(
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a")
                .unwrap()
                .network(),
            &Network::Mainnet
        );

        assert_eq!(
            DidUrl::parse("did:ethr:mainnet:0xb9c5714089478a327f09197987f16f9e5d936e8a")
                .unwrap()
                .network(),
            &Network::Mainnet
        );

        assert_eq!(
            DidUrl::parse("did:ethr:sepolia:0xb9c5714089478a327f09197987f16f9e5d936e8a")
                .unwrap()
                .network(),
            &Network::Sepolia
        );

        assert_eq!(
            DidUrl::parse("did:ethr:0x1a1:0xb9c5714089478a327f09197987f16f9e5d936e8a")
                .unwrap()
                .network(),
            &Network::Other(0x1a1)
        );
    }

    #[test]
    fn test_with_fragment() {
        let did_url =
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#key-1").unwrap();
        assert_eq!(did_url.fragment(), Some("key-1"));
        let last = did_url.clone();
        let did_url = did_url.with_fragment(Some("key-2"));
        assert_eq!(did_url.fragment(), Some("key-2"));
        assert_eq!(last.fragment(), Some("key-1"));
        let did_url = did_url.with_fragment(None);
        assert_eq!(did_url.fragment(), None);
        assert_eq!(did_url.method(), &Method::Ethr,);
        assert_eq!(did_url.network(), &Network::Mainnet,);
        assert_eq!(
            did_url.account(),
            &Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"))
        );
    }

    #[test]
    fn test_with_path() {
        let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(did_url.path(), None);
        let did_url = did_url.with_path(Some("path-2"));
        assert_eq!(did_url.path(), Some("path-2"));
        assert_eq!(did_url.method(), &Method::Ethr,);
        assert_eq!(did_url.network(), &Network::Mainnet,);
        assert_eq!(
            did_url.account(),
            &Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"))
        );
        let did_url = did_url.with_path(None);
        assert_eq!(did_url.path(), None);
    }

    #[test]
    fn test_without_query() {
        let did_url =
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a?versionId=1")
                .unwrap()
                .without_query();
        assert_eq!(did_url.query(), None);
        assert_eq!(did_url.method(), &Method::Ethr,);
        assert_eq!(did_url.network(), &Network::Mainnet,);
        assert_eq!(
            did_url.account(),
            &Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"))
        );
    }

    #[test]
    fn test_with_query() {
        let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(did_url.query(), None);
        let last = did_url.clone();
        let did_url = did_url.with_query("key-1", Some("value-1"));
        assert_eq!(last.query(), None);
        assert_eq!(
            did_url.query(),
            Some(&[("key-1".to_string(), "value-1".to_string())][..])
        );
        let did_url = did_url.with_query("key-2", Some("value-2"));
        assert_eq!(
            did_url.query(),
            Some(
                &[
                    ("key-1".to_string(), "value-1".to_string()),
                    ("key-2".to_string(), "value-2".to_string())
                ][..]
            )
        );
        assert_eq!(did_url.method(), &Method::Ethr,);
        assert_eq!(did_url.network(), &Network::Mainnet,);
        assert_eq!(
            did_url.account(),
            &Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"))
        );
    }

    #[test]
    fn test_with_account() {
        let did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(
            did_url.account(),
            &Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"))
        );
        let last = did_url.clone();
        let did_url = did_url.with_account(Account::HexKey(vec![0x01, 0x02, 0x03]));
        assert_eq!(
            last.account(),
            &Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"))
        );
        assert_eq!(did_url.account(), &Account::HexKey(vec![0x01, 0x02, 0x03]));
        assert_eq!(did_url.method(), &Method::Ethr,);
        assert_eq!(did_url.network(), &Network::Mainnet,);
        assert_eq!(did_url.to_string(), "did:ethr:mainnet:010203")
    }

    #[test]
    fn test_account_from_string() {
        let account = Account::from("0xb9c5714089478a327f09197987f16f9e5d936e8a");
        assert_eq!(
            account,
            Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"))
        );

        let account =
            Account::from("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
        let eth_address: Address = account.into();
        let expect_address: Address =
            Account::Address(address("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")).into();
        assert_eq!(expect_address, eth_address);
    }

    #[test]
    fn test_account_from_hex_key() {
        let account = Account::from(vec![0x01, 0x02, 0x03]);
        assert_eq!(account, Account::HexKey(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_account_from_address() {
        let account = Account::from(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"));
        assert_eq!(
            account,
            Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"))
        );
    }

    #[test]
    fn test_account_to_address_conversion() {
        let account = Account::Address(address("0xb9c5714089478a327f09197987f16f9e5d936e8a"));
        assert_eq!(
            Address::from_slice(
                &hex::decode(as_hex_digits("0xb9c5714089478a327f09197987f16f9e5d936e8a")).unwrap()
            ),
            account.into()
        );

        let account = Account::HexKey(hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap().to_vec());
        assert_eq!(
            Address::from_slice(
                &hex::decode(as_hex_digits("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")).unwrap()
            ),
            account.into()
        );
    }

    #[test]
    fn test_public_key_hash() {
        let pk = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let key = hex::decode(pk).unwrap();
        let address = public_key_to_address(&key);
        assert_eq!(
            address,
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".to_string()
        );
    }

    #[test]
    fn test_as_hex_str() {
        let address = "0x7e575682A8E450E33eB0493f9972821aE333cd7F";
        assert_eq!(
            as_hex_digits(address),
            "7e575682A8E450E33eB0493f9972821aE333cd7F"
        );
        let public_key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        assert_eq!(
            as_hex_digits(public_key),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
    }

    #[test]
    fn test_network_from_usize() {
        assert_eq!(Network::from(1), Network::Mainnet);
        assert_eq!(Network::from(11155111), Network::Sepolia);
        assert_eq!(Network::from(0x1a1), Network::Other(0x1a1));
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!(Network::from("mainnet"), Network::Mainnet);
        assert_eq!(Network::from("sepolia"), Network::Sepolia);
        assert_eq!(Network::from("1a1"), Network::Other(0x1a1));
    }

    #[test]
    fn test_contains_query() {
        let did_url = DidUrl::parse("did:ethr:mainnet:0x0000000000000000000000000000000000000000?meta=hi&username=&password=hunter2").unwrap();

        assert!(did_url.contains_query("meta".into(), "hi".into()));
        assert!(did_url.contains_query("username".into(), "".into()));
        assert!(did_url.contains_query("password".into(), "hunter2".into()));
        assert!(!did_url.contains_query("does".into(), "not exist".into()));

        let did_url =
            DidUrl::parse("did:ethr:mainnet:0x0000000000000000000000000000000000000000").unwrap();
        assert!(!did_url.contains_query("no".into(), "queries".into()));
    }

    #[test]
    fn test_network_to_string() {
        assert_eq!(Network::Mainnet.to_string(), "mainnet");
        assert_eq!(Network::Sepolia.to_string(), "sepolia");
        assert_eq!(Network::Other(0x1a1).to_string(), "417");
    }
}
