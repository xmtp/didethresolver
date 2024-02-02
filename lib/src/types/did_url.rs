//! Convenience Wrapper around [`Url`] for DID URIs according to the [DID Spec](https://www.w3.org/TR/did-core/#did-syntax)

use ethers::types::Address;
use serde::{Deserialize, Serialize, Serializer};
use smart_default::SmartDefault;
use url::Url;

use super::parse_ethr_did;
use crate::error::DidError;

/// A DID URL, based on the did specification, [DID URL Syntax](https://www.w3.org/TR/did-core/#did-url-syntax)
/// Currently only supports did:ethr: [did-ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidUrl {
    pub did: Did,
    pub path: String,
    pub query: Vec<(String, String)>,
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

impl ToString for Account {
    fn to_string(&self) -> String {
        match self {
            Account::Address(addr) => format!("0x{}", hex::encode(addr.as_bytes())),
            Account::HexKey(key) => format!("0x{}", hex::encode(key)),
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

impl<'a> From<&'a str> for Network {
    fn from(chain_id: &'a str) -> Network {
        let chain_id = usize::from_str_radix(chain_id, 16).expect("String must be valid Hex");

        match chain_id {
            1 => Network::Mainnet,
            #[allow(deprecated)]
            5 => Network::Goerli,
            11155111 => Network::Sepolia,
            _ => Network::Other(chain_id),
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
    /// assert_eq!(did_url.to_string(), "Parsing of ethr:did failed, error at 1:1: expected one of \"ethr\", the only supported method is `ethr`");
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
        let url = Url::parse(input.as_ref())?;

        // Note that `url.path()` will return an incorrect path from did url
        // For regular URL("http://w.a.b/path"), the it only returns the string from the first '/' (/path)
        // But for did url, it incorrectly returns the content before the first '/' (ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a/path)
        let mut split = url.path().split('/');
        let did = if let Some(did_str) = split.next() {
            log::debug!("Parsing did from str: {}", did_str);
            Some(parse_ethr_did(did_str)?)
        } else {
            None
        };
        // join the strings in the split with '/' as delimiter
        let path = split.fold(String::new(), |mut acc, s| {
            acc.push_str(format!("/{}", s).as_str());
            acc
        });

        let query = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        let fragment = url.fragment().map(|fragment| fragment.to_owned());

        Ok(Self {
            did: did.unwrap_or_default(),
            path,
            query,
            fragment,
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
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn query(&self) -> Option<String> {
        let q = self.format_query();
        Some(q).filter(|q| !q.is_empty())
    }

    pub fn query_pairs(&self) -> impl Iterator<Item = &(String, String)> {
        self.query.iter()
    }

    pub fn add_query(&mut self, key: &str, value: Option<&str>) {
        self.query
            .push((key.to_string(), value.unwrap_or("").to_string()));
    }

    pub fn contains_query(&self, key: String, value: String) -> bool {
        self.query.contains(&(key, value))
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

    /// Change this DID's fragment identifier
    /// # Examples
    ///
    ///
    /// ```
    /// use lib_didethresolver::types::DidUrl;
    ///
    /// let mut did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// did_url.set_fragment(Some("controller"));
    /// assert_eq!(did_url.fragment(), Some("controller"));
    /// ```
    pub fn set_fragment(&mut self, fragment: Option<&str>) {
        // replace the fragment
        if let Some(fragment) = fragment {
            self.fragment = Some(fragment.to_string());
        } else {
            self.fragment = None;
        }
    }

    /// Change this DID's path
    ///
    /// # Examples
    /// ```
    /// use lib_didethresolver::types::DidUrl;
    ///
    /// let mut did_url = DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
    /// did_url.set_path("/path/to/resource");
    /// assert_eq!(did_url.path, "/path/to/resource");
    /// ```
    ///
    pub fn set_path(&mut self, path: &str) {
        self.path = path.to_string();
    }

    pub fn set_account(&mut self, account: Account) {
        self.did.account = account;
    }

    fn format_query(&self) -> String {
        let mut full_query = String::new();
        let mut pairs = self.query_pairs();

        if let Some((key, value)) = pairs.next() {
            full_query.push_str(&format!("?{}={}", key, value));
        }
        for (key, value) in pairs {
            let query = format!("&{}={}", key, value);
            full_query.push_str(&query);
        }
        full_query
    }
}

impl ToString for DidUrl {
    fn to_string(&self) -> String {
        let mut string = format!(
            "{}{}{}",
            self.did.to_string(),
            self.path(),
            self.format_query()
        );

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
            "Parsing of ethr:did failed, error at 1:1: expected one of \"ethr\", the only supported method is `ethr`"
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
    fn test_set_fragment() {
        let mut did_url =
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#key-1").unwrap();
        assert_eq!(did_url.fragment(), Some("key-1"));

        did_url.set_fragment(Some("key-2"));
        assert_eq!(did_url.fragment(), Some("key-2"));

        did_url.set_fragment(None);
        assert_eq!(did_url.fragment(), None);
    }

    #[test]
    fn test_set_path() {
        let mut did_url =
            DidUrl::parse("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a").unwrap();
        assert_eq!(did_url.path(), "");

        did_url.set_path("path-2");
        assert_eq!(did_url.path(), "path-2");
    }

    #[test]
    fn test_add_query() {
        let mut did_url =
            DidUrl::parse("did:ethr:mainnet:0x0000000000000000000000000000000000000000").unwrap();
        did_url.add_query("meta", Some("test"));
        assert_eq!(
            did_url.to_string(),
            "did:ethr:mainnet:0x0000000000000000000000000000000000000000?meta=test"
        );
    }

    #[test]
    fn test_multiple_queries() {
        let mut did_url =
            DidUrl::parse("did:ethr:mainnet:0x0000000000000000000000000000000000000000").unwrap();
        did_url.add_query("meta", Some("hi"));
        did_url.add_query("username", None);
        did_url.add_query("password", Some("hunter2"));

        assert_eq!(
            did_url.to_string(),
            "did:ethr:mainnet:0x0000000000000000000000000000000000000000?meta=hi&username=&password=hunter2"
        )
    }

    #[test]
    fn test_add_empty_query() {
        let mut did_url =
            DidUrl::parse("did:ethr:mainnet:0x0000000000000000000000000000000000000000").unwrap();
        did_url.add_query("meta", None);
        assert_eq!(
            did_url.to_string(),
            "did:ethr:mainnet:0x0000000000000000000000000000000000000000?meta="
        );
    }

    #[test]
    fn test_query_parses() {
        let did_url = DidUrl::parse("did:ethr:mainnet:0x0000000000000000000000000000000000000000?meta=hi&username=&password=hunter2").unwrap();

        let mut pairs = did_url.query_pairs();
        assert_eq!(pairs.next(), Some(&("meta".into(), "hi".into())));
        assert_eq!(pairs.next(), Some(&("username".into(), "".into())));
        assert_eq!(pairs.next(), Some(&("password".into(), "hunter2".into())));
    }
}
