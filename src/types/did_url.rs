//! Convenience Wrapper around [`Url`] for DID URIs according to the [DID Spec](https://www.w3.org/TR/did-core/#did-syntax)

use serde::{Deserialize, Serialize};
use std::str::Split;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidUrl {
    url: Url,
    #[serde(skip)]
    method_end: usize,
    #[serde(skip)]
    id_end: usize,
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
    pub fn parse<S: AsRef<str>>(input: S) -> Result<Self, ParseError> {
        let url = Url::parse(input.as_ref())?;

        let (method_end, id_end) = Self::extract_method_and_id(&url);

        Ok(Self {
            url,
            method_end,
            id_end,
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
    /// The method name is indicates the underlying consensus system (e.g. ethereum) the DID is associated with.
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
    pub fn id(&self) -> &str {
        let path: &str = self.url.path();
        &path[self.method_end + 1..self.id_end]
    }

    /// Return an iterator of ‘:’ slash-separated id segments, each as a percent-encoded ASCII string.
    /// The iterator always contains at least one string.
    pub fn id_segments(&self) -> Split<'_, char> {
        self.id().split(':')
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use url::Url;

    #[test]
    fn test_parse_did() {
        let did = "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad?service=agent&relativeRef=/credentials#degree";
        let url = DidUrl::parse(did);

        let examples = vec![
            "did:example:123456/path",
            "did:example:123456?versionId=1",
            "did:example:123#public-key-0",
            "did:example:123#agent",
            "did:example:123?service=agent&relativeRef=/credentials#degree",
            "did:example:123?versionTime=2021-05-10T17:00:00Z",
            "did:example:123?service=files&relativeRef=/resume.pdf",
            "did:example:123/file-test_23.png?service=files&relativeRef=/resume.pdf",
        ];

        for did_url in examples {
            let url = DidUrl::parse(did_url);
        }
    }

    #[test]
    fn test_method() {
        assert_eq!(
            DidUrl::parse("did:example:123456/path").unwrap().method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:123456?versionId=1")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:123#public-key-0")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:123#agent").unwrap().method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:123?service=agent&relativeRef=/credentials#degree")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:123?versionTime=2021-05-10T17:00:00Z")
                .unwrap()
                .method(),
            "example"
        );
        assert_eq!(
            DidUrl::parse("did:example:123?service=files&relativeRef=/resume.pdf")
                .unwrap()
                .method(),
            "example"
        );
    }

    #[test]
    fn test_id() {
        assert_eq!(
            DidUrl::parse("did:example:123456/path").unwrap().id(),
            "123456"
        );
        assert_eq!(
            DidUrl::parse("did:example:123456?versionId=1")
                .unwrap()
                .id(),
            "123456"
        );
        assert_eq!(
            DidUrl::parse("did:example:123#public-key-0").unwrap().id(),
            "123"
        );
        assert_eq!(DidUrl::parse("did:example:123#agent").unwrap().id(), "123");
        assert_eq!(
            DidUrl::parse("did:example:123?service=agent&relativeRef=/credentials#degree")
                .unwrap()
                .id(),
            "123"
        );
        assert_eq!(
            DidUrl::parse("did:example:123?versionTime=2021-05-10T17:00:00Z")
                .unwrap()
                .id(),
            "123"
        );
        assert_eq!(
            DidUrl::parse("did:example:123?service=files&relativeRef=/resume.pdf")
                .unwrap()
                .id(),
            "123"
        );
    }
}
