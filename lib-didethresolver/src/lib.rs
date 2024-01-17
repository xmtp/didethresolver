//! did:ethr resolver library
//!
//! This library provides a resolver for did:ethr DIDs according the the W3C [specification](https://www.w3.org/TR/did-core/#abstract) and the did:ethr [specification](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
//! Provided functions include parsing ethr:dids, resolving ethr:dids, and constructing ethr:did
//! documents and associated metadata.
//!
//! # Examples
//!
//!

pub mod error;
mod resolver;
#[cfg(any(feature = "server", feature = "client"))]
pub mod rpc;
pub mod types;
mod util;

pub use crate::resolver::{did_registry, Resolver};

#[cfg(feature = "server")]
pub use rpc::DidRegistryServer;
