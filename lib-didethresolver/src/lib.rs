//! did:ethr resolver library
//!
//! This library provides a resolver for did:ethr DIDs.
//!
//! TODO: docs

pub mod error;
mod resolver;
pub mod rpc;
pub mod types;
mod util;

pub use crate::resolver::{did_registry, Resolver};

#[cfg(feature = "server")]
pub use rpc::DidRegistryServer;
