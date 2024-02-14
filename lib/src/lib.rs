//! did:ethr resolver library
//!
//! This library provides a resolver for did:ethr DIDs according the the W3C [specification](https://www.w3.org/TR/did-core/#abstract) and the did:ethr [specification](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
//! Provided functions include parsing ethr:dids, resolving ethr:dids, and constructing ethr:did
//! documents and associated metadata.
//!
//! # Examples
//!
//! ## Instantiating the [`Resolver`] struct
//! A [`Resolver`] struct requires specifying the address of the deployed did:ethr registry and
//! the middleware to communicate with the chain.
//!
//! Once instantiated, DID Documents may be built by resolving DIDs.
//! ```rust, no_run
//! use ethers::{types::Address, prelude::{Ws, Provider}};
//! use std::str::FromStr;
//! use lib_didethresolver::Resolver;
//!
//! # tokio_test::block_on(async {
//!let registry_address = Address::from_str("0xd1D374DDE031075157fDb64536eF5cC13Ae75000").unwrap();
//!let endpoint = "wss://ethereum-sepolia.publicnode.com";
//!let provider = Provider::<Ws>::connect(endpoint).await.unwrap();
//!let resolver = Resolver::new(provider, registry_address).await.unwrap();
//!
//!resolver
//!   .resolve_did(
//!       Address::from_str("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap(),
//!       None
//!   ).await.unwrap();
//!# })
//! ````
//!
//! # Cargo Feature Flags
//!
//! `server` enables the JSON-RPC server api for did:ethr resolution
//!
//! `client` enables the JSON-RPC client for the did:ethr server
//!
//! ### Using the Server
//! ``` no_run
//! # #[cfg(feature = "server")]
//! # {
//! use std::str::FromStr;
//! use ethers::{types::Address, prelude::{Ws, Provider}};
//! use jsonrpsee::server::Server;
//! use lib_didethresolver::{Resolver, DidRegistryServer, rpc::DidRegistryMethods};
//!
//! # tokio_test::block_on(async {
//! let registry_address = Address::from_str("0xd1D374DDE031075157fDb64536eF5cC13Ae75000").unwrap();
//! let endpoint = "wss://ethereum-sepolia.publicnode.com";
//! let provider = Provider::<Ws>::connect(endpoint).await.unwrap();
//! let resolver = Resolver::new(provider, registry_address).await.unwrap();
//! let server = Server::builder().build("127.0.0.1:0").await.unwrap();
//!
//! let addr = server.local_addr().unwrap();
//! let handle = server.start(DidRegistryMethods::new(resolver).into_rpc());
//! handle.stopped().await;
//!
//! # })
//!
//! # }
//! ````
//!
//! ### Using the Client
//!
//! ```no_run
//! # #[cfg(feature = "client")]
//! # {
//! use jsonrpsee::ws_client::WsClientBuilder;
//! use lib_didethresolver::DidRegistryClient;
//!
//! # tokio_test::block_on(async {  
//! let client = WsClientBuilder::default().build("ws://127.0.0.1:9999").await.unwrap();
//! let document = client.resolve_did("0x5FbDB2315678afecb367f032d93F642f64180aa3".into(), None).await.unwrap();
//! # })
//! # }

pub mod error;
mod resolver;
pub mod types;
mod util;

#[cfg(any(feature = "server", feature = "client"))]
pub mod rpc;

pub use crate::resolver::{did_registry, Resolver};

#[cfg(feature = "server")]
pub use rpc::DidRegistryServer;

#[cfg(feature = "client")]
pub use rpc::DidRegistryClient;
