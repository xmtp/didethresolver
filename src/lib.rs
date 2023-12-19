//! ## Endpoint Documentation: `resolveDid`
//!
//! ### Overview
//!
//! The `resolveDid` endpoint is designed to receive an Ethereum public key and return did document in a JSON format. This endpoint is part of our decentralized data service, which provides access to decentralized identity.
//!
//! ### Endpoint
//!
//! ```text
//! POST /api/v1/resolveDid
//! ```
//!
//! ### Request Format
//!
//! The request should be a JSON object containing one field: `publicKey`.
//!
//! - `publicKey` (string, required): The Ethereum public key (starting with '0x').
//!
//! Example Request:
//! ```json
//! {
//!   "publicKey": "0x123abc..."
//! }
//! ```
//!
//! ### Response Format
//!
//! The response will be a JSON object containing a did document for related to the provided Ethereum public key.
//!
//! Example Response:
//! ```json
//! {
//!   "@context": [
//!     "https://www.w3.org/ns/did/v1",
//!     "https://w3id.org/security/suites/ed25519-2020/v1"
//!   ],
//!   "controller": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!   "id": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!   "service": [
//!     {
//!       "id": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "recipientKeys": "0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "serviceEndpoint": "https://xmtp.com/resolver",
//!       "type": "MessagingService"
//!     }
//!   ],
//!   "verificationMethod": [
//!     {
//!       "controller": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "id": "did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "publicKeyMultibase": "0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad",
//!       "type": "Ed25519VerificationKey2020"
//!     }
//!   ]
//! ```
//!
//! ### Error Handling
//!
//! In case of an error (e.g., invalid public key, server error), the endpoint will return a JSON object with an `error` field describing the issue.
//!
//! Example Error Response:
//! ```json
//! {
//!   "error": "Invalid public key format"
//! }
//! ```
//!
//! ### Security and Authentication
//!
//! - The endpoint is open access.
//!
//! ### Future requirements
//! - Access control
//! - All requests must be made over HTTPS.
//! - Rate limiting is applied to prevent abuse.
//!
//!
//! ### Support
//!
//! Please refer to the DID specification: [DID](https://www.w3.org/TR/did-core/)
pub mod rpc;
pub mod types;
mod util;
