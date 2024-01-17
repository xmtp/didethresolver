//! JSON-RPC Interface and Implementation

mod api;
#[cfg(feature = "server")]
mod methods;

// re-export the defined API
pub use api::*;
#[cfg(feature = "server")]
pub use methods::*;
