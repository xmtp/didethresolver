//! Example Turtle RPC Endpoints
//!
//! These endpoints will be available under the `turtle` namespace. I.e calling `turtle_sayHello`
//! for the `say_hello` method.

use jsonrpsee::{proc_macros::rpc, types::ErrorObjectOwned};

#[rpc(server, client, namespace = "turtle")]
pub trait TurtleRpc {
    #[method(name = "sayHello")]
    async fn say_hello(&self, name: String) -> Result<String, ErrorObjectOwned>;
}

pub struct TurtleMethods;

#[async_trait::async_trait]
impl TurtleRpcServer for TurtleMethods {
    async fn say_hello(&self, name: String) -> Result<String, ErrorObjectOwned> {
        Ok(format!("Hello, {}!", name))
    }
}
