mod api;
mod methods;

// re-export the defined API
pub use api::*;

#[cfg(test)]
mod tests {
    use std::{future::Future, time::Duration};
   
    use jsonrpsee::{server::Server, ws_client::{WsClientBuilder, WsClient}};
    use futures::future::FutureExt;
    use tokio::time::timeout as timeout_tokio;
    
    use super::*;
    
    // Test harness for using a WebSockets Server 
    pub async fn with_client<F, R, T>(timeout: Option<Duration>, fun: F) -> T
    where
        F: FnOnce(WsClient) -> R + 'static,
        R: Future<Output = T> + FutureExt + Send + 'static
    {
        crate::util::init_logging();

        let server = Server::builder().build("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let handle = server.start(methods::DidRegistryMethods.into_rpc());
        
        let client = WsClientBuilder::default().build(&format!("ws://{addr}")).await.unwrap();
        
        // cant catch_unwind b/c jsonrpsee uses tokio mpsc which is !UnwindSafe, so we wrap with a
        // timeout.
        // If we panic in the closure, we never return and the server will never stop, hanging our
        // tests.
        let result = timeout_tokio(timeout.unwrap_or(Duration::from_millis(50)), fun(client)).await;
        
        handle.stop().unwrap();
        handle.stopped().await;
       
        if let Err(_) = result {
            log::debug!("Test timed out due to panic, or running too long.");
        }
        result.unwrap()
    }
}
