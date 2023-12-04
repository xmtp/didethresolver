//! Trait Definitions for JSON-RPC

use crate::types::DidDocument;

use jsonrpsee::{proc_macros::rpc, types::ErrorObjectOwned};

/// Decentralized Identifier JSON-RPC Interface Methods
#[rpc(server, client, namespace = "did")]
pub trait DidRegistry {
    #[method(name = "resolveDid")]
    async fn resolve_did(&self, public_key: String) -> Result<DidDocument, ErrorObjectOwned>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use jsonrpsee::ws_client::WsClientBuilder;
    use mockall::{automock, mock, predicate::*};
    use jsonrpsee::client_transport::ws::{Url, WsTransportClientBuilder};
    use crate::rpc::tests::MockStream; 
    use futures::io::{BufReader, BufWriter};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_stream::{wrappers::TcpListenerStream, StreamExt};
    use tokio_util::compat::{TokioAsyncReadCompatExt, Compat};
    
    mock! {
        pub DidRegistryMethods {}

        #[async_trait]
        impl DidRegistryServer for DidRegistryMethods {
            async fn resolve_did(&self, _public_key: String) -> Result<DidDocument, ErrorObjectOwned>;
        }
    }
    
    #[tokio::test]
    pub async fn test_resolve_did() {
        crate::util::init_logging();
        
        let data_stream = MockStream::default(); 
        let server_stream = data_stream.clone();
    
        log::debug!("HELLO????");
        tokio::spawn(async move {
            crate::util::init_logging();
            log::debug!("BINDING TO 9001");
            let listener = TcpListener::bind("127.0.0.1:9001").await.unwrap();
            let mut incoming = TcpListenerStream::new(listener);
            loop {
                log::debug!("WAITING...");
                let socket = incoming.next().await.unwrap().unwrap();
                log::debug!("GOT INCOMING {:?}", socket);
                let socket = BufReader::with_capacity(8 * 1024, BufWriter::with_capacity(16 * 1024, server_stream.clone()));
                let mut server = soketto::handshake::Server::new(socket);
                let key = {
                    log::debug!("RECEIVING REQUEST");
                    let req = server.receive_request().await.unwrap();
                    req.key()
                };
                let accept = soketto::handshake::server::Response::Accept { key, protocol: None };
                server.send_response(&accept).await.unwrap();
            }
        });
        
        let transport = WsTransportClientBuilder::default().build_with_stream(Url::parse("ws://127.0.0.1:9001").unwrap(), data_stream.clone()).await.unwrap();
        // let client = WsClientBuilder::default().build(&"ws://127.0.0.1:9999").await.unwrap();
        // let mut mock = MockDidRegistryMethods::new();
        // mock.expect_resolve_did().returning(|_| Ok(DidDocument));
        log::info!("I am a test");
    }
}
