//! Shared setup code for integration tests
use std::sync::Once;
use std::{future::Future, time::Duration};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

use crate::Resolver;
use futures::future::FutureExt;
use jsonrpsee::{
    server::Server,
    ws_client::{WsClient, WsClientBuilder},
};
use tokio::time::timeout as timeout_tokio;

static INIT: Once = Once::new();

pub(crate) fn init_logging() {
    INIT.call_once(|| {
        let fmt = fmt::layer().compact();
        Registry::default()
            .with(EnvFilter::from_default_env())
            .with(fmt)
            .init()
    })
}

/// Test harness for using a WebSockets Server
/// Optionally provide a timeout [`std::time::Duration`] deadline by which the test must
/// finish.
///
/// # Panics
///
/// If `fun` panics, the test will end upon reaching `timeout`. Default timeout is 50
/// milliseconds.
pub async fn with_client<F, R, T>(timeout: Option<Duration>, fun: F) -> T
where
    F: FnOnce(WsClient) -> R + 'static,
    R: Future<Output = T> + FutureExt + Send + 'static,
{
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let resolver = crate::resolver::Resolver::new("127.0.0.1:8444")
        .await
        .unwrap();
    let handle = server.start(methods::DidRegistryMethods::new(resolver).into_rpc());

    let client = WsClientBuilder::default()
        .build(&format!("ws://{addr}"))
        .await
        .unwrap();

    // cant catch_unwind b/c jsonrpsee uses tokio mpsc which is !UnwindSafe, so we wrap with a
    // timeout.
    // If we panic in the closure without the timeout or catch_unwind, we never return and the server will never stop, hanging our
    // tests.
    let result = timeout_tokio(timeout.unwrap_or(Duration::from_millis(50)), fun(client)).await;

    handle.stop().unwrap();
    handle.stopped().await;

    if let Err(_) = result {
        log::debug!("Test timed out due to panic, or running too long.");
    }
    result.unwrap()
}
