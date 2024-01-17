//! Shared setup code for integration tests
use ethers::providers::Middleware;
use std::sync::{Arc, Once};
use std::{future::Future, time::Duration};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

// TODO: Would be nice to use the anvil library instead of a CLI interface
use anyhow::Result;
use didethresolver::{
    did_registry::DIDRegistry, types::DidDocument, DidRegistryMethods, DidRegistryServer, Resolver,
};
use ethers::{
    core::utils::{Anvil, AnvilInstance},
    middleware::SignerMiddleware,
    providers::{Provider, Ws},
    signers::{LocalWallet, Signer as _},
    types::Address,
};
use futures::future::FutureExt;
use jsonrpsee::{
    server::Server,
    ws_client::{WsClient, WsClientBuilder},
};
use serde::{Deserialize, Serialize};
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

type Signer = SignerMiddleware<Provider<Ws>, LocalWallet>;

/// Test harness for using a WebSockets Server
/// Optionally provide a timeout [`std::time::Duration`] deadline by which the test must
/// finish.
///
/// # Panics
///
/// If `fun` panics, the test will end upon reaching `timeout`. Default timeout is 50
/// milliseconds.
///
/// If the `anvil` binary is not available in `$PATH`, the test will panic.
pub async fn with_client<F, R, T>(timeout: Option<Duration>, fun: F) -> Result<T>
where
    F: FnOnce(WsClient, DIDRegistry<Signer>, Arc<Signer>, Arc<AnvilInstance>) -> R + 'static,
    R: Future<Output = Result<T>> + FutureExt + Send + 'static,
{
    init_logging();

    let anvil = Anvil::new().args(vec!["--base-fee", "100"]).spawn();
    log::debug!("Anvil spawned at {}", anvil.ws_endpoint());
    let registry_address = deploy_to_anvil(&anvil).await;
    log::debug!("Contract deployed at {}", registry_address);

    let user = client(&anvil, anvil.keys()[2].clone().into()).await;
    let balance = user.get_balance(user.address(), None).await.unwrap();
    log::debug!("Balance {}", balance);

    let registry = DIDRegistry::new(registry_address, user.clone());

    // a port of 0 chooses any open port
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let signer = client(&anvil, anvil.keys()[0].clone().into()).await;
    let resolver = Resolver::new(signer, registry_address).await.unwrap();
    let handle = server.start(DidRegistryMethods::new(resolver).into_rpc());

    let client = WsClientBuilder::default()
        .build(&format!("ws://{addr}"))
        .await
        .unwrap();

    let anvil = Arc::new(anvil);
    // cant catch_unwind b/c jsonrpsee uses tokio mpsc which is !UnwindSafe, so we wrap with a
    // timeout.
    // If we panic in the closure without the timeout or catch_unwind, we never return and the server will never stop, hanging our
    // tests.
    let result = timeout_tokio(
        // this is long b/c of the call to didlint
        timeout.unwrap_or(Duration::from_secs(10)),
        fun(client, registry, user, anvil.clone()),
    )
    .await;

    handle.stop().unwrap();
    handle.stopped().await;

    // it's important to keep a reference to anvil alive, even if we don't use it after or in the
    // predicate, `fun`, otherwise our server will shutoff.
    drop(anvil);

    match result {
        Ok(v) => v,
        Err(_) => {
            log::debug!("Test timed out due to panic, or running too long.");
            panic!("test timed out");
        }
    }
}

async fn deploy_to_anvil(anvil: &AnvilInstance) -> Address {
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let client = client(&anvil, wallet).await;

    let registry = DIDRegistry::deploy(client.clone(), ())
        .unwrap()
        .gas_price(100)
        .send()
        .await
        .unwrap();

    registry.address()
}

async fn client(
    anvil: &AnvilInstance,
    wallet: LocalWallet,
) -> Arc<SignerMiddleware<Provider<Ws>, LocalWallet>> {
    let provider = Provider::<Ws>::connect(anvil.ws_endpoint())
        .await
        .unwrap()
        .interval(std::time::Duration::from_millis(10u64));
    Arc::new(SignerMiddleware::new(
        provider,
        wallet.with_chain_id(anvil.chain_id()),
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResponse {
    infos: Vec<Message>,
    valid: bool,
}

// TODO: Should use the installable didlint command, to make testing faster

/// Validate a DID Document using the didlint service
pub async fn validate_document(document: &DidDocument) {
    log::debug!(
        "document={}",
        serde_json::to_string_pretty(&document).unwrap()
    );
    let endpoint = "https://didlint.ownyourdata.eu/api/validate";
    let res = surf::post(endpoint)
        .body(surf::Body::from_json(&document).unwrap())
        .await;
    let response: ValidationResponse = res.unwrap().body_json().await.unwrap();
    for info in response.infos {
        log::warn!("{}", info.message);
    }
    assert!(response.valid);
}
