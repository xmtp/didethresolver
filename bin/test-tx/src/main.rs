//! NOTE: NOT MEANT FOR PRODUCTION USE

use anyhow::{anyhow, Context, Error};
use argh::FromArgs;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ethers::{
    middleware::{Middleware, SignerMiddleware},
    prelude::{Http, Provider, ProviderExt},
    signers::{LocalWallet, Signer},
    types::Address,
};
use lib_didethresolver::did_registry::DIDRegistry;
use std::{path::PathBuf, str::FromStr, sync::Arc};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

/// One Year of Validity
const VALIDITY: u64 = 60 * 60 * 24 * 365;

#[derive(FromArgs)]
/// A simple CLI to interact with the EVM-Based DID Registries
pub struct App {
    /// the Ws network RPC-URL to interact with
    #[argh(
        short = 'n',
        option,
        default = "String::from(\"https://ethereum-sepolia.publicnode.com\")"
    )]
    pub network: String,

    /// address of the DID Registry contract to interact with
    ///(default: Test deployment on Sepolia)
    #[argh(
        short = 'c',
        option,
        default = "String::from(\"0xd1D374DDE031075157fDb64536eF5cC13Ae75000\")"
    )]
    pub contract: String,

    /// path to a local JSON wallet. Ensure usage of a test wallet, the
    /// security of this binary has not been verified. Use at your own risk. (default:
    /// `./wallet.json`)
    #[argh(short = 'w', option, default = "PathBuf::from(\"./wallet.json\")")]
    pub wallet: PathBuf,

    /// whether to test-run the transaction or commit it to chain
    #[argh(short = 'd', switch)]
    pub dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_logging();
    let app: App = argh::from_env();
    println!("Network: {}", app.network);
    println!("Contract: {}", app.contract);
    println!("Wallet: {:?}", app.wallet);

    set_attr(&app).await?;
    Ok(())
}

/// optimism addr: 0xd1D374D44050cD04f0C1bDBb22A0d5f76BD21900
pub async fn set_attr(app: &App) -> Result<(), Error> {
    let App {
        network,
        contract,
        wallet,
        dry_run,
    } = app;

    let contract = Address::from_str(contract)?;
    let provider = Provider::<Http>::connect(network).await;
    println!("Chain Id: {}", provider.get_chainid().await?);
    let prompt = format!(
        "Enter Password to {} ",
        app.wallet.as_path().to_str().unwrap()
    );
    let password =
        rpassword::prompt_password(prompt).context("I/O Error while inputting password")?;
    let wallet = LocalWallet::decrypt_keystore(wallet, password)
        .context("Could not decrypt keystore; wrong password?")?;

    let signer = SignerMiddleware::new_with_provider_chain(provider, wallet.clone()).await?;
    let registry = DIDRegistry::new(contract, Arc::new(signer));

    // a public ed25519 SSH key -- good example since XMTP Installation keys are ed25519 as well.
    let dummy_key =
        BASE64.decode("AAAAC3NzaC1lZDI1NTE5AAAAILUArrr4oix6p/bSjeuXKi2crVzsuSqSYoz//YJMsTlo")?;
    let dummy_key = hex::encode(dummy_key);
    let tx = registry.set_attribute(
        wallet.address(),
        *b"xmtp/installation/base64        ",
        dummy_key.as_bytes().to_vec().into(),
        VALIDITY.into(),
    );

    if *dry_run {
        println!("Dry running transaction...");
        #[allow(clippy::let_unit_value)]
        let tx_type = tx.call().await?;
        println!("Success, transaction result type {:?}", tx_type);
    } else {
        let pending = tx.send().await.context("Failed to submit transaction")?;
        println!("Transaction is pending! {}", hex::encode(pending.tx_hash()));
        println!("Waiting for inclusion...");
        let result = pending
            .await
            .context("Transaction was not included")?
            .ok_or(anyhow!("Not transaction receipt"))?;
        println!(
            "Transaction has been included in block {}, at transaction hash {} using gas {}",
            result.block_number.unwrap_or(0.into()),
            hex::encode(result.transaction_hash),
            result.gas_used.unwrap_or(0.into())
        );
    }
    Ok(())
}

fn init_logging() {
    let fmt = fmt::layer().compact();
    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt)
        .init()
}
