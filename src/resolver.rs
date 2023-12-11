//! DID Identity Resolver

use std::{str::FromStr, sync::Arc};

use anyhow::{Context, Error, Result};
use ethers::{
    contract::abigen,
    core::k256::ecdsa::SigningKey,
    prelude::{LocalWallet, Provider, SignerMiddleware},
    providers::{Middleware, Ws},
    signers::Signer,
    types::{H160, H256},
};
use rand::{rngs::StdRng, SeedableRng};

use crate::types::DidDocument;

abigen!(
    DIDRegistry,
    "./src/abi/DIDRegistry.json",
    derives(serde::Serialize, serde::Deserialize)
);

type ResolverSigner = SignerMiddleware<Provider<Ws>, LocalWallet>;

pub struct Resolver {
    signer: Arc<ResolverSigner>,
    registry: DIDRegistry<ResolverSigner>,
}

impl Resolver {
    pub async fn new<Contract: AsRef<str>, Endpoint: AsRef<str>>(
        did_contract: Contract,
        provider_endpoint: Endpoint,
    ) -> Result<Self> {
        let address = H160::from_str(did_contract.as_ref())
            .context("Failed to convert address string to H160")?;
        let wallet = LocalWallet::new(&mut StdRng::from_entropy());
        let provider = Provider::<Ws>::connect(provider_endpoint).await?;
        let signer =
            Arc::new(SignerMiddleware::new_with_provider_chain(provider, wallet.clone()).await?);
        let registry = DIDRegistry::new(address, signer.clone());
        Ok(Self { signer, registry })
    }

    pub fn resolve_did(&self, public_key: String) -> DidDocument {
        todo!();
    }
}
