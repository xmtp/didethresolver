//! DID Identity Resolver
pub mod did_registry;

use std::{str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use ethers::{
    contract::LogMeta,
    prelude::{LocalWallet, Provider, SignerMiddleware},
    providers::{Middleware, Ws},
    types::{H160, H256, U256, U64},
};
use rand::{rngs::StdRng, SeedableRng};

use self::did_registry::{DIDRegistry, DIDRegistryEvents};
use crate::types::DidDocument;

pub const DID_ETH_REGISTRY: &str = "0xd1D374DDE031075157fDb64536eF5cC13Ae75000";

type ResolverSigner = SignerMiddleware<Provider<Ws>, LocalWallet>;

pub struct Resolver {
    signer: Arc<ResolverSigner>,
    registry: DIDRegistry<ResolverSigner>,
}

impl Resolver {
    pub async fn new<Endpoint: AsRef<str>>(provider_endpoint: Endpoint) -> Result<Self> {
        let address =
            H160::from_str(DID_ETH_REGISTRY).context("Failed to convert address string to H160")?;
        let wallet = LocalWallet::new(&mut StdRng::from_entropy());
        let provider = Provider::<Ws>::connect(provider_endpoint).await?;
        let signer =
            Arc::new(SignerMiddleware::new_with_provider_chain(provider, wallet.clone()).await?);
        let registry = DIDRegistry::new(address, signer.clone());
        Ok(Self { signer, registry })
    }

    pub async fn resolve_did(&self, public_key: H160) -> Result<DidDocument> {
        let history = self.changelog(public_key).await?;
        Ok(self.wrap_did_document(public_key, history).await?)
    }

    async fn changelog(&self, public_key: H160) -> Result<Vec<(DIDRegistryEvents, LogMeta)>> {
        let mut previous_change: U64 = self
            .registry
            .changed(public_key)
            .call()
            .await?
            .as_u64()
            .into();

        let mut history = Vec::new();

        loop {
            if previous_change == U64::zero() {
                break;
            }

            let events = self
                .registry
                .events()
                .from_block(previous_change)
                .to_block(previous_change)
                .topic1(H256::from(public_key))
                .query_with_meta()
                .await?;

            for (event, meta) in events {
                if event.previous_change() < previous_change {
                    previous_change = event.previous_change();
                }
                history.push((event, meta));
            }
        }
        Ok(history)
    }

    // TODO: Handle version IDs, deactivation
    async fn wrap_did_document(
        &self,
        public_key: H160,
        history: Vec<(DIDRegistryEvents, LogMeta)>,
    ) -> Result<DidDocument> {
        let mut base_document = DidDocument::ethr_builder();
        base_document.public_key(&public_key)?;

        let current_block = self.signer.get_block_number().await?;
        let current_block = self.signer.get_block(current_block).await?;

        let now = current_block.map(|b| b.timestamp).unwrap_or(U256::zero());
        let mut version_id = U64::zero();

        base_document.now(now);

        for (event, meta) in history {
            if version_id < meta.block_number {
                version_id = meta.block_number;
            }

            match event {
                DIDRegistryEvents::DiddelegateChangedFilter(delegate_changed) => {
                    base_document.delegate_event(delegate_changed)
                }
                DIDRegistryEvents::DidattributeChangedFilter(attribute_event) => {
                    base_document.attribute_event(attribute_event)?;
                }
                DIDRegistryEvents::DidownerChangedFilter(owner_changed) => {
                    base_document.owner_event(owner_changed)?;
                }
            }
        }
        Ok(base_document.build())
    }
}
