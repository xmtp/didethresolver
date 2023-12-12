//! DID Identity Resolver
mod did_registry;

use std::{collections::HashSet, str::FromStr, sync::Arc};

use anyhow::{Context, Error, Result};
use ethers::{
    core::k256::ecdsa::SigningKey,
    prelude::{LocalWallet, Provider, SignerMiddleware},
    providers::{Middleware, Ws},
    types::{H160, H256, U256, U64},
};
use rand::{rngs::StdRng, SeedableRng};
use sha3::{Digest, Sha3_256};

use self::did_registry::{DIDRegistry, DIDRegistryEvents};
use crate::types::{DidDocument, DidUrl};

pub const DID_ETH_REGISTRY: &str = "0xd1D374DDE031075157fDb64536eF5cC13Ae75000";

type ResolverSigner = SignerMiddleware<Provider<Ws>, LocalWallet>;
pub type Record = (String, String);

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
        // create a did that resolves an ethereum Address
        // let did = DidUrl::parse(format!("did:ethr:{public_key}"));
        let changelog = self.changelog(public_key).await?;

        Ok(DidDocument {
            context: Default::default(),
            id: DidUrl::parse("did:ethr:0x6CEb0bF1f28ca4165d5C0A04f61DC733987eD6ad?service=agent&relativeRef=/credentials#degree").unwrap(),
            also_known_as: None,
            controller: None,
            verification_method: None,
            service: None
        })
    }

    async fn changelog(&self, public_key: H160) -> Result<Vec<DIDRegistryEvents>> {
        log::debug!("Changelog");
        let mut previous_change: U64 = self
            .registry
            .changed(public_key)
            .call()
            .await?
            .as_u64()
            .into();

        let current_block = self.signer.get_block_number().await?;
        let block = self.signer.get_block(current_block).await.unwrap();

        let block_timestamp = block.map(|b| b.timestamp).unwrap_or(U256::zero());

        log::debug!("Block timestamp");

        let mut revocation_set = HashSet::<String>::new();
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
                .address(self.registry.address().into())
                .topic1(H256::from(public_key))
                .query()
                .await?;

            for event in events {
                log::info!("{:?}", event);

                if event.previous_change() < previous_change {
                    previous_change = event.previous_change();
                }
                history.push(event);
            }
        }
        Ok(history)
    }
}
