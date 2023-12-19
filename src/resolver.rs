//! DID Identity Resolver
mod did_registry;

use std::{str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use ethers::{
    contract::LogMeta,
    prelude::{LocalWallet, Provider, SignerMiddleware},
    providers::{Middleware, Ws},
    types::{Address, H160, H256, U256, U64},
};
use rand::{rngs::StdRng, SeedableRng};

use self::did_registry::{DIDRegistry, DIDRegistryEvents};
use crate::types::{self, Attribute, DidDocument, KeyPurpose};

pub const DID_ETH_REGISTRY: &str = "0xd1D374DDE031075157fDb64536eF5cC13Ae75000";
const NULL_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

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

    // TODO: Handle version IDs
    async fn wrap_did_document(
        &self,
        public_key: H160,
        history: Vec<(DIDRegistryEvents, LogMeta)>,
    ) -> Result<DidDocument> {
        let mut base_document = DidDocument::ethr_builder();
        base_document.public_key(&public_key);

        let current_block = self.signer.get_block_number().await?;
        let current_block = self.signer.get_block(current_block).await?;

        let now = current_block.map(|b| b.timestamp).unwrap_or(U256::zero());

        let mut version_id = U64::zero();

        let mut delegate_count = 0;
        let mut service_count = 0;

        for (event, meta) in history {
            if version_id < meta.block_number {
                version_id = meta.block_number;
            }

            let valid_to = event.valid_to().unwrap_or(U256::zero());

            // handle invalid attributes, they just require incrementing our counters
            if valid_to < now {
                match event {
                    DIDRegistryEvents::DiddelegateChangedFilter(_) => {
                        delegate_count += 1;
                        continue;
                    }
                    DIDRegistryEvents::DidattributeChangedFilter(attribute) => {
                        let name = attribute.name_string_lossy();
                        match types::parse_attribute(&name) {
                            Ok(Attribute::PublicKey(_)) => {
                                delegate_count += 1;
                            }
                            Ok(Attribute::Service(_)) => {
                                service_count += 1;
                            }
                            _ => {}
                        }
                        continue;
                    }
                    _ => {}
                }
            }

            match event {
                DIDRegistryEvents::DiddelegateChangedFilter(delegate_changed) => {
                    delegate_count += 1;
                    let delegate_type = String::from_utf8_lossy(&delegate_changed.delegate_type);
                    match &*delegate_type {
                        "sigAuth" => {
                            base_document.delegate(
                                delegate_count,
                                &delegate_changed.delegate,
                                KeyPurpose::SignatureAuthentication,
                            );
                        }
                        "veriKey" => {
                            base_document.delegate(
                                delegate_count,
                                &delegate_changed.delegate,
                                KeyPurpose::VerificationKey,
                            );
                        }
                        d => {
                            log::warn!("Unsupported or Unknown delegate type {d}");
                        }
                    };
                }
                DIDRegistryEvents::DidattributeChangedFilter(attribute_event) => {
                    let name = attribute_event.name_string_lossy();
                    let attribute =
                        types::parse_attribute(&name).unwrap_or(Attribute::Other(name.to_string()));

                    match attribute {
                        Attribute::PublicKey(key) => {
                            delegate_count += 1;
                            base_document.external_public_key(
                                delegate_count,
                                &attribute_event.value,
                                key,
                            );
                        }
                        Attribute::Service(service) => {
                            service_count += 1;
                            base_document.service(
                                service_count,
                                &attribute_event.value,
                                service,
                            )?;
                        }
                        Attribute::Other(_) => log::trace!(
                            "Unhandled Attribute {name}:{}",
                            attribute_event.value_string_lossy()
                        ),
                    }
                }
                DIDRegistryEvents::DidownerChangedFilter(owner_changed) => {
                    base_document.controller(&owner_changed.owner);
                    if owner_changed.owner
                        == Address::from_str(NULL_ADDRESS).expect("Const address is correct")
                    {
                        log::warn!("This address has been deactivated");
                    }
                }
            }
        }
        Ok(base_document.build())
    }
}
