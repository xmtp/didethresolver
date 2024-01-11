//! DID Identity Resolver
pub mod did_registry;

use std::sync::Arc;

use anyhow::Result;
use ethers::{
    contract::LogMeta,
    prelude::{LocalWallet, Provider, SignerMiddleware},
    providers::{Middleware, Ws},
    types::{Address, Block, H160, H256, U256, U64},
};

use rand::{rngs::StdRng, SeedableRng};

use self::did_registry::{DIDRegistry, DIDRegistryEvents};
use crate::types::{
    DidDocument, DidDocumentMetadata, DidResolutionMetadata, DidResolutionResult, EthrBuilder,
};

type ResolverSigner = SignerMiddleware<Provider<Ws>, LocalWallet>;

/// A resolver for did:ethr that follows the steps outlined in the [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#read-resolve) in order to resolve a did:ethr identifier.
pub struct Resolver {
    signer: Arc<ResolverSigner>,
    registry: DIDRegistry<ResolverSigner>,
}

impl Resolver {
    pub async fn new<Endpoint: AsRef<str>>(
        provider_endpoint: Endpoint,
        registry: Address,
    ) -> Result<Self> {
        let wallet = LocalWallet::new(&mut StdRng::from_entropy());
        let provider = Provider::<Ws>::connect(provider_endpoint).await?;
        let signer =
            Arc::new(SignerMiddleware::new_with_provider_chain(provider, wallet.clone()).await?);
        let registry = DIDRegistry::new(registry, signer.clone());
        log::debug!("Using deployed registry at {}", registry.address());
        Ok(Self { signer, registry })
    }

    pub async fn resolve_did(
        &self,
        public_key: H160,
        version_id: Option<U64>,
    ) -> Result<DidResolutionResult> {
        let history = self.changelog(public_key).await?;
        self.wrap_did_resolution(public_key, version_id, history)
            .await
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

        history.reverse();
        Ok(history)
    }

    fn dispatch_event(
        &self,
        doc: &mut EthrBuilder,
        public_key: H160,
        event: DIDRegistryEvents,
        meta: LogMeta,
        deactivated: &mut bool,
    ) {
        let res = match event {
            DIDRegistryEvents::DiddelegateChangedFilter(delegate_changed) => {
                doc.delegate_event(delegate_changed)
            }
            DIDRegistryEvents::DidattributeChangedFilter(attribute_event) => {
                doc.attribute_event(attribute_event)
            }
            DIDRegistryEvents::DidownerChangedFilter(owner_changed) => {
                if doc
                    .owner_event(owner_changed)
                    .is_ok_and(|deactivated| deactivated)
                {
                    *deactivated = true;
                }
                Ok(())
            }
        };

        // if a did was set with the wrong format, for instance set-attribute was called with
        // raw bytes instead of hex-encoded bytes, we don't want to cancel resolution of the
        // rest of the DID
        //
        // TODO: Send this info as an extra json field to the caller apart from the DID Document
        if let Err(e) = res {
            log::error!(
                    "Error while resolving for {} at event block={}, log index={}, incorrect format?: {}",
                    public_key, meta.block_number, meta.log_index, e,
                );
        };
    }

    async fn wrap_did_resolution(
        &self,
        public_key: H160,
        version_id: Option<U64>,
        history: Vec<(DIDRegistryEvents, LogMeta)>,
    ) -> Result<DidResolutionResult> {
        let mut base_document = DidDocument::ethr_builder();
        base_document.public_key(&public_key)?;

        let current_block = self.signer.get_block_number().await?;
        let current_block = self.signer.get_block(current_block).await?;

        let now = current_block.map(|b| b.timestamp).unwrap_or(U256::zero());
        let mut current_version_id = U64::zero();

        base_document.now(now);
        let mut last_updated_did_version_id: Option<U64> = None;
        let mut deactivated = false;

        for (event, meta) in history {
            let LogMeta { block_number, .. } = meta;

            if version_id.unwrap_or_default() > U64::zero() {
                if meta.block_number <= version_id.unwrap_or_default() {
                    // 1. delegate events
                    Resolver::dispatch_event(
                        self,
                        &mut base_document,
                        public_key,
                        event,
                        meta,
                        &mut deactivated,
                    );
                    // 2. set latest version
                    if current_version_id < block_number {
                        current_version_id = block_number;
                    }
                } else {
                    // just update the next version before quitting.
                    last_updated_did_version_id = Some(block_number);
                    break;
                }
            } else {
                // 1. delegate events
                Resolver::dispatch_event(
                    self,
                    &mut base_document,
                    public_key,
                    event,
                    meta,
                    &mut deactivated,
                );
                // 2. set latest version
                if current_version_id < block_number {
                    current_version_id = block_number;
                }
            };
        }
        let block_time = |block: Block<H256>| {
            block
                .time()
                .unwrap_or_default()
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
        };

        // get the timestamp for the current_verison_id
        let current_version_timestamp = self
            .signer
            .get_block(current_version_id)
            .await?
            .map(block_time);

        let resolution_result = DidResolutionResult {
            document: base_document.build()?,
            metadata: Some(DidDocumentMetadata {
                deactivated,
                version_id: current_version_id.as_u64(),
                updated: current_version_timestamp,
                next_version_id: last_updated_did_version_id.map(|ver| ver.as_u64()),
                next_update: match last_updated_did_version_id {
                    Some(ver) => self.signer.get_block(ver).await?.map(block_time),
                    None => None::<String>,
                },
            }),
            resolution_metadata: Some(DidResolutionMetadata {
                content_type: "application/did+ld+json".to_string(),
            }),
        };
        Ok(resolution_result)
    }
}
