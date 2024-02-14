//! DID Identity Resolver
pub mod did_registry;

use std::sync::Arc;

use ethers::{
    contract::LogMeta,
    providers::Middleware,
    types::{Address, Block, H160, H256, U256, U64},
};

use self::did_registry::{DIDRegistry, DIDRegistryEvents};
use crate::{
    error::ResolverError,
    types::{
        DidDocument, DidDocumentMetadata, DidResolutionMetadata, DidResolutionResult, EthrBuilder,
    },
};

/// A resolver for did:ethr that follows the steps outlined in the [spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#read-resolve) in order to resolve a did:ethr identifier.
pub struct Resolver<M> {
    registry: DIDRegistry<M>,
}

impl<M> From<DIDRegistry<M>> for Resolver<M> {
    fn from(registry: DIDRegistry<M>) -> Self {
        Self { registry }
    }
}

/// Extra context passed to the document builder from the [`Resolver`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventContext {
    /// the timestamp in nanoseconds in which the block from the document was built.
    pub timestamp: i64
}

impl EventContext {
    pub async fn new<M: Middleware>(meta: &LogMeta, signer: impl Middleware) -> Result<Self, ResolverError<M>> {
        let block = signer.get_block(meta.block_number).await.map_err(|e| ResolverError::Middleware(e.to_string()))?;
        let timestamp = block
            .ok_or(ResolverError::MissingBlock(meta.block_number))?
            .time()
            .unwrap_or_default()
            .timestamp_nanos_opt()
            .ok_or(ResolverError::TimestampOutOfRange(meta.block_number))?;

        Ok(Self { timestamp })
    }
}

impl<M: Middleware + 'static> Resolver<M> {
    /// Instantiate a new did:ethr resolver
    pub async fn new(middleware: M, registry: Address) -> Result<Self, ResolverError<M>> {
        let registry = DIDRegistry::new(registry, middleware.into());
        log::debug!("Using deployed registry at {}", registry.address());
        Ok(Self { registry })
    }

    /// Resolve a did:ethr identifier
    pub async fn resolve_did(
        &self,
        public_key: H160,
        version_id: Option<U64>,
    ) -> Result<DidResolutionResult, ResolverError<M>> {
        let history = self.changelog(public_key).await?;
        self.wrap_did_resolution(public_key, version_id, history)
            .await
    }

    async fn changelog(
        &self,
        public_key: H160,
    ) -> Result<Vec<(DIDRegistryEvents, LogMeta)>, ResolverError<M>> {
        let mut previous_change: U64 = self
            .registry
            .changed(public_key)
            .call()
            .await?
            .as_u64()
            .into();

        log::trace!("Previous Change for {}: {:?}", public_key, previous_change);

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
                log::trace!("Adding {:?} event to history", event);
                if event.previous_change() < previous_change {
                    previous_change = event.previous_change();
                }
                history.push((event, meta));
            }
        }

        history.reverse();
        Ok(history)
    }

    async fn dispatch_event(
        &self,
        doc: &mut EthrBuilder,
        public_key: H160,
        event: DIDRegistryEvents,
        meta: LogMeta,
    ) -> Result<(), ResolverError<M>> {
        let context = EventContext::new(&meta, self.signer()).await?;
        let res = match event {
            DIDRegistryEvents::DiddelegateChangedFilter(delegate_changed) => {
                log::trace!("Delegate Changed {:?}", delegate_changed);
                doc.delegate_event(delegate_changed, &context)
            }
            DIDRegistryEvents::DidattributeChangedFilter(attribute_event) => {
                log::trace!("Attribute Changed {:?}", attribute_event);
                doc.attribute_event(attribute_event, &context)
            }
            DIDRegistryEvents::DidownerChangedFilter(owner_changed) => {
                log::trace!("Owner Changed {:?}", owner_changed);
                doc.owner_event(owner_changed)
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
        Ok(())
    }

    async fn wrap_did_resolution(
        &self,
        public_key: H160,
        version_id: Option<U64>,
        history: Vec<(DIDRegistryEvents, LogMeta)>,
    ) -> Result<DidResolutionResult, ResolverError<M>> {
        let mut base_document = DidDocument::ethr_builder();
        base_document.account_address(&public_key)?;

        let current_block = self
            .signer()
            .get_block_number()
            .await
            .map_err(|e| ResolverError::Middleware(e.to_string()))?;
        let current_block = self
            .signer()
            .get_block(current_block)
            .await
            .map_err(|e| ResolverError::Middleware(e.to_string()))?;

        let now = current_block.map(|b| b.timestamp).unwrap_or(U256::zero());
        let mut current_version_id = U64::zero();

        base_document.now(now);
        let mut last_updated_did_version_id: Option<U64> = None;

        for (event, meta) in history {
            let LogMeta { block_number, .. } = meta;

            if version_id.unwrap_or_default() > U64::zero() {
                if meta.block_number <= version_id.unwrap_or_default() {
                    // 1. delegate events
                    Resolver::dispatch_event(self, &mut base_document, public_key, event, meta).await?;
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
                Resolver::dispatch_event(self, &mut base_document, public_key, event, meta).await?;
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
            .signer()
            .get_block(current_version_id)
            .await
            .map_err(|e| ResolverError::Middleware(e.to_string()))?
            .map(block_time);

        let resolution_result = DidResolutionResult {
            metadata: DidDocumentMetadata {
                deactivated: base_document.is_deactivated(),
                version_id: current_version_id.as_u64(),
                updated: current_version_timestamp,
                next_version_id: last_updated_did_version_id.map(|ver| ver.as_u64()),
                next_update: match last_updated_did_version_id {
                    Some(ver) => self
                        .signer()
                        .get_block(ver)
                        .await
                        .map_err(|e| ResolverError::Middleware(e.to_string()))?
                        .map(block_time),
                    None => None::<String>,
                },
            },
            document: base_document.build()?,
            resolution_metadata: DidResolutionMetadata {
                content_type: "application/did+ld+json".to_string(),
            },
        };
        Ok(resolution_result)
    }

    fn signer(&self) -> Arc<M> {
        self.registry.client()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_registry() {
        let (provider, _) = ethers::providers::Provider::mocked();
        let registry = DIDRegistry::new(Address::zero(), Arc::new(provider));
        let resolver = Resolver::from(registry);
        assert_eq!(resolver.registry.address(), Address::zero());
    }
}
