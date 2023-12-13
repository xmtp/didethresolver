//! DID Identity Resolver
mod did_registry;

use std::{collections::HashMap, str::FromStr, sync::Arc};

use anyhow::{Context, Error, Result};
use ethers::{
    contract::LogMeta,
    prelude::{LocalWallet, Provider, SignerMiddleware},
    providers::{Middleware, Ws},
    types::{Address, H160, H256, U256, U64},
};
use rand::{rngs::StdRng, SeedableRng};
use sha3::{Digest, Sha3_256};

use self::did_registry::{DIDRegistry, DIDRegistryEvents};
use crate::types::{DidDocument, DidUrl, VerificationMethod, VerificationType};

pub const DID_ETH_REGISTRY: &str = "0xd1D374DDE031075157fDb64536eF5cC13Ae75000";
const NULL_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

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

    async fn changelog(&self, public_key: H160) -> Result<Vec<(DIDRegistryEvents, LogMeta)>> {
        let mut previous_change: U64 = self
            .registry
            .changed(public_key)
            .call()
            .await?
            .as_u64()
            .into();

        log::debug!("Block timestamp");

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
                log::info!("{:?}", event);

                if event.previous_change() < previous_change {
                    previous_change = event.previous_change();
                }
                history.push((event, meta));
            }
        }
        Ok(history)
    }

    fn event_key(event: &DIDRegistryEvents) -> String {
        let event_name = event.event_name();
        match event {
            DIDRegistryEvents::DidattributeChangedFilter(attr) => {
                format!(
                    "{event_name}-{}-{}",
                    String::from_utf8_lossy(&attr.name.to_vec()),
                    String::from_utf8_lossy(&attr.value.to_vec())
                )
            }
            DIDRegistryEvents::DiddelegateChangedFilter(delegate) => {
                format!(
                    "{event_name}-{}-{}",
                    String::from_utf8_lossy(&delegate.delegate_type.to_vec()),
                    hex::encode(delegate.delegate)
                )
            }
            _ => format!("{event_name}"),
        }
    }

    async fn wrap_did_document(
        &self,
        public_key: H160,
        controller_key: Option<H160>,
        history: Vec<(DIDRegistryEvents, LogMeta)>,
    ) -> Result<()> {
        let did = DidUrl::parse("did:ethr:{publickey}")?;
        let base_document = DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".try_into()?,
                "https://w3id.org/security/suites/secp256k1recovery-2020/v2".try_into()?,
            ],
            id: did.clone(),
            also_known_as: None,
            controller: None,
            verification_method: None,
            service: None,
        };

        let current_block = self.signer.get_block_number().await?;
        let current_block = self.signer.get_block(current_block).await.unwrap();

        let now = current_block.map(|b| b.timestamp).unwrap_or(U256::zero());

        let mut auth_did = did.clone();
        let authentication = vec![auth_did.set_fragment(Some("controller"))];

        let mut controller: Option<Address> = None;
        let mut version_id = U64::zero();
        let next_version_id = u32::MAX;
        let mut deactivated = false;
        let mut delegate_count = 0;
        let service_count = 0;
        let endpoint = "";

        let mut auth: HashMap<String, DidUrl> = HashMap::new();
        let mut pks = HashMap::<String, VerificationMethod>::new();

        for (event, meta) in history {
            if version_id < meta.block_number {
                version_id = meta.block_number;
            }

            let valid_to = event.valid_to().unwrap_or(U256::zero());
            let event_key = Self::event_key(&event);

            if valid_to >= now {
                match event {
                    DIDRegistryEvents::DiddelegateChangedFilter(delegate_changed) => {
                        delegate_count += 1;
                        let delegate_type =
                            String::from_utf8_lossy(&delegate_changed.delegate_type);
                        match &*delegate_type {
                            "sigAuth" => {
                                let mut did = did.clone();
                                did.set_fragment(Some(&format!("delegate-{delegate_count}")));
                                auth.insert(event_key, did);
                            }
                            "veriKey" => {
                                let mut did_delegate = did.clone();
                                did_delegate
                                    .set_fragment(Some(&format!("delegate-{delegate_count}")));
                                let mut verification_method = VerificationMethod::new(
                                    did_delegate,
                                    did.clone(),
                                    VerificationType::Ed25519VerificationKey2020,
                                );
                                verification_method.set_blockchain_id(format!(
                                    "eip155:{}:{}",
                                    "TODO",
                                    hex::encode(delegate_changed.delegate)
                                ));

                                pks.insert(event_key, verification_method);
                            }
                            d => {
                                log::warn!("Unsupported or Unknown delegate type {d}");
                            }
                        };
                    }

                    DIDRegistryEvents::DidattributeChangedFilter(attribute_changed) => {
                        todo!()
                    }
                    _ => (),
                }
            } else {
                if let DIDRegistryEvents::DidownerChangedFilter(owner_changed) = event {
                    controller = Some(owner_changed.owner);
                    if owner_changed.owner
                        == Address::from_str(NULL_ADDRESS).expect("Const address is correct")
                    {
                        deactivated = true;
                    }
                }
            }
        }
        Ok(())
    }
}
