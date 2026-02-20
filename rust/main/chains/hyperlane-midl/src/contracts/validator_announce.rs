#![allow(clippy::enum_variant_names)]
#![allow(missing_docs)]

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use ethers::providers::Middleware;
use ethers_contract::builders::ContractCall;
use hyperlane_core::{
    Announcement, ChainResult, ContractLocator, HyperlaneAbi, HyperlaneChain, HyperlaneContract,
    HyperlaneDomain, HyperlaneProvider, SignedType, TxOutcome, ValidatorAnnounce, H160, H256, U256,
};
use tracing::instrument;

use crate::{
    interfaces::i_validator_announce::{
        IValidatorAnnounce as EthereumValidatorAnnounceInternal, IVALIDATORANNOUNCE_ABI,
    },
    tx::{fill_tx_gas_params, report_tx},
    BuildableWithProvider, ConnectionConf, EthereumProvider, MidlMetadataProvider,
};

impl<M> std::fmt::Display for EthereumValidatorAnnounceInternal<M>
where
    M: Middleware,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub struct ValidatorAnnounceBuilder {
    pub metadata_provider: Option<Arc<dyn MidlMetadataProvider>>,
}

#[async_trait]
impl BuildableWithProvider for ValidatorAnnounceBuilder {
    type Output = Box<dyn ValidatorAnnounce>;
    const NEEDS_SIGNER: bool = true;

    async fn build_with_provider<M: Middleware + 'static>(
        &self,
        provider: M,
        conn: &ConnectionConf,
        locator: &ContractLocator,
    ) -> Self::Output {
        Box::new(EthereumValidatorAnnounce::new(
            Arc::new(provider),
            conn,
            locator,
            self.metadata_provider.clone(),
        ))
    }
}

/// A reference to a ValidatorAnnounce contract on some Ethereum chain
pub struct EthereumValidatorAnnounce<M>
where
    M: Middleware,
{
    contract: Arc<EthereumValidatorAnnounceInternal<M>>,
    domain: HyperlaneDomain,
    provider: Arc<M>,
    conn: ConnectionConf,
    metadata_provider: Option<Arc<dyn MidlMetadataProvider>>,
}

impl<M: Middleware> std::fmt::Debug for EthereumValidatorAnnounce<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthereumValidatorAnnounce")
            .field("domain", &self.domain)
            .field("has_metadata_provider", &self.metadata_provider.is_some())
            .finish()
    }
}

impl<M> EthereumValidatorAnnounce<M>
where
    M: Middleware + 'static,
{
    /// Create a reference to a ValidatorAnnounce contract at a specific Ethereum
    /// address on some chain
    pub fn new(
        provider: Arc<M>,
        conn: &ConnectionConf,
        locator: &ContractLocator,
        metadata_provider: Option<Arc<dyn MidlMetadataProvider>>,
    ) -> Self {
        Self {
            contract: Arc::new(EthereumValidatorAnnounceInternal::new(
                locator.address,
                provider.clone(),
            )),
            domain: locator.domain.clone(),
            provider,
            conn: conn.clone(),
            metadata_provider,
        }
    }

    /// Returns a ContractCall that processes the provided message.
    /// If the provided tx_gas_limit is None, gas estimation occurs.
    async fn announce_contract_call(
        &self,
        announcement: SignedType<Announcement>,
    ) -> ChainResult<ContractCall<M, bool>> {
        let serialized_signature: [u8; 65] = announcement.signature.into();
        let tx = self.contract.announce(
            announcement.value.validator.into(),
            announcement.value.storage_location,
            serialized_signature.into(),
        );
        fill_tx_gas_params(
            tx,
            self.provider.clone(),
            &self.conn.transaction_overrides,
            &self.domain,
            true,
            // pass an empty value as the cache
            Default::default(),
        )
        .await
    }
}

impl<M> HyperlaneChain for EthereumValidatorAnnounce<M>
where
    M: Middleware + 'static,
{
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(EthereumProvider::new(
            self.contract.client(),
            self.domain.clone(),
        ))
    }
}

impl<M> HyperlaneContract for EthereumValidatorAnnounce<M>
where
    M: Middleware + 'static,
{
    fn address(&self) -> H256 {
        self.contract.address().into()
    }
}

#[async_trait]
impl<M> ValidatorAnnounce for EthereumValidatorAnnounce<M>
where
    M: Middleware + 'static,
{
    async fn get_announced_storage_locations(
        &self,
        validators: &[H256],
    ) -> ChainResult<Vec<Vec<String>>> {
        let storage_locations = self
            .contract
            .get_announced_storage_locations(
                validators.iter().map(|v| H160::from(*v).into()).collect(),
            )
            .call()
            .await?;
        Ok(storage_locations)
    }

    #[instrument(ret, skip(self))]
    async fn announce_tokens_needed(
        &self,
        _announcement: SignedType<Announcement>,
        _chain_signer: H256,
    ) -> Option<U256> {
        if let Some(provider) = &self.metadata_provider {
            provider.check_btc_funds_available().await.map(|v| {
                // Convert ethers::types::U256 → hyperlane_core::U256 via big-endian bytes
                let mut bytes = [0u8; 32];
                v.to_big_endian(&mut bytes);
                U256::from_big_endian(&bytes)
            })
        } else {
            // No metadata provider — can't check BTC balance, allow announce
            Some(U256::zero())
        }
    }

    #[instrument(err, ret, skip(self))]
    #[allow(clippy::blocks_in_conditions)] // TODO: `rustc` 1.80.1 clippy issue
    async fn announce(&self, announcement: SignedType<Announcement>) -> ChainResult<TxOutcome> {
        let contract_call = self.announce_contract_call(announcement).await?;
        let receipt = report_tx(contract_call).await?;
        Ok(receipt.into())
    }
}

pub struct EthereumValidatorAnnounceAbi;

impl HyperlaneAbi for EthereumValidatorAnnounceAbi {
    const SELECTOR_SIZE_BYTES: usize = 4;

    fn fn_map() -> HashMap<Vec<u8>, &'static str> {
        crate::extract_fn_map(&IVALIDATORANNOUNCE_ABI)
    }
}
