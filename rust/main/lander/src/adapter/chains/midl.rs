use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ethers_core::abi::Function;
use ethers_core::types::transaction::eip2718::TypedTransaction;
use eyre::{eyre, Result};
use tokio::sync::Mutex;

use hyperlane_base::{
    db::HyperlaneRocksDB,
    settings::{
        ChainConf, RawChainConf,
    },
    CoreMetrics,
};
use hyperlane_core::{ChainResult, ContractLocator, H256, H512, U256};

use hyperlane_ethereum::{EthereumReorgPeriod, TransactionOverrides as EthTransactionOverrides};
use hyperlane_midl::ConnectionConf;

use crate::adapter::{
    chains::ethereum::{EthereumAdapter, EthereumAdapterMetrics},
    AdaptsChain, AdaptsChainAction, GasLimit, TxBuildingResult,
};
use crate::dispatcher::PayloadDb;
use crate::payload::{FullPayload, PayloadDetails};
use crate::transaction::{Transaction, TransactionStatus};
use crate::{DispatcherMetrics, LanderError};

/// Midl adapter for Lander.
///
/// Implementation strategy: build a Midl provider (which can apply Midl-specific tx rewriting)
/// and adapt it to the existing EVM adapter logic so we don't have to fork the whole ethereum
/// adapter stack yet.
pub struct MidlAdapter {
    inner: EthereumAdapter,
}

impl MidlAdapter {
    pub async fn new(
        conf: ChainConf,
        connection_conf: ConnectionConf,
        _raw_conf: RawChainConf,
        db: Arc<HyperlaneRocksDB>,
        metrics: &CoreMetrics,
        dispatcher_metrics: DispatcherMetrics,
    ) -> Result<Self> {
        let domain = conf.domain.name();

        // Locator is only used for building the provider; address isn't required for lander submission.
        let locator = ContractLocator {
            domain: &conf.domain,
            address: H256::zero(),
        };

        // Build a Midl provider so chain-specific middleware (e.g. tx rewriting) can be applied.
        let midl_provider = conf
            .build_midl(
                &connection_conf,
                &locator,
                metrics,
                hyperlane_midl::LanderProviderBuilder {},
            )
            .await?;

        let signer = midl_provider
            .get_signer()
            .ok_or_else(|| eyre!("No signer found in provider for domain {}", domain))?;

        let provider: Arc<dyn hyperlane_ethereum::EvmProviderForLander> = Arc::new(
            MidlEvmProviderAdapter::new(midl_provider),
        );

        let metrics = EthereumAdapterMetrics::new(
            conf.domain.clone(),
            dispatcher_metrics.get_batched_transactions(),
            dispatcher_metrics.get_finalized_nonce(domain, &signer.to_string()),
            dispatcher_metrics.get_upper_nonce(domain, &signer.to_string()),
            dispatcher_metrics.get_mismatched_nonce(domain, &signer.to_string()),
        );

        let payload_db = db.clone() as Arc<dyn PayloadDb>;

        let reorg_period = EthereumReorgPeriod::try_from(&conf.reorg_period)?;
        let nonce_manager =
            crate::adapter::chains::ethereum::NonceManager::new(&conf, db, provider.clone(), metrics.clone()).await?;

        let inner = EthereumAdapter {
            estimated_block_time: conf.estimated_block_time,
            domain: conf.domain.clone(),
            transaction_overrides: convert_transaction_overrides(&connection_conf.transaction_overrides),
            submission_config: connection_conf.op_submission_config.clone(),
            provider,
            reorg_period,
            nonce_manager,
            batch_cache: Default::default(),
            batch_contract_address: connection_conf.batch_contract_address(),
            payload_db,
            signer,
            minimum_time_between_resubmissions: Duration::from_secs(1),
            metrics,
        };

        Ok(Self { inner })
    }
}

#[async_trait]
impl AdaptsChain for MidlAdapter {
    async fn estimate_gas_limit(
        &self,
        payload: &FullPayload,
    ) -> std::result::Result<Option<GasLimit>, LanderError> {
        self.inner.estimate_gas_limit(payload).await
    }

    async fn build_transactions(&self, payloads: &[FullPayload]) -> Vec<TxBuildingResult> {
        self.inner.build_transactions(payloads).await
    }

    async fn simulate_tx(
        &self,
        tx: &mut Transaction,
    ) -> std::result::Result<Vec<PayloadDetails>, LanderError> {
        self.inner.simulate_tx(tx).await
    }

    async fn estimate_tx(&self, tx: &mut Transaction) -> std::result::Result<(), LanderError> {
        self.inner.estimate_tx(tx).await
    }

    async fn submit(&self, tx: &mut Transaction) -> std::result::Result<(), LanderError> {
        self.inner.submit(tx).await
    }

    async fn get_tx_hash_status(
        &self,
        hash: H512,
    ) -> std::result::Result<TransactionStatus, LanderError> {
        self.inner.get_tx_hash_status(hash).await
    }

    async fn tx_ready_for_resubmission(&self, tx: &Transaction) -> bool {
        self.inner.tx_ready_for_resubmission(tx).await
    }

    async fn reverted_payloads(
        &self,
        tx: &Transaction,
    ) -> std::result::Result<Vec<PayloadDetails>, LanderError> {
        self.inner.reverted_payloads(tx).await
    }

    fn estimated_block_time(&self) -> &Duration {
        self.inner.estimated_block_time()
    }

    fn max_batch_size(&self) -> u32 {
        self.inner.max_batch_size()
    }

    fn update_vm_specific_metrics(&self, tx: &Transaction, metrics: &DispatcherMetrics) {
        self.inner.update_vm_specific_metrics(tx, metrics)
    }

    fn reprocess_txs_poll_rate(&self) -> Option<Duration> {
        self.inner.reprocess_txs_poll_rate()
    }

    async fn get_reprocess_txs(&self) -> std::result::Result<Vec<Transaction>, LanderError> {
        self.inner.get_reprocess_txs().await
    }

    async fn run_command(&self, action: AdaptsChainAction) -> std::result::Result<(), LanderError> {
        self.inner.run_command(action).await
    }
}

fn convert_transaction_overrides(midl: &hyperlane_midl::TransactionOverrides) -> EthTransactionOverrides {
    EthTransactionOverrides {
        gas_price: midl.gas_price,
        gas_limit: midl.gas_limit,
        max_fee_per_gas: midl.max_fee_per_gas,
        max_priority_fee_per_gas: midl.max_priority_fee_per_gas,
        min_gas_price: midl.min_gas_price,
        min_fee_per_gas: midl.min_fee_per_gas,
        min_priority_fee_per_gas: midl.min_priority_fee_per_gas,
        gas_price_multiplier_denominator: midl.gas_price_multiplier_denominator,
        gas_price_multiplier_numerator: midl.gas_price_multiplier_numerator,
        gas_price_cap_multiplier: midl.gas_price_cap_multiplier,
        gas_price_cap: midl.gas_price_cap,
        gas_limit_cap: midl.gas_limit_cap,
    }
}

/// Adapts `hyperlane_midl::EvmProviderForLander` to the trait expected by the existing
/// ethereum adapter implementation (`hyperlane_ethereum::EvmProviderForLander`).
struct MidlEvmProviderAdapter {
    inner: Arc<dyn hyperlane_midl::EvmProviderForLander>,
    // We can't reuse the ethereum BatchCache type in the midl provider, so keep our own.
    batch_cache: Arc<Mutex<hyperlane_midl::multicall::BatchCache>>,
}

impl MidlEvmProviderAdapter {
    fn new(inner: Arc<dyn hyperlane_midl::EvmProviderForLander>) -> Self {
        Self {
            inner,
            batch_cache: Default::default(),
        }
    }
}

#[async_trait]
impl hyperlane_ethereum::EvmProviderForLander for MidlEvmProviderAdapter {
    async fn get_transaction_receipt(
        &self,
        transaction_hash: H256,
    ) -> ChainResult<Option<ethers::types::TransactionReceipt>> {
        self.inner.get_transaction_receipt(transaction_hash).await
    }

    async fn get_finalized_block_number(
        &self,
        reorg_period: &hyperlane_ethereum::EthereumReorgPeriod,
    ) -> ChainResult<u32> {
        self.inner
            .get_finalized_block_number(&to_midl_reorg_period(reorg_period))
            .await
    }

    async fn get_block(
        &self,
        block_number: ethers_core::types::BlockNumber,
    ) -> ChainResult<Option<ethers::types::Block<ethers::types::H256>>> {
        self.inner.get_block(block_number).await
    }

    async fn estimate_gas_limit(
        &self,
        tx: &TypedTransaction,
        function: &Function,
    ) -> ChainResult<U256> {
        self.inner.estimate_gas_limit(tx, function).await
    }

    async fn batch(
        &self,
        _cache: Arc<Mutex<hyperlane_ethereum::multicall::BatchCache>>,
        batch_contract_address: H256,
        precursors: Vec<(TypedTransaction, Function)>,
        signer: ethers::types::H160,
    ) -> ChainResult<(TypedTransaction, Function)> {
        self.inner
            .batch(
                self.batch_cache.clone(),
                batch_contract_address,
                precursors,
                signer,
            )
            .await
    }

    async fn simulate_batch(
        &self,
        multi_precursor: (TypedTransaction, Function),
    ) -> ChainResult<(Vec<usize>, Vec<(usize, String)>)> {
        self.inner.simulate_batch(multi_precursor).await
    }

    async fn estimate_batch(
        &self,
        multi_precursor: (TypedTransaction, Function),
        precursors: Vec<(TypedTransaction, Function)>,
    ) -> ChainResult<U256> {
        self.inner.estimate_batch(multi_precursor, precursors).await
    }

    async fn send(&self, tx: &TypedTransaction, function: &Function) -> ChainResult<H256> {
        self.inner.send(tx, function).await
    }

    async fn check(&self, tx: &TypedTransaction, function: &Function) -> ChainResult<bool> {
        self.inner.check(tx, function).await
    }

    async fn get_next_nonce_on_finalized_block(
        &self,
        address: &ethers_core::abi::Address,
        reorg_period: &hyperlane_ethereum::EthereumReorgPeriod,
    ) -> ChainResult<U256> {
        self.inner
            .get_next_nonce_on_finalized_block(address, &to_midl_reorg_period(reorg_period))
            .await
    }

    async fn fee_history(
        &self,
        block_count: U256,
        last_block: ethers_core::types::BlockNumber,
        reward_percentiles: &[f64],
    ) -> ChainResult<ethers_core::types::FeeHistory> {
        self.inner
            .fee_history(block_count, last_block, reward_percentiles)
            .await
    }

    async fn zk_estimate_fee(
        &self,
        tx: &TypedTransaction,
    ) -> ChainResult<hyperlane_ethereum::ZksyncEstimateFeeResponse> {
        let resp = self.inner.zk_estimate_fee(tx).await?;
        Ok(hyperlane_ethereum::ZksyncEstimateFeeResponse {
            gas_limit: resp.gas_limit,
            max_fee_per_gas: resp.max_fee_per_gas,
            max_priority_fee_per_gas: resp.max_priority_fee_per_gas,
            gas_per_pubdata_limit: resp.gas_per_pubdata_limit,
        })
    }

    fn get_signer(&self) -> Option<ethers::types::H160> {
        self.inner.get_signer()
    }
}

fn to_midl_reorg_period(
    value: &hyperlane_ethereum::EthereumReorgPeriod,
) -> hyperlane_midl::EthereumReorgPeriod {
    match value {
        hyperlane_ethereum::EthereumReorgPeriod::Blocks(b) => hyperlane_midl::EthereumReorgPeriod::Blocks(*b),
        hyperlane_ethereum::EthereumReorgPeriod::Tag(tag) => hyperlane_midl::EthereumReorgPeriod::Tag(*tag),
    }
}


