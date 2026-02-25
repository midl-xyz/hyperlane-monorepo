use std::{ops::Deref, sync::Arc};

use ethers::{
    abi::RawLog,
    providers::Middleware,
    types::{H160 as EthersH160, H256 as EthersH256},
};
use ethers_contract::{ContractError, EthEvent, LogMeta as EthersLogMeta};
use hyperlane_core::{ChainCommunicationError, ChainResult, LogMeta, H512};
use tracing::debug;

use crate::{
    config::{MidlExecutionConf, MidlFinalityConf},
    rpc_clients::btc_tx_status::BtcTxStatusClient,
    EthereumReorgPeriod,
};

pub async fn fetch_raw_logs_and_meta<T: EthEvent, M>(
    tx_hash: H512,
    provider: Arc<M>,
    contract_address: EthersH160,
) -> ChainResult<Vec<(T, LogMeta)>>
where
    M: Middleware + 'static,
{
    let ethers_tx_hash: EthersH256 = tx_hash.into();
    let receipt = provider
        .get_transaction_receipt(ethers_tx_hash)
        .await
        .map_err(|err| ContractError::<M>::MiddlewareError(err))?;
    let Some(receipt) = receipt else {
        return Err(eyre::eyre!("No receipt found for tx hash {:?}", tx_hash).into());
    };

    let logs: Vec<(T, LogMeta)> = receipt
        .logs
        .into_iter()
        .filter_map(|log| {
            // Filter out logs that aren't emitted by this contract
            if log.address != contract_address {
                return None;
            }
            let raw_log = RawLog {
                topics: log.topics.clone(),
                data: log.data.to_vec(),
            };
            let log_meta: EthersLogMeta = (&log).into();
            let event_filter = T::decode_log(&raw_log).ok();
            event_filter.map(|log| (log, log_meta.into()))
        })
        .collect();
    Ok(logs)
}

pub async fn get_finalized_block_number<M, T>(
    provider: T,
    reorg_period: &EthereumReorgPeriod,
) -> ChainResult<u32>
where
    M: Middleware + 'static,
    T: Deref<Target = M>,
{
    let number = match *reorg_period {
        EthereumReorgPeriod::Blocks(blocks) => provider
            .get_block_number()
            .await
            .map_err(ChainCommunicationError::from_other)?
            .as_u32()
            .saturating_sub(blocks),

        EthereumReorgPeriod::Tag(tag) => provider
            .get_block(tag)
            .await
            .map_err(ChainCommunicationError::from_other)?
            .and_then(|block| block.number)
            .ok_or(ChainCommunicationError::CustomError(
                "Unable to get finalized block number".into(),
            ))?
            .as_u32(),
    };

    Ok(number)
}

/// BTC finality configuration resolved from the chain config, bundling the
/// HTTP client, required confirmations, and the earliest block to scan.
pub struct BtcFinalityState {
    pub btc_client: BtcTxStatusClient,
    pub btc_confirmations: u64,
    /// Earliest MIDL block that can contain contract events (from `index.from`).
    pub deploy_block: u32,
}

impl std::fmt::Debug for BtcFinalityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtcFinalityState")
            .field("btc_client", &self.btc_client)
            .field("btc_confirmations", &self.btc_confirmations)
            .field("deploy_block", &self.deploy_block)
            .finish()
    }
}

/// Build a [`BtcFinalityState`] from the finality and execution configs.
/// Returns `None` when no mempool URL is available.
pub fn build_btc_finality(
    finality: &MidlFinalityConf,
    execution: Option<&MidlExecutionConf>,
    deploy_block: u32,
) -> Option<BtcFinalityState> {
    let mempool_url = execution.and_then(|e| e.mempool_url.clone())?;
    Some(BtcFinalityState {
        btc_client: BtcTxStatusClient::new(mempool_url),
        btc_confirmations: finality.btc_confirmations,
        deploy_block,
    })
}

/// Number of MIDL blocks to scan per `eth_getLogs` chunk when walking
/// backwards from the tip looking for BTC-confirmed events.
const BTC_FINALITY_CHUNK_SIZE: u32 = 1000;

/// Determine the finalized block by checking BTC confirmations on the
/// indexer's own events.
///
/// Walks backwards from the chain tip in chunks, querying `eth_getLogs` for
/// event type `E`.  For each event (newest first) it fetches the MIDL
/// transaction's `btcTxHash` and checks BTC confirmations.  Returns the
/// block number of the first event with >= required confirmations, or 0 if
/// none is found.
pub async fn get_event_based_finalized_block<M, E>(
    provider: Arc<M>,
    contract_address: EthersH160,
    btc_finality: &BtcFinalityState,
) -> ChainResult<u32>
where
    M: Middleware + 'static,
    E: EthEvent,
{
    let tip = provider
        .get_block_number()
        .await
        .map_err(ChainCommunicationError::from_other)?
        .as_u32();

    if tip == 0 {
        return Ok(0);
    }

    let min_block = btc_finality.deploy_block;
    let mut to_block = tip;

    loop {
        let from_block = to_block
            .saturating_sub(BTC_FINALITY_CHUNK_SIZE - 1)
            .max(min_block);

        let filter = ethers::types::Filter::new()
            .address(contract_address)
            .topic0(E::signature())
            .from_block(from_block)
            .to_block(to_block);

        let logs = provider
            .get_logs(&filter)
            .await
            .map_err(ChainCommunicationError::from_other)?;

        // Walk newest-first within this chunk.
        for log in logs.iter().rev() {
            let Some(block_number) = log.block_number else {
                continue;
            };
            let Some(tx_hash) = log.transaction_hash else {
                continue;
            };

            let tx = provider
                .get_transaction(tx_hash)
                .await
                .map_err(ChainCommunicationError::from_other)?;
            let Some(tx) = tx else { continue };
            let Some(btc_hash) = tx.btc_tx_hash else {
                continue;
            };

            let btc_tx_id = format!("{:x}", btc_hash);
            let confirmations = btc_finality
                .btc_client
                .get_tx_confirmations(&btc_tx_id)
                .await?;

            if confirmations >= btc_finality.btc_confirmations {
                debug!(
                    block = block_number.as_u32(),
                    btc_tx = %btc_tx_id,
                    confirmations,
                    "Event-based finality: found confirmed BTC tx"
                );
                return Ok(block_number.as_u32());
            }
        }

        // Reached the deploy block without finding a confirmed event.
        if from_block <= min_block {
            break;
        }

        to_block = from_block.saturating_sub(1);
    }

    Ok(0)
}
