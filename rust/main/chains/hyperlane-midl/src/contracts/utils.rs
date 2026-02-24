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

/// Build a `(BtcTxStatusClient, btc_confirmations)` pair from the finality
/// and execution configs.  Returns `None` when no mempool URL is available.
pub fn build_btc_finality(
    finality: &MidlFinalityConf,
    execution: Option<&MidlExecutionConf>,
) -> Option<(BtcTxStatusClient, u64)> {
    let mempool_url = execution.and_then(|e| e.mempool_url.clone())?;
    let use_electrs_api = execution.and_then(|e| e.use_electrs_api).unwrap_or(false);
    Some((
        BtcTxStatusClient::new(mempool_url, use_electrs_api),
        finality.btc_confirmations,
    ))
}

/// Determine the finalized block by checking BTC confirmations on the
/// indexer's own events.
///
/// 1. `eth_getLogs` for event type `E` on `contract_address` (full range)
/// 2. Walk backwards from the latest event
/// 3. For each event, get the transaction's `btcTxHash`, check BTC confirmations
/// 4. Return the block number of the first event with >= required confirmations
/// 5. If no events or none confirmed, return 0
pub async fn get_event_based_finalized_block<M, E>(
    provider: Arc<M>,
    contract_address: EthersH160,
    btc_client: &BtcTxStatusClient,
    btc_confirmations: u64,
) -> ChainResult<u32>
where
    M: Middleware + 'static,
    E: EthEvent,
{
    let filter = ethers::types::Filter::new()
        .address(contract_address)
        .topic0(E::signature());

    let logs = provider
        .get_logs(&filter)
        .await
        .map_err(ChainCommunicationError::from_other)?;

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
        let confirmations = btc_client.get_tx_confirmations(&btc_tx_id).await?;

        if confirmations >= btc_confirmations {
            debug!(
                block = block_number.as_u32(),
                btc_tx = %btc_tx_id,
                confirmations,
                "Event-based finality: found confirmed BTC tx"
            );
            return Ok(block_number.as_u32());
        }
    }

    Ok(0)
}
