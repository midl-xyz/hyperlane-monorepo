use std::{ops::Deref, sync::Arc};

use ethers::{
    abi::RawLog,
    providers::Middleware,
    types::{H160 as EthersH160, H256 as EthersH256},
};
use ethers_contract::{Contract, ContractError, EthEvent, LogMeta as EthersLogMeta};
use ethers_core::{abi::Abi, types::U256};
use hyperlane_core::{ChainCommunicationError, ChainResult, LogMeta, H512};
use once_cell::sync::Lazy;
use serde_json::from_str;

use crate::{config::MidlFinalityConf, EthereumReorgPeriod};

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

static EXECUTOR_ABI: Lazy<Abi> = Lazy::new(|| {
    from_str(
        r#"[{"inputs":[],"name":"lastCommittedMidlBlock","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]"#,
    )
    .expect("executor ABI")
});

pub async fn get_midl_finalized_block_number<M>(
    provider: Arc<M>,
    finality: &MidlFinalityConf,
) -> ChainResult<u32>
where
    M: Middleware + 'static,
{
    let contract: Contract<M> = Contract::new(
        finality.executor_address,
        EXECUTOR_ABI.clone(),
        provider.clone(),
    );
    let last_committed: U256 = contract
        .method::<_, U256>("lastCommittedMidlBlock", ())
        .map_err(ChainCommunicationError::from_other)?
        .call()
        .await
        .map_err(ChainCommunicationError::from_other)?;

    let confirmations = finality.btc_confirmations.saturating_sub(1);
    let finalized = last_committed.saturating_sub(U256::from(confirmations));
    u32::try_from(finalized)
        .map_err(|_| ChainCommunicationError::CustomError("finalized block overflow".into()))
}
