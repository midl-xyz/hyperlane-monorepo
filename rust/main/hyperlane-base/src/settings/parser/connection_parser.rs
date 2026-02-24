use std::{ops::Add, str::FromStr};

use ethers_core::types::Bytes;
use eyre::eyre;
use hex;
use hyperlane_sealevel::{
    HeliusPriorityFeeLevel, HeliusPriorityFeeOracleConfig, PriorityFeeOracleConfig,
};
use url::Url;

use h_eth::TransactionOverrides;
use hyperlane_midl as h_midl;

use hyperlane_core::config::{ConfigErrResultExt, OpSubmissionConfig};
use hyperlane_core::utils::hex_or_base58_or_bech32_to_h256;
use hyperlane_core::{config::ConfigParsingError, HyperlaneDomainProtocol, NativeToken};

use hyperlane_starknet as h_starknet;

use crate::settings::envs::*;
use crate::settings::ChainConnectionConf;

use super::{parse_base_and_override_urls, parse_cosmos_gas_price, ValueParser};

#[allow(clippy::question_mark)] // TODO: `rustc` 1.80.1 clippy issue
pub fn build_ethereum_connection_conf(
    rpcs: &[Url],
    chain: &ValueParser,
    err: &mut ConfigParsingError,
    default_rpc_consensus_type: &str,
    operation_batch: OpSubmissionConfig,
) -> Option<ChainConnectionConf> {
    let Some(first_url) = rpcs.to_owned().clone().into_iter().next() else {
        return None;
    };
    let rpc_consensus_type = chain
        .chain(err)
        .get_opt_key("rpcConsensusType")
        .parse_string()
        .unwrap_or(default_rpc_consensus_type);

    let rpc_connection_conf = match rpc_consensus_type {
        "single" => Some(h_eth::RpcConnectionConf::Http { url: first_url }),
        "fallback" => Some(h_eth::RpcConnectionConf::HttpFallback {
            urls: rpcs.to_owned().clone(),
        }),
        "quorum" => Some(h_eth::RpcConnectionConf::HttpQuorum {
            urls: rpcs.to_owned().clone(),
        }),
        ty => Err(eyre!("unknown rpc consensus type `{ty}`"))
            .take_err(err, || (&chain.cwp).add("rpc_consensus_type")),
    };

    let transaction_overrides = chain
        .get_opt_key("transactionOverrides")
        .take_err(err, || (&chain.cwp).add("transaction_overrides"))
        .flatten()
        .map(|value_parser| TransactionOverrides {
            gas_price: value_parser
                .chain(err)
                .get_opt_key("gasPrice")
                .parse_u256()
                .end(),
            gas_limit: value_parser
                .chain(err)
                .get_opt_key("gasLimit")
                .parse_u256()
                .end(),
            max_fee_per_gas: value_parser
                .chain(err)
                .get_opt_key("maxFeePerGas")
                .parse_u256()
                .end(),
            max_priority_fee_per_gas: value_parser
                .chain(err)
                .get_opt_key("maxPriorityFeePerGas")
                .parse_u256()
                .end(),

            min_gas_price: value_parser
                .chain(err)
                .get_opt_key("minGasPrice")
                .parse_u256()
                .end(),
            min_fee_per_gas: value_parser
                .chain(err)
                .get_opt_key("minFeePerGas")
                .parse_u256()
                .end(),
            min_priority_fee_per_gas: value_parser
                .chain(err)
                .get_opt_key("minPriorityFeePerGas")
                .parse_u256()
                .end(),

            gas_price_multiplier_denominator: value_parser
                .chain(err)
                .get_opt_key("gasPriceMultiplierDenominator")
                .parse_u256()
                .end(),
            gas_price_multiplier_numerator: value_parser
                .chain(err)
                .get_opt_key("gasPriceMultiplierNumerator")
                .parse_u256()
                .end(),
            gas_price_cap_multiplier: value_parser
                .chain(err)
                .get_opt_key("gasPriceCapMultiplier")
                .parse_u256()
                .end(),

            gas_price_cap: value_parser
                .chain(err)
                .get_opt_key("gasPriceCap")
                .parse_u256()
                .end(),
            gas_limit_cap: value_parser
                .chain(err)
                .get_opt_key("gasLimitCap")
                .parse_u256()
                .end(),
        })
        .unwrap_or_default();

    Some(ChainConnectionConf::Ethereum(h_eth::ConnectionConf {
        rpc_connection: rpc_connection_conf?,
        transaction_overrides,
        op_submission_config: operation_batch,
    }))
}

#[allow(clippy::question_mark)] // TODO: `rustc` 1.80.1 clippy issue
pub fn build_midl_connection_conf(
    rpcs: &[Url],
    chain: &ValueParser,
    err: &mut ConfigParsingError,
    default_rpc_consensus_type: &str,
    operation_batch: OpSubmissionConfig,
) -> Option<ChainConnectionConf> {
    let Some(first_url) = rpcs.to_owned().clone().into_iter().next() else {
        return None;
    };
    let rpc_consensus_type = chain
        .chain(err)
        .get_opt_key("rpcConsensusType")
        .parse_string()
        .unwrap_or(default_rpc_consensus_type);

    let rpc_connection_conf = match rpc_consensus_type {
        "single" => Some(h_midl::RpcConnectionConf::Http { url: first_url }),
        "fallback" => Some(h_midl::RpcConnectionConf::HttpFallback {
            urls: rpcs.to_owned().clone(),
        }),
        "quorum" => Some(h_midl::RpcConnectionConf::HttpQuorum {
            urls: rpcs.to_owned().clone(),
        }),
        ty => Err(eyre!("unknown rpc consensus type `{ty}`"))
            .take_err(err, || (&chain.cwp).add("rpc_consensus_type")),
    };

    let transaction_overrides = chain
        .get_opt_key("transactionOverrides")
        .take_err(err, || (&chain.cwp).add("transaction_overrides"))
        .flatten()
        .map(|value_parser| h_midl::TransactionOverrides {
            gas_price: value_parser
                .chain(err)
                .get_opt_key("gasPrice")
                .parse_u256()
                .end(),
            gas_limit: value_parser
                .chain(err)
                .get_opt_key("gasLimit")
                .parse_u256()
                .end(),
            max_fee_per_gas: value_parser
                .chain(err)
                .get_opt_key("maxFeePerGas")
                .parse_u256()
                .end(),
            max_priority_fee_per_gas: value_parser
                .chain(err)
                .get_opt_key("maxPriorityFeePerGas")
                .parse_u256()
                .end(),

            min_gas_price: value_parser
                .chain(err)
                .get_opt_key("minGasPrice")
                .parse_u256()
                .end(),
            min_fee_per_gas: value_parser
                .chain(err)
                .get_opt_key("minFeePerGas")
                .parse_u256()
                .end(),
            min_priority_fee_per_gas: value_parser
                .chain(err)
                .get_opt_key("minPriorityFeePerGas")
                .parse_u256()
                .end(),

            gas_price_multiplier_denominator: value_parser
                .chain(err)
                .get_opt_key("gasPriceMultiplierDenominator")
                .parse_u256()
                .end(),
            gas_price_multiplier_numerator: value_parser
                .chain(err)
                .get_opt_key("gasPriceMultiplierNumerator")
                .parse_u256()
                .end(),
            gas_price_cap_multiplier: value_parser
                .chain(err)
                .get_opt_key("gasPriceCapMultiplier")
                .parse_u256()
                .end(),

            gas_price_cap: value_parser
                .chain(err)
                .get_opt_key("gasPriceCap")
                .parse_u256()
                .end(),
            gas_limit_cap: value_parser
                .chain(err)
                .get_opt_key("gasLimitCap")
                .parse_u256()
                .end(),
        })
        .unwrap_or_default();

    let execution = parse_midl_execution_conf(chain, err);
    let finality = parse_midl_finality_conf(chain, err);

    Some(ChainConnectionConf::Midl(h_midl::ConnectionConf {
        rpc_connection: rpc_connection_conf?,
        transaction_overrides,
        op_submission_config: operation_batch,
        execution,
        finality,
    }))
}

pub fn build_cosmos_connection_conf(
    rpcs: &[Url],
    chain: &ValueParser,
    err: &mut ConfigParsingError,
    operation_batch: OpSubmissionConfig,
    protocol: HyperlaneDomainProtocol,
) -> Option<ChainConnectionConf> {
    let mut local_err = ConfigParsingError::default();
    let grpcs = parse_base_and_override_urls(
        chain,
        "grpcUrls",
        "customGrpcUrls",
        "http",
        &mut local_err,
        false,
    );

    let chain_id = chain
        .chain(&mut local_err)
        .get_key("chainId")
        .parse_string()
        .end()
        .or_else(|| {
            local_err.push(
                (&chain.cwp).add("chain_id"),
                eyre!("Missing chain id for chain"),
            );
            None
        });

    let prefix = chain
        .chain(err)
        .get_key("bech32Prefix")
        .parse_string()
        .end()
        .or_else(|| {
            local_err.push(
                (&chain.cwp).add("bech32Prefix"),
                eyre!("Missing bech32 prefix for chain"),
            );
            None
        });

    let gas_price = chain
        .chain(err)
        .get_opt_key("gasPrice")
        .and_then(parse_cosmos_gas_price)
        .end();

    let contract_address_bytes = chain
        .chain(err)
        .get_opt_key("contractAddressBytes")
        .parse_u64()
        .end();

    let native_token = parse_native_token(chain, err, 18);

    let gas_multiplier = chain
        .chain(err)
        .get_opt_key("gasMultiplier")
        .parse_f64()
        .end()
        .unwrap_or(1.35);

    let compat_mode = chain
        .chain(err)
        .get_opt_key("compatMode")
        .parse_string()
        .end();

    if !local_err.is_ok() {
        err.merge(local_err);
        return None;
    }

    let chain_id = chain_id?;
    let prefix = prefix?;
    let gas_price = gas_price?;
    let contract_address_bytes = contract_address_bytes?;

    let canonical_asset = match chain
        .chain(err)
        .get_opt_key("canonicalAsset")
        .parse_string()
        .end()
    {
        Some(asset) => asset.to_string(),
        None => format!("u{prefix}"),
    };
    let config = h_cosmos::ConnectionConf::new(
        grpcs,
        rpcs.to_owned(),
        chain_id.to_string(),
        prefix.to_string(),
        canonical_asset,
        gas_price,
        contract_address_bytes as usize,
        operation_batch,
        native_token,
        gas_multiplier,
        compat_mode,
    );

    match config {
        Err(e) => {
            err.push((&chain.cwp).add("compatMode"), eyre!(e));
            None
        }
        Ok(config) => match protocol {
            HyperlaneDomainProtocol::Cosmos => Some(ChainConnectionConf::Cosmos(config)),
            HyperlaneDomainProtocol::CosmosNative => {
                Some(ChainConnectionConf::CosmosNative(config))
            }
            _ => None,
        },
    }
}

fn build_starknet_connection_conf(
    urls: &[Url],
    chain: &ValueParser,
    err: &mut ConfigParsingError,
    operation_batch: OpSubmissionConfig,
) -> Option<ChainConnectionConf> {
    let native_token_address = chain
        .chain(err)
        .get_key("nativeToken")
        .get_key("denom")
        .parse_address_hash()
        .end();

    let Some(native_token_address) = native_token_address else {
        err.push(
            (&chain.cwp).add("nativeToken.denom"),
            eyre!("nativeToken denom required"),
        );
        return None;
    };

    Some(ChainConnectionConf::Starknet(h_starknet::ConnectionConf {
        urls: urls.to_vec(),
        native_token_address,
        op_submission_config: operation_batch,
    }))
}

fn build_sealevel_connection_conf(
    urls: &[Url],
    chain: &ValueParser,
    err: &mut ConfigParsingError,
    operation_batch: OpSubmissionConfig,
) -> Option<ChainConnectionConf> {
    let mut local_err = ConfigParsingError::default();

    let native_token = parse_native_token(chain, err, 9);
    let priority_fee_oracle = parse_sealevel_priority_fee_oracle_config(chain, &mut local_err);
    let transaction_submitter = parse_transaction_submitter_config(chain, &mut local_err);

    if !local_err.is_ok() {
        err.merge(local_err);
        return None;
    }

    let priority_fee_oracle = priority_fee_oracle?;
    let transaction_submitter = transaction_submitter?;
    Some(ChainConnectionConf::Sealevel(h_sealevel::ConnectionConf {
        urls: urls.to_owned(),
        op_submission_config: operation_batch,
        native_token,
        priority_fee_oracle,
        transaction_submitter,
    }))
}

fn parse_native_token(
    chain: &ValueParser,
    err: &mut ConfigParsingError,
    default_decimals: u32,
) -> NativeToken {
    let native_token_decimals = chain
        .chain(err)
        .get_opt_key("nativeToken")
        .get_opt_key("decimals")
        .parse_u32()
        .unwrap_or(default_decimals);

    let native_token_denom = chain
        .chain(err)
        .get_opt_key("nativeToken")
        .get_opt_key("denom")
        .parse_string()
        .unwrap_or("");

    NativeToken {
        decimals: native_token_decimals,
        denom: native_token_denom.to_owned(),
    }
}

fn parse_sealevel_priority_fee_oracle_config(
    chain: &ValueParser,
    err: &mut ConfigParsingError,
) -> Option<PriorityFeeOracleConfig> {
    let value_parser = chain.chain(err).get_opt_key("priorityFeeOracle").end();

    let priority_fee_oracle = if let Some(value_parser) = value_parser {
        let oracle_type = value_parser
            .chain(err)
            .get_key("type")
            .parse_string()
            .end()
            .or_else(|| {
                err.push(
                    (&value_parser.cwp).add("type"),
                    eyre!("Missing priority fee oracle type"),
                );
                None
            })
            .unwrap_or_default();

        match oracle_type {
            "constant" => {
                let fee = value_parser
                    .chain(err)
                    .get_key("fee")
                    .parse_u64()
                    .end()
                    .unwrap_or(0);
                Some(PriorityFeeOracleConfig::Constant(fee))
            }
            "helius" => {
                let fee_level = parse_helius_priority_fee_level(&value_parser, err);
                if !err.is_ok() {
                    return None;
                }
                let url: Url = value_parser
                    .chain(err)
                    .get_key("url")
                    .parse_from_str("Invalid url")
                    .end()?;
                let fee_level = fee_level?;
                let config = HeliusPriorityFeeOracleConfig { url, fee_level };
                Some(PriorityFeeOracleConfig::Helius(config))
            }
            _ => {
                err.push(
                    (&value_parser.cwp).add("type"),
                    eyre!("Unknown priority fee oracle type"),
                );
                None
            }
        }
    } else {
        // If not specified at all, use default
        Some(PriorityFeeOracleConfig::default())
    };

    priority_fee_oracle
}

fn parse_helius_priority_fee_level(
    value_parser: &ValueParser,
    err: &mut ConfigParsingError,
) -> Option<HeliusPriorityFeeLevel> {
    let level = value_parser
        .chain(err)
        .get_opt_key("feeLevel")
        .parse_string()
        .end();

    if let Some(level) = level {
        match level.to_lowercase().as_str() {
            "recommended" => Some(HeliusPriorityFeeLevel::Recommended),
            "min" => Some(HeliusPriorityFeeLevel::Min),
            "low" => Some(HeliusPriorityFeeLevel::Low),
            "medium" => Some(HeliusPriorityFeeLevel::Medium),
            "high" => Some(HeliusPriorityFeeLevel::High),
            "veryhigh" => Some(HeliusPriorityFeeLevel::VeryHigh),
            "unsafemax" => Some(HeliusPriorityFeeLevel::UnsafeMax),
            _ => {
                err.push(
                    (&value_parser.cwp).add("fee_level"),
                    eyre!("Unknown priority fee level"),
                );
                None
            }
        }
    } else {
        // If not specified at all, use the default
        Some(HeliusPriorityFeeLevel::default())
    }
}

fn parse_transaction_submitter_config(
    chain: &ValueParser,
    err: &mut ConfigParsingError,
) -> Option<h_sealevel::config::TransactionSubmitterConfig> {
    let submitter_type = chain
        .chain(err)
        .get_opt_key("transactionSubmitter")
        .get_opt_key("type")
        .parse_string()
        .end();

    if let Some(submitter_type) = submitter_type {
        match submitter_type.to_lowercase().as_str() {
            "rpc" => {
                let urls: Vec<String> = chain
                    .chain(err)
                    .get_opt_key("transactionSubmitter")
                    .get_opt_key("urls")
                    .parse_string()
                    .map(|str| str.split(",").map(|s| s.to_owned()).collect())
                    .unwrap_or_default();
                Some(h_sealevel::config::TransactionSubmitterConfig::Rpc { urls })
            }
            "jito" => {
                let urls: Vec<String> = chain
                    .chain(err)
                    .get_opt_key("transactionSubmitter")
                    .get_opt_key("urls")
                    .parse_string()
                    .map(|str| str.split(",").map(|s| s.to_owned()).collect())
                    .unwrap_or_default();
                Some(h_sealevel::config::TransactionSubmitterConfig::Jito { urls })
            }
            _ => {
                err.push(
                    (&chain.cwp).add("transaction_submitter.type"),
                    eyre!("Unknown transaction submitter type"),
                );
                None
            }
        }
    } else {
        // If not specified at all, use default
        Some(h_sealevel::config::TransactionSubmitterConfig::default())
    }
}

fn parse_midl_execution_conf(
    chain: &ValueParser,
    err: &mut ConfigParsingError,
) -> Option<h_midl::MidlExecutionConf> {
    let exec_parser = chain
        .get_opt_key("midlExecution")
        .take_err(err, || (&chain.cwp).add("midlExecution"))
        .flatten();

    let Some(exec_parser) = exec_parser else {
        // No midlExecution config - return None (will use defaults when btcKey signer is present)
        return None;
    };

    let static_metadata = exec_parser
        .get_opt_key("staticMetadata")
        .take_err(err, || (&exec_parser.cwp).add("staticMetadata"))
        .flatten()
        .as_ref()
        .and_then(|parser| parse_static_metadata(parser, err));

    let btc_fee_rate_sat_per_vbyte = exec_parser
        .chain(err)
        .get_opt_key("btcFeeRateSatPerVbyte")
        .parse_u64()
        .end();

    let mempool_url = exec_parser
        .chain(err)
        .get_opt_key("mempoolUrl")
        .parse_string()
        .end()
        .map(|s| s.to_owned());

    let use_electrs_api = exec_parser
        .chain(err)
        .get_opt_key("useElectrsApi")
        .parse_bool()
        .end();

    let min_confirmations = exec_parser
        .chain(err)
        .get_opt_key("minConfirmations")
        .parse_u64()
        .end();

    // Return config if any field is specified
    Some(h_midl::MidlExecutionConf {
        static_metadata,
        btc_fee_rate_sat_per_vbyte,
        mempool_url,
        use_electrs_api,
        min_confirmations,
    })
}

fn parse_static_metadata(
    parser: &ValueParser,
    err: &mut ConfigParsingError,
) -> Option<h_midl::MidlStaticMetadata> {
    let btc_tx_hash = parser
        .chain(err)
        .get_key("btcTxHash")
        .parse_string()
        .end()
        .and_then(|value| {
            hex_or_base58_or_bech32_to_h256(value)
                .map_err(|e| err.push((&parser.cwp).add("btcTxHash"), eyre!(e)))
                .ok()
        })?;

    let btc_transaction = parse_bytes_field(parser, "btcTransaction", err)?;
    let public_key = parse_bytes_field(parser, "publicKey", err)?;

    if public_key.len() != 32 {
        err.push(
            (&parser.cwp).add("publicKey"),
            eyre!("expected 32-byte public key"),
        );
        return None;
    }

    let btc_address_byte = parser
        .chain(err)
        .get_key("btcAddressByte")
        .parse_u256()
        .end()?;

    Some(h_midl::MidlStaticMetadata {
        btc_tx_hash,
        btc_transaction,
        public_key,
        btc_address_byte,
    })
}

fn parse_bytes_field(
    parser: &ValueParser,
    key: &str,
    err: &mut ConfigParsingError,
) -> Option<Bytes> {
    let value = parser.chain(err).get_key(key).parse_string().end()?;
    let raw = value.strip_prefix("0x").unwrap_or(value);
    match hex::decode(raw) {
        Ok(bytes) => Some(Bytes::from(bytes)),
        Err(e) => {
            err.push((&parser.cwp).add(key), eyre!("invalid hex: {e}"));
            None
        }
    }
}

fn parse_midl_finality_conf(
    chain: &ValueParser,
    err: &mut ConfigParsingError,
) -> Option<h_midl::MidlFinalityConf> {
    let parser = chain
        .get_opt_key("midlFinality")
        .take_err(err, || (&chain.cwp).add("midlFinality"))
        .flatten()?;

    let btc_confirmations = parser
        .chain(err)
        .get_opt_key("btcConfirmations")
        .parse_u64()
        .end()
        .unwrap_or(6)
        .max(1);

    Some(h_midl::MidlFinalityConf { btc_confirmations })
}

pub fn build_radix_connection_conf(
    rpcs: &[Url],
    chain: &ValueParser,
    err: &mut ConfigParsingError,
    _operation_batch: OpSubmissionConfig,
) -> Option<ChainConnectionConf> {
    let mut local_err = ConfigParsingError::default();
    let gateway_urls = parse_base_and_override_urls(
        chain,
        "gatewayUrls",
        "customGatewayUrls",
        "http",
        &mut local_err,
        false,
    );

    let network_name = chain
        .chain(&mut local_err)
        .get_key("networkName")
        .parse_string()
        .end()
        .or_else(|| {
            local_err.push(
                (&chain.cwp).add("network_name"),
                eyre!("Missing network name for chain"),
            );
            None
        });

    if !local_err.is_ok() {
        err.merge(local_err);
        None
    } else {
        Some(ChainConnectionConf::Radix(
            hyperlane_radix::ConnectionConf::new(
                rpcs.to_vec(),
                gateway_urls,
                network_name?.to_string(),
            ),
        ))
    }
}

pub fn build_aleo_connection_conf(
    rpcs: &[Url],
    chain: &ValueParser,
    err: &mut ConfigParsingError,
    _operation_batch: OpSubmissionConfig,
) -> Option<ChainConnectionConf> {
    let mut local_err = ConfigParsingError::default();

    let mailbox_program = chain
        .chain(&mut local_err)
        .get_key("mailboxProgram")
        .parse_string()
        .end()
        .or_else(|| {
            local_err.push(
                (&chain.cwp).add("mailbox_program"),
                eyre!("Missing mailbox_program for chain"),
            );
            None
        });

    let hook_manager_program = chain
        .chain(&mut local_err)
        .get_key("hookManagerProgram")
        .parse_string()
        .end()
        .or_else(|| {
            local_err.push(
                (&chain.cwp).add("hook_manager_program"),
                eyre!("Missing hook_manager_program for chain"),
            );
            None
        });
    let ism_manager_program = chain
        .chain(&mut local_err)
        .get_key("ismManagerProgram")
        .parse_string()
        .end()
        .or_else(|| {
            local_err.push(
                (&chain.cwp).add("ism_manager_program"),
                eyre!("Missing ism_manager_program for chain"),
            );
            None
        });
    let validator_announce_program = chain
        .chain(&mut local_err)
        .get_key("validatorAnnounceProgram")
        .parse_string()
        .end()
        .or_else(|| {
            local_err.push(
                (&chain.cwp).add("validator_announce_program"),
                eyre!("Missing validator_announce_program for chain"),
            );
            None
        });

    let chain_id = chain
        .chain(err)
        .get_opt_key("chainId")
        .parse_u16()
        .end()
        .or_else(|| {
            local_err.push(
                (&chain.cwp).add("chain_id"),
                eyre!("Missing chain_id for chain"),
            );
            None
        });

    let consensus_heights = chain
        .chain(err)
        .get_opt_key("consensusHeights")
        .into_array_iter()
        .map(|value| {
            value
                .map(|x| x.parse_u32())
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_default()
        });

    let priority_fee_multiplier = chain
        .chain(err)
        .get_opt_key("priorityFeeMultiplier")
        .parse_f64()
        .end();

    let proving_service_urls = parse_base_and_override_urls(
        chain,
        "provingServiceUrls",
        "customProvingServiceUrls",
        "http",
        &mut local_err,
        true,
    );

    if !local_err.is_ok() {
        err.merge(local_err);
        None
    } else {
        Some(ChainConnectionConf::Aleo(
            hyperlane_aleo::ConnectionConf::new(
                rpcs.to_vec(),
                mailbox_program?.to_string(),
                hook_manager_program?.to_string(),
                ism_manager_program?.to_string(),
                validator_announce_program?.to_string(),
                chain_id?,
                consensus_heights,
                proving_service_urls,
                priority_fee_multiplier.unwrap_or_default(),
            ),
        ))
    }
}

pub fn build_connection_conf(
    domain_protocol: HyperlaneDomainProtocol,
    rpcs: &[Url],
    chain: &ValueParser,
    err: &mut ConfigParsingError,
    default_rpc_consensus_type: &str,
    operation_batch: OpSubmissionConfig,
) -> Option<ChainConnectionConf> {
    match domain_protocol {
        HyperlaneDomainProtocol::Ethereum => build_ethereum_connection_conf(
            rpcs,
            chain,
            err,
            default_rpc_consensus_type,
            operation_batch,
        ),
        HyperlaneDomainProtocol::Midl => build_midl_connection_conf(
            rpcs,
            chain,
            err,
            default_rpc_consensus_type,
            operation_batch,
        ),
        HyperlaneDomainProtocol::Fuel => rpcs
            .iter()
            .next()
            .map(|url| ChainConnectionConf::Fuel(h_fuel::ConnectionConf { url: url.clone() })),
        HyperlaneDomainProtocol::Sealevel => {
            let urls = rpcs.to_vec();
            build_sealevel_connection_conf(&urls, chain, err, operation_batch)
        }
        HyperlaneDomainProtocol::Cosmos | HyperlaneDomainProtocol::CosmosNative => {
            build_cosmos_connection_conf(rpcs, chain, err, operation_batch, domain_protocol)
        }
        HyperlaneDomainProtocol::Starknet => {
            build_starknet_connection_conf(rpcs, chain, err, operation_batch)
        }
        HyperlaneDomainProtocol::Radix => {
            build_radix_connection_conf(rpcs, chain, err, operation_batch)
        }
        HyperlaneDomainProtocol::Aleo => {
            build_aleo_connection_conf(rpcs, chain, err, operation_batch)
        }
    }
}
