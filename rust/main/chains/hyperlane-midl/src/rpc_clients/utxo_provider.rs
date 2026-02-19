//! UTXO provider implementations for Bitcoin transaction building.
//!
//! This module provides implementations of the `UtxoProvider` trait that fetch
//! UTXOs from various sources like mempool.space-compatible APIs.

use async_trait::async_trait;
use hyperlane_core::ChainCommunicationError;
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, warn};

use super::tx_rewrite_middleware::{BtcUtxo, UtxoProvider};

/// Response format for UTXO status from mempool API.
#[derive(Debug, Deserialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
}

/// Response format for a single UTXO from mempool API.
#[derive(Debug, Deserialize)]
pub struct MempoolUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

/// A UTXO provider that fetches UTXOs from a mempool.space-compatible API.
///
/// This provider supports any API that implements the mempool.space UTXO endpoint:
/// `GET /api/address/{address}/utxo`
///
/// Compatible services include:
/// - mempool.space (public) - uses `/api` prefix
/// - Self-hosted mempool backend - uses `/api` prefix
/// - Electrs with HTTP API - no prefix (set `api_prefix` to empty string)
pub struct MempoolUtxoProvider {
    client: Client,
    base_url: String,
    bitcoin_address: String,
    /// Minimum confirmations required for a UTXO to be considered spendable
    min_confirmations: u64,
    /// API path prefix (e.g., "/api" for mempool.space, "" for electrs)
    api_prefix: String,
}

impl MempoolUtxoProvider {
    /// Create a new MempoolUtxoProvider for mempool.space-compatible APIs.
    ///
    /// # Arguments
    /// * `base_url` - The base URL of the mempool API (e.g., "https://mempool.space")
    /// * `bitcoin_address` - The Bitcoin address to fetch UTXOs for
    /// * `min_confirmations` - Minimum confirmations required (default: 1)
    pub fn new(base_url: String, bitcoin_address: String, min_confirmations: u64) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            bitcoin_address,
            min_confirmations,
            api_prefix: "/api".to_string(),
        }
    }

    /// Create a new MempoolUtxoProvider for electrs HTTP API.
    ///
    /// Electrs uses the same response format but without the `/api` prefix.
    ///
    /// # Arguments
    /// * `base_url` - The base URL of the electrs API (e.g., "http://localhost:3002")
    /// * `bitcoin_address` - The Bitcoin address to fetch UTXOs for
    /// * `min_confirmations` - Minimum confirmations required (default: 1)
    pub fn new_electrs(base_url: String, bitcoin_address: String, min_confirmations: u64) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            bitcoin_address,
            min_confirmations,
            api_prefix: String::new(),
        }
    }

    /// Fetch all UTXOs for the configured address.
    async fn fetch_utxos(&self) -> Result<Vec<MempoolUtxo>, ChainCommunicationError> {
        let url = format!(
            "{}{}/address/{}/utxo",
            self.base_url, self.api_prefix, self.bitcoin_address
        );

        debug!(url = %url, "Fetching UTXOs from mempool API");

        let response = self.client.get(&url).send().await.map_err(|e| {
            ChainCommunicationError::CustomError(format!("Failed to fetch UTXOs: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(ChainCommunicationError::CustomError(format!(
                "Mempool API returned error: {}",
                response.status()
            )));
        }

        let utxos: Vec<MempoolUtxo> = response.json().await.map_err(|e| {
            ChainCommunicationError::CustomError(format!("Failed to parse UTXO response: {}", e))
        })?;

        debug!(count = utxos.len(), "Fetched UTXOs from mempool API");

        Ok(utxos)
    }

    /// Get the current block height from the mempool API.
    async fn get_block_height(&self) -> Result<u64, ChainCommunicationError> {
        let url = format!("{}{}/blocks/tip/height", self.base_url, self.api_prefix);

        let response = self.client.get(&url).send().await.map_err(|e| {
            ChainCommunicationError::CustomError(format!("Failed to fetch block height: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(ChainCommunicationError::CustomError(format!(
                "Mempool API returned error: {}",
                response.status()
            )));
        }

        let height: u64 = response.json().await.map_err(|e| {
            ChainCommunicationError::CustomError(format!("Failed to parse block height: {}", e))
        })?;

        Ok(height)
    }

    /// Convert a hex string to a 32-byte array (reversed for Bitcoin txid).
    fn hex_to_txid(hex: &str) -> Result<[u8; 32], ChainCommunicationError> {
        let bytes = hex::decode(hex).map_err(|e| {
            ChainCommunicationError::CustomError(format!("Invalid txid hex: {}", e))
        })?;

        if bytes.len() != 32 {
            return Err(ChainCommunicationError::CustomError(format!(
                "Invalid txid length: expected 32, got {}",
                bytes.len()
            )));
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        // Note: We don't reverse here - the BTC transaction builder handles endianness
        Ok(result)
    }
}

impl std::fmt::Debug for MempoolUtxoProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MempoolUtxoProvider")
            .field("base_url", &self.base_url)
            .field("api_prefix", &self.api_prefix)
            .field("bitcoin_address", &self.bitcoin_address)
            .field("min_confirmations", &self.min_confirmations)
            .finish()
    }
}

#[async_trait]
impl UtxoProvider for MempoolUtxoProvider {
    async fn get_utxos(
        &self,
        min_total_value: u64,
    ) -> Result<Vec<BtcUtxo>, ChainCommunicationError> {
        let utxos = self.fetch_utxos().await?;
        let current_height = self.get_block_height().await?;

        // Filter for confirmed UTXOs with enough confirmations, sort by value descending
        let mut confirmed: Vec<MempoolUtxo> = utxos
            .into_iter()
            .filter(|utxo| {
                if !utxo.status.confirmed {
                    return false;
                }
                let confirmations = utxo
                    .status
                    .block_height
                    .map(|h| current_height.saturating_sub(h) + 1)
                    .unwrap_or(0);
                confirmations >= self.min_confirmations
            })
            .collect();
        confirmed.sort_by(|a, b| b.value.cmp(&a.value));

        // Accumulate UTXOs until their sum >= min_total_value
        let mut selected = Vec::new();
        let mut total: u64 = 0;
        for utxo in confirmed {
            total = total.saturating_add(utxo.value);
            debug!(
                txid = %utxo.txid,
                vout = utxo.vout,
                value = utxo.value,
                running_total = total,
                "Selected UTXO for transaction"
            );
            selected.push(BtcUtxo {
                tx_hash: Self::hex_to_txid(&utxo.txid)?,
                vout: utxo.vout,
                value: utxo.value,
                script_pubkey: vec![], // Will be filled by the transaction builder
            });
            if total >= min_total_value {
                break;
            }
        }

        if total < min_total_value {
            warn!(
                address = %self.bitcoin_address,
                min_total_value = min_total_value,
                available = total,
                min_confirmations = self.min_confirmations,
                "Insufficient confirmed balance across all UTXOs"
            );
            return Err(ChainCommunicationError::CustomError(format!(
                "Insufficient balance: need {} satoshis but only {} available across {} UTXOs with {} confirmations for address {}",
                min_total_value, total, selected.len(), self.min_confirmations, self.bitcoin_address
            )));
        }

        debug!(
            count = selected.len(),
            total_value = total,
            min_total_value = min_total_value,
            "Selected UTXOs for transaction"
        );

        Ok(selected)
    }
}

/// Fee rate response from mempool API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeRateResponse {
    pub fastest_fee: u64,
    pub half_hour_fee: u64,
    pub hour_fee: u64,
    pub economy_fee: u64,
    pub minimum_fee: u64,
}

/// Fetch the recommended fee rate from a mempool API.
pub async fn fetch_fee_rate(base_url: &str) -> Result<FeeRateResponse, ChainCommunicationError> {
    let client = Client::new();
    let url = format!("{}/api/v1/fees/recommended", base_url.trim_end_matches('/'));

    let response = client.get(&url).send().await.map_err(|e| {
        ChainCommunicationError::CustomError(format!("Failed to fetch fee rate: {}", e))
    })?;

    if !response.status().is_success() {
        return Err(ChainCommunicationError::CustomError(format!(
            "Mempool API returned error: {}",
            response.status()
        )));
    }

    response.json().await.map_err(|e| {
        ChainCommunicationError::CustomError(format!("Failed to parse fee rate: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_txid() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let result = MempoolUtxoProvider::hex_to_txid(hex).unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(result[0], 0x01);
        assert_eq!(result[31], 0x20);
    }

    #[test]
    fn test_hex_to_txid_invalid_length() {
        let hex = "0102030405";
        let result = MempoolUtxoProvider::hex_to_txid(hex);
        assert!(result.is_err());
    }
}
