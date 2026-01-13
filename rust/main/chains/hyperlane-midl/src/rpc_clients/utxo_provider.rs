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
/// - mempool.space (public)
/// - Self-hosted mempool backend
/// - Electrs with HTTP API
pub struct MempoolUtxoProvider {
    client: Client,
    base_url: String,
    bitcoin_address: String,
    /// Minimum confirmations required for a UTXO to be considered spendable
    min_confirmations: u64,
}

impl MempoolUtxoProvider {
    /// Create a new MempoolUtxoProvider.
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
        }
    }

    /// Fetch all UTXOs for the configured address.
    async fn fetch_utxos(&self) -> Result<Vec<MempoolUtxo>, ChainCommunicationError> {
        let url = format!(
            "{}/api/address/{}/utxo",
            self.base_url, self.bitcoin_address
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
        let url = format!("{}/api/blocks/tip/height", self.base_url);

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
            .field("bitcoin_address", &self.bitcoin_address)
            .field("min_confirmations", &self.min_confirmations)
            .finish()
    }
}

#[async_trait]
impl UtxoProvider for MempoolUtxoProvider {
    async fn get_utxo(&self, min_value: u64) -> Result<BtcUtxo, ChainCommunicationError> {
        let utxos = self.fetch_utxos().await?;
        let current_height = self.get_block_height().await?;

        // Filter UTXOs by confirmation count and find one with sufficient value
        let suitable_utxo = utxos
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
                confirmations >= self.min_confirmations && utxo.value >= min_value
            })
            .max_by_key(|utxo| utxo.value);

        match suitable_utxo {
            Some(utxo) => {
                debug!(
                    txid = %utxo.txid,
                    vout = utxo.vout,
                    value = utxo.value,
                    "Selected UTXO for transaction"
                );

                Ok(BtcUtxo {
                    tx_hash: Self::hex_to_txid(&utxo.txid)?,
                    vout: utxo.vout,
                    value: utxo.value,
                    script_pubkey: vec![], // Will be filled by the transaction builder
                })
            }
            None => {
                warn!(
                    address = %self.bitcoin_address,
                    min_value = min_value,
                    min_confirmations = self.min_confirmations,
                    "No suitable UTXO found"
                );
                Err(ChainCommunicationError::CustomError(format!(
                    "No UTXO found with at least {} satoshis and {} confirmations for address {}",
                    min_value, self.min_confirmations, self.bitcoin_address
                )))
            }
        }
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
