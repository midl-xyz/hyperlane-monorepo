//! BTC transaction status client for checking Bitcoin confirmations.
//!
//! Used by the MIDL finality checker to determine whether a MIDL block's
//! associated Bitcoin transaction has enough confirmations.

use hyperlane_core::ChainCommunicationError;
use reqwest::Client;
use serde::Deserialize;
use tracing::debug;

/// BTC transaction confirmation status from the mempool/electrs API.
#[derive(Debug, Deserialize)]
pub struct BtcTxStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
}

/// Client for querying BTC transaction confirmation status via mempool.space API.
pub struct BtcTxStatusClient {
    client: Client,
    base_url: String,
}

impl std::fmt::Debug for BtcTxStatusClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtcTxStatusClient")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl BtcTxStatusClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Get the current BTC block tip height.
    pub async fn get_btc_tip_height(&self) -> Result<u64, ChainCommunicationError> {
        let url = format!("{}/api/blocks/tip/height", self.base_url);

        let response = self.client.get(&url).send().await.map_err(|e| {
            ChainCommunicationError::CustomError(format!("Failed to fetch BTC tip height: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(ChainCommunicationError::CustomError(format!(
                "BTC tip height API returned error: {}",
                response.status()
            )));
        }

        response.json().await.map_err(|e| {
            ChainCommunicationError::CustomError(format!("Failed to parse BTC tip height: {}", e))
        })
    }

    /// Get the confirmation status for a BTC transaction.
    /// Returns `None` if the transaction is not found (404).
    pub async fn get_tx_status(
        &self,
        btc_tx_hash: &str,
    ) -> Result<Option<BtcTxStatus>, ChainCommunicationError> {
        let url = format!("{}/api/tx/{}/status", self.base_url, btc_tx_hash);

        debug!(url = %url, btc_tx_hash, "Checking BTC tx status");

        let response = self.client.get(&url).send().await.map_err(|e| {
            ChainCommunicationError::CustomError(format!(
                "Failed to fetch BTC tx status for {}: {}",
                btc_tx_hash, e
            ))
        })?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(ChainCommunicationError::CustomError(format!(
                "BTC tx status API returned error for {}: {}",
                btc_tx_hash,
                response.status()
            )));
        }

        let status: BtcTxStatus = response.json().await.map_err(|e| {
            ChainCommunicationError::CustomError(format!(
                "Failed to parse BTC tx status for {}: {}",
                btc_tx_hash, e
            ))
        })?;

        Ok(Some(status))
    }

    /// Returns the number of confirmations for a BTC transaction,
    /// or 0 if the transaction is unconfirmed or not found.
    pub async fn get_tx_confirmations(
        &self,
        btc_tx_hash: &str,
    ) -> Result<u64, ChainCommunicationError> {
        let tip = self.get_btc_tip_height().await?;
        match self.get_tx_status(btc_tx_hash).await? {
            Some(status) if status.confirmed => Ok(status
                .block_height
                .map(|h| tip.saturating_sub(h) + 1)
                .unwrap_or(0)),
            _ => Ok(0),
        }
    }
}
