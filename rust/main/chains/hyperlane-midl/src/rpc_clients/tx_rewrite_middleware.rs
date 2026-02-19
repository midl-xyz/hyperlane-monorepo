use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::blockdata::script::{Builder as ScriptBuilder, ScriptBuf};
use bitcoin::blockdata::transaction::{OutPoint, Sequence, Transaction, TxIn, TxOut, Version};
use bitcoin::blockdata::witness::Witness;
use bitcoin::consensus::encode as btc_encode;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Amount, EcdsaSighashType, TapSighashType, Txid, WPubkeyHash};
use ethers::prelude::FromErr;
use ethers::providers::{Middleware, PendingTransaction};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::transaction::midl::MidlTransactionRequest;
use ethers::types::{Address, Bytes, TransactionRequest, U256};
use ethers_core::utils::rlp;
use ethers_signers::Signer;
use hyperlane_core::{ChainCommunicationError, H256};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Key for caching MIDL metadata: (to_address, nonce)
/// We use `to` instead of `from` because `from` requires signature recovery,
/// which fails for MIDL transactions that use BIP322/BIP143 signatures.
type TxKey = (Option<ethers::types::Address>, U256);

/// Metadata required to convert an EVM write into a Midl submission.
#[derive(Clone, Debug)]
pub struct MidlPreparedMetadata {
    pub btc_tx_hash: H256,
    pub btc_transaction: ethers::types::Bytes,
    pub public_key: ethers::types::Bytes,
    pub btc_address_byte: U256,
}

#[async_trait]
pub trait MidlMetadataProvider: Send + Sync {
    async fn prepare_metadata(
        &self,
        tx: &TypedTransaction,
    ) -> Result<MidlPreparedMetadata, ChainCommunicationError>;
}

/// Static provider that always returns the same metadata blob. Useful for tests
/// or environments where another agent handles BTC lifecycle management.
#[derive(Clone, Debug)]
pub struct StaticMidlMetadataProvider {
    metadata: MidlPreparedMetadata,
}

impl StaticMidlMetadataProvider {
    pub fn new(metadata: MidlPreparedMetadata) -> Self {
        Self { metadata }
    }
}

#[async_trait]
impl MidlMetadataProvider for StaticMidlMetadataProvider {
    async fn prepare_metadata(
        &self,
        _tx: &TypedTransaction,
    ) -> Result<MidlPreparedMetadata, ChainCommunicationError> {
        Ok(self.metadata.clone())
    }
}

/// A UTXO (Unspent Transaction Output) for Bitcoin transaction building.
#[derive(Clone, Debug)]
pub struct BtcUtxo {
    /// The transaction hash containing this UTXO
    pub tx_hash: [u8; 32],
    /// The output index within the transaction
    pub vout: u32,
    /// The value in satoshis
    pub value: u64,
    /// The script pubkey (locking script)
    pub script_pubkey: Vec<u8>,
}

/// Trait for providing UTXOs for Bitcoin transaction building.
#[async_trait]
pub trait UtxoProvider: Send + Sync {
    /// Get UTXOs whose total value is at least `min_total_value` satoshis.
    /// Returns a vector of UTXOs selected using largest-first accumulation.
    async fn get_utxos(
        &self,
        min_total_value: u64,
    ) -> Result<Vec<BtcUtxo>, ChainCommunicationError>;
}

/// GlobalParams contract address for fetching TSS address
static GLOBAL_PARAMS_CONTRACT: std::sync::LazyLock<Address> = std::sync::LazyLock::new(|| {
    Address::from_str("0x0000000000000000000000000000000000001006")
        .expect("Invalid GLOBAL_PARAMS_CONTRACT address")
});

/// Function selector for getTSSAddress() - 0x15b0162f
const GET_TSS_ADDRESS_SELECTOR: [u8; 4] = [0x15, 0xb0, 0x16, 0x2f];

/// Convert a BtcUtxo to a bitcoin::OutPoint.
/// BtcUtxo.tx_hash is in display order (big-endian hex from API).
/// bitcoin::Txid uses internal byte order (little-endian).
fn btcutxo_to_outpoint(utxo: &BtcUtxo) -> OutPoint {
    let mut internal_bytes = utxo.tx_hash;
    internal_bytes.reverse(); // display order → internal order
    OutPoint::new(Txid::from_byte_array(internal_bytes), utxo.vout)
}

/// Build a P2TR scriptPubKey from a raw (untweaked) x-only public key.
///
/// We do NOT use `ScriptBuf::new_p2tr()` because both TSS and signer P2TR
/// scripts use raw untweaked x-only pubkeys. `new_p2tr` applies BIP341 key tweaking.
fn build_p2tr_script_untweaked(x_only_pubkey: &[u8; 32]) -> ScriptBuf {
    ScriptBuilder::new()
        .push_opcode(opcodes::OP_PUSHNUM_1)
        .push_slice(x_only_pubkey)
        .into_script()
}

/// Build an unsigned bitcoin::Transaction from UTXOs and outputs.
///
/// Creates a transaction with empty witnesses containing:
/// - One input per UTXO
/// - Output 0: TSS output (P2TR to TSS taproot address)
/// - Output 1: OP_RETURN with EVM tx hash
/// - Output 2: Change output (if change_value > 0)
fn build_unsigned_tx(
    utxos: &[BtcUtxo],
    tss_pubkey: &[u8; 32],
    tss_value: u64,
    change_value: u64,
    change_script: &ScriptBuf,
    evm_tx_hash: &[u8; 32],
) -> Transaction {
    let inputs: Vec<TxIn> = utxos
        .iter()
        .map(|utxo| TxIn {
            previous_output: btcutxo_to_outpoint(utxo),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX, // 0xffffffff — final, no RBF
            witness: Witness::default(),
        })
        .collect();

    let mut outputs = Vec::with_capacity(3);

    // Output 0: TSS output (P2TR)
    outputs.push(TxOut {
        value: Amount::from_sat(tss_value),
        script_pubkey: build_p2tr_script_untweaked(tss_pubkey),
    });

    // Output 1: OP_RETURN with EVM transaction hash
    let op_return_script = ScriptBuilder::new()
        .push_opcode(opcodes::OP_RETURN)
        .push_slice(evm_tx_hash)
        .into_script();
    outputs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: op_return_script,
    });

    // Output 2: Change output (if there's change)
    if change_value > 0 {
        outputs.push(TxOut {
            value: Amount::from_sat(change_value),
            script_pubkey: change_script.clone(),
        });
    }

    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

/// Provider that uses a BtcSigner to create MIDL metadata dynamically.
///
/// This provider builds Bitcoin transactions to fund MIDL EVM transactions.
/// It requires a UTXO provider to supply the inputs for BTC transactions.
pub struct BtcSignerMidlMetadataProvider {
    signer: crate::signer::BtcSigner,
    utxo_provider: Arc<dyn UtxoProvider>,
    /// Default fee rate in satoshis per vbyte (used if dynamic fetch fails)
    default_fee_rate: u64,
    /// Optional mempool URL for dynamic fee estimation
    mempool_url: Option<String>,
    provider: ethers::providers::Provider<ethers::providers::Http>,
    /// Cached TSS x-only public key (32 bytes)
    tss_pubkey: tokio::sync::OnceCell<[u8; 32]>,
}

impl BtcSignerMidlMetadataProvider {
    /// Create a new BtcSignerMidlMetadataProvider.
    ///
    /// # Arguments
    /// * `signer` - The BtcSigner to use for signing
    /// * `utxo_provider` - Provider for UTXOs to spend
    /// * `default_fee_rate` - Default fee rate in satoshis per virtual byte
    /// * `provider` - Ethers provider for fetching TSS address
    pub fn new(
        signer: crate::signer::BtcSigner,
        utxo_provider: Arc<dyn UtxoProvider>,
        default_fee_rate: u64,
        provider: ethers::providers::Provider<ethers::providers::Http>,
    ) -> Self {
        Self {
            signer,
            utxo_provider,
            default_fee_rate,
            mempool_url: None,
            provider,
            tss_pubkey: tokio::sync::OnceCell::new(),
        }
    }

    /// Create a new BtcSignerMidlMetadataProvider with dynamic fee estimation.
    ///
    /// # Arguments
    /// * `signer` - The BtcSigner to use for signing
    /// * `utxo_provider` - Provider for UTXOs to spend
    /// * `default_fee_rate` - Default fee rate (fallback if API fails)
    /// * `mempool_url` - URL for mempool API to fetch fee rates
    /// * `provider` - Ethers provider for fetching TSS address
    pub fn with_mempool_url(
        signer: crate::signer::BtcSigner,
        utxo_provider: Arc<dyn UtxoProvider>,
        default_fee_rate: u64,
        mempool_url: String,
        provider: ethers::providers::Provider<ethers::providers::Http>,
    ) -> Self {
        Self {
            signer,
            utxo_provider,
            default_fee_rate,
            mempool_url: Some(mempool_url),
            provider,
            tss_pubkey: tokio::sync::OnceCell::new(),
        }
    }

    /// Fetch the TSS x-only public key from GlobalParams contract.
    /// The result is cached after the first successful fetch.
    async fn get_tss_pubkey(&self) -> Result<[u8; 32], ChainCommunicationError> {
        self.tss_pubkey
            .get_or_try_init(|| async { self.fetch_tss_pubkey_from_contract().await })
            .await
            .copied()
    }

    /// Fetch TSS address from GlobalParams contract via eth_call.
    async fn fetch_tss_pubkey_from_contract(&self) -> Result<[u8; 32], ChainCommunicationError> {
        use ethers::providers::Middleware as _;

        let tx = TransactionRequest::new()
            .to(*GLOBAL_PARAMS_CONTRACT)
            .data(Bytes::from(GET_TSS_ADDRESS_SELECTOR.to_vec()));

        let result_bytes = self.provider.call(&tx.into(), None).await.map_err(|e| {
            ChainCommunicationError::CustomError(format!(
                "Failed to fetch TSS address from GlobalParams: {}",
                e
            ))
        })?;

        // bytes32 = 32 bytes
        if result_bytes.len() != 32 {
            return Err(ChainCommunicationError::CustomError(format!(
                "Invalid TSS address length: expected 32 bytes, got {}",
                result_bytes.len()
            )));
        }

        let mut tss_pubkey = [0u8; 32];
        tss_pubkey.copy_from_slice(&result_bytes);

        info!(
            tss_pubkey = %hex::encode(&tss_pubkey),
            "Fetched TSS x-only public key from GlobalParams contract"
        );

        Ok(tss_pubkey)
    }

    /// Fetch the current fee rate from mempool API or use default.
    async fn get_fee_rate(&self) -> u64 {
        if let Some(url) = &self.mempool_url {
            match crate::rpc_clients::fetch_fee_rate(url).await {
                Ok(rates) => {
                    // Use half_hour_fee for a balance of speed and cost
                    debug!(
                        fastest = rates.fastest_fee,
                        half_hour = rates.half_hour_fee,
                        hour = rates.hour_fee,
                        "Fetched fee rates from mempool API"
                    );
                    rates.half_hour_fee
                }
                Err(e) => {
                    warn!(error = %e, default = self.default_fee_rate, "Failed to fetch fee rate, using default");
                    self.default_fee_rate
                }
            }
        } else {
            self.default_fee_rate
        }
    }

    /// Sign a hash using BIP340 Schnorr signature (for Taproot).
    ///
    /// Returns a 64-byte Schnorr signature.
    fn sign_schnorr(&self, hash: &[u8; 32]) -> Result<[u8; 64], ChainCommunicationError> {
        use k256::schnorr::{signature::Signer, SigningKey as SchnorrSigningKey};

        // Get the raw private key bytes from our signer
        // The BtcSigner internally uses k256::ecdsa::SigningKey
        // We need to create a Schnorr signing key from the same secret
        let secret_bytes = self.signer.signing_key_bytes();
        let schnorr_key = SchnorrSigningKey::from_bytes(&secret_bytes).map_err(|e| {
            ChainCommunicationError::CustomError(format!(
                "Failed to create Schnorr signing key: {}",
                e
            ))
        })?;

        let signature = schnorr_key.sign(hash);
        let sig_bytes: [u8; 64] = signature.to_bytes().into();
        Ok(sig_bytes)
    }
}

impl std::fmt::Debug for BtcSignerMidlMetadataProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtcSignerMidlMetadataProvider")
            .field("signer_address", &self.signer.address())
            .field("default_fee_rate", &self.default_fee_rate)
            .field("mempool_url", &self.mempool_url)
            .finish()
    }
}

/// Base transaction vsize: version + marker/flag + output count + 3 outputs
/// (TSS P2TR + OP_RETURN + change) + locktime.
const BASE_VSIZE: u64 = 120;
/// Per-input vsize for P2WPKH (witness v0) inputs.
const P2WPKH_INPUT_VSIZE: u64 = 68;
/// Per-input vsize for P2TR (witness v1 / Taproot) inputs.
const P2TR_INPUT_VSIZE: u64 = 58;

#[async_trait]
impl MidlMetadataProvider for BtcSignerMidlMetadataProvider {
    async fn prepare_metadata(
        &self,
        tx: &TypedTransaction,
    ) -> Result<MidlPreparedMetadata, ChainCommunicationError> {
        use crate::signer::BtcAddressType;

        // Fetch the TSS x-only public key from GlobalParams contract
        let tss_pubkey = self.get_tss_pubkey().await?;

        // Get dynamic fee rate from mempool API (or use default)
        let fee_rate = self.get_fee_rate().await;

        // Determine address type
        let address_type = self.signer.address_type();
        let is_taproot = matches!(address_type, BtcAddressType::P2TR);

        let per_input_vsize = if is_taproot {
            P2TR_INPUT_VSIZE
        } else {
            P2WPKH_INPUT_VSIZE
        };

        // Dust threshold (546 satoshis for standard outputs)
        const DUST_THRESHOLD: u64 = 546;

        // TSS funding value - minimum dust threshold for the TSS output
        let tss_value = DUST_THRESHOLD;

        // Initial fee estimate assuming 1 input
        let initial_fee = BASE_VSIZE
            .saturating_add(per_input_vsize)
            .saturating_mul(fee_rate);

        // Total required: fee + TSS value + potential change dust
        let min_utxo_value = initial_fee
            .saturating_add(tss_value)
            .saturating_add(DUST_THRESHOLD);
        let utxos = self.utxo_provider.get_utxos(min_utxo_value).await?;

        // Re-estimate fee based on actual input count
        let num_inputs = utxos.len() as u64;
        let actual_vsize = BASE_VSIZE.saturating_add(num_inputs.saturating_mul(per_input_vsize));
        let actual_fee = actual_vsize.saturating_mul(fee_rate);

        // If extra inputs increased the fee, we may need more UTXOs.
        // Re-fetch only if the current total is now insufficient.
        let total_utxo_value: u64 = utxos.iter().map(|u| u.value).sum();
        let min_required = actual_fee
            .saturating_add(tss_value)
            .saturating_add(DUST_THRESHOLD);

        let (utxos, total_utxo_value, actual_fee) = if total_utxo_value < min_required {
            // Need more UTXOs to cover the higher fee
            let utxos = self.utxo_provider.get_utxos(min_required).await?;
            let num_inputs = utxos.len() as u64;
            let vsize = BASE_VSIZE.saturating_add(num_inputs.saturating_mul(per_input_vsize));
            let fee = vsize.saturating_mul(fee_rate);
            let total: u64 = utxos.iter().map(|u| u.value).sum();
            (utxos, total, fee)
        } else {
            (utxos, total_utxo_value, actual_fee)
        };

        // Calculate change (if above dust threshold)
        let total_output_without_change = tss_value.saturating_add(actual_fee);
        let change_value =
            if total_utxo_value > total_output_without_change.saturating_add(DUST_THRESHOLD) {
                total_utxo_value.saturating_sub(total_output_without_change)
            } else {
                0 // No change output - remaining goes to fee
            };

        // Compute the EVM transaction hash for reference
        let evm_tx_hash = tx.sighash().0;

        // Get the 32-byte public key from the signer
        let pubkey_32 = self.signer.public_key_32();
        let btc_address_byte = self.signer.btc_address_byte();

        // Build change script
        let change_script: ScriptBuf;
        let mut all_signatures: Vec<Vec<u8>> = Vec::with_capacity(utxos.len());
        let mut all_pubkeys: Vec<Vec<u8>> = Vec::with_capacity(utxos.len());

        if is_taproot {
            // P2TR: Use x-only pubkey for script and Schnorr signature
            change_script = build_p2tr_script_untweaked(pubkey_32);

            // Build unsigned transaction once
            let unsigned_tx = build_unsigned_tx(
                &utxos,
                &tss_pubkey,
                tss_value,
                change_value,
                &change_script,
                &evm_tx_hash,
            );

            // Build prevouts for all inputs (all use same script)
            let prevouts: Vec<TxOut> = utxos
                .iter()
                .map(|u| TxOut {
                    value: Amount::from_sat(u.value),
                    script_pubkey: build_p2tr_script_untweaked(pubkey_32),
                })
                .collect();

            // Compute sighashes and sign each input
            let mut cache = SighashCache::new(&unsigned_tx);
            for input_index in 0..utxos.len() {
                let sighash = cache
                    .taproot_key_spend_signature_hash(
                        input_index,
                        &Prevouts::All(&prevouts),
                        TapSighashType::Default,
                    )
                    .map_err(|e| {
                        ChainCommunicationError::CustomError(format!(
                            "Failed to compute taproot sighash for input {}: {}",
                            input_index, e
                        ))
                    })?;

                let schnorr_sig = self.sign_schnorr(&sighash.to_byte_array())?;
                all_signatures.push(schnorr_sig.to_vec());
                all_pubkeys.push(pubkey_32.to_vec());
            }
        } else {
            // P2WPKH/P2SH_P2WPKH: Use compressed pubkey and ECDSA
            let mut full_pubkey = vec![btc_address_byte];
            full_pubkey.extend_from_slice(pubkey_32);

            let pubkey_hash = bitcoin::hashes::hash160::Hash::hash(&full_pubkey).to_byte_array();
            let wpkh = WPubkeyHash::from_byte_array(pubkey_hash);
            change_script = ScriptBuf::new_p2wpkh(&wpkh);

            // Build unsigned transaction once
            let unsigned_tx = build_unsigned_tx(
                &utxos,
                &tss_pubkey,
                tss_value,
                change_value,
                &change_script,
                &evm_tx_hash,
            );

            // Compute sighashes and sign each input
            let mut cache = SighashCache::new(&unsigned_tx);
            for input_index in 0..utxos.len() {
                let sighash = cache
                    .p2wpkh_signature_hash(
                        input_index,
                        &ScriptBuf::new_p2wpkh(&wpkh),
                        Amount::from_sat(utxos[input_index].value),
                        EcdsaSighashType::All,
                    )
                    .map_err(|e| {
                        ChainCommunicationError::CustomError(format!(
                            "Failed to compute P2WPKH sighash for input {}: {}",
                            input_index, e
                        ))
                    })?;

                let der_sig = self
                    .signer
                    .sign_hash_der(&sighash.to_byte_array())
                    .map_err(|e| {
                        ChainCommunicationError::CustomError(format!(
                            "Failed to sign Bitcoin transaction input {}: {}",
                            input_index, e
                        ))
                    })?;

                all_signatures.push(der_sig);
                all_pubkeys.push(full_pubkey.clone());
            }
        }

        // Fill witnesses on a mutable copy of the unsigned transaction
        let mut signed_tx = build_unsigned_tx(
            &utxos,
            &tss_pubkey,
            tss_value,
            change_value,
            &change_script,
            &evm_tx_hash,
        );

        for (i, input) in signed_tx.input.iter_mut().enumerate() {
            if is_taproot {
                // P2TR key-path spend: single witness item (64-byte Schnorr signature)
                // For SIGHASH_DEFAULT, no sighash byte is appended
                let mut witness = Witness::new();
                witness.push(&all_signatures[i]);
                input.witness = witness;
            } else {
                // P2WPKH: two witness items (signature with SIGHASH_ALL + pubkey)
                let mut witness = Witness::new();
                let mut sig_with_hashtype = all_signatures[i].clone();
                sig_with_hashtype.push(EcdsaSighashType::All as u8);
                witness.push(&sig_with_hashtype);
                witness.push(&all_pubkeys[i]);
                input.witness = witness;
            }
        }

        // Serialize the signed transaction
        let btc_tx = btc_encode::serialize(&signed_tx);

        // Compute the BTC transaction hash (txid)
        let mut txid_bytes = signed_tx.compute_txid().to_byte_array();
        txid_bytes.reverse(); // internal order → display order for H256

        debug!(
            btc_tx_hash = ?hex::encode(&txid_bytes),
            evm_tx_hash = ?hex::encode(&evm_tx_hash),
            num_inputs = utxos.len(),
            total_input_value = total_utxo_value,
            tss_pubkey = ?hex::encode(&tss_pubkey),
            tss_value = tss_value,
            fee_rate = fee_rate,
            actual_fee = actual_fee,
            change_value = change_value,
            is_taproot = is_taproot,
            "Built signed Bitcoin transaction for MIDL with TSS output"
        );

        Ok(MidlPreparedMetadata {
            btc_tx_hash: H256::from_slice(&txid_bytes),
            btc_transaction: Bytes::from(btc_tx),
            public_key: Bytes::from(pubkey_32.to_vec()),
            btc_address_byte: U256::from(btc_address_byte),
        })
    }
}

/// Middleware that rewrites legacy EVM transactions into Midl-aware payloads
/// and ensures the bundle is submitted alongside the BTC transaction hex.
pub struct TxRewriteMiddleware<M>
where
    M: Middleware,
{
    inner: M,
    metadata_provider: Option<Arc<dyn MidlMetadataProvider>>,
    metadata_cache: Arc<Mutex<HashMap<TxKey, MidlPreparedMetadata>>>,
}

impl<M> fmt::Debug for TxRewriteMiddleware<M>
where
    M: Middleware,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxRewriteMiddleware")
            .field("inner", &self.inner)
            .field(
                "metadata_provider",
                &self
                    .metadata_provider
                    .as_ref()
                    .map(|_| "<dyn MidlMetadataProvider>"),
            )
            .field("metadata_cache", &"<mutex>")
            .finish()
    }
}

impl<M> TxRewriteMiddleware<M>
where
    M: Middleware,
{
    pub fn new(inner: M, metadata_provider: Option<Arc<dyn MidlMetadataProvider>>) -> Self {
        Self {
            inner,
            metadata_provider,
            metadata_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn into_inner(self) -> M {
        self.inner
    }

    fn insert_metadata(&self, key: TxKey, metadata: MidlPreparedMetadata) {
        let mut guard = self.metadata_cache.lock().expect("metadata cache poisoned");
        guard.insert(key, metadata);
    }

    fn remove_metadata(&self, key: &TxKey) -> Option<MidlPreparedMetadata> {
        self.metadata_cache
            .lock()
            .ok()
            .and_then(|mut guard| guard.remove(key))
    }
}

/// Error type for [`TxRewriteMiddleware`].
#[derive(Debug, Error)]
pub enum TxRewriteMiddlewareError<M>
where
    M: Middleware,
    M::Error: 'static,
{
    /// Error surfaced by the inner middleware layer.
    #[error("{0}")]
    Inner(#[source] M::Error),
    #[error(transparent)]
    Chain(ChainCommunicationError),
}

impl<M> TxRewriteMiddlewareError<M>
where
    M: Middleware,
{
    fn from_inner(err: M::Error) -> Self {
        Self::Inner(err)
    }
}

impl<M> FromErr<M::Error> for TxRewriteMiddlewareError<M>
where
    M: Middleware,
    M::Error: 'static,
{
    fn from(src: M::Error) -> Self {
        Self::Inner(src)
    }
}

impl<M> From<ChainCommunicationError> for TxRewriteMiddlewareError<M>
where
    M: Middleware,
{
    fn from(value: ChainCommunicationError) -> Self {
        Self::Chain(value)
    }
}

#[async_trait]
impl<M> Middleware for TxRewriteMiddleware<M>
where
    M: Middleware + Send + Sync,
    M::Error: 'static,
{
    type Error = TxRewriteMiddlewareError<M>;
    type Provider = M::Provider;
    type Inner = M;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    async fn fill_transaction(
        &self,
        tx: &mut TypedTransaction,
        block: Option<ethers::types::BlockId>,
    ) -> Result<(), Self::Error> {
        self.inner
            .fill_transaction(tx, block)
            .await
            .map_err(TxRewriteMiddlewareError::from_inner)?;

        let Some(metadata_provider) = &self.metadata_provider else {
            return Ok(());
        };

        let Some(key) = extract_key(tx) else {
            warn!("Could not extract key from transaction (missing from or nonce)");
            return Ok(());
        };

        debug!(
            from = ?key.0,
            nonce = ?key.1,
            "Preparing MIDL metadata for transaction"
        );

        let metadata = metadata_provider.prepare_metadata(tx).await?;

        // Convert the transaction to MIDL type 7 with BTC metadata
        // This must happen before signing so the signer signs a type 7 transaction
        let midl_tx = convert_to_midl_transaction(tx, &metadata);
        *tx = midl_tx;

        self.insert_metadata(key, metadata);
        Ok(())
    }

    /// Override send_raw_transaction to use eth_sendBTCTransactions for MIDL chains
    /// when we have cached metadata for this transaction.
    async fn send_raw_transaction<'life0>(
        &'life0 self,
        tx: Bytes,
    ) -> Result<PendingTransaction<'life0, Self::Provider>, Self::Error> {
        // If no metadata provider is configured, pass through to inner middleware
        if self.metadata_provider.is_none() {
            return self
                .inner
                .send_raw_transaction(tx)
                .await
                .map_err(TxRewriteMiddlewareError::from_inner);
        }

        // Try to decode the signed transaction to extract (from, nonce) key
        let tx_key = decode_tx_key(&tx);

        let metadata = tx_key.as_ref().and_then(|key| self.remove_metadata(key));

        match metadata {
            Some(meta) => {
                debug!(
                    btc_tx_hash = ?meta.btc_tx_hash,
                    "Submitting MIDL transaction bundle via eth_sendBTCTransactions"
                );

                // Use eth_sendBTCTransactions to submit the EVM tx bundled with BTC tx
                let pending_txs = self
                    .inner
                    .send_btc_transactions(vec![tx], meta.btc_transaction)
                    .await
                    .map_err(TxRewriteMiddlewareError::from_inner)?;

                // Return the first pending transaction (we only submitted one)
                pending_txs.into_iter().next().ok_or_else(|| {
                    TxRewriteMiddlewareError::Chain(ChainCommunicationError::CustomError(
                        "eth_sendBTCTransactions returned empty result".to_string(),
                    ))
                })
            }
            None => {
                if tx_key.is_some() {
                    warn!(
                        "No cached MIDL metadata found for transaction, falling back to standard submission"
                    );
                }
                // Fall back to standard eth_sendRawTransaction
                self.inner
                    .send_raw_transaction(tx)
                    .await
                    .map_err(TxRewriteMiddlewareError::from_inner)
            }
        }
    }
}

/// Convert a TypedTransaction to a MIDL type 7 transaction with BTC metadata.
/// MIDL fixed gas price: 1,000,000 wei (1 gwei)
const MIDL_GAS_PRICE: u64 = 1_000_000;

fn convert_to_midl_transaction(
    tx: &TypedTransaction,
    metadata: &MidlPreparedMetadata,
) -> TypedTransaction {
    // Create base transaction request from the existing transaction
    // MIDL uses a fixed static gas price of 1,000,000 wei (1 gwei)
    let base_tx = ethers::types::TransactionRequest {
        from: tx.from().copied(),
        to: tx.to().cloned(),
        gas: tx.gas().copied(),
        gas_price: Some(U256::from(MIDL_GAS_PRICE)),
        value: tx.value().copied(),
        data: tx.data().cloned(),
        nonce: tx.nonce().copied(),
        chain_id: tx.chain_id().map(|id| id.as_u64().into()),
    };

    // Create MIDL transaction with BTC metadata
    let midl_tx = MidlTransactionRequest {
        tx: base_tx,
        btc_tx_hash: Some(metadata.btc_tx_hash.into()),
        public_key: Some(metadata.public_key.clone()),
        btc_address_byte: Some(metadata.btc_address_byte),
        access_list: tx.access_list().cloned().unwrap_or_default(),
    };

    TypedTransaction::Midl(midl_tx)
}

fn extract_key(tx: &TypedTransaction) -> Option<TxKey> {
    use ethers::types::NameOrAddress;

    // Convert NameOrAddress to Address (we only support Address targets for caching)
    let to = tx.to().and_then(|t| match t {
        NameOrAddress::Address(addr) => Some(*addr),
        NameOrAddress::Name(_) => None, // ENS names not supported for cache key
    });
    let nonce = tx.nonce().cloned()?;
    Some((to, nonce))
}

/// Decode a signed transaction to extract the (to, nonce) key.
/// Returns None if decoding fails.
///
/// This function manually decodes the RLP without requiring signature recovery,
/// which is necessary for MIDL transactions that use BIP322/BIP143 signatures
/// (standard signature recovery would fail for these transactions).
fn decode_tx_key(tx_bytes: &Bytes) -> Option<TxKey> {
    let bytes = tx_bytes.as_ref();
    if bytes.is_empty() {
        return None;
    }

    // Check transaction type
    let (tx_type, rlp_data) = if bytes[0] <= 0x7f {
        // EIP-2718 typed transaction: first byte is the type
        (Some(bytes[0]), &bytes[1..])
    } else {
        // Legacy transaction (starts with RLP list)
        (None, bytes)
    };

    let rlp = rlp::Rlp::new(rlp_data);
    if !rlp.is_list() {
        return None;
    }

    // Extract `to` and `nonce` based on transaction type
    // The field positions vary by type:
    // - Legacy (None): [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    // - EIP-2930 (0x01): [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, v, r, s]
    // - EIP-1559 (0x02): [chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList, v, r, s]
    // - MIDL (0x07): [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, btcTxHash, publicKey, btcAddressByte, v, r, s]
    let (nonce_idx, to_idx) = match tx_type {
        None => (0, 3),       // Legacy
        Some(0x01) => (1, 4), // EIP-2930
        Some(0x02) => (1, 5), // EIP-1559
        Some(0x07) => (1, 4), // MIDL
        _ => return None,     // Unknown type
    };

    // Extract nonce
    let nonce: U256 = rlp.val_at(nonce_idx).ok()?;

    // Extract `to` (can be empty for contract creation)
    let to_bytes: Vec<u8> = rlp.val_at(to_idx).ok()?;
    let to = if to_bytes.is_empty() {
        None
    } else if to_bytes.len() == 20 {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&to_bytes);
        Some(ethers::types::Address::from(addr))
    } else {
        return None; // Invalid `to` field
    };

    Some((to, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::{Address, U256};

    #[test]
    fn test_extract_key_from_transaction() {
        let mut tx = TypedTransaction::default();
        tx.set_to(Address::from_low_u64_be(1));
        tx.set_nonce(U256::from(42));

        let key = extract_key(&tx);
        assert!(key.is_some());
        let (to, nonce) = key.unwrap();
        assert_eq!(to, Some(Address::from_low_u64_be(1)));
        assert_eq!(nonce, U256::from(42));
    }

    #[test]
    fn test_extract_key_no_to_address() {
        // Transaction without `to` (contract creation) should still work
        let mut tx = TypedTransaction::default();
        tx.set_nonce(U256::from(42));
        // to is not set (contract creation)

        let key = extract_key(&tx);
        assert!(key.is_some());
        let (to, nonce) = key.unwrap();
        assert_eq!(to, None);
        assert_eq!(nonce, U256::from(42));
    }

    #[test]
    fn test_extract_key_missing_nonce() {
        let mut tx = TypedTransaction::default();
        tx.set_to(Address::from_low_u64_be(1));
        // nonce is not set

        let key = extract_key(&tx);
        assert!(key.is_none());
    }

    #[test]
    fn test_metadata_cache_operations() {
        // Test the cache directly without needing a middleware wrapper
        let cache: Arc<Mutex<HashMap<TxKey, MidlPreparedMetadata>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let key = (Some(Address::from_low_u64_be(1)), U256::from(42));
        let metadata = MidlPreparedMetadata {
            btc_tx_hash: H256::from_low_u64_be(123),
            btc_transaction: Bytes::from(vec![1, 2, 3]),
            public_key: Bytes::from(vec![4, 5, 6]),
            btc_address_byte: U256::from(7),
        };

        // Insert metadata
        {
            let mut guard = cache.lock().unwrap();
            guard.insert(key, metadata.clone());
        }

        // Remove and verify
        let retrieved = cache.lock().ok().and_then(|mut guard| guard.remove(&key));
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.btc_tx_hash, metadata.btc_tx_hash);
        assert_eq!(retrieved.btc_transaction, metadata.btc_transaction);
        assert_eq!(retrieved.public_key, metadata.public_key);
        assert_eq!(retrieved.btc_address_byte, metadata.btc_address_byte);

        // Second remove should return None
        let retrieved_again = cache.lock().ok().and_then(|mut guard| guard.remove(&key));
        assert!(retrieved_again.is_none());
    }

    #[test]
    fn test_static_metadata_provider() {
        use tokio::runtime::Runtime;

        let metadata = MidlPreparedMetadata {
            btc_tx_hash: H256::from_low_u64_be(999),
            btc_transaction: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
            public_key: Bytes::from(vec![0x01; 32]),
            btc_address_byte: U256::from(1),
        };

        let provider = StaticMidlMetadataProvider::new(metadata.clone());

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let tx = TypedTransaction::default();
            let result = provider.prepare_metadata(&tx).await;
            assert!(result.is_ok());
            let prepared = result.unwrap();
            assert_eq!(prepared.btc_tx_hash, metadata.btc_tx_hash);
            assert_eq!(prepared.btc_transaction, metadata.btc_transaction);
        });
    }
}
