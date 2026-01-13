use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ethers::prelude::FromErr;
use ethers::providers::{Middleware, PendingTransaction};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Bytes, U256};
use ethers_core::utils::rlp;
use ethers_signers::Signer;
use hyperlane_core::{ChainCommunicationError, H256};
use thiserror::Error;
use tracing::{debug, warn};

type TxKey = (ethers::types::Address, U256);

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
    /// Get a UTXO with at least the specified value in satoshis.
    async fn get_utxo(&self, min_value: u64) -> Result<BtcUtxo, ChainCommunicationError>;
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
}

impl BtcSignerMidlMetadataProvider {
    /// Create a new BtcSignerMidlMetadataProvider.
    ///
    /// # Arguments
    /// * `signer` - The BtcSigner to use for signing
    /// * `utxo_provider` - Provider for UTXOs to spend
    /// * `default_fee_rate` - Default fee rate in satoshis per virtual byte
    pub fn new(
        signer: crate::signer::BtcSigner,
        utxo_provider: Arc<dyn UtxoProvider>,
        default_fee_rate: u64,
    ) -> Self {
        Self {
            signer,
            utxo_provider,
            default_fee_rate,
            mempool_url: None,
        }
    }

    /// Create a new BtcSignerMidlMetadataProvider with dynamic fee estimation.
    ///
    /// # Arguments
    /// * `signer` - The BtcSigner to use for signing
    /// * `utxo_provider` - Provider for UTXOs to spend
    /// * `default_fee_rate` - Default fee rate (fallback if API fails)
    /// * `mempool_url` - URL for mempool API to fetch fee rates
    pub fn with_mempool_url(
        signer: crate::signer::BtcSigner,
        utxo_provider: Arc<dyn UtxoProvider>,
        default_fee_rate: u64,
        mempool_url: String,
    ) -> Self {
        Self {
            signer,
            utxo_provider,
            default_fee_rate,
            mempool_url: Some(mempool_url),
        }
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

    /// Serialize outputs for sighash computation.
    /// Returns the serialized outputs (change output + OP_RETURN output).
    fn serialize_outputs(
        change_value: u64,
        change_script: &[u8],
        evm_tx_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut outputs = Vec::new();

        // Output 1: Change output (if there's change)
        if change_value > 0 {
            outputs.extend_from_slice(&change_value.to_le_bytes());
            push_varint(&mut outputs, change_script.len() as u64);
            outputs.extend_from_slice(change_script);
        }

        // Output 2: OP_RETURN with EVM tx hash
        outputs.extend_from_slice(&0u64.to_le_bytes()); // Value: 0 satoshis
        let op_return_script_len = 2usize.saturating_add(evm_tx_hash.len());
        push_varint(&mut outputs, op_return_script_len as u64);
        outputs.push(0x6a); // OP_RETURN
        outputs.push(evm_tx_hash.len() as u8);
        outputs.extend_from_slice(evm_tx_hash);

        outputs
    }

    /// Compute the BIP143 sighash for a P2WPKH input.
    ///
    /// BIP143 defines the sighash algorithm for SegWit (witness version 0) transactions.
    fn compute_bip143_sighash(
        utxo: &BtcUtxo,
        pubkey_hash: &[u8; 20],
        change_value: u64,
        change_script: &[u8],
        evm_tx_hash: &[u8; 32],
    ) -> [u8; 32] {
        use sha2::Digest;

        let mut preimage = Vec::new();

        // 1. nVersion (2 for SegWit)
        preimage.extend_from_slice(&2u32.to_le_bytes());

        // 2. hashPrevouts - double SHA256 of all outpoints
        let mut prevouts = Vec::new();
        let mut txid_reversed = utxo.tx_hash;
        txid_reversed.reverse();
        prevouts.extend_from_slice(&txid_reversed);
        prevouts.extend_from_slice(&utxo.vout.to_le_bytes());
        let hash_prevouts = Self::double_sha256(&prevouts);
        preimage.extend_from_slice(&hash_prevouts);

        // 3. hashSequence - double SHA256 of all sequences
        let sequence = 0xfffffffdu32.to_le_bytes();
        let hash_sequence = Self::double_sha256(&sequence);
        preimage.extend_from_slice(&hash_sequence);

        // 4. outpoint being signed
        preimage.extend_from_slice(&txid_reversed);
        preimage.extend_from_slice(&utxo.vout.to_le_bytes());

        // 5. scriptCode for P2WPKH
        let mut script_code = Vec::new();
        script_code.push(0x19); // Length of script (25 bytes)
        script_code.push(0x76); // OP_DUP
        script_code.push(0xa9); // OP_HASH160
        script_code.push(0x14); // Push 20 bytes
        script_code.extend_from_slice(pubkey_hash);
        script_code.push(0x88); // OP_EQUALVERIFY
        script_code.push(0xac); // OP_CHECKSIG
        preimage.extend_from_slice(&script_code);

        // 6. value of the UTXO being spent
        preimage.extend_from_slice(&utxo.value.to_le_bytes());

        // 7. nSequence
        preimage.extend_from_slice(&sequence);

        // 8. hashOutputs - double SHA256 of all outputs
        let outputs = Self::serialize_outputs(change_value, change_script, evm_tx_hash);
        let hash_outputs = Self::double_sha256(&outputs);
        preimage.extend_from_slice(&hash_outputs);

        // 9. nLockTime
        preimage.extend_from_slice(&0u32.to_le_bytes());

        // 10. sighash type (SIGHASH_ALL = 0x01)
        preimage.extend_from_slice(&1u32.to_le_bytes());

        Self::double_sha256(&preimage)
    }

    /// Compute the BIP341 sighash for a P2TR (Taproot) key-path spend.
    ///
    /// BIP341 defines the sighash algorithm for Taproot transactions.
    /// For key-path spending with SIGHASH_DEFAULT (0x00), we use a tagged hash.
    fn compute_bip341_sighash(
        utxo: &BtcUtxo,
        x_only_pubkey: &[u8; 32],
        change_value: u64,
        change_script: &[u8],
        evm_tx_hash: &[u8; 32],
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        // BIP341 uses tagged hashes: SHA256(SHA256(tag) || SHA256(tag) || data)
        fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
            let tag_hash = Sha256::digest(tag.as_bytes());
            let mut hasher = Sha256::new();
            hasher.update(&tag_hash);
            hasher.update(&tag_hash);
            hasher.update(data);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            out
        }

        let mut txid_reversed = utxo.tx_hash;
        txid_reversed.reverse();

        // Build the sighash message for SIGHASH_DEFAULT (0x00)
        let mut sig_msg = Vec::new();

        // epoch (1 byte) - always 0 for now
        sig_msg.push(0x00);

        // hash_type (1 byte) - SIGHASH_DEFAULT = 0x00
        sig_msg.push(0x00);

        // nVersion (4 bytes)
        sig_msg.extend_from_slice(&2u32.to_le_bytes());

        // nLockTime (4 bytes)
        sig_msg.extend_from_slice(&0u32.to_le_bytes());

        // sha_prevouts - SHA256 of all outpoints
        let mut prevouts = Vec::new();
        prevouts.extend_from_slice(&txid_reversed);
        prevouts.extend_from_slice(&utxo.vout.to_le_bytes());
        let sha_prevouts = Sha256::digest(&prevouts);
        sig_msg.extend_from_slice(&sha_prevouts);

        // sha_amounts - SHA256 of all input amounts
        let sha_amounts = Sha256::digest(&utxo.value.to_le_bytes());
        sig_msg.extend_from_slice(&sha_amounts);

        // sha_scriptpubkeys - SHA256 of all input scriptPubKeys
        // For P2TR: OP_1 <32-byte x-only pubkey>
        let mut scriptpubkey = Vec::new();
        scriptpubkey.push(0x22); // Length (34 bytes)
        scriptpubkey.push(0x51); // OP_1 (witness version 1)
        scriptpubkey.push(0x20); // Push 32 bytes
        scriptpubkey.extend_from_slice(x_only_pubkey);
        let sha_scriptpubkeys = Sha256::digest(&scriptpubkey);
        sig_msg.extend_from_slice(&sha_scriptpubkeys);

        // sha_sequences - SHA256 of all sequences
        let sha_sequences = Sha256::digest(&0xfffffffdu32.to_le_bytes());
        sig_msg.extend_from_slice(&sha_sequences);

        // sha_outputs - SHA256 of all outputs
        let outputs = Self::serialize_outputs(change_value, change_script, evm_tx_hash);
        let sha_outputs = Sha256::digest(&outputs);
        sig_msg.extend_from_slice(&sha_outputs);

        // spend_type (1 byte) - 0x00 for key-path spend with no annex
        sig_msg.push(0x00);

        // input_index (4 bytes) - we only have one input
        sig_msg.extend_from_slice(&0u32.to_le_bytes());

        // Compute the tagged hash "TapSighash"
        tagged_hash("TapSighash", &sig_msg)
    }

    /// Compute double SHA256 hash.
    fn double_sha256(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let hash1 = Sha256::digest(data);
        let hash2 = Sha256::digest(hash1);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash2);
        result
    }

    /// Compute HASH160 (RIPEMD160(SHA256(data))) for public key hashing.
    fn hash160(data: &[u8]) -> [u8; 20] {
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};
        let sha256_hash = Sha256::digest(data);
        let ripemd_hash = Ripemd160::digest(sha256_hash);
        let mut result = [0u8; 20];
        result.copy_from_slice(&ripemd_hash);
        result
    }

    /// Encode an ECDSA signature in DER format.
    ///
    /// DER format: 0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s>
    /// Where r and s may need a leading 0x00 byte if the high bit is set
    /// (to indicate positive integer in ASN.1 DER).
    fn encode_der_signature(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        // Helper to encode an integer in DER format
        fn encode_integer(value: &[u8]) -> Vec<u8> {
            // Skip leading zeros
            let mut start = 0;
            while start < value.len() && value[start] == 0 {
                start = start.saturating_add(1);
            }
            let trimmed = if start < value.len() {
                &value[start..]
            } else {
                &[0u8]
            };

            let mut result = Vec::new();
            result.push(0x02); // INTEGER tag

            // If high bit is set, prepend 0x00 to indicate positive
            if !trimmed.is_empty() && (trimmed[0] & 0x80) != 0 {
                result.push((trimmed.len().saturating_add(1)) as u8); // Length includes leading 0x00
                result.push(0x00);
            } else {
                result.push(trimmed.len() as u8);
            }
            result.extend_from_slice(trimmed);
            result
        }

        let r_der = encode_integer(r);
        let s_der = encode_integer(s);

        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE tag
        der.push((r_der.len().saturating_add(s_der.len())) as u8); // Total length
        der.extend_from_slice(&r_der);
        der.extend_from_slice(&s_der);
        der
    }

    /// Build a Bitcoin transaction for MIDL with optional change output.
    ///
    /// Creates a transaction that spends a UTXO and creates:
    /// - An optional change output (if change_value > 0)
    /// - An OP_RETURN output containing the EVM transaction data reference
    ///
    /// # Arguments
    /// * `utxo` - The UTXO to spend
    /// * `evm_tx_hash` - The EVM transaction hash to embed in OP_RETURN
    /// * `signature` - The signature (DER for P2WPKH, Schnorr for P2TR)
    /// * `pubkey` - The public key (33 bytes compressed for P2WPKH, 32 bytes x-only for P2TR)
    /// * `change_value` - Amount to return as change (0 for no change output)
    /// * `change_script` - The scriptPubKey for the change output
    /// * `is_taproot` - Whether this is a Taproot (P2TR) transaction
    fn build_btc_transaction(
        &self,
        utxo: &BtcUtxo,
        evm_tx_hash: &[u8; 32],
        signature: &[u8],
        pubkey: &[u8],
        change_value: u64,
        change_script: &[u8],
        is_taproot: bool,
    ) -> Result<Vec<u8>, ChainCommunicationError> {
        let mut tx = Vec::new();

        // Version (2 for SegWit)
        tx.extend_from_slice(&2u32.to_le_bytes());

        // Marker and flag for SegWit (0x00, 0x01)
        tx.push(0x00);
        tx.push(0x01);

        // Input count (1 input)
        tx.push(0x01);

        // Input: previous output
        // txid (reversed for Bitcoin)
        let mut txid_reversed = utxo.tx_hash;
        txid_reversed.reverse();
        tx.extend_from_slice(&txid_reversed);

        // vout
        tx.extend_from_slice(&utxo.vout.to_le_bytes());

        // Script sig (empty for SegWit)
        tx.push(0x00);

        // Sequence (0xfffffffd for RBF)
        tx.extend_from_slice(&0xfffffffdu32.to_le_bytes());

        // Output count (1 or 2 outputs)
        let output_count = if change_value > 0 { 2u8 } else { 1u8 };
        tx.push(output_count);

        // Output 1: Change output (if there's change)
        if change_value > 0 {
            tx.extend_from_slice(&change_value.to_le_bytes());
            push_varint(&mut tx, change_script.len() as u64);
            tx.extend_from_slice(change_script);
        }

        // Output 2 (or 1 if no change): OP_RETURN with EVM transaction hash
        tx.extend_from_slice(&0u64.to_le_bytes()); // Value: 0 satoshis
        let op_return_script_len = 2usize.saturating_add(evm_tx_hash.len());
        push_varint(&mut tx, op_return_script_len as u64);
        tx.push(0x6a); // OP_RETURN
        tx.push(evm_tx_hash.len() as u8); // Push length
        tx.extend_from_slice(evm_tx_hash);

        // Witness data (for the single input)
        if is_taproot {
            // P2TR key-path spend: single witness item (64-byte Schnorr signature)
            // For SIGHASH_DEFAULT, no sighash byte is appended
            tx.push(0x01); // Number of witness items
            push_varint(&mut tx, signature.len() as u64);
            tx.extend_from_slice(signature);
        } else {
            // P2WPKH: two witness items (signature + pubkey)
            tx.push(0x02); // Number of witness items

            // Witness item 1: signature (with SIGHASH_ALL)
            let sig_with_hashtype = [signature, &[0x01]].concat();
            push_varint(&mut tx, sig_with_hashtype.len() as u64);
            tx.extend_from_slice(&sig_with_hashtype);

            // Witness item 2: public key (33 bytes compressed)
            push_varint(&mut tx, pubkey.len() as u64);
            tx.extend_from_slice(pubkey);
        }

        // Locktime
        tx.extend_from_slice(&0u32.to_le_bytes());

        Ok(tx)
    }

    /// Compute the Bitcoin transaction hash (txid) by excluding witness data.
    ///
    /// For SegWit transactions, the txid is computed from the non-witness serialization:
    /// - nVersion (4 bytes)
    /// - inputs (without witness)
    /// - outputs
    /// - nLockTime (4 bytes)
    ///
    /// The marker (0x00) and flag (0x01) bytes and witness data are excluded.
    fn compute_btc_tx_hash(tx_bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        // Check if this is a SegWit transaction (has marker 0x00 and flag 0x01 after version)
        if tx_bytes.len() > 6 && tx_bytes[4] == 0x00 && tx_bytes[5] == 0x01 {
            // This is a SegWit transaction - we need to strip witness data
            let mut non_witness = Vec::new();

            // Copy nVersion (4 bytes)
            non_witness.extend_from_slice(&tx_bytes[0..4]);

            // Skip marker and flag, start from byte 6
            let mut pos = 6;

            // Read input count (varint)
            let (input_count, varint_len) = read_varint(&tx_bytes[pos..]);
            non_witness.extend_from_slice(&tx_bytes[pos..pos + varint_len]);
            pos += varint_len;

            // Copy all inputs (without witness data)
            for _ in 0..input_count {
                // txid (32 bytes)
                non_witness.extend_from_slice(&tx_bytes[pos..pos + 32]);
                pos += 32;
                // vout (4 bytes)
                non_witness.extend_from_slice(&tx_bytes[pos..pos + 4]);
                pos += 4;
                // scriptSig length (varint)
                let (script_len, varint_len) = read_varint(&tx_bytes[pos..]);
                non_witness.extend_from_slice(&tx_bytes[pos..pos + varint_len]);
                pos += varint_len;
                // scriptSig
                non_witness.extend_from_slice(&tx_bytes[pos..pos + script_len as usize]);
                pos += script_len as usize;
                // sequence (4 bytes)
                non_witness.extend_from_slice(&tx_bytes[pos..pos + 4]);
                pos += 4;
            }

            // Read output count (varint)
            let (output_count, varint_len) = read_varint(&tx_bytes[pos..]);
            non_witness.extend_from_slice(&tx_bytes[pos..pos + varint_len]);
            pos += varint_len;

            // Copy all outputs
            for _ in 0..output_count {
                // value (8 bytes)
                non_witness.extend_from_slice(&tx_bytes[pos..pos + 8]);
                pos += 8;
                // scriptPubKey length (varint)
                let (script_len, varint_len) = read_varint(&tx_bytes[pos..]);
                non_witness.extend_from_slice(&tx_bytes[pos..pos + varint_len]);
                pos += varint_len;
                // scriptPubKey
                non_witness.extend_from_slice(&tx_bytes[pos..pos + script_len as usize]);
                pos += script_len as usize;
            }

            // Skip witness data - find locktime at the end
            // The last 4 bytes are always locktime
            non_witness.extend_from_slice(&tx_bytes[tx_bytes.len() - 4..]);

            // Double SHA256 of non-witness serialization
            let hash1 = Sha256::digest(&non_witness);
            let hash2 = Sha256::digest(&hash1);
            let mut result = [0u8; 32];
            result.copy_from_slice(&hash2);
            result.reverse(); // Bitcoin uses little-endian display
            result
        } else {
            // Legacy transaction - hash entire transaction
            let hash1 = Sha256::digest(tx_bytes);
            let hash2 = Sha256::digest(&hash1);
            let mut result = [0u8; 32];
            result.copy_from_slice(&hash2);
            result.reverse();
            result
        }
    }

    /// Build a P2WPKH scriptPubKey from a public key hash.
    /// Format: OP_0 <20-byte-pubkey-hash>
    fn build_p2wpkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
        let mut script = Vec::with_capacity(22);
        script.push(0x00); // OP_0 (witness version 0)
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(pubkey_hash);
        script
    }

    /// Build a P2TR scriptPubKey from an x-only public key.
    /// Format: OP_1 <32-byte-x-only-pubkey>
    fn build_p2tr_script(x_only_pubkey: &[u8; 32]) -> Vec<u8> {
        let mut script = Vec::with_capacity(34);
        script.push(0x51); // OP_1 (witness version 1)
        script.push(0x20); // Push 32 bytes
        script.extend_from_slice(x_only_pubkey);
        script
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

/// Read a Bitcoin varint from a byte slice.
/// Returns (value, bytes_read).
fn read_varint(data: &[u8]) -> (u64, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    match data[0] {
        0xff if data.len() >= 9 => {
            let value = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            (value, 9)
        }
        0xfe if data.len() >= 5 => {
            let value = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64;
            (value, 5)
        }
        0xfd if data.len() >= 3 => {
            let value = u16::from_le_bytes([data[1], data[2]]) as u64;
            (value, 3)
        }
        _ => (data[0] as u64, 1),
    }
}

/// Push a variable-length integer (varint) to a buffer.
fn push_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        buf.push(value as u8);
    } else if value <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&value.to_le_bytes());
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

#[async_trait]
impl MidlMetadataProvider for BtcSignerMidlMetadataProvider {
    async fn prepare_metadata(
        &self,
        tx: &TypedTransaction,
    ) -> Result<MidlPreparedMetadata, ChainCommunicationError> {
        use crate::signer::BtcAddressType;

        // Get dynamic fee rate from mempool API (or use default)
        let fee_rate = self.get_fee_rate().await;

        // Determine address type and calculate transaction size
        let address_type = self.signer.address_type();
        let is_taproot = matches!(address_type, BtcAddressType::P2TR);

        // Estimate vsize based on address type and whether we'll have change
        // P2WPKH: ~110 vbytes without change, ~141 vbytes with change
        // P2TR: ~111 vbytes without change, ~154 vbytes with change (Schnorr sigs are 64 bytes)
        let estimated_vsize_with_change = if is_taproot { 154u64 } else { 141u64 };
        let estimated_fee = estimated_vsize_with_change.saturating_mul(fee_rate);

        // Dust threshold (546 satoshis for standard outputs)
        const DUST_THRESHOLD: u64 = 546;

        // Get a UTXO that can cover the fee plus potential dust
        // We request more than just the fee to have room for change
        let min_utxo_value = estimated_fee.saturating_add(DUST_THRESHOLD);
        let utxo = self.utxo_provider.get_utxo(min_utxo_value).await?;

        // Calculate change (if above dust threshold)
        let change_value = if utxo.value > estimated_fee.saturating_add(DUST_THRESHOLD) {
            utxo.value.saturating_sub(estimated_fee)
        } else {
            0 // No change output - all goes to fee
        };

        // Compute the EVM transaction hash for reference
        let evm_tx_hash = tx.sighash().0;

        // Get the 32-byte public key from the signer
        let pubkey_32 = self.signer.public_key_32();
        let btc_address_byte = self.signer.btc_address_byte();

        // Build change script based on address type
        let change_script: Vec<u8>;
        let signature_bytes: Vec<u8>;
        let pubkey_for_witness: Vec<u8>;

        if is_taproot {
            // P2TR: Use x-only pubkey for script and Schnorr signature
            change_script = Self::build_p2tr_script(pubkey_32);

            // Compute BIP341 sighash
            let sighash = Self::compute_bip341_sighash(
                &utxo,
                pubkey_32,
                change_value,
                &change_script,
                &evm_tx_hash,
            );

            // Sign with Schnorr (64 bytes)
            let schnorr_sig = self.sign_schnorr(&sighash)?;
            signature_bytes = schnorr_sig.to_vec();
            pubkey_for_witness = pubkey_32.to_vec(); // x-only pubkey for P2TR
        } else {
            // P2WPKH/P2SH_P2WPKH: Use compressed pubkey and ECDSA
            let mut full_pubkey = vec![btc_address_byte];
            full_pubkey.extend_from_slice(pubkey_32);

            // Compute public key hash for change script
            let pubkey_hash = Self::hash160(&full_pubkey);
            change_script = Self::build_p2wpkh_script(&pubkey_hash);

            // Compute BIP143 sighash
            let sighash = Self::compute_bip143_sighash(
                &utxo,
                &pubkey_hash,
                change_value,
                &change_script,
                &evm_tx_hash,
            );

            // Sign with ECDSA and encode as DER
            let signature = self.signer.sign_hash(&sighash).map_err(|e| {
                ChainCommunicationError::CustomError(format!(
                    "Failed to sign Bitcoin transaction: {}",
                    e
                ))
            })?;

            let r_bytes = {
                let mut r = [0u8; 32];
                signature.r.to_big_endian(&mut r);
                r
            };
            let s_bytes = {
                let mut s = [0u8; 32];
                signature.s.to_big_endian(&mut s);
                s
            };
            signature_bytes = Self::encode_der_signature(&r_bytes, &s_bytes);
            pubkey_for_witness = full_pubkey; // 33-byte compressed pubkey for P2WPKH
        }

        // Build the Bitcoin transaction
        let btc_tx = self.build_btc_transaction(
            &utxo,
            &evm_tx_hash,
            &signature_bytes,
            &pubkey_for_witness,
            change_value,
            &change_script,
            is_taproot,
        )?;

        // Compute the BTC transaction hash (txid without witness)
        let btc_tx_hash = Self::compute_btc_tx_hash(&btc_tx);

        debug!(
            btc_tx_hash = ?hex::encode(&btc_tx_hash),
            evm_tx_hash = ?hex::encode(&evm_tx_hash),
            utxo_txid = ?hex::encode(&utxo.tx_hash),
            utxo_vout = utxo.vout,
            utxo_value = utxo.value,
            fee_rate = fee_rate,
            change_value = change_value,
            is_taproot = is_taproot,
            "Built signed Bitcoin transaction for MIDL"
        );

        Ok(MidlPreparedMetadata {
            btc_tx_hash: H256::from_slice(&btc_tx_hash),
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
            return Ok(());
        };

        let metadata = metadata_provider.prepare_metadata(tx).await?;
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

fn extract_key(tx: &TypedTransaction) -> Option<TxKey> {
    let from = tx.from().copied()?;
    let nonce = tx.nonce().cloned()?;
    Some((from, nonce))
}

/// Decode a signed transaction to extract the (from, nonce) key.
/// Returns None if decoding fails.
fn decode_tx_key(tx_bytes: &Bytes) -> Option<TxKey> {
    let rlp = rlp::Rlp::new(tx_bytes.as_ref());
    let (decoded_tx, _signature) = TypedTransaction::decode_signed(&rlp).ok()?;
    extract_key(&decoded_tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::{Address, U256};

    #[test]
    fn test_extract_key_from_transaction() {
        let mut tx = TypedTransaction::default();
        tx.set_from(Address::from_low_u64_be(1));
        tx.set_nonce(U256::from(42));

        let key = extract_key(&tx);
        assert!(key.is_some());
        let (from, nonce) = key.unwrap();
        assert_eq!(from, Address::from_low_u64_be(1));
        assert_eq!(nonce, U256::from(42));
    }

    #[test]
    fn test_extract_key_missing_from() {
        let mut tx = TypedTransaction::default();
        tx.set_nonce(U256::from(42));
        // from is not set

        let key = extract_key(&tx);
        assert!(key.is_none());
    }

    #[test]
    fn test_extract_key_missing_nonce() {
        let mut tx = TypedTransaction::default();
        tx.set_from(Address::from_low_u64_be(1));
        // nonce is not set

        let key = extract_key(&tx);
        assert!(key.is_none());
    }

    #[test]
    fn test_metadata_cache_operations() {
        // Test the cache directly without needing a middleware wrapper
        let cache: Arc<Mutex<HashMap<TxKey, MidlPreparedMetadata>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let key = (Address::from_low_u64_be(1), U256::from(42));
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
