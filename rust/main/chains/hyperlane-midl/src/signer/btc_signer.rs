//! Bitcoin-compatible signer for MIDL transactions.
//!
//! This module provides a signer that uses a Bitcoin private key to sign
//! MIDL (type 0x07) EVM transactions. The signer derives the EVM address
//! from the Bitcoin public key and signs transaction hashes using ECDSA.
//!
//! For MIDL transactions, the signature uses BIP322 message signing with
//! BIP143 witness signature hash computation, not a simple keccak256.

use async_trait::async_trait;
use bech32::Hrp;
use ethers::prelude::{Address, Signature};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::transaction::eip712::Eip712;
use ethers_core::utils::keccak256;
use ethers_signers::{Signer, WalletError};
use k256::ecdsa::{
    signature::hazmat::PrehashSigner, RecoveryId, Signature as K256Signature, SigningKey,
    VerifyingKey,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::debug;

/// Bitcoin network for address generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
    /// Bitcoin regtest (local development)
    Regtest,
    /// Bitcoin signet
    Signet,
}

impl Default for BitcoinNetwork {
    fn default() -> Self {
        Self::Mainnet
    }
}

impl BitcoinNetwork {
    /// Get the bech32 human-readable part for this network.
    pub fn hrp(&self) -> &'static str {
        match self {
            BitcoinNetwork::Mainnet => "bc",
            BitcoinNetwork::Testnet | BitcoinNetwork::Signet => "tb",
            BitcoinNetwork::Regtest => "bcrt",
        }
    }
}

/// Bitcoin address type for signature derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcAddressType {
    /// Pay-to-Witness-Public-Key-Hash (native SegWit)
    P2WPKH,
    /// Pay-to-Script-Hash wrapping P2WPKH (nested SegWit)
    P2SH_P2WPKH,
    /// Pay-to-Taproot
    P2TR,
}

impl Default for BtcAddressType {
    fn default() -> Self {
        Self::P2WPKH
    }
}

/// A signer that uses a Bitcoin private key to sign MIDL transactions.
///
/// The MIDL node expects transactions signed with Bitcoin keys, where:
/// - The EVM address is derived from the Bitcoin public key
/// - The transaction includes Bitcoin-specific metadata (btcTxHash, publicKey, btcAddressByte)
/// - The signature uses ECDSA with the Bitcoin private key
#[derive(Debug, Clone)]
pub struct BtcSigner {
    /// The Bitcoin private key
    signing_key: SigningKey,
    /// The derived EVM address
    address: Address,
    /// The chain ID for EIP-155 replay protection
    chain_id: u64,
    /// The Bitcoin address type
    address_type: BtcAddressType,
    /// The Bitcoin network
    network: BitcoinNetwork,
    /// The 32-byte public key for MIDL transactions
    public_key_32: [u8; 32],
    /// The BTC address byte for MIDL transactions
    btc_address_byte: u8,
    /// The Bitcoin address (bech32 encoded)
    bitcoin_address: String,
}

/// Error type for BtcSigner operations.
#[derive(Debug, Error)]
pub enum BtcSignerError {
    /// Invalid private key
    #[error("Invalid Bitcoin private key: {0}")]
    InvalidKey(String),
    /// Signing error
    #[error("Signing failed: {0}")]
    SigningError(String),
    /// Invalid hex encoding
    #[error("Invalid hex encoding: {0}")]
    HexError(#[from] hex::FromHexError),
}

impl From<BtcSignerError> for WalletError {
    fn from(err: BtcSignerError) -> Self {
        WalletError::Eip712Error(err.to_string())
    }
}

/// Compute HASH160 = RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(sha256_hash);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

impl BtcSigner {
    /// Create a new BtcSigner from a 32-byte private key.
    ///
    /// # Arguments
    /// * `private_key` - The 32-byte Bitcoin private key
    /// * `address_type` - The Bitcoin address type (P2WPKH, P2SH_P2WPKH, or P2TR)
    /// * `network` - The Bitcoin network (mainnet, testnet, regtest, signet)
    /// * `chain_id` - The EVM chain ID for replay protection
    pub fn new(
        private_key: &[u8; 32],
        address_type: BtcAddressType,
        network: BitcoinNetwork,
        chain_id: u64,
    ) -> Result<Self, BtcSignerError> {
        let secret_key = SecretKey::from_bytes(private_key.into())
            .map_err(|e| BtcSignerError::InvalidKey(e.to_string()))?;
        let signing_key = SigningKey::from(secret_key);
        let verifying_key = VerifyingKey::from(&signing_key);

        // Get compressed public key (33 bytes)
        let compressed_pubkey = verifying_key.to_encoded_point(true);
        let compressed_bytes = compressed_pubkey.as_bytes();

        // Derive the 32-byte public key for MIDL transactions
        // For P2WPKH/P2SH_P2WPKH: x-coordinate of the public key
        // For P2TR: x-only public key (same as x-coordinate for our purposes)
        let public_key_32: [u8; 32] = compressed_bytes[1..33]
            .try_into()
            .expect("x-coordinate is 32 bytes");

        // Derive the BTC address byte
        let btc_address_byte = match address_type {
            BtcAddressType::P2WPKH => compressed_bytes[0],
            BtcAddressType::P2SH_P2WPKH => compressed_bytes[0].wrapping_add(2),
            BtcAddressType::P2TR => 0,
        };

        // Derive Bitcoin address based on address type
        let bitcoin_address = Self::derive_bitcoin_address(
            &address_type,
            &network,
            compressed_bytes,
            &public_key_32,
        )?;

        // Derive EVM address from uncompressed public key
        let uncompressed_pubkey = verifying_key.to_encoded_point(false);
        let uncompressed_bytes = uncompressed_pubkey.as_bytes();
        // Skip the 0x04 prefix, take 64 bytes
        let pubkey_without_prefix = &uncompressed_bytes[1..65];
        let hash = keccak256(pubkey_without_prefix);
        let address = Address::from_slice(&hash[12..32]);

        Ok(Self {
            signing_key,
            address,
            chain_id,
            address_type,
            network,
            public_key_32,
            btc_address_byte,
            bitcoin_address,
        })
    }

    /// Derive the Bitcoin address from public key based on address type.
    fn derive_bitcoin_address(
        address_type: &BtcAddressType,
        network: &BitcoinNetwork,
        compressed_pubkey: &[u8],
        x_only_pubkey: &[u8; 32],
    ) -> Result<String, BtcSignerError> {
        let hrp = Hrp::parse(network.hrp())
            .map_err(|e| BtcSignerError::InvalidKey(format!("Invalid HRP: {}", e)))?;

        match address_type {
            BtcAddressType::P2WPKH => {
                // P2WPKH: witness version 0 + HASH160(compressed_pubkey)
                let pubkey_hash = hash160(compressed_pubkey);
                bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &pubkey_hash).map_err(|e| {
                    BtcSignerError::InvalidKey(format!("Bech32 encoding failed: {}", e))
                })
            }
            BtcAddressType::P2SH_P2WPKH => {
                // P2SH-P2WPKH: This is a nested SegWit address
                // Script: OP_0 <20-byte-pubkey-hash>
                // Then wrapped in P2SH
                // For simplicity, we'll encode as a native SegWit address
                // since the MIDL node primarily needs the public key bytes
                let pubkey_hash = hash160(compressed_pubkey);
                bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &pubkey_hash).map_err(|e| {
                    BtcSignerError::InvalidKey(format!("Bech32 encoding failed: {}", e))
                })
            }
            BtcAddressType::P2TR => {
                // P2TR: witness version 1 + x-only pubkey (32 bytes)
                // Uses Bech32m encoding
                bech32::segwit::encode(hrp, bech32::segwit::VERSION_1, x_only_pubkey).map_err(|e| {
                    BtcSignerError::InvalidKey(format!("Bech32m encoding failed: {}", e))
                })
            }
        }
    }

    /// Create a new BtcSigner from a hex-encoded private key.
    ///
    /// # Arguments
    /// * `hex_key` - The hex-encoded private key (with or without 0x prefix)
    /// * `address_type` - The Bitcoin address type
    /// * `network` - The Bitcoin network
    /// * `chain_id` - The EVM chain ID
    pub fn from_hex(
        hex_key: &str,
        address_type: BtcAddressType,
        network: BitcoinNetwork,
        chain_id: u64,
    ) -> Result<Self, BtcSignerError> {
        let hex_key = hex_key.strip_prefix("0x").unwrap_or(hex_key);
        let bytes = hex::decode(hex_key)?;
        if bytes.len() != 32 {
            return Err(BtcSignerError::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&bytes);
        Self::new(&private_key, address_type, network, chain_id)
    }

    /// Get the 32-byte public key for MIDL transactions.
    pub fn public_key_32(&self) -> &[u8; 32] {
        &self.public_key_32
    }

    /// Get the BTC address byte for MIDL transactions.
    pub fn btc_address_byte(&self) -> u8 {
        self.btc_address_byte
    }

    /// Get the Bitcoin address type.
    pub fn address_type(&self) -> BtcAddressType {
        self.address_type
    }

    /// Get the Bitcoin network.
    pub fn network(&self) -> BitcoinNetwork {
        self.network
    }

    /// Get the Bitcoin address (bech32 encoded).
    pub fn bitcoin_address(&self) -> &str {
        &self.bitcoin_address
    }

    /// Get the raw signing key bytes (32 bytes).
    /// This is needed for creating Schnorr signatures for Taproot.
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        let bytes = self.signing_key.to_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        result
    }

    /// Sign a 32-byte hash and return the EVM-compatible signature.
    ///
    /// This signs the hash using ECDSA and converts the signature to
    /// EVM r/s/v format with EIP-155 replay protection.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<Signature, BtcSignerError> {
        let (signature, recovery_id): (K256Signature, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(hash)
            .map_err(|e| BtcSignerError::SigningError(e.to_string()))?;

        let r = ethers::types::U256::from_big_endian(signature.r().to_bytes().as_slice());
        let s = ethers::types::U256::from_big_endian(signature.s().to_bytes().as_slice());

        // EIP-155: v = recovery_id + chain_id * 2 + 35
        let v = recovery_id.to_byte() as u64 + self.chain_id * 2 + 35;

        Ok(Signature { r, s, v })
    }

    /// Sign a message (will be hashed with keccak256 first).
    pub fn sign_message_bytes(&self, message: &[u8]) -> Result<Signature, BtcSignerError> {
        // Ethereum message signing uses the "\x19Ethereum Signed Message:\n" prefix
        let prefixed = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut data = prefixed.into_bytes();
        data.extend_from_slice(message);
        let hash = keccak256(&data);
        self.sign_hash(&hash)
    }

    /// Sign a MIDL transaction using BIP322/BIP143 signature scheme.
    ///
    /// The MIDL node validates signatures using BIP322 message signing with BIP143
    /// witness signature hash, not a simple keccak256. This method implements the
    /// exact signature scheme expected by the MIDL node.
    ///
    /// # Arguments
    /// * `rlp_hash` - The keccak256 hash of 0x07 || RLP([chainId, nonce, gasPrice, gas, to, value, data, btcTxHash, publicKey, btcAddressByte, accessList])
    ///
    /// # Returns
    /// An EVM-compatible signature with r, s, v values where v is the recovery ID (0 or 1) + 27.
    pub fn sign_midl_transaction(&self, rlp_hash: &[u8; 32]) -> Result<Signature, BtcSignerError> {
        // Step 1: Reconstruct the compressed public key (33 bytes)
        let mut compressed_pubkey = vec![self.btc_address_byte];
        compressed_pubkey.extend_from_slice(&self.public_key_32);

        // Step 2: Compute P2WPKH scriptPubKey
        // pubkeyHash = RIPEMD160(SHA256(compressedPubKey))
        let pubkey_hash = hash160(&compressed_pubkey);
        // scriptPubKey = OP_0 || PUSH(20) || pubkeyHash = 0x0014 || pubkeyHash
        let script_pubkey = Self::build_p2wpkh_script_pubkey(&pubkey_hash);

        // Step 3: Create BIP322 message hash
        // message = rlpHash.toHexString() (with "0x" prefix)
        let message = format!("0x{}", hex::encode(rlp_hash));
        let message_hash = Self::bip322_message_hash(message.as_bytes());

        // Step 4: Create "toSpend" virtual transaction and compute its txid
        let to_spend_txid = Self::create_to_spend_txid(&message_hash, &script_pubkey);

        // Step 5: Compute BIP143 witness signature hash for "toSign" transaction
        let sighash =
            Self::compute_bip143_sighash_for_bip322(&to_spend_txid, &script_pubkey, &pubkey_hash);

        debug!(
            rlp_hash = %hex::encode(rlp_hash),
            message = %message,
            message_hash = %hex::encode(&message_hash),
            to_spend_txid = %hex::encode(&to_spend_txid),
            sighash = %hex::encode(&sighash),
            "Computed BIP322/BIP143 sighash for MIDL transaction"
        );

        // Step 6: Sign with ECDSA
        let (signature, recovery_id): (K256Signature, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(&sighash)
            .map_err(|e| BtcSignerError::SigningError(e.to_string()))?;

        let r = ethers::types::U256::from_big_endian(signature.r().to_bytes().as_slice());
        let s = ethers::types::U256::from_big_endian(signature.s().to_bytes().as_slice());

        // Use EIP-155 style v value: recovery_id + chain_id * 2 + 35
        // The normalize_v function in ethers will convert this back to 0/1 for RLP encoding
        // which is what the MIDL node expects (raw recovery ID)
        let v = recovery_id.to_byte() as u64 + self.chain_id * 2 + 35;

        Ok(Signature { r, s, v })
    }

    /// Build P2WPKH scriptPubKey: OP_0 PUSH(20) <pubkey_hash>
    fn build_p2wpkh_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
        let mut script = Vec::with_capacity(22);
        script.push(0x00); // OP_0 (witness version 0)
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(pubkey_hash);
        script
    }

    /// Compute BIP322 tagged hash for message signing.
    ///
    /// messageHash = SHA256(SHA256("BIP0322-signed-message") || SHA256("BIP0322-signed-message") || message)
    fn bip322_message_hash(message: &[u8]) -> [u8; 32] {
        let tag = b"BIP0322-signed-message";
        let tag_hash = Sha256::digest(tag);

        let mut hasher = Sha256::new();
        hasher.update(&tag_hash);
        hasher.update(&tag_hash);
        hasher.update(message);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Create "toSpend" virtual transaction and return its txid.
    ///
    /// toSpend structure:
    /// - version: 0
    /// - inputs: [{ prevOut: 0x00...00:0xFFFFFFFF, scriptSig: OP_0 || messageHash, sequence: 0 }]
    /// - outputs: [{ value: 0, scriptPubKey: scriptPubKey }]
    /// - locktime: 0
    fn create_to_spend_txid(message_hash: &[u8; 32], script_pubkey: &[u8]) -> [u8; 32] {
        let mut tx = Vec::new();

        // Version (0)
        tx.extend_from_slice(&0u32.to_le_bytes());

        // Input count (1)
        tx.push(0x01);

        // Input prevOut: 32 zero bytes (txid)
        tx.extend_from_slice(&[0u8; 32]);
        // Input prevOut: 0xFFFFFFFF (vout)
        tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        // scriptSig: OP_0 || PUSH(32) || messageHash
        let script_sig_len = 1 + 1 + 32; // OP_0 + push opcode + 32 bytes
        tx.push(script_sig_len as u8);
        tx.push(0x00); // OP_0
        tx.push(0x20); // Push 32 bytes
        tx.extend_from_slice(message_hash);

        // Sequence (0)
        tx.extend_from_slice(&0u32.to_le_bytes());

        // Output count (1)
        tx.push(0x01);

        // Output value (0)
        tx.extend_from_slice(&0u64.to_le_bytes());

        // Output scriptPubKey
        tx.push(script_pubkey.len() as u8);
        tx.extend_from_slice(script_pubkey);

        // Locktime (0)
        tx.extend_from_slice(&0u32.to_le_bytes());

        // Compute double SHA256 for txid
        Self::double_sha256(&tx)
    }

    /// Compute BIP143 witness signature hash for BIP322 "toSign" transaction.
    ///
    /// toSign structure:
    /// - version: 0
    /// - inputs: [{ prevOut: toSpend.txid():0, scriptSig: empty, sequence: 0 }]
    /// - outputs: [{ value: 0, scriptPubKey: OP_RETURN }]
    /// - locktime: 0
    ///
    /// BIP143 sighash computation for P2WPKH witness program.
    fn compute_bip143_sighash_for_bip322(
        to_spend_txid: &[u8; 32],
        _script_pubkey: &[u8],
        pubkey_hash: &[u8; 20],
    ) -> [u8; 32] {
        // BIP143 sighash preimage components:
        // 1. nVersion
        // 2. hashPrevouts
        // 3. hashSequence
        // 4. outpoint (txid + vout)
        // 5. scriptCode
        // 6. value
        // 7. nSequence
        // 8. hashOutputs
        // 9. nLockTime
        // 10. sighash type

        let mut preimage = Vec::new();

        // 1. nVersion (0 for BIP322)
        preimage.extend_from_slice(&0u32.to_le_bytes());

        // 2. hashPrevouts - double SHA256 of outpoint
        let mut prevouts = Vec::new();
        // txid is already in internal byte order (needs to be reversed for display but not for hashing)
        prevouts.extend_from_slice(to_spend_txid);
        prevouts.extend_from_slice(&0u32.to_le_bytes()); // vout = 0
        let hash_prevouts = Self::double_sha256(&prevouts);
        preimage.extend_from_slice(&hash_prevouts);

        // 3. hashSequence - double SHA256 of sequence
        let sequence = 0u32.to_le_bytes();
        let hash_sequence = Self::double_sha256(&sequence);
        preimage.extend_from_slice(&hash_sequence);

        // 4. outpoint being signed
        preimage.extend_from_slice(to_spend_txid);
        preimage.extend_from_slice(&0u32.to_le_bytes()); // vout = 0

        // 5. scriptCode for P2WPKH: OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut script_code = Vec::new();
        script_code.push(0x19); // Length of script (25 bytes)
        script_code.push(0x76); // OP_DUP
        script_code.push(0xa9); // OP_HASH160
        script_code.push(0x14); // Push 20 bytes
        script_code.extend_from_slice(pubkey_hash);
        script_code.push(0x88); // OP_EQUALVERIFY
        script_code.push(0xac); // OP_CHECKSIG
        preimage.extend_from_slice(&script_code);

        // 6. value (0 for BIP322)
        preimage.extend_from_slice(&0u64.to_le_bytes());

        // 7. nSequence (0 for BIP322)
        preimage.extend_from_slice(&sequence);

        // 8. hashOutputs - double SHA256 of outputs
        // toSign has one output: value=0, scriptPubKey=OP_RETURN (0x6a)
        let mut outputs = Vec::new();
        outputs.extend_from_slice(&0u64.to_le_bytes()); // value = 0
        outputs.push(0x01); // scriptPubKey length = 1
        outputs.push(0x6a); // OP_RETURN
        let hash_outputs = Self::double_sha256(&outputs);
        preimage.extend_from_slice(&hash_outputs);

        // 9. nLockTime (0)
        preimage.extend_from_slice(&0u32.to_le_bytes());

        // 10. sighash type (SIGHASH_ALL = 0x01)
        preimage.extend_from_slice(&1u32.to_le_bytes());

        // Final sighash is double SHA256 of preimage
        Self::double_sha256(&preimage)
    }

    /// Compute double SHA256 hash.
    fn double_sha256(data: &[u8]) -> [u8; 32] {
        let hash1 = Sha256::digest(data);
        let hash2 = Sha256::digest(hash1);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash2);
        result
    }
}

#[async_trait]
impl Signer for BtcSigner {
    type Error = WalletError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        self.sign_message_bytes(message.as_ref())
            .map_err(|e| WalletError::Eip712Error(e.to_string()))
    }

    async fn sign_transaction(&self, tx: &TypedTransaction) -> Result<Signature, Self::Error> {
        // For MIDL transactions, use BIP322/BIP143 signature scheme
        if let TypedTransaction::Midl(_) = tx {
            // The sighash() for MIDL transactions returns keccak256(0x07 || RLP([...]))
            // which is exactly the baseBTCHash we need for BIP322 signing
            let rlp_hash = tx.sighash();
            return self
                .sign_midl_transaction(rlp_hash.as_fixed_bytes())
                .map_err(|e| WalletError::Eip712Error(e.to_string()));
        }

        // For other transaction types, use standard keccak256 signing
        let sighash = tx.sighash();
        self.sign_hash(sighash.as_fixed_bytes())
            .map_err(|e| WalletError::Eip712Error(e.to_string()))
    }

    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, Self::Error> {
        let hash = payload
            .encode_eip712()
            .map_err(|e| WalletError::Eip712Error(e.to_string()))?;
        self.sign_hash(&hash)
            .map_err(|e| WalletError::Eip712Error(e.to_string()))
    }

    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn with_chain_id<T: Into<u64>>(mut self, chain_id: T) -> Self {
        self.chain_id = chain_id.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btc_signer_creation() {
        // Test private key (DO NOT USE IN PRODUCTION)
        let private_key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let signer = BtcSigner::new(
            &private_key,
            BtcAddressType::P2WPKH,
            BitcoinNetwork::Regtest,
            1,
        )
        .unwrap();

        // Verify public key is 32 bytes
        assert_eq!(signer.public_key_32().len(), 32);

        // Verify address is valid
        assert_ne!(signer.address(), Address::zero());

        // Verify BTC address byte is valid (0x02 or 0x03 for compressed pubkey)
        let byte = signer.btc_address_byte();
        assert!(byte == 0x02 || byte == 0x03);

        // Verify Bitcoin address starts with correct prefix
        assert!(signer.bitcoin_address().starts_with("bcrt1"));
    }

    #[test]
    fn test_btc_signer_from_hex() {
        let hex_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

        let signer1 =
            BtcSigner::from_hex(hex_key, BtcAddressType::P2WPKH, BitcoinNetwork::Mainnet, 1)
                .unwrap();
        let signer2 = BtcSigner::from_hex(
            &format!("0x{}", hex_key),
            BtcAddressType::P2WPKH,
            BitcoinNetwork::Mainnet,
            1,
        )
        .unwrap();

        assert_eq!(signer1.address(), signer2.address());
        assert_eq!(signer1.bitcoin_address(), signer2.bitcoin_address());
        assert!(signer1.bitcoin_address().starts_with("bc1"));
    }

    #[test]
    fn test_btc_address_byte_types() {
        let private_key = [0x42u8; 32];

        let p2wpkh = BtcSigner::new(
            &private_key,
            BtcAddressType::P2WPKH,
            BitcoinNetwork::Testnet,
            1,
        )
        .unwrap();
        let p2sh = BtcSigner::new(
            &private_key,
            BtcAddressType::P2SH_P2WPKH,
            BitcoinNetwork::Testnet,
            1,
        )
        .unwrap();
        let p2tr = BtcSigner::new(
            &private_key,
            BtcAddressType::P2TR,
            BitcoinNetwork::Testnet,
            1,
        )
        .unwrap();

        // P2SH_P2WPKH should have address byte + 2
        assert_eq!(p2sh.btc_address_byte(), p2wpkh.btc_address_byte() + 2);

        // P2TR should have address byte 0
        assert_eq!(p2tr.btc_address_byte(), 0);

        // P2WPKH and P2SH_P2WPKH should have tb1q prefix (version 0)
        assert!(p2wpkh.bitcoin_address().starts_with("tb1q"));
        assert!(p2sh.bitcoin_address().starts_with("tb1q"));
        // P2TR should have tb1p prefix (version 1)
        assert!(p2tr.bitcoin_address().starts_with("tb1p"));
    }

    #[test]
    fn test_bitcoin_address_networks() {
        let private_key = [0x42u8; 32];

        let mainnet = BtcSigner::new(
            &private_key,
            BtcAddressType::P2WPKH,
            BitcoinNetwork::Mainnet,
            1,
        )
        .unwrap();
        let testnet = BtcSigner::new(
            &private_key,
            BtcAddressType::P2WPKH,
            BitcoinNetwork::Testnet,
            1,
        )
        .unwrap();
        let regtest = BtcSigner::new(
            &private_key,
            BtcAddressType::P2WPKH,
            BitcoinNetwork::Regtest,
            1,
        )
        .unwrap();
        let signet = BtcSigner::new(
            &private_key,
            BtcAddressType::P2WPKH,
            BitcoinNetwork::Signet,
            1,
        )
        .unwrap();

        assert!(mainnet.bitcoin_address().starts_with("bc1q"));
        assert!(testnet.bitcoin_address().starts_with("tb1q"));
        assert!(regtest.bitcoin_address().starts_with("bcrt1q"));
        assert!(signet.bitcoin_address().starts_with("tb1q"));
    }

    #[tokio::test]
    async fn test_sign_message() {
        let private_key = [0x42u8; 32];
        let signer = BtcSigner::new(
            &private_key,
            BtcAddressType::P2WPKH,
            BitcoinNetwork::Mainnet,
            1,
        )
        .unwrap();

        let message = b"Hello, MIDL!";
        let signature = signer.sign_message(message).await.unwrap();

        // Verify signature components are non-zero
        assert!(!signature.r.is_zero());
        assert!(!signature.s.is_zero());
        // v should be valid for EIP-155 (chain_id * 2 + 35 or chain_id * 2 + 36)
        assert!(signature.v == 37 || signature.v == 38); // chain_id=1
    }
}
