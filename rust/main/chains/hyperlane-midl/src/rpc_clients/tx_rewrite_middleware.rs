use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ethers::prelude::FromErr;
use ethers::providers::{Middleware, PendingTransaction};
use ethers::types::transaction::{
    eip2718::TypedTransaction, eip2930::AccessListWithGasUsed, midl::MidlTransactionRequest,
};
use ethers::types::{BlockId, Bytes, TransactionRequest, H256, U256};
use hyperlane_core::{ChainCommunicationError, H256};
use rlp::Rlp;
use thiserror::Error;

type TxKey = (ethers::types::Address, U256);

/// Metadata required to convert an EVM write into a Midl submission.
#[derive(Clone, Debug)]
pub struct MidlPreparedMetadata {
    pub btc_tx_hash: H256,
    pub btc_transaction: Bytes,
    pub public_key: Bytes,
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

/// Middleware that rewrites legacy EVM transactions into Midl-aware payloads
/// and ensures the bundle is submitted alongside the BTC transaction hex.
#[derive(Debug)]
pub struct TxRewriteMiddleware<M>
where
    M: Middleware,
{
    inner: M,
    metadata_provider: Option<Arc<dyn MidlMetadataProvider>>,
    metadata_cache: Arc<Mutex<HashMap<TxKey, MidlPreparedMetadata>>>,
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
        self.metadata_cache.lock().ok().and_then(|mut guard| guard.remove(key))
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
    #[error("failed to decode signed transaction")]
    DecodeSigned(#[source] rlp::DecoderError),
    #[error("transaction missing from/nonce after rewrite")]
    MissingKey,
    #[error("no Midl metadata available for tx")]
    MissingMetadata,
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
        block: Option<BlockId>,
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
        rewrite_transaction(tx, &metadata);
        self.insert_metadata(key, metadata);
        Ok(())
    }

    async fn send_raw_transaction<'a>(
        &'a self,
        tx: Bytes,
    ) -> Result<PendingTransaction<'a, Self::Provider>, Self::Error> {
        let Some(_) = self.metadata_provider else {
            return self
                .inner
                .send_raw_transaction(tx)
                .await
                .map_err(TxRewriteMiddlewareError::from_inner);
        };

        let rlp = Rlp::new(tx.as_ref());
        let (typed, _) = TypedTransaction::decode_signed(&rlp)
            .map_err(TxRewriteMiddlewareError::DecodeSigned)?;
        if !matches!(typed, TypedTransaction::Midl(_)) {
            return self
                .inner
                .send_raw_transaction(tx)
                .await
                .map_err(TxRewriteMiddlewareError::from_inner);
        }

        let Some(key) = extract_key(&typed) else {
            return Err(TxRewriteMiddlewareError::MissingKey);
        };
        let metadata = self
            .remove_metadata(&key)
            .ok_or(TxRewriteMiddlewareError::MissingMetadata)?;

        let mut pending = self
            .inner
            .send_btc_transactions(vec![tx], metadata.btc_transaction.clone())
            .await
            .map_err(TxRewriteMiddlewareError::from_inner)?;
        pending
            .pop()
            .ok_or(TxRewriteMiddlewareError::MissingMetadata)
    }
    async fn call(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<Bytes, Self::Error> {
        let mut rewritten = tx.clone();
        ensure_midl_variant(&mut rewritten);
        self.inner
            .call(&rewritten, block)
            .await
            .map_err(TxRewriteMiddlewareError::from_inner)
    }

    async fn estimate_gas(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<U256, Self::Error> {
        let mut rewritten = tx.clone();
        ensure_midl_variant(&mut rewritten);
        self.inner
            .estimate_gas(&rewritten, block)
            .await
            .map_err(TxRewriteMiddlewareError::from_inner)
    }

    async fn create_access_list(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<AccessListWithGasUsed, Self::Error> {
        let mut rewritten = tx.clone();
        ensure_midl_variant(&mut rewritten);
        self.inner
            .create_access_list(&rewritten, block)
            .await
            .map_err(TxRewriteMiddlewareError::from_inner)
    }
}

fn extract_key(tx: &TypedTransaction) -> Option<TxKey> {
    let from = tx.from().copied()?;
    let nonce = tx.nonce().cloned()?;
    Some((from, nonce))
}

fn rewrite_transaction(tx: &mut TypedTransaction, metadata: &MidlPreparedMetadata) {
    let mut midl_request = convert_to_midl(tx);
    midl_request.btc_tx_hash = Some(metadata.btc_tx_hash);
    midl_request.public_key = Some(metadata.public_key.clone());
    midl_request.btc_address_byte = Some(metadata.btc_address_byte);
    *tx = TypedTransaction::Midl(midl_request);
}

fn ensure_midl_variant(tx: &mut TypedTransaction) {
    if matches!(tx, TypedTransaction::Midl(_)) {
        return;
    }
    *tx = TypedTransaction::Midl(convert_to_midl(tx));
}

fn convert_to_midl(tx: &TypedTransaction) -> MidlTransactionRequest {
    match tx {
        TypedTransaction::Midl(inner) => inner.clone(),
        TypedTransaction::Legacy(req) => req.clone().into_midl(),
        TypedTransaction::Eip2930(req) => req.tx.clone().into_midl(),
        TypedTransaction::Eip1559(req) => {
            let legacy: TransactionRequest = req.clone().into();
            legacy.into_midl()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::{
        transaction::eip1559::Eip1559TransactionRequest, Address, TransactionRequest,
    };

    fn sample_metadata() -> MidlPreparedMetadata {
        MidlPreparedMetadata {
            btc_tx_hash: H256::repeat_byte(0xaa),
            btc_transaction: Bytes::from_static(&[1, 2, 3]),
            public_key: Bytes::from(vec![0xbb; 32]),
            btc_address_byte: U256::from(5),
        }
    }

    #[test]
    fn rewrite_legacy_tx() {
        let mut tx = TypedTransaction::Legacy(
            TransactionRequest::new()
                .from(Address::zero())
                .chain_id(1u64)
                .nonce(1u64),
        );
        let metadata = sample_metadata();

        rewrite_transaction(&mut tx, &metadata);

        match tx {
            TypedTransaction::Midl(inner) => {
                assert_eq!(inner.btc_tx_hash, Some(metadata.btc_tx_hash));
                assert_eq!(inner.public_key, Some(metadata.public_key.clone()));
                assert_eq!(inner.btc_address_byte, Some(metadata.btc_address_byte));
            }
            _ => panic!("expected midl transaction"),
        }
    }

    #[test]
    fn rewrite_eip1559_tx_preserves_chain_id() {
        let mut tx = TypedTransaction::Eip1559(
            Eip1559TransactionRequest::new()
                .from(Address::zero())
                .chain_id(10u64)
                .nonce(9u64),
        );
        let metadata = sample_metadata();

        rewrite_transaction(&mut tx, &metadata);

        match tx {
            TypedTransaction::Midl(inner) => {
                assert_eq!(inner.tx.chain_id, Some(10u64.into()));
                assert_eq!(inner.tx.nonce, Some(9u64.into()));
            }
            _ => panic!("expected midl transaction"),
        }
    }

    #[test]
    fn ensure_midl_variant_upgrades_legacy_txs() {
        let mut tx = TypedTransaction::Legacy(
            TransactionRequest::new()
                .from(Address::zero())
                .chain_id(5u64)
                .nonce(2u64),
        );
        ensure_midl_variant(&mut tx);

        match tx {
            TypedTransaction::Midl(inner) => {
                assert_eq!(inner.tx.chain_id, Some(5u64.into()));
                assert_eq!(inner.tx.nonce, Some(2u64.into()));
            }
            other => panic!("expected midl transaction, got {other:?}"),
        }
    }
}

