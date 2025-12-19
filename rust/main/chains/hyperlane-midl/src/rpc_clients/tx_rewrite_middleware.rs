use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ethers::prelude::FromErr;
use ethers::providers::Middleware;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::U256;
use hyperlane_core::{ChainCommunicationError, H256};
use thiserror::Error;

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
                &self.metadata_provider.as_ref().map(|_| "<dyn MidlMetadataProvider>"),
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
}

fn extract_key(tx: &TypedTransaction) -> Option<TxKey> {
    let from = tx.from().copied()?;
    let nonce = tx.nonce().cloned()?;
    Some((from, nonce))
}