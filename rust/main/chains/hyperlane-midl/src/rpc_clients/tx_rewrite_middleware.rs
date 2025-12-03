use std::fmt::Debug;

use async_trait::async_trait;
use ethers::prelude::FromErr;
use ethers::providers::{Middleware, PendingTransaction};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::BlockId;
use thiserror::Error;

/// Middleware placeholder that will eventually rewrite how "write" transactions
/// are constructed and signed. For now it is a no-op wrapper that delegates to
/// the inner middleware so we can slot it into the stack without changing
/// behaviour.
#[derive(Debug)]
pub struct TxRewriteMiddleware<M>
where
    M: Middleware,
{
    inner: M,
}

impl<M> TxRewriteMiddleware<M>
where
    M: Middleware,
{
    /// Create a new middleware layer that forwards calls to `inner`.
    pub fn new(inner: M) -> Self {
        Self { inner }
    }

    /// Consume the wrapper and return the inner middleware.
    pub fn into_inner(self) -> M {
        self.inner
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

    /// Hook point for future transaction-shaping logic. Currently just forwards
    /// to the inner middleware untouched.
    async fn fill_transaction(
        &self,
        tx: &mut TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<(), Self::Error> {
        self.inner
            .fill_transaction(tx, block)
            .await
            .map_err(TxRewriteMiddlewareError::from_inner)
    }

    /// Hook point for future custom signing/submission logic while delegating
    /// to the inner middleware for now.
    async fn send_transaction<T: Into<TypedTransaction> + Send + Sync>(
        &self,
        tx: T,
        block: Option<BlockId>,
    ) -> Result<PendingTransaction<'_, Self::Provider>, Self::Error> {
        self.inner
            .send_transaction(tx, block)
            .await
            .map_err(TxRewriteMiddlewareError::from_inner)
    }
}

