use crate::DatabaseRef;
use alloy_primitives::{B256, U256};
use reth_db::tables;
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    transaction::DbTx,
};
use reth_primitives::Account;
use reth_trie::hashed_cursor::{HashedCursor, HashedCursorFactory, HashedStorageCursor};

extern crate alloc;
use alloc::sync::Arc;

/// A struct wrapping database transaction that implements [`HashedCursorFactory`].
#[derive(Debug)]
pub struct DatabaseHashedCursorFactory<Provider> {
    provider: Arc<Provider>,
}

impl<Provider> Clone for DatabaseHashedCursorFactory<Provider> {
    fn clone(&self) -> Self {
        Self { provider: self.provider.clone() }
    }
}

impl<Provider> DatabaseHashedCursorFactory<Provider> {
    /// Create new database hashed cursor factory.
    pub const fn new(provider: Arc<Provider>) -> Self {
        Self { provider }
    }
}

impl<Provider: DatabaseRef> HashedCursorFactory for DatabaseHashedCursorFactory<Provider> {
    type AccountCursor =
        DatabaseHashedAccountCursor<<Provider::Tx as DbTx>::Cursor<tables::HashedAccounts>>;
    type StorageCursor =
        DatabaseHashedStorageCursor<<Provider::Tx as DbTx>::DupCursor<tables::HashedStorages>>;

    fn hashed_account_cursor(&self) -> Result<Self::AccountCursor, reth_db::DatabaseError> {
        Ok(DatabaseHashedAccountCursor(
            self.provider.tx_reference().cursor_read::<tables::HashedAccounts>()?,
        ))
    }

    fn hashed_storage_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageCursor, reth_db::DatabaseError> {
        Ok(DatabaseHashedStorageCursor::new(
            self.provider.tx_reference().cursor_dup_read::<tables::HashedStorages>()?,
            hashed_address,
        ))
    }
}

/// A struct wrapping database cursor over hashed accounts implementing [`HashedCursor`] for
/// iterating over accounts.
#[derive(Debug)]
pub struct DatabaseHashedAccountCursor<C>(C);

impl<C> DatabaseHashedAccountCursor<C> {
    /// Create new database hashed account cursor.
    pub const fn new(cursor: C) -> Self {
        Self(cursor)
    }
}

impl<C> HashedCursor for DatabaseHashedAccountCursor<C>
where
    C: DbCursorRO<tables::HashedAccounts>,
{
    type Value = Account;

    fn seek(&mut self, key: B256) -> Result<Option<(B256, Self::Value)>, reth_db::DatabaseError> {
        self.0.seek(key)
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, reth_db::DatabaseError> {
        self.0.next()
    }
}

/// The structure wrapping a database cursor for hashed storage and
/// a target hashed address. Implements [`HashedCursor`] and [`HashedStorageCursor`]
/// for iterating over hashed storage.
#[derive(Debug)]
pub struct DatabaseHashedStorageCursor<C> {
    /// Database hashed storage cursor.
    cursor: C,
    /// Target hashed address of the account that the storage belongs to.
    hashed_address: B256,
}

impl<C> DatabaseHashedStorageCursor<C> {
    /// Create new [`DatabaseHashedStorageCursor`].
    pub const fn new(cursor: C, hashed_address: B256) -> Self {
        Self { cursor, hashed_address }
    }
}

impl<C> HashedCursor for DatabaseHashedStorageCursor<C>
where
    C: DbCursorRO<tables::HashedStorages> + DbDupCursorRO<tables::HashedStorages>,
{
    type Value = U256;

    fn seek(
        &mut self,
        subkey: B256,
    ) -> Result<Option<(B256, Self::Value)>, reth_db::DatabaseError> {
        Ok(self.cursor.seek_by_key_subkey(self.hashed_address, subkey)?.map(|e| (e.key, e.value)))
    }

    fn next(&mut self) -> Result<Option<(B256, Self::Value)>, reth_db::DatabaseError> {
        Ok(self.cursor.next_dup_val()?.map(|e| (e.key, e.value)))
    }
}

impl<C> HashedStorageCursor for DatabaseHashedStorageCursor<C>
where
    C: DbCursorRO<tables::HashedStorages> + DbDupCursorRO<tables::HashedStorages>,
{
    fn is_storage_empty(&mut self) -> Result<bool, reth_db::DatabaseError> {
        Ok(self.cursor.seek_exact(self.hashed_address)?.is_none())
    }
}
