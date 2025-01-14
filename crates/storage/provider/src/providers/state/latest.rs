use crate::{
    providers::state::macros::delegate_provider_impls, AccountReader, BlockHashReader,
    HashedPostStateProvider, StateProvider, StateRootProvider,
};
use alloy_primitives::{
    map::B256HashMap, Address, BlockNumber, Bytes, StorageKey, StorageValue, B256,
};
use reth_db::tables;
use reth_db_api::{cursor::DbDupCursorRO, transaction::DbTx};
use reth_primitives::{Account, Bytecode};
use reth_storage_api::{
    DBProvider, StateCommitmentProvider, StateProofProvider, StorageRootProvider,
};
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use reth_trie::{
    proof::{Proof, StorageProof},
    updates::TrieUpdates,
    witness::TrieWitness,
    AccountProof, HashedPostState, HashedStorage, MultiProof, MultiProofTargets, StateRoot,
    StorageMultiProof, StorageRoot, TrieInput,
};
use reth_trie_db::{
    DatabaseProof, DatabaseRef, DatabaseStateRoot, DatabaseStorageProof, DatabaseStorageRoot,
    DatabaseTrieWitness, StateCommitment,
};

extern crate alloc;
use alloc::sync::Arc;

/// State provider over latest state that takes tx reference.
///
/// Wraps a [`DBProvider`] to get access to database.
#[derive(Debug)]
pub struct LatestStateProviderRef<Provider>(Arc<Provider>);

impl<Provider: DBProvider> LatestStateProviderRef<Provider> {
    /// Create new state provider
    pub const fn new(provider: Arc<Provider>) -> Self {
        Self(provider)
    }

    fn tx(&self) -> &Provider::Tx {
        self.0.tx_ref()
    }
}

impl<Provider: DBProvider> AccountReader for LatestStateProviderRef<Provider> {
    /// Get basic account information.
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.tx().get_by_encoded_key::<tables::PlainAccountState>(address).map_err(Into::into)
    }
}

impl<Provider: BlockHashReader> BlockHashReader for LatestStateProviderRef<Provider> {
    /// Get block hash by number.
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.0.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.0.canonical_hashes_range(start, end)
    }
}

impl<Provider: DBProvider + StateCommitmentProvider + DatabaseRef> StateRootProvider
    for LatestStateProviderRef<Provider>
{
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        StateRoot::overlay_root(self.0.clone(), hashed_state)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        StateRoot::overlay_root_from_nodes(self.0.clone(), input)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        StateRoot::overlay_root_with_updates(self.0.clone(), hashed_state)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        StateRoot::overlay_root_from_nodes_with_updates(self.0.clone(), input)
            .map_err(|err| ProviderError::Database(err.into()))
    }
}

impl<Provider: DBProvider + StateCommitmentProvider + DatabaseRef> StorageRootProvider
    for LatestStateProviderRef<Provider>
{
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        StorageRoot::overlay_root(self.0.clone(), address, hashed_storage)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<reth_trie::StorageProof> {
        StorageProof::overlay_storage_proof(self.0.clone(), address, slot, hashed_storage)
            .map_err(ProviderError::from)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        StorageProof::overlay_storage_multiproof(self.0.clone(), address, slots, hashed_storage)
            .map_err(ProviderError::from)
    }
}

impl<Provider: DBProvider + StateCommitmentProvider + DatabaseRef> StateProofProvider
    for LatestStateProviderRef<Provider>
{
    fn proof(
        &self,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        Proof::overlay_account_proof(self.0.clone(), input, address, slots)
            .map_err(ProviderError::from)
    }

    fn multiproof(
        &self,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        Proof::overlay_multiproof(self.0.clone(), input, targets).map_err(ProviderError::from)
    }

    fn witness(
        &self,
        input: TrieInput,
        target: HashedPostState,
    ) -> ProviderResult<B256HashMap<Bytes>> {
        TrieWitness::overlay_witness(self.0.clone(), input, target).map_err(ProviderError::from)
    }
}

impl<Provider: DBProvider + StateCommitmentProvider> HashedPostStateProvider
    for LatestStateProviderRef<Provider>
{
    fn hashed_post_state(&self, bundle_state: &revm::db::BundleState) -> HashedPostState {
        HashedPostState::from_bundle_state::<
            <Provider::StateCommitment as StateCommitment>::KeyHasher,
        >(bundle_state.state())
    }
}

impl<Provider: DBProvider + BlockHashReader + StateCommitmentProvider + DatabaseRef> StateProvider
    for LatestStateProviderRef<Provider>
{
    /// Get storage.
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        let mut cursor = self.tx().cursor_dup_read::<tables::PlainStorageState>()?;
        if let Some(entry) = cursor.seek_by_key_subkey(account, storage_key)? {
            if entry.key == storage_key {
                return Ok(Some(entry.value))
            }
        }
        Ok(None)
    }

    /// Get account code by its hash
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.tx().get_by_encoded_key::<tables::Bytecodes>(code_hash).map_err(Into::into)
    }
}

impl<Provider: StateCommitmentProvider> StateCommitmentProvider
    for LatestStateProviderRef<Provider>
{
    type StateCommitment = Provider::StateCommitment;
}

/// State provider for the latest state.
#[derive(Debug)]
pub struct LatestStateProvider<Provider>(Arc<Provider>);

impl<Provider: DBProvider + StateCommitmentProvider> LatestStateProvider<Provider> {
    /// Create new state provider
    pub const fn new(db: Arc<Provider>) -> Self {
        Self(db)
    }

    /// Returns a new provider that takes the `TX` as reference
    #[inline(always)]
    fn as_ref(&self) -> LatestStateProviderRef<Provider> {
        LatestStateProviderRef::new(self.0.clone())
    }
}

impl<Provider: DatabaseRef> DatabaseRef for LatestStateProvider<Provider> {
    type Tx = Provider::Tx;

    fn tx_reference(&self) -> &Self::Tx {
        self.0.tx_reference()
    }
}

impl<Provider: StateCommitmentProvider> StateCommitmentProvider for LatestStateProvider<Provider> {
    type StateCommitment = Provider::StateCommitment;
}

// Delegates all provider impls to [LatestStateProviderRef]
delegate_provider_impls!(LatestStateProvider<Provider> where [Provider: DBProvider + BlockHashReader + StateCommitmentProvider + DatabaseRef]);

#[cfg(test)]
mod tests {
    use super::*;

    const fn assert_state_provider<T: StateProvider>() {}
    #[allow(dead_code)]
    const fn assert_latest_state_provider<
        T: DBProvider + BlockHashReader + StateCommitmentProvider + DatabaseRef,
    >() {
        assert_state_provider::<LatestStateProvider<T>>();
    }
}
