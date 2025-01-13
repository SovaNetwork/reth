use crate::{DatabaseHashedCursorFactory, DatabaseRef, DatabaseTrieCursorFactory};
use alloy_primitives::{keccak256, map::HashMap, Address, B256};
use reth_execution_errors::StateProofError;
use reth_trie::{
    hashed_cursor::HashedPostStateCursorFactory,
    proof::{Proof, StorageProof},
    trie_cursor::InMemoryTrieCursorFactory,
    AccountProof, HashedPostStateSorted, HashedStorage, MultiProof, MultiProofTargets,
    StorageMultiProof, TrieInput,
};

extern crate alloc;
use alloc::sync::Arc;

/// Extends [`Proof`] with operations specific for working with a database transaction.
pub trait DatabaseProof<Provider> {
    /// Create a new [Proof] from database transaction.
    fn from_provider(provider: Arc<Provider>) -> Self;

    /// Generates the state proof for target account based on [`TrieInput`].
    fn overlay_account_proof(
        provider: Arc<Provider>,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> Result<AccountProof, StateProofError>;

    /// Generates the state [`MultiProof`] for target hashed account and storage keys.
    fn overlay_multiproof(
        provider: Arc<Provider>,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> Result<MultiProof, StateProofError>;
}

impl<Provider: DatabaseRef> DatabaseProof<Provider>
    for Proof<DatabaseTrieCursorFactory<Provider>, DatabaseHashedCursorFactory<Provider>>
{
    /// Create a new [Proof] instance from database provider.
    fn from_provider(provider: Arc<Provider>) -> Self {
        Self::new(
            Arc::new(DatabaseTrieCursorFactory::new(provider.clone())),
            Arc::new(DatabaseHashedCursorFactory::new(provider)),
        )
    }

    fn overlay_account_proof(
        provider: Arc<Provider>,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> Result<AccountProof, StateProofError> {
        let nodes_sorted = input.nodes.into_sorted();
        let state_sorted = input.state.into_sorted();
        Self::from_provider(provider.clone())
            .with_trie_cursor_factory(InMemoryTrieCursorFactory::new(
                DatabaseTrieCursorFactory::new(provider.clone()),
                Arc::new(nodes_sorted),
            ))
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(provider),
                Arc::new(state_sorted),
            ))
            .with_prefix_sets_mut(input.prefix_sets)
            .account_proof(address, slots)
    }

    fn overlay_multiproof(
        provider: Arc<Provider>,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> Result<MultiProof, StateProofError> {
        let nodes_sorted = input.nodes.into_sorted();
        let state_sorted = input.state.into_sorted();
        Self::from_provider(provider.clone())
            .with_trie_cursor_factory(InMemoryTrieCursorFactory::new(
                DatabaseTrieCursorFactory::new(provider.clone()),
                Arc::new(nodes_sorted),
            ))
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(provider),
                Arc::new(state_sorted),
            ))
            .with_prefix_sets_mut(input.prefix_sets)
            .multiproof(targets)
    }
}

/// Extends [`StorageProof`] with operations specific for working with a database transaction.
pub trait DatabaseStorageProof<Provider> {
    /// Create a new [`StorageProof`] from database transaction and account address.
    fn from_provider(provider: Arc<Provider>, address: Address) -> Self;

    /// Generates the storage proof for target slot based on [`TrieInput`].
    fn overlay_storage_proof(
        provider: Arc<Provider>,
        address: Address,
        slot: B256,
        storage: HashedStorage,
    ) -> Result<reth_trie::StorageProof, StateProofError>;

    /// Generates the storage multiproof for target slots based on [`TrieInput`].
    fn overlay_storage_multiproof(
        provider: Arc<Provider>,
        address: Address,
        slots: &[B256],
        storage: HashedStorage,
    ) -> Result<StorageMultiProof, StateProofError>;
}

impl<Provider: DatabaseRef> DatabaseStorageProof<Provider>
    for StorageProof<DatabaseTrieCursorFactory<Provider>, DatabaseHashedCursorFactory<Provider>>
{
    fn from_provider(provider: Arc<Provider>, address: Address) -> Self {
        Self::new(
            Arc::new(DatabaseTrieCursorFactory::new(provider.clone())),
            Arc::new(DatabaseHashedCursorFactory::new(provider)),
            address,
        )
    }

    fn overlay_storage_proof(
        provider: Arc<Provider>,
        address: Address,
        slot: B256,
        storage: HashedStorage,
    ) -> Result<reth_trie::StorageProof, StateProofError> {
        let hashed_address = keccak256(address);
        let prefix_set = storage.construct_prefix_set();
        let state_sorted = HashedPostStateSorted::new(
            Default::default(),
            HashMap::from_iter([(hashed_address, storage.into_sorted())]),
        );
        Self::from_provider(provider.clone(), address)
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(provider),
                Arc::new(state_sorted),
            ))
            .with_prefix_set_mut(prefix_set)
            .storage_proof(slot)
    }

    fn overlay_storage_multiproof(
        provider: Arc<Provider>,
        address: Address,
        slots: &[B256],
        storage: HashedStorage,
    ) -> Result<StorageMultiProof, StateProofError> {
        let hashed_address = keccak256(address);
        let targets = slots.iter().map(keccak256).collect();
        let prefix_set = storage.construct_prefix_set();
        let state_sorted = HashedPostStateSorted::new(
            Default::default(),
            HashMap::from_iter([(hashed_address, storage.into_sorted())]),
        );
        Self::from_provider(provider.clone(), address)
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(provider),
                Arc::new(state_sorted),
            ))
            .with_prefix_set_mut(prefix_set)
            .storage_multiproof(targets)
    }
}
