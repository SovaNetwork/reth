use crate::{DatabaseHashedCursorFactory, DatabaseRef, DatabaseTrieCursorFactory};
use alloy_primitives::{map::B256HashMap, Bytes};
use reth_execution_errors::TrieWitnessError;
use reth_trie::{
    hashed_cursor::HashedPostStateCursorFactory, trie_cursor::InMemoryTrieCursorFactory,
    witness::TrieWitness, HashedPostState, TrieInput,
};

extern crate alloc;
use alloc::sync::Arc;

/// Extends [`TrieWitness`] with operations specific for working with a database transaction.
pub trait DatabaseTrieWitness<Provider> {
    /// Create a new [`TrieWitness`] from database transaction.
    fn from_provider(provider: Arc<Provider>) -> Self;

    /// Generates trie witness for target state based on [`TrieInput`].
    fn overlay_witness(
        provider: Arc<Provider>,
        input: TrieInput,
        target: HashedPostState,
    ) -> Result<B256HashMap<Bytes>, TrieWitnessError>;
}

impl<Provider: DatabaseRef> DatabaseTrieWitness<Provider>
    for TrieWitness<DatabaseTrieCursorFactory<Provider>, DatabaseHashedCursorFactory<Provider>>
{
    fn from_provider(provider: Arc<Provider>) -> Self {
        Self::new(
            DatabaseTrieCursorFactory::new(provider.clone()),
            DatabaseHashedCursorFactory::new(provider),
        )
    }

    fn overlay_witness(
        provider: Arc<Provider>,
        input: TrieInput,
        target: HashedPostState,
    ) -> Result<B256HashMap<Bytes>, TrieWitnessError> {
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
            .compute(target)
    }
}
