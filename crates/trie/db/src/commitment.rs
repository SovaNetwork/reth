use crate::{
    DatabaseHashedCursorFactory, DatabaseProof, DatabaseRef, DatabaseStateRoot,
    DatabaseStorageRoot, DatabaseTrieCursorFactory, DatabaseTrieWitness,
};
use reth_trie::{
    proof::Proof, witness::TrieWitness, KeccakKeyHasher, KeyHasher, StateRoot, StorageRoot,
};

/// The `StateCommitment` trait provides associated types for state commitment operations.
pub trait StateCommitment: std::fmt::Debug + Send + Sync + Unpin + 'static {
    /// The state root type.
    type StateRoot<Provider: DatabaseRef>: DatabaseStateRoot<Provider>;
    /// The storage root type.
    type StorageRoot<Provider: DatabaseRef>: DatabaseStorageRoot<Provider>;
    /// The state proof type.
    type StateProof<Provider: DatabaseRef>: DatabaseProof<Provider>;
    /// The state witness type.
    type StateWitness<Provider: DatabaseRef>: DatabaseTrieWitness<Provider>;
    /// The key hasher type.
    type KeyHasher: KeyHasher;
}

/// The state commitment type for Ethereum's Merkle Patricia Trie.
#[derive(Debug)]
#[non_exhaustive]
pub struct MerklePatriciaTrie;

impl StateCommitment for MerklePatriciaTrie {
    type StateRoot<Provider: DatabaseRef> =
        StateRoot<DatabaseTrieCursorFactory<Provider>, DatabaseHashedCursorFactory<Provider>>;
    type StorageRoot<Provider: DatabaseRef> =
        StorageRoot<DatabaseTrieCursorFactory<Provider>, DatabaseHashedCursorFactory<Provider>>;
    type StateProof<Provider: DatabaseRef> =
        Proof<DatabaseTrieCursorFactory<Provider>, DatabaseHashedCursorFactory<Provider>>;
    type StateWitness<Provider: DatabaseRef> =
        TrieWitness<DatabaseTrieCursorFactory<Provider>, DatabaseHashedCursorFactory<Provider>>;
    type KeyHasher = KeccakKeyHasher;
}
