use crate::{root::ParallelStateRootError, stats::ParallelTrieTracker, StorageRootTargets};
use alloy_primitives::{
    map::{B256HashMap, HashMap, HashSet},
    B256,
};
use alloy_rlp::{BufMut, Encodable};
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use reth_db::DatabaseError;
use reth_execution_errors::StorageRootError;
use reth_provider::{
    providers::ConsistentDbView, BlockReader, DBProvider, DatabaseProviderFactory, ProviderError,
    ProviderResult, StateCommitmentProvider,
};
use reth_trie::{
    hashed_cursor::{HashedCursorFactory, HashedPostStateCursorFactory},
    node_iter::{TrieElement, TrieNodeIter},
    prefix_set::{PrefixSetMut, TriePrefixSetsMut},
    proof::StorageProof,
    trie_cursor::{InMemoryTrieCursorFactory, TrieCursorFactory},
    walker::TrieWalker,
    HashBuilder, MultiProof, Nibbles, StorageMultiProof, TrieAccount, TrieInput,
    TRIE_ACCOUNT_RLP_MAX_SIZE,
};
use reth_trie_common::proof::ProofRetainer;
use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
use std::sync::Arc;
use tracing::debug;

#[cfg(feature = "metrics")]
use crate::metrics::ParallelStateRootMetrics;

/// TODO:
#[derive(Debug)]
pub struct ParallelProof<Factory> {
    /// Consistent view of the database.
    view: ConsistentDbView<Factory>,
    /// Trie input.
    input: Arc<TrieInput>,
    /// Flag indicating whether to include branch node hash masks in the proof.
    collect_branch_node_hash_masks: bool,
    /// Parallel state root metrics.
    #[cfg(feature = "metrics")]
    metrics: ParallelStateRootMetrics,
}

impl<Factory> ParallelProof<Factory> {
    /// Create new state proof generator.
    pub fn new(view: ConsistentDbView<Factory>, input: Arc<TrieInput>) -> Self {
        Self {
            view,
            input,
            collect_branch_node_hash_masks: false,
            #[cfg(feature = "metrics")]
            metrics: ParallelStateRootMetrics::default(),
        }
    }

    /// Set the flag indicating whether to include branch node hash masks in the proof.
    pub const fn with_branch_node_hash_masks(mut self, branch_node_hash_masks: bool) -> Self {
        self.collect_branch_node_hash_masks = branch_node_hash_masks;
        self
    }
}

impl<Factory> ParallelProof<Factory>
where
    Factory: DatabaseProviderFactory<Provider: BlockReader>
        + StateCommitmentProvider
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Generate a state multiproof according to specified targets.
    pub fn multiproof(
        self,
        targets: HashMap<B256, HashSet<B256>>,
    ) -> Result<MultiProof, ParallelStateRootError> {
        let mut tracker = ParallelTrieTracker::default();

        let trie_nodes_sorted = self.input.nodes.clone().into_sorted();
        let hashed_state_sorted = self.input.state.clone().into_sorted();

        // Extend prefix sets with targets
        let mut prefix_sets = self.input.prefix_sets.clone();
        prefix_sets.extend(TriePrefixSetsMut {
            account_prefix_set: PrefixSetMut::from(targets.keys().copied().map(Nibbles::unpack)),
            storage_prefix_sets: targets
                .iter()
                .filter(|&(_hashed_address, slots)| (!slots.is_empty()))
                .map(|(hashed_address, slots)| {
                    (*hashed_address, PrefixSetMut::from(slots.iter().map(Nibbles::unpack)))
                })
                .collect(),
            destroyed_accounts: Default::default(),
        });
        let prefix_sets = prefix_sets.freeze();

        let storage_root_targets = StorageRootTargets::new(
            prefix_sets.account_prefix_set.iter().map(|nibbles| B256::from_slice(&nibbles.pack())),
            prefix_sets.storage_prefix_sets.clone(),
        );
        let storage_root_targets_len = storage_root_targets.len();

        // Pre-calculate storage roots for accounts which were changed.
        tracker.set_precomputed_storage_roots(storage_root_targets_len as u64);
        debug!(target: "trie::parallel_state_root", len = storage_root_targets.len(), "pre-generating storage proofs");
        let mut storage_proofs = storage_root_targets
            .into_iter()
            .sorted_unstable_by_key(|(address, _)| *address)
            .par_bridge()
            .map_init(
                || (self.view.clone(), trie_nodes_sorted.clone(), hashed_state_sorted.clone()),
                |(view, trie_nodes_sorted, hashed_state_sorted), (hashed_address, prefix_set)| {
                    let target_slots = targets.get(&hashed_address).cloned().unwrap_or_default();

                    let provider_ro = view.provider_ro()?;
                    let trie_cursor_factory = InMemoryTrieCursorFactory::new(
                        DatabaseTrieCursorFactory::new(provider_ro.tx_ref()),
                        trie_nodes_sorted,
                    );
                    let hashed_cursor_factory = HashedPostStateCursorFactory::new(
                        DatabaseHashedCursorFactory::new(provider_ro.tx_ref()),
                        hashed_state_sorted,
                    );

                    let result = StorageProof::new_hashed(
                        trie_cursor_factory,
                        hashed_cursor_factory,
                        hashed_address,
                    )
                    .with_prefix_set_mut(PrefixSetMut::from(prefix_set.iter().cloned()))
                    .with_branch_node_hash_masks(self.collect_branch_node_hash_masks)
                    .storage_multiproof(target_slots)
                    .map_err(|e| ParallelStateRootError::Other(e.to_string()));

                    ProviderResult::Ok((hashed_address, result))
                },
            )
            .try_fold(B256HashMap::default, |mut acc, result| {
                let (hashed_address, result) = result?;

                acc.insert(hashed_address, result);
                ProviderResult::Ok(acc)
            })
            .reduce(
                || {
                    Ok(B256HashMap::with_capacity_and_hasher(
                        storage_root_targets_len,
                        Default::default(),
                    ))
                },
                |m1, m2| {
                    let mut m1 = m1?;
                    let m2 = m2?;
                    m1.extend(m2);
                    Ok(m1)
                },
            )
            .map_err(|err| {
                ParallelStateRootError::StorageRoot(StorageRootError::Database(
                    DatabaseError::Other(format!("{err:?}")),
                ))
            })?;

        let provider_ro = self.view.provider_ro()?;
        let trie_cursor_factory = InMemoryTrieCursorFactory::new(
            DatabaseTrieCursorFactory::new(provider_ro.tx_ref()),
            &trie_nodes_sorted,
        );
        let hashed_cursor_factory = HashedPostStateCursorFactory::new(
            DatabaseHashedCursorFactory::new(provider_ro.tx_ref()),
            &hashed_state_sorted,
        );

        // Create the walker.
        let walker = TrieWalker::new(
            trie_cursor_factory.account_trie_cursor().map_err(ProviderError::Database)?,
            prefix_sets.account_prefix_set,
        )
        .with_deletions_retained(true);

        // Create a hash builder to rebuild the root node since it is not available in the database.
        let retainer: ProofRetainer = targets.keys().map(Nibbles::unpack).collect();
        let mut hash_builder = HashBuilder::default()
            .with_proof_retainer(retainer)
            .with_updates(self.collect_branch_node_hash_masks);

        // Initialize all storage multiproofs as empty.
        // Storage multiproofs for non empty tries will be overwritten if necessary.
        let mut storages: B256HashMap<_> =
            targets.keys().map(|key| (*key, StorageMultiProof::empty())).collect();
        let mut account_rlp = Vec::with_capacity(TRIE_ACCOUNT_RLP_MAX_SIZE);
        let mut account_node_iter = TrieNodeIter::new(
            walker,
            hashed_cursor_factory.hashed_account_cursor().map_err(ProviderError::Database)?,
        );
        while let Some(account_node) =
            account_node_iter.try_next().map_err(ProviderError::Database)?
        {
            match account_node {
                TrieElement::Branch(node) => {
                    hash_builder.add_branch(node.key, node.value, node.children_are_in_trie);
                }
                TrieElement::Leaf(hashed_address, account) => {
                    let storage_multiproof = match storage_proofs.remove(&hashed_address) {
                        Some(result) => result?,
                        // Since we do not store all intermediate nodes in the database, there might
                        // be a possibility of re-adding a non-modified leaf to the hash builder.
                        None => {
                            tracker.inc_missed_leaves();
                            StorageProof::new_hashed(
                                trie_cursor_factory.clone(),
                                hashed_cursor_factory.clone(),
                                hashed_address,
                            )
                            .with_prefix_set_mut(Default::default())
                            .storage_multiproof(
                                targets.get(&hashed_address).cloned().unwrap_or_default(),
                            )
                            .map_err(|e| {
                                ParallelStateRootError::StorageRoot(StorageRootError::Database(
                                    DatabaseError::Other(e.to_string()),
                                ))
                            })?
                        }
                    };

                    // Encode account
                    account_rlp.clear();
                    let account = TrieAccount::from((account, storage_multiproof.root));
                    account.encode(&mut account_rlp as &mut dyn BufMut);

                    hash_builder.add_leaf(Nibbles::unpack(hashed_address), &account_rlp);

                    // We might be adding leaves that are not necessarily our proof targets.
                    if targets.contains_key(&hashed_address) {
                        storages.insert(hashed_address, storage_multiproof);
                    }
                }
            }
        }
        let _ = hash_builder.root();

        #[cfg(feature = "metrics")]
        self.metrics.record_state_trie(tracker.finish());

        let account_subtree = hash_builder.take_proof_nodes();
        let branch_node_hash_masks = if self.collect_branch_node_hash_masks {
            hash_builder
                .updated_branch_nodes
                .unwrap_or_default()
                .into_iter()
                .map(|(path, node)| (path, node.hash_mask))
                .collect()
        } else {
            HashMap::default()
        };

        Ok(MultiProof { account_subtree, branch_node_hash_masks, storages })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, map::DefaultHashBuilder, Address, U256};
    use rand::Rng;
    use reth_primitives::{Account, StorageEntry};
    use reth_provider::{test_utils::create_test_provider_factory, HashingWriter};
    use reth_trie::proof::Proof;

    #[test]
    fn random_parallel_proof() {
        let factory = create_test_provider_factory();
        let consistent_view = ConsistentDbView::new(factory.clone(), None);

        let mut rng = rand::thread_rng();
        let state = (0..100)
            .map(|_| {
                let address = Address::random();
                let account =
                    Account { balance: U256::from(rng.gen::<u64>()), ..Default::default() };
                let mut storage = HashMap::<B256, U256, DefaultHashBuilder>::default();
                let has_storage = rng.gen_bool(0.7);
                if has_storage {
                    for _ in 0..100 {
                        storage.insert(
                            B256::from(U256::from(rng.gen::<u64>())),
                            U256::from(rng.gen::<u64>()),
                        );
                    }
                }
                (address, (account, storage))
            })
            .collect::<HashMap<_, _, DefaultHashBuilder>>();

        {
            let provider_rw = factory.provider_rw().unwrap();
            provider_rw
                .insert_account_for_hashing(
                    state.iter().map(|(address, (account, _))| (*address, Some(*account))),
                )
                .unwrap();
            provider_rw
                .insert_storage_for_hashing(state.iter().map(|(address, (_, storage))| {
                    (
                        *address,
                        storage
                            .iter()
                            .map(|(slot, value)| StorageEntry { key: *slot, value: *value }),
                    )
                }))
                .unwrap();
            provider_rw.commit().unwrap();
        }

        let mut targets =
            HashMap::<B256, HashSet<B256, DefaultHashBuilder>, DefaultHashBuilder>::default();
        for (address, (_, storage)) in state.iter().take(10) {
            let hashed_address = keccak256(*address);
            let mut target_slots = HashSet::<B256, DefaultHashBuilder>::default();

            for (slot, _) in storage.iter().take(5) {
                target_slots.insert(*slot);
            }

            if !target_slots.is_empty() {
                targets.insert(hashed_address, target_slots);
            }
        }

        let provider_rw = factory.provider_rw().unwrap();
        let trie_cursor_factory = DatabaseTrieCursorFactory::new(provider_rw.tx_ref());
        let hashed_cursor_factory = DatabaseHashedCursorFactory::new(provider_rw.tx_ref());

        assert_eq!(
            ParallelProof::new(consistent_view, Default::default())
                .multiproof(targets.clone())
                .unwrap(),
            Proof::new(trie_cursor_factory, hashed_cursor_factory).multiproof(targets).unwrap()
        );
    }
}
