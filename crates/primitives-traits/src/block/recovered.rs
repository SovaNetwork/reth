//! Recovered Block variant.

use crate::{block::SealedBlock, sync::OnceLock, transaction::signed::{RecoveryError, SignedTransactionIntoRecoveredExt}, Block, BlockBody, InMemorySize, SealedHeader};
use alloc::vec::Vec;
use alloy_consensus::BlockHeader;
use alloy_consensus::transaction::Recovered;
use alloy_eips::BlockNumHash;
use alloy_eips::eip1898::BlockWithParent;
use alloy_primitives::{Address, BlockHash, BlockNumber, Sealable};
use derive_more::Deref;

/// A block with senders recovered from transactions.
#[derive(Debug, Clone, PartialEq, Eq, Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecoveredBlock<B> {
    /// Block hash
    #[cfg_attr(feature = "serde", serde(skip))]
    hash: OnceLock<BlockHash>,
    /// Block
    #[deref]
    block: B,
    /// List of senders that match the transactions in the block
    senders: Vec<Address>,
}

impl<B> RecoveredBlock<B> {
    /// Creates a new recovered block instance with the given senders as provided and the block
    /// hash.
    pub fn new(block: B, senders: Vec<Address>, hash: BlockHash) -> Self {
        Self { hash: hash.into(), block, senders }
    }
    /// Creates a new recovered block instance with the given senders as provided
    pub fn new_unhashed(block: B, senders: Vec<Address>) -> Self {
        Self { hash: Default::default(), block, senders }
    }

    /// Returns the recovered senders.
    pub fn sender(&self) -> &[Address] {
        &self.senders
    }

    /// Returns an iterator over the recovered senders.
    pub fn senders_iter(&self) -> impl Iterator<Item = &Address> {
        self.senders.iter()
    }

    /// Consumes the type and returns the inner block.
    pub fn into_block(self) -> B {
        self.block
    }

    /// Returns a reference to the inner block.
    pub const fn block(&self) -> &B {
        &self.block
    }
}

impl<B: Block> RecoveredBlock<B> {
    /// A safer variant of [`Self::new_unhashed`] that checks if the number of senders is equal to
    /// the number of transactions in the block and recovers the senders from the transactions, if
    /// not using [`SignedTransaction::recover_signer`](crate::transaction::signed::SignedTransaction)
    /// to recover the senders.
    pub fn try_new(
        block: B,
        senders: Vec<Address>,
        hash: BlockHash,
    ) -> Result<Self, RecoveryError> {
        let senders = if block.body().transaction_count() == senders.len() {
            senders
        } else {
            block.body().try_recover_signers()?
        };
        Ok(Self::new(block, senders, hash))
    }

    /// A safer variant of [`Self::new`] that checks if the number of senders is equal to
    /// the number of transactions in the block and recovers the senders from the transactions, if
    /// not using [`SignedTransaction::recover_signer_unchecked`](crate::transaction::signed::SignedTransaction)
    /// to recover the senders.
    pub fn try_new_unchecked(
        block: B,
        senders: Vec<Address>,
        hash: BlockHash,
    ) -> Result<Self, RecoveryError> {
        let senders = if block.body().transaction_count() == senders.len() {
            senders
        } else {
            block.body().try_recover_signers_unchecked()?
        };
        Ok(Self::new(block, senders, hash))
    }

    /// A safer variant of [`Self::new_unhashed`] that checks if the number of senders is equal to
    /// the number of transactions in the block and recovers the senders from the transactions, if
    /// not using [`SignedTransaction::recover_signer`](crate::transaction::signed::SignedTransaction)
    /// to recover the senders.
    pub fn try_new_unhashed(block: B, senders: Vec<Address>) -> Result<Self, RecoveryError> {
        let senders = if block.body().transaction_count() == senders.len() {
            senders
        } else {
            block.body().try_recover_signers()?
        };
        Ok(Self::new_unhashed(block, senders))
    }

    /// A safer variant of [`Self::new_unhashed`] that checks if the number of senders is equal to
    /// the number of transactions in the block and recovers the senders from the transactions, if
    /// not using [`SignedTransaction::recover_signer_unchecked`](crate::transaction::signed::SignedTransaction)
    /// to recover the senders.
    pub fn try_new_unhashed_unchecked(
        block: B,
        senders: Vec<Address>,
    ) -> Result<Self, RecoveryError> {
        let senders = if block.body().transaction_count() == senders.len() {
            senders
        } else {
            block.body().try_recover_signers_unchecked()?
        };
        Ok(Self::new_unhashed(block, senders))
    }

    /// Recovers the senders from the transactions in the block using
    /// [`SignedTransaction::recover_signer`](crate::transaction::signed::SignedTransaction).
    ///
    /// Returns an error if any of the transactions fail to recover the sender.
    pub fn try_recover(block: B) -> Result<Self, RecoveryError> {
        let senders = block.body().try_recover_signers()?;
        Ok(Self::new_unhashed(block, senders))
    }

    /// Recovers the senders from the transactions in the block using
    /// [`SignedTransaction::recover_signer_unchecked`](crate::transaction::signed::SignedTransaction).
    ///
    /// Returns an error if any of the transactions fail to recover the sender.
    pub fn try_recover_unchecked(block: B) -> Result<Self, RecoveryError> {
        let senders = block.body().try_recover_signers_unchecked()?;
        Ok(Self::new_unhashed(block, senders))
    }

    /// Recovers the senders from the transactions in the block using
    /// [`SignedTransaction::recover_signer`](crate::transaction::signed::SignedTransaction).
    ///
    /// Returns an error if any of the transactions fail to recover the sender.
    pub fn try_recover_sealed(block: SealedBlock<B>) -> Result<Self, RecoveryError> {
        let senders = block.body().try_recover_signers()?;
        let (block, hash) = block.split();
        Ok(Self::new(block, senders, hash))
    }

    /// Recovers the senders from the transactions in the sealed block using
    /// [`SignedTransaction::recover_signer_unchecked`](crate::transaction::signed::SignedTransaction).
    ///
    /// Returns an error if any of the transactions fail to recover the sender.
    pub fn try_recover_sealed_unchecked(block: SealedBlock<B>) -> Result<Self, RecoveryError> {
        let senders = block.body().try_recover_signers_unchecked()?;
        let (block, hash) = block.split();
        Ok(Self::new(block, senders, hash))
    }

    /// A safer variant of [`Self::new_unhashed`] that checks if the number of senders is equal to
    /// the number of transactions in the block and recovers the senders from the transactions, if
    /// not using [`SignedTransaction::recover_signer_unchecked`](crate::transaction::signed::SignedTransaction)
    /// to recover the senders.
    ///
    /// Returns an error if any of the transactions fail to recover the sender.
    pub fn try_recover_sealed_with_senders(
        block: SealedBlock<B>,
        senders: Vec<Address>,
    ) -> Result<Self, RecoveryError> {
        let (block, hash) = block.split();
        Self::try_new(block, senders, hash)
    }

    /// A safer variant of [`Self::new`] that checks if the number of senders is equal to
    /// the number of transactions in the block and recovers the senders from the transactions, if
    /// not using [`SignedTransaction::recover_signer_unchecked`](crate::transaction::signed::SignedTransaction)
    /// to recover the senders.
    pub fn try_recover_sealed_with_senders_unchecked(
        block: SealedBlock<B>,
        senders: Vec<Address>,
    ) -> Result<Self, RecoveryError> {
        let (block, hash) = block.split();
        Self::try_new_unchecked(block, senders, hash)
    }

    /// Returns the block hash.
    pub fn hash_ref(&self) -> &BlockHash {
        self.hash.get_or_init(|| self.block.header().hash_slow())
    }

    /// Returns a copy of the block hash.
    pub fn hash(&self) -> BlockHash {
        *self.hash_ref()
    }

    /// Return the number hash tuple.
    pub fn num_hash(&self) -> BlockNumHash {
        BlockNumHash::new(self.header().number(), self.hash())
    }

    /// Return a [`BlockWithParent`] for this header.
    pub fn block_with_parent(&self) -> BlockWithParent {
        BlockWithParent { parent: self.header().parent_hash(), block: self.num_hash() }
    }

    /// Clones the internal header and returns a [`SealedHeader`] sealed with the hash.
    pub fn clone_sealed_header(&self) -> SealedHeader<B::Header> {
        SealedHeader::new(self.header().clone(), self.hash())
    }

    /// Clones the wrapped block and returns the [`SealedBlock`] sealed with the hash.
    pub fn clone_sealed_block(&self) -> SealedBlock<B> {
        let hash = self.hash();
        SealedBlock::new(self.block.clone(), hash)
    }

    /// Consumes the block and returns the [`SealedBlock`] and drops the recovered senders.
    pub fn into_sealed_block(self) -> SealedBlock<B> {
        let hash = self.hash();
        SealedBlock::new(self.block, hash)
    }

    /// Consumes the type and returns its components.
    pub fn split_sealed(self) -> (SealedBlock<B>, Vec<Address>) {
        let hash = self.hash();
        (SealedBlock::new(self.block, hash), self.senders)
    }

    /// Consumes the type and returns its components.
    #[doc(alias = "into_components")]
    pub fn split(self) -> (B, Vec<Address>) {
        (self.block, self.senders)
    }

    /// Returns an iterator over all transactions and their sender.
    #[inline]
    pub fn transactions_with_sender(
        &self,
    ) -> impl Iterator<Item = (&Address, &<B::Body as BlockBody>::Transaction)> + '_ {
        self.senders.iter().zip(self.block.body().transactions())
    }

    /// Returns an iterator over all transactions in the block.
    #[inline]
    pub fn into_transactions_ecrecovered(
        self,
    ) -> impl Iterator<Item = Recovered<<B::Body as BlockBody>::Transaction>> {
        self.block
            .split()
            .1
            .into_transactions()
            .into_iter()
            .zip(self.senders)
            .map(|(tx, sender)| tx.with_signer(sender))
    }

    /// Consumes the block and returns the transactions of the block.
    #[inline]
    pub fn into_transactions(self) -> Vec<<B::Body as BlockBody>::Transaction> {
        self.block.split().1.into_transactions()
    }

    /// Retrieves the block number
    pub fn number(&self) -> BlockNumber {
        self.header().number()
    }
}

impl<B: Default> Default for RecoveredBlock<B> {
    #[inline]
    fn default() -> Self {
        Self::new_unhashed(B::default(), Default::default())
    }
}

impl<B: InMemorySize> InMemorySize for RecoveredBlock<B> {
    #[inline]
    fn size(&self) -> usize {
        self.block.size() +
            core::mem::size_of::<BlockHash>() +
            self.senders.len() * core::mem::size_of::<Address>()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl<B> RecoveredBlock<B>
where
    B: Block,
{

    /// Returns a mutable reference to the block.
    pub fn block_mut(&mut self) -> &mut B {
        &mut self.block
    }

    /// Returns a mutable reference to the recovered senders.
    pub fn senders_mut(&mut self) -> &mut Vec<Address> {
        &mut self.senders
    }

    /// Appends the sender to the list of senders.
    pub fn push_sender(&mut self, sender: Address) {
        self.senders.push(sender);
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl<B> core::ops::DerefMut for RecoveredBlock<B>
where
    B: Block,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.block
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, B> arbitrary::Arbitrary<'a> for RecoveredBlock<B>
where
    B: Block + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let block = B::arbitrary(u)?;
        Ok(Self::try_recover(block).unwrap())
    }
}

/// Bincode-compatible [`RecoveredBlock`] serde implementation.
#[cfg(feature = "serde-bincode-compat")]
pub(super) mod serde_bincode_compat {
    use crate::{serde_bincode_compat::SerdeBincodeCompat, Block};
    use alloc::{borrow::Cow, vec::Vec};
    use alloy_primitives::{Address, BlockHash};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    /// Bincode-compatible [`super::RecoveredBlock`] serde implementation.
    ///
    /// Intended to use with the [`serde_with::serde_as`] macro in the following way:
    /// ```rust
    /// use reth_primitives_traits::{block::SealedBlock, serde_bincode_compat};
    /// use serde::{Deserialize, Serialize};
    /// use serde_with::serde_as;
    ///
    /// #[serde_as]
    /// #[derive(Serialize, Deserialize)]
    /// struct Data<T: SerdeBincodeCompat> {
    ///     #[serde_as(as = "serde_bincode_compat::RecoveredBlock<'a, T>")]
    ///     header: RecoveredBlock<T>,
    /// }
    /// ```
    #[derive(derive_more::Debug, Serialize, Deserialize)]
    #[debug(bound(T::BincodeRepr<'a>: core::fmt::Debug))]
    pub struct RecoveredBlock<'a, T: Block + SerdeBincodeCompat> {
        hash: BlockHash,
        block: T::BincodeRepr<'a>,
        senders: Cow<'a, Vec<Address>>,
    }

    impl<'a, T: Block + SerdeBincodeCompat> From<&'a super::RecoveredBlock<T>>
        for RecoveredBlock<'a, T>
    {
        fn from(value: &'a super::RecoveredBlock<T>) -> Self {
            Self {
                hash: value.hash(),
                block: (&value.block).into(),
                senders: Cow::Borrowed(&value.senders),
            }
        }
    }

    impl<'a, T: Block + SerdeBincodeCompat> From<RecoveredBlock<'a, T>> for super::RecoveredBlock<T> {
        fn from(value: RecoveredBlock<'a, T>) -> Self {
            Self::new(value.block.into(), value.senders.into_owned(), value.hash)
        }
    }

    impl<T: Block + SerdeBincodeCompat> SerializeAs<super::RecoveredBlock<T>>
        for RecoveredBlock<'_, T>
    {
        fn serialize_as<S>(
            source: &super::RecoveredBlock<T>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            RecoveredBlock::from(source).serialize(serializer)
        }
    }

    impl<'de, T: Block + SerdeBincodeCompat> DeserializeAs<'de, super::RecoveredBlock<T>>
        for RecoveredBlock<'de, T>
    {
        fn deserialize_as<D>(deserializer: D) -> Result<super::RecoveredBlock<T>, D::Error>
        where
            D: Deserializer<'de>,
        {
            RecoveredBlock::deserialize(deserializer).map(Into::into)
        }
    }

    impl<T: Block + SerdeBincodeCompat> SerdeBincodeCompat for super::RecoveredBlock<T> {
        type BincodeRepr<'a> = RecoveredBlock<'a, T>;
    }
}
