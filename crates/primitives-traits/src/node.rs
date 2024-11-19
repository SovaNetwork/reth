use core::fmt;

use crate::{
    BlockBody, FullBlock, FullBlockBody, FullBlockHeader, FullReceipt, FullSignedTx, FullTxType,
    MaybeSerde,
};

/// Configures all the primitive types of the node.
pub trait NodePrimitives:
    Send + Sync + Unpin + Clone + Default + fmt::Debug + PartialEq + Eq + 'static
{
    /// Block primitive.
    type Block: Send
        + Sync
        + Unpin
        + Clone
        + Default
        + fmt::Debug
        + PartialEq
        + Eq
        + MaybeSerde
        + 'static;
    /// Block header primitive.
    type BlockHeader: Send
        + Sync
        + Unpin
        + Clone
        + Default
        + fmt::Debug
        + PartialEq
        + Eq
        + MaybeSerde
        + 'static;
    /// Block body primitive.
    type BlockBody: Send
        + Sync
        + Unpin
        + Clone
        + Default
        + fmt::Debug
        + PartialEq
        + Eq
        + MaybeSerde
        + 'static;
    /// Signed version of the transaction type.
    type SignedTx: Send
        + Sync
        + Unpin
        + Clone
        + Default
        + fmt::Debug
        + PartialEq
        + Eq
        + MaybeSerde
        + 'static;
    /// Transaction envelope type ID.
    type TxType: Send + Sync + Unpin + Clone + Default + fmt::Debug + PartialEq + Eq + 'static;
    /// A receipt.
    type Receipt: Send
        + Sync
        + Unpin
        + Clone
        + Default
        + fmt::Debug
        + PartialEq
        + Eq
        + MaybeSerde
        + 'static;
}

impl NodePrimitives for () {
    type Block = ();
    type BlockHeader = ();
    type BlockBody = ();
    type SignedTx = ();
    type TxType = ();
    type Receipt = ();
}

/// Helper trait that sets trait bounds on [`NodePrimitives`].
pub trait FullNodePrimitives:
    Send + Sync + Unpin + Clone + Default + fmt::Debug + PartialEq + Eq + 'static
{
    /// Block primitive.
    type Block: FullBlock<Body: BlockBody<Transaction = Self::SignedTx>>;
    /// Signed version of the transaction type.
    type SignedTx: FullSignedTx;
    /// Block header primitive.
    type BlockHeader: FullBlockHeader + 'static;
    /// Block body primitive.
    type BlockBody: FullBlockBody<Header = Self::BlockHeader, Transaction = Self::SignedTx>
        + 'static;
    /// Transaction envelope type ID.
    type TxType: FullTxType;
    /// A receipt.
    type Receipt: FullReceipt;
}

impl<T> NodePrimitives for T
where
    T: FullNodePrimitives,
{
    type Block = T::Block;
    type BlockHeader = T::BlockHeader;
    type BlockBody = T::BlockBody;
    type SignedTx = T::SignedTx;
    type TxType = T::TxType;
    type Receipt = T::Receipt;
}
