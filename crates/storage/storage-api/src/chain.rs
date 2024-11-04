use reth_primitives::BlockHashOrNumber;
use reth_primitives_traits::NodePrimitives;
use reth_storage_errors::provider::ProviderResult;
use std::fmt::Debug;

/// Trait that implements how complex types (eg. Block) should be read from disk.
pub trait ChainStorageReader<P>: Send + Sync + Unpin + Default + Debug + 'static {
    /// Primitive types of the node.
    type Primitives: NodePrimitives;

    /// Returns the block with given id from storage.
    ///
    /// Returns `None` if block is not found.
    fn read_block(
        &self,
        provider: &P,
        id: BlockHashOrNumber,
    ) -> ProviderResult<Option<<Self::Primitives as NodePrimitives>::Block>>;
}

/// Trait that implements how complex types (eg. Block) should be written to disk.
pub trait ChainStorageWriter<P>: Send + Sync + Unpin + Default + Debug + 'static {
    /// Primitive types of the node.
    type Primitives: NodePrimitives;

    /// Writes block to disk.
    fn write_block(
        &self,
        provider: &P,
        block: &<Self::Primitives as NodePrimitives>::Block,
    ) -> ProviderResult<()>;
}

impl<P> ChainStorageReader<P> for () {
    type Primitives = ();

    fn read_block(
        &self,
        _: &P,
        _: BlockHashOrNumber,
    ) -> ProviderResult<Option<<Self::Primitives as NodePrimitives>::Block>> {
        todo!()
    }
}

impl<P> ChainStorageWriter<P> for () {
    type Primitives = ();

    fn write_block(
        &self,
        _: &P,
        _: &<Self::Primitives as NodePrimitives>::Block,
    ) -> ProviderResult<()> {
        todo!()
    }
}
