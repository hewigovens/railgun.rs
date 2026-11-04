#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("note: {0}")]
    Note(#[from] rg_notes::Error),
    #[error("tree: {0:?}")]
    Tree(rg_tree::Error),
    #[error("unspent notes do not cover {0} of this token")]
    InsufficientNote(u128),
    #[error("{0} is out of range")]
    OutOfRange(&'static str),
    #[error("RelayAdapt calls need a gas limit of at least {0}")]
    GasLimitTooLow(u64),
    #[error("value must be above zero")]
    ZeroValue,
    #[error("{0} inputs and {1} outputs: no such circuit")]
    Shape(usize, usize),
    #[error("Merkle proof does not match the root or the note")]
    BadProof,
    #[error("bad verifying key: {0}")]
    BadKey(&'static str),
    #[error("signing: {0}")]
    Signing(#[from] rg_keys::Error),
}
