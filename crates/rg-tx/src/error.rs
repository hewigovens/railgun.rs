use crate::MAX_INPUTS;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("note: {0}")]
    Note(#[from] rg_notes::Error),
    #[error("tree: {0:?}")]
    Tree(rg_tree::Error),
    #[error("no one tree holds {0} of this token in at most {MAX_INPUTS} unspent notes")]
    InsufficientNote(u128),
    #[error("value must be above zero")]
    ZeroValue,
    #[error("{0} inputs and {1} outputs: no such circuit")]
    Shape(usize, usize),
    #[error("Merkle proof does not match the root or the note")]
    BadProof,
    #[error("bad verifying key: {0}")]
    BadKey(&'static str),
}
