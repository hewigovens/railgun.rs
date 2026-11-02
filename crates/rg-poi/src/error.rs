#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("tree: {0}")]
    Tree(#[from] rg_tree::Error),
    #[error("{0} inputs and {1} outputs do not fit this circuit")]
    TooLarge(usize, usize),
    #[error("{0} of {1} inputs have a POI merkle proof")]
    ProofCount(usize, usize),
    #[error("invalid merkle proof: {0}")]
    BadProof(&'static str),
}
