#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("leaves start at {start} but the tree has {len}")]
    NotContiguous { start: usize, len: usize },
    #[error("{count} leaves at {start} overflow the tree")]
    Overflow { start: usize, count: usize },
    #[error("no leaf at {0}")]
    MissingLeaf(usize),
}
