#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad log: {0}")]
    BadLog(String),
    #[error("abi decode: {0}")]
    Abi(String),
    #[error("value out of range: {0}")]
    Range(&'static str),
    #[error("unknown token type {0}")]
    TokenType(u8),
    #[error("tree: {0}")]
    Tree(#[from] rg_tree::Error),
    #[error(
        "log out of order: block {block} index {index} after block {last_block} index {last_index}"
    )]
    OutOfOrder {
        block: u64,
        index: u64,
        last_block: u64,
        last_index: u64,
    },
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("node refused: {0}")]
    Refused(String),
}
