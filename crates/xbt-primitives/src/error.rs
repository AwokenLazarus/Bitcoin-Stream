use thiserror::Error;

/// Everything a primitive can refuse.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("unexpected end of data: need {need} more bytes")]
    Truncated { need: usize },
    #[error("{0} trailing bytes after the object")]
    Trailing(usize),
    #[error("bad transaction encoding: {0}")]
    BadTx(&'static str),
    #[error("bad hex: {0}")]
    BadHex(String),
    #[error("bad address: {0}")]
    BadAddress(String),
    #[error("bad script: {0}")]
    BadScript(&'static str),
    #[error("bad key: {0}")]
    BadKey(&'static str),
    #[error("bad signature: {0}")]
    BadSignature(&'static str),
    #[error("sighash: {0}")]
    Sighash(&'static str),
    #[error("header: {0}")]
    Header(String),
    #[error("amount: {0}")]
    Amount(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
