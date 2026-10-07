use thiserror::Error;
use xbt402::ChannelError;

/// What went wrong, for callers that branch on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A server could not be reached, dropped the connection, or stopped answering.
    Unreachable,
    /// A server answered with a JSON-RPC error (its own words, e.g. a broadcast refused).
    Server,
    /// Too few servers answered (`min_servers`).
    TooFewServers,
    /// Servers answered, but none is on the pinned checkpoint: the wrong chain (or the wrong checkpoint).
    CheckpointMismatch,
    /// Nothing verifiable: no server served the checkpoint yet, a height beyond our chain, ...
    NotFound,
    /// The call needs a full node (a node wallet, blocks, or mining).
    LightBackend,
    /// A malformed argument or configuration.
    BadRequest,
}

/// A light-backend failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{msg}")]
pub struct ElectrumError {
    pub kind: Kind,
    pub msg: String,
}

impl ElectrumError {
    pub fn new(kind: Kind, msg: impl Into<String>) -> Self {
        let mut msg = msg.into();
        if msg.len() > 400 {
            let mut i = 400;
            while !msg.is_char_boundary(i) {
                i -= 1;
            }
            msg.truncate(i);
        }
        Self { kind, msg }
    }
}

impl From<ElectrumError> for ChannelError {
    /// `light_backend` for calls a light client cannot answer, `chain_error` otherwise.
    fn from(e: ElectrumError) -> Self {
        let code = if e.kind == Kind::LightBackend { "light_backend" } else { "chain_error" };
        ChannelError::new(code, e.msg)
    }
}

pub type Result<T> = std::result::Result<T, ElectrumError>;

pub(crate) fn err<T>(kind: Kind, msg: impl Into<String>) -> Result<T> {
    Err(ElectrumError::new(kind, msg))
}
