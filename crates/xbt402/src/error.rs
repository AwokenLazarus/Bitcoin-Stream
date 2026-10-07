use thiserror::Error;

/// A state, funding or request the protocol refuses. `code` is the wire error code (the 402
/// `error` field, or a control endpoint's `{"error": code}`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{}", if .msg.is_empty() { .code.clone() } else { format!("{}: {}", .code, .msg) })]
pub struct ChannelError {
    pub code: String,
    pub msg: String,
}

impl ChannelError {
    pub fn new(code: &str, msg: impl Into<String>) -> Self {
        Self { code: code.to_string(), msg: msg.into() }
    }

    pub fn code(code: &str) -> Self {
        Self { code: code.to_string(), msg: String::new() }
    }
}

impl From<xbt_primitives::Error> for ChannelError {
    fn from(e: xbt_primitives::Error) -> Self {
        ChannelError::new("bad_request", e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ChannelError>;

/// `ChannelError::new(code, msg)` as an `Err`.
pub(crate) fn fail<T>(code: &str, msg: impl Into<String>) -> Result<T> {
    Err(ChannelError::new(code, msg))
}
