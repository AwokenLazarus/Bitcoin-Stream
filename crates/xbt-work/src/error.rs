//! Errors: a grammar violation (a field outside §4/§5.1), and a scheme error carrying the §14
//! short code a 402 refusal names.
use std::fmt;

/// A value outside its grammar. Verifiers refuse it before any signature check (§5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrammarError(pub String);

impl GrammarError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for GrammarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "grammar: {}", self.0)
    }
}

impl std::error::Error for GrammarError {}

pub type GResult<T> = std::result::Result<T, GrammarError>;

/// A scheme error: `code` is the §14 short code (`bad_payload`, `bad_sig`, `equivocation`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkError {
    pub code: String,
    pub msg: String,
}

impl WorkError {
    pub fn new(code: &str, msg: impl Into<String>) -> Self {
        Self { code: code.into(), msg: msg.into() }
    }

    pub fn code(code: &str) -> Self {
        Self::new(code, "")
    }
}

impl fmt::Display for WorkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.msg.is_empty() { write!(f, "{}", self.code) } else { write!(f, "{}: {}", self.code, self.msg) }
    }
}

impl std::error::Error for WorkError {}

impl From<GrammarError> for WorkError {
    fn from(e: GrammarError) -> Self {
        Self::new("bad_payload", e.0)
    }
}

impl From<xbt402::ChannelError> for WorkError {
    fn from(e: xbt402::ChannelError) -> Self {
        Self::new(&e.code, e.msg)
    }
}

pub type Result<T> = std::result::Result<T, WorkError>;

pub(crate) fn fail<T>(code: &str, msg: impl Into<String>) -> Result<T> {
    Err(WorkError::new(code, msg))
}

impl From<xbt_primitives::Error> for WorkError {
    fn from(e: xbt_primitives::Error) -> Self {
        Self::new("bad_key", e.to_string())
    }
}
