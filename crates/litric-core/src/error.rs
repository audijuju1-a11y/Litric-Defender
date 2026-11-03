//! Error types for the Litric engine.
//!
//! The engine parses hostile input, so every parser returns `Result` rather than
//! panicking. A malformed sample must never take down the scanning service.

use std::fmt;

/// Errors produced while parsing an untrusted file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The buffer is shorter than the structure being read.
    Truncated { what: &'static str, need: usize, have: usize },
    /// A magic number or structural invariant did not hold.
    BadMagic(&'static str),
    /// A size or offset field points outside the file.
    OutOfBounds { what: &'static str, offset: u64, len: u64 },
    /// A recursion or count limit was hit while parsing.
    LimitExceeded(&'static str),
    /// The file is not the format the parser expects.
    NotThisFormat,
    /// An arithmetic overflow occurred while computing an offset.
    Overflow(&'static str),
    /// The structure is present but semantically invalid.
    Invalid(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { what, need, have } => {
                write!(f, "truncated {what}: need {need} bytes, have {have}")
            }
            ParseError::BadMagic(w) => write!(f, "bad magic in {w}"),
            ParseError::OutOfBounds { what, offset, len } => {
                write!(f, "{what} out of bounds: offset {offset} len {len}")
            }
            ParseError::LimitExceeded(w) => write!(f, "limit exceeded: {w}"),
            ParseError::NotThisFormat => write!(f, "not this format"),
            ParseError::Overflow(w) => write!(f, "arithmetic overflow in {w}"),
            ParseError::Invalid(w) => write!(f, "invalid structure: {w}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Errors produced by the quarantine vault.
#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    /// The entry or key file is not in the expected format.
    Corrupt(String),
    /// AEAD authentication failed: wrong key or tampered data.
    Authentication,
    /// The restored content hash does not match the recorded hash.
    IntegrityMismatch { expected: String, actual: String },
    /// The requested object does not exist (already restored or purged).
    NotFound(String),
    /// The operation would overwrite or conflict with existing user data.
    Conflict(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "io error: {e}"),
            VaultError::Corrupt(m) => write!(f, "vault entry corrupt: {m}"),
            VaultError::Authentication => write!(f, "vault authentication failed"),
            VaultError::IntegrityMismatch { expected, actual } => {
                write!(f, "integrity mismatch: expected {expected}, got {actual}")
            }
            VaultError::NotFound(m) => write!(f, "{m}"),
            VaultError::Conflict(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

/// Errors produced while loading or verifying the threat database.
#[derive(Debug)]
pub enum DbError {
    Io(std::io::Error),
    Json(String),
    /// The detached signature over the payload did not verify.
    BadSignature,
    /// The manifest advertises a database the engine cannot use.
    EngineTooOld { required: String, actual: String },
    /// Anti-rollback: the candidate database is not newer than the installed one.
    Rollback { installed: u64, candidate: u64 },
    /// The payload hash does not match the manifest.
    PayloadHashMismatch,
    Invalid(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::Io(e) => write!(f, "io error: {e}"),
            DbError::Json(m) => write!(f, "json error: {m}"),
            DbError::BadSignature => write!(f, "threat database signature is invalid"),
            DbError::EngineTooOld { required, actual } => {
                write!(f, "database requires engine {required}, running {actual}")
            }
            DbError::Rollback { installed, candidate } => {
                write!(f, "rollback refused: installed {installed}, candidate {candidate}")
            }
            DbError::PayloadHashMismatch => write!(f, "threat database payload hash mismatch"),
            DbError::Invalid(m) => write!(f, "invalid threat database: {m}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        DbError::Io(e)
    }
}
