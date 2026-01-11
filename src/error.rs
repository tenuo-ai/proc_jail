//! Error types for proc_jail.
//!
//! This module defines two main error categories:
//! - [`Violation`]: Policy violations detected during `prepare()` - the request is rejected
//! - [`ExecError`]: Execution errors during `spawn()` - the command was valid but execution failed

use std::time::Duration;
use thiserror::Error;

/// Risk category for dangerous binaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskCategory {
    /// Shell interpreters (sh, bash, zsh, etc.)
    Shell,
    /// Script interpreters (python, perl, ruby, node, etc.)
    Interpreter,
    /// Process spawners (env, xargs, find -exec, etc.)
    Spawner,
    /// Privilege escalation tools (sudo, su, pkexec, etc.)
    Privilege,
}

impl std::fmt::Display for RiskCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskCategory::Shell => write!(f, "shell"),
            RiskCategory::Interpreter => write!(f, "interpreter"),
            RiskCategory::Spawner => write!(f, "spawner"),
            RiskCategory::Privilege => write!(f, "privilege"),
        }
    }
}

/// Policy violation detected during `prepare()`.
///
/// These errors indicate the request was rejected before any execution attempt.
/// All error messages are safe to log (no secrets included).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Violation {
    // Binary errors
    /// Binary path is not absolute
    #[error("binary path must be absolute: {path}")]
    BinNotAbsolute { path: String },

    /// Binary does not exist
    #[error("binary not found: {path}")]
    BinNotFound { path: String },

    /// Failed to canonicalize binary path
    #[error("failed to canonicalize binary path {path}: {reason}")]
    BinCanonicalizeFailed { path: String, reason: String },

    /// Binary is not in the allowlist
    #[error("binary not allowed: {path} (resolved to {canonical})")]
    BinNotAllowed { path: String, canonical: String },

    /// Binary is a risky type and policy denies it
    #[error("risky binary denied ({category}): {path}")]
    BinRiskyDenied {
        path: String,
        category: RiskCategory,
    },

    /// Binary path points to a directory
    #[error("binary path is a directory: {path}")]
    BinIsDirectory { path: String },

    /// Binary is not a regular file
    #[error("binary is not a regular file: {path}")]
    BinNotRegularFile { path: String },

    /// Binary is not executable
    #[error("binary is not executable: {path}")]
    BinNotExecutable { path: String },

    // Argument errors
    /// ArgRules not defined for a binary in the allowlist
    #[error("argument rules required for binary: {bin}")]
    ArgRulesRequired { bin: String },

    /// First argument does not match required subcommand
    #[error("subcommand mismatch: expected {expected}, got {got:?}")]
    ArgSubcommandMismatch {
        expected: String,
        got: Option<String>,
    },

    /// Flag is not in the allowlist
    #[error("flag not allowed: {flag}")]
    ArgFlagNotAllowed { flag: String },

    /// Too many flags provided
    #[error("too many flags: max {max}, got {got}")]
    ArgTooManyFlags { max: usize, got: usize },

    /// Too many positional arguments provided
    #[error("too many positional arguments: max {max}, got {got}")]
    ArgTooManyPositionals { max: usize, got: usize },

    // Environment errors
    /// Environment variable is forbidden
    #[error("environment variable forbidden: {key} ({reason})")]
    EnvForbidden { key: String, reason: &'static str },

    // Working directory errors
    /// Working directory is not allowed
    #[error("working directory forbidden: {path} ({reason})")]
    CwdForbidden { path: String, reason: String },
}

/// Execution error during `spawn()`.
///
/// These errors indicate the command was valid but execution failed.
#[derive(Debug, Error)]
pub enum ExecError {
    /// Process exceeded timeout and was killed
    #[error("process timed out after {elapsed:?} (limit: {limit:?})")]
    Timeout { limit: Duration, elapsed: Duration },

    /// Process exceeded stdout limit and was killed
    #[error("stdout limit exceeded: {limit} bytes")]
    StdoutLimitExceeded { limit: usize },

    /// Process exceeded stderr limit and was killed
    #[error("stderr limit exceeded: {limit} bytes")]
    StderrLimitExceeded { limit: usize },

    /// Failed to spawn the process
    #[error("failed to spawn process: {reason}")]
    SpawnFailed { reason: String },

    /// Process exited with non-zero status
    #[error("process exited with code {code}")]
    NonZeroExit { code: i32, stderr: String },
}

/// Combined error type for the prepare-and-spawn flow.
#[derive(Debug, Error)]
pub enum ProcError {
    #[error(transparent)]
    Violation(#[from] Violation),

    #[error(transparent)]
    Exec(#[from] ExecError),
}
