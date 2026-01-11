//! Process execution request.

use std::collections::HashMap;
use std::path::PathBuf;

/// A proposed process execution request.
///
/// This struct represents what the caller wants to execute.
/// It must be validated by `ProcPolicy::prepare()` before execution.
#[derive(Debug, Clone)]
pub struct ProcRequest {
    /// Absolute path to the binary to execute.
    ///
    /// Must be an absolute path (starts with `/`).
    /// Will be canonicalized during validation.
    pub bin: PathBuf,

    /// Arguments to pass to the binary (not including the binary path itself).
    ///
    /// These are passed directly to execve as argv[1..].
    pub argv: Vec<String>,

    /// Environment variables to pass to the process.
    ///
    /// Subject to filtering by the policy's `EnvPolicy`.
    /// Default is empty.
    pub env: HashMap<String, String>,

    /// Working directory for the process.
    ///
    /// If `None`, the policy's default cwd will be used.
    /// If `Some`, must be allowed by the policy's `CwdPolicy`.
    pub cwd: Option<PathBuf>,
}

impl ProcRequest {
    /// Create a new request with minimal arguments.
    pub fn new(bin: impl Into<PathBuf>, argv: Vec<String>) -> Self {
        Self {
            bin: bin.into(),
            argv,
            env: HashMap::new(),
            cwd: None,
        }
    }

    /// Set the working directory.
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set environment variables.
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Add a single environment variable.
    pub fn with_env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }
}

impl Default for ProcRequest {
    fn default() -> Self {
        Self {
            bin: PathBuf::new(),
            argv: Vec::new(),
            env: HashMap::new(),
            cwd: None,
        }
    }
}
