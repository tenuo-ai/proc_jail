//! Resource limits for process execution.

use std::time::Duration;

/// Resource limits applied during process execution.
///
/// When any limit is exceeded, the process is killed with SIGKILL
/// and partial output up to the limit is captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Wall-clock timeout for the process.
    ///
    /// Default: 30 seconds.
    pub timeout: Duration,

    /// Maximum bytes to capture from stdout.
    ///
    /// If exceeded, process is killed and `ExecError::StdoutLimitExceeded` is returned.
    /// Default: 10 MB.
    pub max_stdout: usize,

    /// Maximum bytes to capture from stderr.
    ///
    /// If exceeded, process is killed and `ExecError::StderrLimitExceeded` is returned.
    /// Default: 1 MB.
    pub max_stderr: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_stdout: 10 * 1024 * 1024, // 10 MB
            max_stderr: 1024 * 1024,      // 1 MB
        }
    }
}

impl ResourceLimits {
    /// Create new limits with specified timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set maximum stdout bytes.
    pub fn with_max_stdout(mut self, max: usize) -> Self {
        self.max_stdout = max;
        self
    }

    /// Set maximum stderr bytes.
    pub fn with_max_stderr(mut self, max: usize) -> Self {
        self.max_stderr = max;
        self
    }
}
