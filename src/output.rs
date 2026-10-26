//! Output capture utilities.

use std::process::ExitStatus;

/// Output from a successfully executed command.
#[derive(Debug, Clone)]
pub struct Output {
    /// Standard output bytes.
    pub stdout: Vec<u8>,

    /// Standard error bytes.
    pub stderr: Vec<u8>,

    /// Exit status of the process.
    pub status: ExitStatus,
}

impl Output {
    /// Get stdout as a string (lossy UTF-8 conversion).
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Get stderr as a string (lossy UTF-8 conversion).
    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Check if the process exited successfully (code 0).
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// Get the exit code if available.
    pub fn code(&self) -> Option<i32> {
        self.status.code()
    }
}

/// Output read before a command was stopped by its timeout or an output
/// limit, capped at the limits.
///
/// Its `Debug` shows only the byte counts, so logging the error does not
/// log the command's output.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PartialOutput {
    /// Standard output bytes.
    pub stdout: Vec<u8>,

    /// Standard error bytes.
    pub stderr: Vec<u8>,
}

impl PartialOutput {
    /// Get stdout as a string (lossy UTF-8 conversion).
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Get stderr as a string (lossy UTF-8 conversion).
    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

impl std::fmt::Debug for PartialOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartialOutput")
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .finish()
    }
}
