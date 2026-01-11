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
