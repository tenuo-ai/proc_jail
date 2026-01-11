//! Prepared command ready for execution.
//!
//! This module contains `PreparedCommand`, which can only be created
//! by `ProcPolicy::prepare()`. This ensures all execution goes through validation.

use crate::error::ExecError;
use crate::limits::ResourceLimits;
use crate::output::Output;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

/// A validated command ready for execution.
///
/// This type cannot be constructed outside of `proc_jail`.
/// The only way to create it is via `ProcPolicy::prepare()`.
#[derive(Debug, Clone)]
pub struct PreparedCommand {
    pub(crate) bin: PathBuf,
    pub(crate) argv: Vec<String>,
    pub(crate) env: HashMap<String, String>,
    pub(crate) cwd: PathBuf,
    pub(crate) limits: ResourceLimits,
}

impl PreparedCommand {
    /// Execute the prepared command asynchronously.
    ///
    /// # Returns
    ///
    /// The output of the command, or an error if execution failed.
    ///
    /// # Errors
    ///
    /// - `ExecError::SpawnFailed` if the process couldn't be started
    /// - `ExecError::Timeout` if the process exceeded the timeout
    /// - `ExecError::StdoutLimitExceeded` if stdout exceeded the limit
    /// - `ExecError::StderrLimitExceeded` if stderr exceeded the limit
    pub async fn spawn(self) -> Result<Output, ExecError> {
        let start = Instant::now();

        // Build the command
        let mut cmd = Command::new(&self.bin);
        cmd.args(&self.argv)
            .current_dir(&self.cwd)
            .env_clear()
            .envs(&self.env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Spawn
        let mut child = cmd.spawn().map_err(|e| ExecError::SpawnFailed {
            reason: e.to_string(),
        })?;

        // Take ownership of stdout/stderr
        let mut stdout = child.stdout.take().expect("stdout piped");
        let mut stderr = child.stderr.take().expect("stderr piped");

        let limits = self.limits;

        // Read stdout and stderr concurrently with limits
        let read_future = async {
            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();

            // Read stdout with limit
            let stdout_result = async {
                let mut buf = [0u8; 8192];
                loop {
                    match stdout.read(&mut buf).await {
                        Ok(0) => break Ok(()), // EOF
                        Ok(n) => {
                            if stdout_buf.len() + n > limits.max_stdout {
                                let remaining = limits.max_stdout.saturating_sub(stdout_buf.len());
                                stdout_buf.extend_from_slice(&buf[..remaining]);
                                break Err(ExecError::StdoutLimitExceeded {
                                    limit: limits.max_stdout,
                                });
                            }
                            stdout_buf.extend_from_slice(&buf[..n]);
                        }
                        Err(e) => {
                            break Err(ExecError::SpawnFailed {
                                reason: format!("stdout read error: {}", e),
                            });
                        }
                    }
                }
            };

            // Read stderr with limit
            let stderr_result = async {
                let mut buf = [0u8; 8192];
                loop {
                    match stderr.read(&mut buf).await {
                        Ok(0) => break Ok(()), // EOF
                        Ok(n) => {
                            if stderr_buf.len() + n > limits.max_stderr {
                                let remaining = limits.max_stderr.saturating_sub(stderr_buf.len());
                                stderr_buf.extend_from_slice(&buf[..remaining]);
                                break Err(ExecError::StderrLimitExceeded {
                                    limit: limits.max_stderr,
                                });
                            }
                            stderr_buf.extend_from_slice(&buf[..n]);
                        }
                        Err(e) => {
                            break Err(ExecError::SpawnFailed {
                                reason: format!("stderr read error: {}", e),
                            });
                        }
                    }
                }
            };

            // Run both concurrently
            let (stdout_res, stderr_res) = tokio::join!(stdout_result, stderr_result);

            // Check for errors
            if let Err(e) = stdout_res {
                return Err((e, stdout_buf, stderr_buf));
            }
            if let Err(e) = stderr_res {
                return Err((e, stdout_buf, stderr_buf));
            }

            Ok((stdout_buf, stderr_buf))
        };

        // Apply timeout
        let result = timeout(limits.timeout, read_future).await;

        match result {
            Ok(Ok((stdout_buf, stderr_buf))) => {
                // Wait for process to complete
                let status = child.wait().await.map_err(|e| ExecError::SpawnFailed {
                    reason: format!("wait error: {}", e),
                })?;

                Ok(Output {
                    stdout: stdout_buf,
                    stderr: stderr_buf,
                    status,
                })
            }
            Ok(Err((error, _stdout_buf, _stderr_buf))) => {
                // Kill the process on limit exceeded
                let _ = child.kill().await;
                Err(error)
            }
            Err(_) => {
                // Timeout - kill and return error
                let elapsed = start.elapsed();
                let _ = child.kill().await;
                Err(ExecError::Timeout {
                    limit: limits.timeout,
                    elapsed,
                })
            }
        }
    }

    /// Execute the prepared command synchronously.
    ///
    /// This is a convenience wrapper that creates a runtime if needed.
    pub fn spawn_sync(self) -> Result<Output, ExecError> {
        // Try to use existing runtime handle
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // We're in an async context, use block_on
            // Note: This can cause issues if called from within an async context
            std::thread::scope(|s| s.spawn(|| handle.block_on(self.spawn())).join().unwrap())
        } else {
            // Create a new runtime
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| ExecError::SpawnFailed {
                    reason: format!("failed to create runtime: {}", e),
                })?;
            rt.block_on(self.spawn())
        }
    }

    /// Get the binary path.
    pub fn bin(&self) -> &PathBuf {
        &self.bin
    }

    /// Get the arguments.
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// Get the environment.
    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    /// Get the working directory.
    pub fn cwd(&self) -> &PathBuf {
        &self.cwd
    }
}
