//! Prepared command ready for execution.
//!
//! This module contains `PreparedCommand`, which can only be created
//! by `ProcPolicy::prepare()`. This ensures all execution goes through validation.

use crate::error::ExecError;
use crate::limits::ResourceLimits;
use crate::output::Output;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
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
    pub(crate) wrapper: Option<Wrapper>,
    pub(crate) launch_env: Vec<(String, String)>,
}

/// A launcher program that the validated command is run through.
#[derive(Debug, Clone)]
pub(crate) struct Wrapper {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<OsString>,
}

impl PreparedCommand {
    /// Launch the validated command through another program.
    ///
    /// The process is started as `program args_before... bin argv...`, where
    /// `bin` and `argv` are the validated binary and arguments. This is meant
    /// for OS sandbox launchers (for example `sandbox-exec -p <profile>` or a
    /// namespace launcher that ends its own options with `--`).
    ///
    /// Validation is unaffected: the binary allowlist, argument rules, env
    /// policy and cwd policy were applied to the original `bin`/`argv` by
    /// `ProcPolicy::prepare()`, and [`bin()`](Self::bin) and
    /// [`argv()`](Self::argv) keep returning those. `program` and
    /// `args_before` are trusted caller input and are not checked against the
    /// policy. Use [`launch_program()`](Self::launch_program) and
    /// [`launch_args()`](Self::launch_args) to see what will actually be
    /// executed.
    ///
    /// Calling this again replaces the previous wrapper.
    pub fn wrap_with<P, I, A>(mut self, program: P, args_before: I) -> Self
    where
        P: Into<PathBuf>,
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        self.wrapper = Some(Wrapper {
            program: program.into(),
            args: args_before.into_iter().map(Into::into).collect(),
        });
        self
    }

    /// Add an environment variable to the launched process.
    ///
    /// Launch variables are applied after the env policy, so they are passed
    /// even if the policy would not allow them, and they override policy
    /// values with the same name. They are trusted caller input (for example a
    /// sandbox-specific `TMPDIR`), not something to fill from a request.
    pub fn with_launch_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.launch_env.push((key.into(), value.into()));
        self
    }

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
        let mut cmd = Command::new(self.launch_program());
        cmd.args(self.launch_args())
            .current_dir(&self.cwd)
            .env_clear()
            .envs(&self.env)
            .envs(self.launch_env.iter().map(|(k, v)| (k, v)))
            // Own process group, so limits can kill grandchildren too.
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Spawn
        let mut child = cmd.spawn().map_err(|e| ExecError::SpawnFailed {
            reason: e.to_string(),
        })?;
        let pgid = child.id();

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

            // Run both concurrently; the first limit error stops both, so a
            // descendant holding the other pipe open cannot stall us.
            tokio::try_join!(stdout_result, stderr_result)?;

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
            Ok(Err(error)) => {
                // Kill the process group on limit exceeded
                kill_process_group(pgid);
                let _ = child.kill().await;
                Err(error)
            }
            Err(_) => {
                // Timeout - kill and return error
                let elapsed = start.elapsed();
                kill_process_group(pgid);
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

    /// Get the validated binary path.
    ///
    /// This is the binary checked against the policy, even after
    /// [`wrap_with()`](Self::wrap_with).
    pub fn bin(&self) -> &PathBuf {
        &self.bin
    }

    /// Get the validated arguments (not including the binary).
    ///
    /// These are unchanged by [`wrap_with()`](Self::wrap_with).
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// Get the environment produced by the env policy.
    ///
    /// Does not include variables added with
    /// [`with_launch_env()`](Self::with_launch_env).
    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    /// Get the variables added with [`with_launch_env()`](Self::with_launch_env).
    pub fn launch_env(&self) -> &[(String, String)] {
        &self.launch_env
    }

    /// Get the program that will be executed: the wrapper if set, else [`bin()`](Self::bin).
    pub fn launch_program(&self) -> &Path {
        match &self.wrapper {
            Some(w) => &w.program,
            None => &self.bin,
        }
    }

    /// Get the arguments passed to [`launch_program()`](Self::launch_program).
    ///
    /// Without a wrapper this equals [`argv()`](Self::argv). With one it is
    /// `args_before... bin argv...`.
    pub fn launch_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some(w) = &self.wrapper {
            args.extend(w.args.iter().cloned());
            args.push(self.bin.clone().into_os_string());
        }
        args.extend(self.argv.iter().map(OsString::from));
        args
    }

    /// Get the working directory.
    pub fn cwd(&self) -> &PathBuf {
        &self.cwd
    }
}

/// SIGKILL the process group led by `pgid` (the child spawned with `process_group(0)`).
///
/// Must be called before the child is reaped, so the group id cannot have
/// been reused.
fn kill_process_group(pgid: Option<u32>) {
    let Some(pgid) = pgid.and_then(|p| libc::pid_t::try_from(p).ok()) else {
        return;
    };
    if pgid <= 1 {
        return;
    }
    // SAFETY: killpg only sends a signal; it has no memory-safety preconditions.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}
